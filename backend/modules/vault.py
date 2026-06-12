"""
AegisXDR Secrets Vault - HashiCorp Vault-like implementation
Stores: API Keys, Cloud Credentials, DB Passwords, Certs, JWT Secrets, SSH Keys
Features: Auto-rotation, Access Policies, Secret Leasing, Emergency Revocation
"""
import os
import uuid
import json
import base64
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from core.config import settings


class VaultError(Exception):
    pass


class SecretsVault:
    """Enterprise Secrets Management Vault"""

    SECRET_TYPES = ["api_key", "db_password", "certificate", "jwt_secret",
                    "ssh_key", "cloud_credential", "oauth_token", "custom"]

    def __init__(self):
        self.storage_path = Path(settings.VAULT_STORAGE_PATH)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._vault_key = self._derive_vault_key()
        self._lease_store: Dict[str, Dict] = {}

    def _derive_vault_key(self) -> bytes:
        salt_path = self.storage_path / ".vault_salt"
        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = os.urandom(32)
            salt_path.write_bytes(salt)
            os.chmod(salt_path, 0o600)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        password = settings.VAULT_MASTER_PASSWORD.encode()
        return kdf.derive(password)

    def _encrypt(self, plaintext: str) -> str:
        aesgcm = AESGCM(self._vault_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def _decrypt(self, ciphertext: str) -> str:
        raw = base64.b64decode(ciphertext)
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(self._vault_key)
        return aesgcm.decrypt(nonce, ct, None).decode()

    def store_secret(self, name: str, value: str, secret_type: str = "custom",
                     tenant_id: str = "default", access_policy: Dict = None,
                     lease_duration: int = 3600, auto_rotate: bool = False,
                     metadata: Dict = None) -> Dict:
        secret_id = str(uuid.uuid4())
        if access_policy is None:
            access_policy = {"roles": ["admin"], "users": []}

        secret_data = {
            "id": secret_id,
            "name": name,
            "secret_type": secret_type,
            "tenant_id": tenant_id,
            "encrypted_value": self._encrypt(value),
            "access_policy": access_policy,
            "lease_duration": lease_duration,
            "auto_rotate": auto_rotate,
            "revoked": False,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat(),
            "last_accessed": None,
            "last_rotated": None,
            "version": 1
        }

        self._save_secret(secret_id, secret_data)
        return {k: v for k, v in secret_data.items() if k != "encrypted_value"}

    def get_secret(self, secret_id: str, requester_role: str = "admin",
                   requester_id: str = None) -> Dict:
        secret = self._load_secret(secret_id)

        if secret["revoked"]:
            raise VaultError(f"Secret {secret_id} has been revoked")

        policy = secret.get("access_policy", {})
        allowed_roles = policy.get("roles", ["admin"])
        allowed_users = policy.get("users", [])

        if requester_role not in allowed_roles and requester_id not in allowed_users:
            raise VaultError(f"Access denied to secret {secret_id}")

        # Update last accessed
        secret["last_accessed"] = datetime.utcnow().isoformat()
        self._save_secret(secret_id, secret)

        # Create lease
        lease_id = str(uuid.uuid4())
        self._lease_store[lease_id] = {
            "secret_id": secret_id,
            "expires_at": (datetime.utcnow() + timedelta(seconds=secret["lease_duration"])).isoformat(),
            "requester": requester_id
        }

        return {
            "id": secret_id,
            "name": secret["name"],
            "value": self._decrypt(secret["encrypted_value"]),
            "secret_type": secret["secret_type"],
            "lease_id": lease_id,
            "lease_duration": secret["lease_duration"],
            "metadata": secret.get("metadata", {})
        }

    def rotate_secret(self, secret_id: str, new_value: str) -> Dict:
        secret = self._load_secret(secret_id)
        old_version = secret["version"]

        # Archive old version
        archive = dict(secret)
        archive["archived_at"] = datetime.utcnow().isoformat()
        self._save_secret(f"{secret_id}_v{old_version}", archive)

        # Update with new value
        secret["encrypted_value"] = self._encrypt(new_value)
        secret["version"] = old_version + 1
        secret["last_rotated"] = datetime.utcnow().isoformat()
        self._save_secret(secret_id, secret)

        return {"secret_id": secret_id, "version": secret["version"], "rotated_at": secret["last_rotated"]}

    def revoke_secret(self, secret_id: str, reason: str = "manual") -> Dict:
        secret = self._load_secret(secret_id)
        secret["revoked"] = True
        secret["revoked_at"] = datetime.utcnow().isoformat()
        secret["revocation_reason"] = reason
        self._save_secret(secret_id, secret)
        return {"secret_id": secret_id, "revoked": True, "reason": reason}

    def emergency_revoke_all(self, tenant_id: str) -> Dict:
        revoked = []
        for sf in self.storage_path.glob("*.json"):
            try:
                with open(sf) as f:
                    secret = json.load(f)
                if secret.get("tenant_id") == tenant_id and not secret.get("revoked"):
                    secret["revoked"] = True
                    secret["revoked_at"] = datetime.utcnow().isoformat()
                    secret["revocation_reason"] = "emergency_revoke"
                    with open(sf, "w") as f:
                        json.dump(secret, f)
                    revoked.append(secret["id"])
            except Exception:
                continue
        return {"tenant_id": tenant_id, "revoked_count": len(revoked), "secret_ids": revoked}

    def list_secrets(self, tenant_id: str = None) -> List[Dict]:
        secrets = []
        for sf in self.storage_path.glob("*.json"):
            if "_v" in sf.stem:
                continue
            try:
                with open(sf) as f:
                    s = json.load(f)
                if tenant_id is None or s.get("tenant_id") == tenant_id:
                    secrets.append({k: v for k, v in s.items() if k not in ["encrypted_value"]})
            except Exception:
                continue
        return secrets

    def check_lease(self, lease_id: str) -> Dict:
        lease = self._lease_store.get(lease_id)
        if not lease:
            return {"valid": False, "reason": "lease not found"}
        expires = datetime.fromisoformat(lease["expires_at"])
        if datetime.utcnow() > expires:
            del self._lease_store[lease_id]
            return {"valid": False, "reason": "lease expired"}
        return {"valid": True, "lease": lease}

    def _save_secret(self, secret_id: str, data: Dict):
        path = self.storage_path / f"{secret_id}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(path, 0o600)

    def _load_secret(self, secret_id: str) -> Dict:
        path = self.storage_path / f"{secret_id}.json"
        if not path.exists():
            raise VaultError(f"Secret {secret_id} not found")
        with open(path) as f:
            return json.load(f)


# Singleton
vault = SecretsVault()
