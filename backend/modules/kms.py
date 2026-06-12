"""
AegisXDR Enterprise Key Management System (KMS)
Supports: AES-256-GCM, RSA-4096, ECC (Curve25519, P-256)
Features: Key generation, rotation, revocation, escrow, audit trails
"""
import os
import uuid
import json
import base64
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from core.config import settings


class KMSError(Exception):
    pass


class EnterpriseKMS:
    """Mini Amazon KMS / Google Cloud KMS implementation"""

    SUPPORTED_ALGORITHMS = ["AES-256-GCM", "RSA-4096", "ECC-P256", "ECC-X25519"]

    def __init__(self):
        self.key_store_path = Path(settings.KMS_KEY_STORE_PATH)
        self.key_store_path.mkdir(parents=True, exist_ok=True)
        self._master_key = self._load_or_create_master_key()
        self._key_cache: Dict[str, Any] = {}

    def _load_or_create_master_key(self) -> bytes:
        master_path = Path(settings.KMS_MASTER_KEY_PATH)
        master_path.parent.mkdir(parents=True, exist_ok=True)
        if master_path.exists():
            return master_path.read_bytes()
        key = os.urandom(32)
        master_path.write_bytes(key)
        os.chmod(master_path, 0o600)
        return key

    def _encrypt_key_material(self, plaintext: bytes) -> str:
        aesgcm = AESGCM(self._master_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ct).decode()

    def _decrypt_key_material(self, ciphertext: str) -> bytes:
        raw = base64.b64decode(ciphertext)
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(self._master_key)
        return aesgcm.decrypt(nonce, ct, None)

    def generate_key(self, name: str, algorithm: str, purpose: str = "encrypt",
                     tenant_id: str = "default", rotation_days: int = 90) -> Dict:
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise KMSError(f"Unsupported algorithm: {algorithm}")

        key_id = str(uuid.uuid4())
        key_data = {"id": key_id, "name": name, "algorithm": algorithm,
                    "purpose": purpose, "tenant_id": tenant_id,
                    "status": "active", "version": 1,
                    "created_at": datetime.utcnow().isoformat(),
                    "next_rotation": (datetime.utcnow() + timedelta(days=rotation_days)).isoformat()}

        if algorithm == "AES-256-GCM":
            raw_key = os.urandom(32)
            key_data["key_material"] = self._encrypt_key_material(raw_key)
            key_data["public_key"] = None

        elif algorithm == "RSA-4096":
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend())
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            key_data["key_material"] = self._encrypt_key_material(priv_pem)
            key_data["public_key"] = pub_pem.decode()

        elif algorithm == "ECC-P256":
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            key_data["key_material"] = self._encrypt_key_material(priv_pem)
            key_data["public_key"] = pub_pem.decode()

        elif algorithm == "ECC-X25519":
            private_key = X25519PrivateKey.generate()
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            key_data["key_material"] = self._encrypt_key_material(priv_pem)
            key_data["public_key"] = pub_pem.decode()

        self._save_key(key_id, key_data)
        self._key_cache[key_id] = key_data
        return {k: v for k, v in key_data.items() if k != "key_material"}

    def encrypt_data(self, key_id: str, plaintext: bytes) -> Dict:
        key_data = self._load_key(key_id)
        if key_data["status"] != "active":
            raise KMSError(f"Key {key_id} is not active (status: {key_data['status']})")
        if key_data["algorithm"] != "AES-256-GCM":
            raise KMSError("Data encryption requires AES-256-GCM key")

        raw_key = self._decrypt_key_material(key_data["key_material"])
        aesgcm = AESGCM(raw_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return {
            "key_id": key_id,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_data(self, key_id: str, ciphertext: str, nonce: str) -> bytes:
        key_data = self._load_key(key_id)
        if key_data["status"] == "revoked":
            raise KMSError(f"Key {key_id} has been revoked")

        raw_key = self._decrypt_key_material(key_data["key_material"])
        aesgcm = AESGCM(raw_key)
        return aesgcm.decrypt(
            base64.b64decode(nonce),
            base64.b64decode(ciphertext),
            None
        )

    def sign_data(self, key_id: str, data: bytes) -> Dict:
        key_data = self._load_key(key_id)
        if key_data["status"] != "active":
            raise KMSError(f"Key {key_id} is not active")
        if key_data["algorithm"] not in ["RSA-4096", "ECC-P256"]:
            raise KMSError("Signing requires RSA-4096 or ECC-P256 key")

        priv_pem = self._decrypt_key_material(key_data["key_material"])

        if key_data["algorithm"] == "RSA-4096":
            private_key = serialization.load_pem_private_key(priv_pem, None, default_backend())
            signature = private_key.sign(data, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        else:
            private_key = serialization.load_pem_private_key(priv_pem, None, default_backend())
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        return {
            "key_id": key_id,
            "signature": base64.b64encode(signature).decode(),
            "algorithm": key_data["algorithm"],
            "timestamp": datetime.utcnow().isoformat()
        }

    def verify_signature(self, key_id: str, data: bytes, signature: str) -> bool:
        try:
            key_data = self._load_key(key_id)
            pub_pem = key_data["public_key"].encode()

            if key_data["algorithm"] == "RSA-4096":
                public_key = serialization.load_pem_public_key(pub_pem, default_backend())
                public_key.verify(
                    base64.b64decode(signature), data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256())
            else:
                public_key = serialization.load_pem_public_key(pub_pem, default_backend())
                public_key.verify(base64.b64decode(signature), data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def rotate_key(self, key_id: str) -> Dict:
        old_key = self._load_key(key_id)
        old_key["status"] = "rotated"
        old_key["rotated_at"] = datetime.utcnow().isoformat()
        self._save_key(key_id, old_key)

        new_key = self.generate_key(
            name=f"{old_key['name']}_v{old_key['version'] + 1}",
            algorithm=old_key["algorithm"],
            purpose=old_key.get("purpose", "encrypt"),
            tenant_id=old_key["tenant_id"]
        )
        return {"old_key_id": key_id, "new_key_id": new_key["id"], "rotated_at": datetime.utcnow().isoformat()}

    def revoke_key(self, key_id: str, reason: str = "manual") -> Dict:
        key_data = self._load_key(key_id)
        key_data["status"] = "revoked"
        key_data["revoked_at"] = datetime.utcnow().isoformat()
        key_data["revocation_reason"] = reason
        self._save_key(key_id, key_data)
        if key_id in self._key_cache:
            del self._key_cache[key_id]
        return {"key_id": key_id, "revoked": True, "reason": reason}

    def list_keys(self, tenant_id: str = None) -> list:
        keys = []
        for kf in self.key_store_path.glob("*.json"):
            try:
                with open(kf) as f:
                    k = json.load(f)
                if tenant_id is None or k.get("tenant_id") == tenant_id:
                    safe = {x: k[x] for x in k if x not in ["key_material"]}
                    keys.append(safe)
            except Exception:
                continue
        return keys

    def _save_key(self, key_id: str, key_data: Dict):
        path = self.key_store_path / f"{key_id}.json"
        with open(path, "w") as f:
            json.dump(key_data, f, indent=2)
        os.chmod(path, 0o600)

    def _load_key(self, key_id: str) -> Dict:
        if key_id in self._key_cache:
            return self._key_cache[key_id]
        path = self.key_store_path / f"{key_id}.json"
        if not path.exists():
            raise KMSError(f"Key {key_id} not found")
        with open(path) as f:
            data = json.load(f)
        self._key_cache[key_id] = data
        return data


# Singleton instance
kms = EnterpriseKMS()
