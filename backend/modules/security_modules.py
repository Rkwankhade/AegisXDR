"""
AegisXDR Security Modules:
- Secure Evidence Chain (Digital Forensics)
- Malware Sample Vault
- Signed Threat Intelligence
- Password Security Research Lab
- Ransomware Crypto Analysis
- Cryptographic Threat Detection
- Post-Quantum Cryptography (simulation)
"""
import os
import uuid
import json
import base64
import hashlib
import math
import re
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from core.config import settings


# ═══════════════════════════════════════════════════════════════
# 1. SECURE EVIDENCE CHAIN (Digital Forensics + Chain of Custody)
# ═══════════════════════════════════════════════════════════════

class ForensicsEngine:
    """SHA256 + SHA512 + Timestamp + Analyst Signature for every artifact"""

    def __init__(self):
        self.forensics_path = Path(settings.FORENSICS_PATH)
        self.forensics_path.mkdir(parents=True, exist_ok=True)
        self._signing_key = self._load_or_create_signing_key()

    def _load_or_create_signing_key(self):
        key_path = Path("./data/keys/forensics_signing.key")
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            return serialization.load_pem_private_key(
                key_path.read_bytes(), None, default_backend())
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        return key

    def collect_artifact(self, file_data: bytes, name: str, analyst: str,
                         incident_id: str = None, tenant_id: str = "default",
                         artifact_type: str = "file") -> Dict:
        artifact_id = str(uuid.uuid4())
        sha256 = hashlib.sha256(file_data).hexdigest()
        sha512 = hashlib.sha512(file_data).hexdigest()
        blake3_hash = self._blake3_simulate(file_data)
        timestamp = datetime.utcnow().isoformat()

        # Analyst signature over hash+timestamp
        sign_payload = f"{sha256}:{sha512}:{timestamp}:{analyst}".encode()
        signature = self._signing_key.sign(sign_payload, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(signature).decode()

        chain_entry = {
            "action": "collected",
            "analyst": analyst,
            "timestamp": timestamp,
            "signature": sig_b64,
            "hash_at_collection": sha256
        }

        artifact_meta = {
            "id": artifact_id,
            "name": name,
            "artifact_type": artifact_type,
            "sha256": sha256,
            "sha512": sha512,
            "blake3": blake3_hash,
            "file_size": len(file_data),
            "analyst": analyst,
            "analyst_signature": sig_b64,
            "tenant_id": tenant_id,
            "incident_id": incident_id,
            "chain_of_custody": [chain_entry],
            "created_at": timestamp
        }

        # Save artifact data
        artifact_path = self.forensics_path / f"{artifact_id}.bin"
        artifact_path.write_bytes(file_data)
        meta_path = self.forensics_path / f"{artifact_id}.meta.json"
        with open(meta_path, "w") as f:
            json.dump(artifact_meta, f, indent=2)

        return artifact_meta

    def transfer_custody(self, artifact_id: str, from_analyst: str,
                         to_analyst: str, reason: str) -> Dict:
        meta_path = self.forensics_path / f"{artifact_id}.meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Artifact {artifact_id} not found")
        with open(meta_path) as f:
            meta = json.load(f)

        timestamp = datetime.utcnow().isoformat()
        transfer_payload = f"{artifact_id}:{from_analyst}:{to_analyst}:{timestamp}".encode()
        signature = self._signing_key.sign(transfer_payload, ec.ECDSA(hashes.SHA256()))

        custody_entry = {
            "action": "transferred",
            "from_analyst": from_analyst,
            "to_analyst": to_analyst,
            "reason": reason,
            "timestamp": timestamp,
            "signature": base64.b64encode(signature).decode()
        }
        meta["chain_of_custody"].append(custody_entry)
        meta["analyst"] = to_analyst

        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        return custody_entry

    def verify_artifact_integrity(self, artifact_id: str) -> Dict:
        meta_path = self.forensics_path / f"{artifact_id}.meta.json"
        artifact_path = self.forensics_path / f"{artifact_id}.bin"
        if not meta_path.exists() or not artifact_path.exists():
            return {"valid": False, "reason": "Artifact or metadata missing"}

        with open(meta_path) as f:
            meta = json.load(f)
        data = artifact_path.read_bytes()

        current_sha256 = hashlib.sha256(data).hexdigest()
        current_sha512 = hashlib.sha512(data).hexdigest()

        hash_valid = (current_sha256 == meta["sha256"] and
                      current_sha512 == meta["sha512"])
        return {
            "valid": hash_valid,
            "artifact_id": artifact_id,
            "hash_match": hash_valid,
            "chain_entries": len(meta.get("chain_of_custody", [])),
            "original_sha256": meta["sha256"],
            "current_sha256": current_sha256,
            "tampered": not hash_valid
        }

    def _blake3_simulate(self, data: bytes) -> str:
        """BLAKE3 simulation using SHA3-256 + custom mixing"""
        h = hashlib.sha3_256(data).digest()
        mixed = hashlib.sha256(h + b"BLAKE3").hexdigest()
        return mixed

    def list_artifacts(self, tenant_id: str = None) -> List[Dict]:
        artifacts = []
        for f in self.forensics_path.glob("*.meta.json"):
            try:
                with open(f) as fp:
                    meta = json.load(fp)
                if tenant_id is None or meta.get("tenant_id") == tenant_id:
                    artifacts.append(meta)
            except Exception:
                pass
        return artifacts


# ═══════════════════════════════════════════════════════════════
# 2. MALWARE SAMPLE VAULT
# ═══════════════════════════════════════════════════════════════

class MalwareVault:
    """Encrypted, versioned, signed, audited malware storage"""

    def __init__(self):
        self.vault_path = Path(settings.MALWARE_VAULT_PATH)
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self._encryption_key = hashlib.sha256(
            settings.MALWARE_VAULT_KEY.encode()).digest()

    def _encrypt_sample(self, data: bytes) -> Tuple[bytes, bytes]:
        aesgcm = AESGCM(self._encryption_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce, ct

    def _decrypt_sample(self, nonce: bytes, ct: bytes) -> bytes:
        aesgcm = AESGCM(self._encryption_key)
        return aesgcm.decrypt(nonce, ct, None)

    def upload_sample(self, file_data: bytes, name: str, uploaded_by: str,
                      tenant_id: str = "default", tags: List[str] = None) -> Dict:
        sha256 = hashlib.sha256(file_data).hexdigest()
        md5 = hashlib.md5(file_data).hexdigest()
        sample_id = str(uuid.uuid4())

        nonce, ct = self._encrypt_sample(file_data)

        # Save encrypted sample
        enc_path = self.vault_path / f"{sample_id}.enc"
        with open(enc_path, "wb") as f:
            f.write(struct.pack(">I", len(nonce)) + nonce + ct)

        meta = {
            "id": sample_id,
            "name": name,
            "original_name": name,
            "sha256": sha256,
            "md5": md5,
            "file_size": len(file_data),
            "encrypted_path": str(enc_path),
            "version": 1,
            "tenant_id": tenant_id,
            "tags": tags or [],
            "uploaded_by": uploaded_by,
            "created_at": datetime.utcnow().isoformat(),
            "audit_log": [{"action": "uploaded", "by": uploaded_by,
                           "at": datetime.utcnow().isoformat()}]
        }
        with open(self.vault_path / f"{sample_id}.meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        return {k: v for k, v in meta.items() if k != "audit_log"}

    def get_sample(self, sample_id: str, requester: str) -> bytes:
        meta_path = self.vault_path / f"{sample_id}.meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Sample {sample_id} not found")
        with open(meta_path) as f:
            meta = json.load(f)

        enc_path = Path(meta["encrypted_path"])
        with open(enc_path, "rb") as f:
            raw = f.read()
        nonce_len = struct.unpack(">I", raw[:4])[0]
        nonce = raw[4:4 + nonce_len]
        ct = raw[4 + nonce_len:]
        data = self._decrypt_sample(nonce, ct)

        # Audit
        meta["audit_log"].append({"action": "retrieved", "by": requester,
                                   "at": datetime.utcnow().isoformat()})
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        return data

    def list_samples(self, tenant_id: str = None) -> List[Dict]:
        samples = []
        for f in self.vault_path.glob("*.meta.json"):
            try:
                with open(f) as fp:
                    meta = json.load(fp)
                if tenant_id is None or meta.get("tenant_id") == tenant_id:
                    safe = {k: v for k, v in meta.items() if k != "audit_log"}
                    samples.append(safe)
            except Exception:
                pass
        return samples


# ═══════════════════════════════════════════════════════════════
# 3. SIGNED THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════

class ThreatIntelEngine:
    """Signed IOC feeds: Hash + Signature + Timestamp + Publisher"""

    MITRE_TACTICS = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    ]

    def __init__(self):
        self.intel_path = Path(settings.THREAT_INTEL_FEEDS)
        self.intel_path.mkdir(parents=True, exist_ok=True)
        self._signing_key = self._load_or_create_key()
        self._indicators: List[Dict] = []
        self._load_indicators()

    def _load_or_create_key(self):
        key_path = Path("./data/keys/threat_intel_signing.key")
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            return serialization.load_pem_private_key(
                key_path.read_bytes(), None, default_backend())
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        return key

    def add_indicator(self, ioc_type: str, value: str, severity: str = "medium",
                      confidence: float = 0.7, source: str = "manual",
                      publisher: str = "AegisXDR", tags: List[str] = None,
                      mitre_tactics: List[str] = None,
                      tenant_id: str = "default") -> Dict:
        ioc_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        # Sign the indicator
        payload = f"{ioc_type}:{value}:{severity}:{timestamp}:{publisher}".encode()
        signature = self._signing_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        ioc_hash = hashlib.sha256(payload).hexdigest()

        indicator = {
            "id": ioc_id,
            "ioc_type": ioc_type,
            "value": value,
            "severity": severity,
            "confidence": confidence,
            "source": source,
            "publisher": publisher,
            "signature": base64.b64encode(signature).decode(),
            "hash": ioc_hash,
            "timestamp": timestamp,
            "verified": True,
            "tags": tags or [],
            "mitre_tactics": mitre_tactics or [],
            "tenant_id": tenant_id
        }
        self._indicators.append(indicator)
        self._save_indicators()
        return indicator

    def verify_indicator(self, indicator: Dict) -> bool:
        try:
            payload = f"{indicator['ioc_type']}:{indicator['value']}:{indicator['severity']}:{indicator['timestamp']}:{indicator['publisher']}".encode()
            pub_key = self._signing_key.public_key()
            pub_key.verify(
                base64.b64decode(indicator["signature"]),
                payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def lookup_ioc(self, value: str) -> List[Dict]:
        return [i for i in self._indicators if i["value"] == value]

    def get_feed(self, ioc_type: str = None, severity: str = None,
                 tenant_id: str = None) -> List[Dict]:
        feed = self._indicators[:]
        if ioc_type:
            feed = [i for i in feed if i["ioc_type"] == ioc_type]
        if severity:
            feed = [i for i in feed if i["severity"] == severity]
        if tenant_id:
            feed = [i for i in feed if i.get("tenant_id") == tenant_id]
        return feed

    def bulk_import(self, indicators: List[Dict], publisher: str) -> Dict:
        imported, failed = 0, 0
        for ind in indicators:
            try:
                self.add_indicator(
                    ioc_type=ind.get("type", "unknown"),
                    value=ind["value"],
                    severity=ind.get("severity", "medium"),
                    confidence=ind.get("confidence", 0.5),
                    publisher=publisher
                )
                imported += 1
            except Exception:
                failed += 1
        return {"imported": imported, "failed": failed}

    def _save_indicators(self):
        with open(self.intel_path / "indicators.json", "w") as f:
            json.dump(self._indicators, f, indent=2)

    def _load_indicators(self):
        ind_file = self.intel_path / "indicators.json"
        if ind_file.exists():
            with open(ind_file) as f:
                self._indicators = json.load(f)


# ═══════════════════════════════════════════════════════════════
# 4. PASSWORD SECURITY RESEARCH LAB
# ═══════════════════════════════════════════════════════════════

class PasswordSecurityLab:
    """Entropy analysis, pattern detection, Argon2id hashing"""

    COMMON_PASSWORDS = {
        "password", "123456", "password123", "admin", "letmein",
        "qwerty", "abc123", "monkey", "1234567890", "dragon",
        "master", "sunshine", "iloveyou", "1234", "12345678"
    }
    KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1234", "abcd"]
    LEET_MAP = {"@": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t"}

    def analyze_password(self, password: str) -> Dict:
        entropy = self._calculate_entropy(password)
        strength = self._rate_strength(password, entropy)
        issues = self._detect_issues(password)
        patterns = self._detect_patterns(password)

        return {
            "entropy_bits": round(entropy, 2),
            "length": len(password),
            "strength": strength,
            "strength_score": self._strength_score(entropy, issues),
            "issues": issues,
            "patterns_detected": patterns,
            "character_classes": self._char_classes(password),
            "estimated_crack_time": self._estimate_crack_time(entropy),
            "recommendations": self._generate_recommendations(issues, entropy)
        }

    def _calculate_entropy(self, password: str) -> float:
        charset = 0
        if re.search(r'[a-z]', password): charset += 26
        if re.search(r'[A-Z]', password): charset += 26
        if re.search(r'[0-9]', password): charset += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset += 32
        if charset == 0:
            charset = 26
        return len(password) * math.log2(charset)

    def _rate_strength(self, password: str, entropy: float) -> str:
        if entropy >= 80 and len(password) >= 16:
            return "very_strong"
        elif entropy >= 60 and len(password) >= 12:
            return "strong"
        elif entropy >= 40:
            return "moderate"
        elif entropy >= 25:
            return "weak"
        return "very_weak"

    def _strength_score(self, entropy: float, issues: List[str]) -> int:
        score = min(int(entropy / 2), 100)
        score -= len(issues) * 10
        return max(0, score)

    def _detect_issues(self, password: str) -> List[str]:
        issues = []
        if len(password) < 8:
            issues.append("Too short (< 8 characters)")
        if len(password) < 12:
            issues.append("Consider using 12+ characters")
        if not re.search(r'[A-Z]', password):
            issues.append("Missing uppercase letters")
        if not re.search(r'[0-9]', password):
            issues.append("Missing numbers")
        if not re.search(r'[!@#$%^&*]', password):
            issues.append("Missing special characters")
        lower = password.lower()
        # Leet speak normalization
        normalized = ""
        for c in lower:
            normalized += self.LEET_MAP.get(c, c)
        if normalized in self.COMMON_PASSWORDS or lower in self.COMMON_PASSWORDS:
            issues.append("Common password detected")
        if re.search(r'(.)\1{2,}', password):
            issues.append("Repeated characters detected")
        return issues

    def _detect_patterns(self, password: str) -> List[str]:
        patterns = []
        lower = password.lower()
        for p in self.KEYBOARD_PATTERNS:
            if p in lower:
                patterns.append(f"Keyboard pattern: {p}")
        if re.search(r'(19|20)\d{2}', password):
            patterns.append("Year pattern detected")
        if re.search(r'\b\d{4}\b', password):
            patterns.append("4-digit sequence (possible PIN)")
        return patterns

    def _char_classes(self, password: str) -> Dict:
        return {
            "lowercase": bool(re.search(r'[a-z]', password)),
            "uppercase": bool(re.search(r'[A-Z]', password)),
            "digits": bool(re.search(r'[0-9]', password)),
            "special": bool(re.search(r'[!@#$%^&*]', password))
        }

    def _estimate_crack_time(self, entropy: float) -> Dict:
        # Assuming 10^9 guesses/second (modern GPU)
        combinations = 2 ** entropy
        seconds = combinations / 1e9
        if seconds < 60:
            return {"time": f"{seconds:.1f} seconds", "feasible": True}
        elif seconds < 3600:
            return {"time": f"{seconds/60:.1f} minutes", "feasible": True}
        elif seconds < 86400:
            return {"time": f"{seconds/3600:.1f} hours", "feasible": True}
        elif seconds < 86400 * 365:
            return {"time": f"{seconds/86400:.0f} days", "feasible": True}
        elif seconds < 86400 * 365 * 1000:
            return {"time": f"{seconds/(86400*365):.0f} years", "feasible": False}
        return {"time": "Millions of years", "feasible": False}

    def _generate_recommendations(self, issues: List[str], entropy: float) -> List[str]:
        recs = []
        if entropy < 60:
            recs.append("Use a passphrase: 4+ random words (e.g., correct-horse-battery-staple)")
        if "Missing special characters" in issues:
            recs.append("Add special characters: !, @, #, $, %, ^")
        if "Too short" in issues:
            recs.append("Increase length to at least 16 characters")
        recs.append("Use a password manager (Bitwarden, KeePass)")
        recs.append("Enable MFA on all accounts")
        return recs

    def hash_password(self, password: str) -> Dict:
        """Hash using Argon2id"""
        from argon2 import PasswordHasher
        ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=1,
            hash_len=32,
            salt_len=16
        )
        hashed = ph.hash(password)
        return {
            "algorithm": "argon2id",
            "hash": hashed,
            "parameters": {
                "time_cost": 3,
                "memory_cost_kb": 65536,
                "parallelism": 1,
                "hash_len": 32,
                "salt_len": 16
            }
        }

    def verify_password(self, password: str, hash_str: str) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
        ph = PasswordHasher()
        try:
            return ph.verify(hash_str, password)
        except VerifyMismatchError:
            return False


# ═══════════════════════════════════════════════════════════════
# 5. RANSOMWARE CRYPTO ANALYSIS
# ═══════════════════════════════════════════════════════════════

class RansomwareCryptoAnalyzer:
    """Detects encryption APIs, key generation, file encryption, entropy increase"""

    CRYPTO_API_PATTERNS = [
        r'CryptGenKey|CryptEncrypt|CryptDecrypt',
        r'BCryptGenerateSymmetricKey|BCryptEncrypt',
        r'AES|RSA|DES|RC4|Salsa20|ChaCha20',
        r'CreateFileW?|WriteFile|SetEndOfFile',
        r'HKEY_|RegOpenKey|RegSetValue',
        r'GetSystemTime|GetTickCount',
        r'VirtualAlloc|VirtualProtect',
        r'CreateThread|CreateProcess',
        r'InternetOpen|HttpSendRequest',
        r'\.encrypted|\.locked|\.crypto|\.crypt',
    ]

    RANSOMWARE_EXTENSIONS = [
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
        ".rans", ".wannacry", ".petya", ".locky", ".cerber",
        ".dharma", ".ryuk", ".maze", ".revil", ".conti"
    ]

    def analyze_sample(self, file_data: bytes, filename: str = "") -> Dict:
        entropy = self._calculate_file_entropy(file_data)
        try:
            text_content = file_data.decode('utf-8', errors='ignore')
        except Exception:
            text_content = ""

        crypto_matches = self._detect_crypto_apis(text_content)
        suspicious_extensions = self._detect_extension_changes(text_content)
        key_gen_indicators = self._detect_key_generation(text_content)
        network_indicators = self._detect_network_indicators(text_content)
        ransom_note = self._detect_ransom_note(text_content)

        risk_score = self._calculate_risk_score(
            entropy, crypto_matches, suspicious_extensions,
            key_gen_indicators, ransom_note)

        verdict = "clean"
        if risk_score >= 0.8:
            verdict = "ransomware"
        elif risk_score >= 0.5:
            verdict = "suspicious"
        elif risk_score >= 0.3:
            verdict = "potentially_unwanted"

        return {
            "filename": filename,
            "file_entropy": round(entropy, 4),
            "high_entropy": entropy > 7.2,
            "verdict": verdict,
            "risk_score": round(risk_score, 4),
            "crypto_api_matches": crypto_matches,
            "suspicious_extension_changes": suspicious_extensions,
            "key_generation_indicators": key_gen_indicators,
            "network_indicators": network_indicators,
            "ransom_note_detected": ransom_note,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "recommendations": self._generate_recommendations(verdict, risk_score)
        }

    def _calculate_file_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        total = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _detect_crypto_apis(self, content: str) -> List[str]:
        matches = []
        for pattern in self.CRYPTO_API_PATTERNS:
            found = re.findall(pattern, content, re.IGNORECASE)
            matches.extend(found)
        return list(set(matches))[:20]

    def _detect_extension_changes(self, content: str) -> List[str]:
        found = []
        for ext in self.RANSOMWARE_EXTENSIONS:
            if ext in content.lower():
                found.append(ext)
        return found

    def _detect_key_generation(self, content: str) -> List[str]:
        indicators = []
        if re.search(r'rand(om)?|urandom|genrand', content, re.IGNORECASE):
            indicators.append("Random number generation")
        if re.search(r'pbkdf2|scrypt|bcrypt|argon', content, re.IGNORECASE):
            indicators.append("Key derivation function")
        if re.search(r'private.?key|public.?key|keypair', content, re.IGNORECASE):
            indicators.append("Key pair operations")
        if re.search(r'iv|nonce|salt', content, re.IGNORECASE):
            indicators.append("Cryptographic IV/nonce/salt usage")
        return indicators

    def _detect_network_indicators(self, content: str) -> List[str]:
        indicators = []
        if re.search(r'bitcoin|btc|monero|xmr|ethereum', content, re.IGNORECASE):
            indicators.append("Cryptocurrency references")
        if re.search(r'\.onion', content, re.IGNORECASE):
            indicators.append("Tor hidden service (.onion)")
        if re.search(r'c2|c&c|command.?and.?control', content, re.IGNORECASE):
            indicators.append("C2 server reference")
        return indicators

    def _detect_ransom_note(self, content: str) -> bool:
        ransom_keywords = [
            "your files", "encrypted", "decrypt", "bitcoin",
            "pay", "ransom", "recover", "wallet", "contact us"
        ]
        count = sum(1 for kw in ransom_keywords if kw in content.lower())
        return count >= 3

    def _calculate_risk_score(self, entropy: float, crypto_matches: List,
                               ext_changes: List, key_gen: List, ransom_note: bool) -> float:
        score = 0.0
        if entropy > 7.5:
            score += 0.3
        elif entropy > 7.0:
            score += 0.15
        score += min(len(crypto_matches) * 0.05, 0.25)
        score += min(len(ext_changes) * 0.1, 0.2)
        score += min(len(key_gen) * 0.05, 0.15)
        if ransom_note:
            score += 0.3
        return min(score, 1.0)

    def _generate_recommendations(self, verdict: str, score: float) -> List[str]:
        recs = []
        if verdict == "ransomware":
            recs.append("ISOLATE: Immediately disconnect from network")
            recs.append("PRESERVE: Take memory dump before shutdown")
            recs.append("REPORT: Notify SOC and IR team immediately")
            recs.append("BACKUP: Check integrity of offline backups")
        elif verdict == "suspicious":
            recs.append("SANDBOX: Execute in isolated environment")
            recs.append("MONITOR: Watch for file system changes")
        else:
            recs.append("Continue monitoring for behavioral changes")
        return recs


# ═══════════════════════════════════════════════════════════════
# 6. CRYPTOGRAPHIC THREAT DETECTION (TLS/Certificate Analysis)
# ═══════════════════════════════════════════════════════════════

class CryptoThreatDetector:
    """Detect weak TLS, self-signed certs, expired certs, deprecated ciphers"""

    WEAK_CIPHER_SUITES = [
        "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
        "MD5", "SHA1WithRSA", "TLS_RSA_WITH_RC4",
        "SSL_CK_RC4_128_WITH_MD5"
    ]

    DEPRECATED_TLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
    RECOMMENDED_TLS = ["TLSv1.2", "TLSv1.3"]
    MIN_RSA_BITS = 2048
    MIN_EC_BITS = 256

    def analyze_network_event(self, event: Dict) -> Dict:
        findings = []
        risk_score = 0.0

        tls_version = event.get("tls_version", "")
        cipher = event.get("cipher_suite", "")
        cert_subject = event.get("cert_subject", "")
        cert_issuer = event.get("cert_issuer", "")
        cert_valid = event.get("cert_valid")
        cert_expiry = event.get("cert_expiry")

        # Check TLS version
        if tls_version in self.DEPRECATED_TLS:
            findings.append({
                "type": "deprecated_tls",
                "severity": "high",
                "detail": f"Deprecated TLS version: {tls_version}",
                "remediation": f"Upgrade to TLS 1.2 or 1.3"
            })
            risk_score += 0.4

        # Check cipher suite
        for weak in self.WEAK_CIPHER_SUITES:
            if weak.lower() in cipher.lower():
                findings.append({
                    "type": "weak_cipher",
                    "severity": "critical",
                    "detail": f"Weak cipher: {cipher}",
                    "remediation": "Use AES-128-GCM or AES-256-GCM"
                })
                risk_score += 0.5
                break

        # Check self-signed
        if cert_subject and cert_issuer and cert_subject == cert_issuer:
            findings.append({
                "type": "self_signed_cert",
                "severity": "medium",
                "detail": "Self-signed certificate detected",
                "remediation": "Use certificates from a trusted CA"
            })
            risk_score += 0.3

        # Check validity
        if cert_valid is False:
            findings.append({
                "type": "invalid_cert",
                "severity": "high",
                "detail": "Certificate validation failed",
                "remediation": "Investigate potential MITM or misconfiguration"
            })
            risk_score += 0.4

        # Check expiry
        if cert_expiry:
            try:
                expiry = datetime.fromisoformat(cert_expiry)
                if expiry < datetime.utcnow():
                    findings.append({
                        "type": "expired_cert",
                        "severity": "high",
                        "detail": f"Certificate expired: {cert_expiry}",
                        "remediation": "Renew the certificate immediately"
                    })
                    risk_score += 0.35
                elif (expiry - datetime.utcnow()).days < 30:
                    findings.append({
                        "type": "expiring_soon",
                        "severity": "medium",
                        "detail": f"Certificate expires in {(expiry - datetime.utcnow()).days} days",
                        "remediation": "Plan certificate renewal"
                    })
                    risk_score += 0.1
            except Exception:
                pass

        return {
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "findings": findings,
            "finding_count": len(findings),
            "risk_score": min(risk_score, 1.0),
            "risk_level": "critical" if risk_score >= 0.8 else
                          "high" if risk_score >= 0.5 else
                          "medium" if risk_score >= 0.3 else "low",
            "compliant": len(findings) == 0,
            "analyzed_at": datetime.utcnow().isoformat()
        }

    def scan_bulk(self, events: List[Dict]) -> Dict:
        results = [self.analyze_network_event(e) for e in events]
        non_compliant = [r for r in results if not r["compliant"]]
        return {
            "total_scanned": len(events),
            "compliant": len(events) - len(non_compliant),
            "non_compliant": len(non_compliant),
            "results": results,
            "summary": {
                "deprecated_tls": sum(1 for r in results
                                      for f in r["findings"] if f["type"] == "deprecated_tls"),
                "weak_ciphers": sum(1 for r in results
                                    for f in r["findings"] if f["type"] == "weak_cipher"),
                "self_signed": sum(1 for r in results
                                   for f in r["findings"] if f["type"] == "self_signed_cert"),
                "expired": sum(1 for r in results
                               for f in r["findings"] if f["type"] == "expired_cert")
            }
        }


# ═══════════════════════════════════════════════════════════════
# 7. POST-QUANTUM CRYPTOGRAPHY MODULE (Simulation)
# ═══════════════════════════════════════════════════════════════

class PostQuantumCrypto:
    """
    CRYSTALS-Kyber (KEM) and CRYSTALS-Dilithium (Signatures) simulation
    Research/academic demonstration - uses classical crypto as placeholders
    until liboqs Python bindings are available
    """

    ALGORITHMS = {
        "kyber": {
            "name": "CRYSTALS-Kyber-1024",
            "type": "KEM",
            "security_level": "Level 5 (AES-256 equivalent)",
            "nist_round": "Standardized (FIPS 203)",
            "description": "Lattice-based key encapsulation mechanism"
        },
        "dilithium": {
            "name": "CRYSTALS-Dilithium3",
            "type": "Digital Signature",
            "security_level": "Level 3 (128-bit classical)",
            "nist_round": "Standardized (FIPS 204)",
            "description": "Lattice-based digital signature scheme"
        }
    }

    def kyber_keygen(self) -> Dict:
        """Simulate Kyber key generation (classical simulation)"""
        # In production: use liboqs or oqs-python
        # pip install liboqs-python
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        priv = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return {
            "algorithm": "CRYSTALS-Kyber-1024 (simulated)",
            "public_key": pub,
            "secret_key": priv,
            "key_size_bytes": {"public": 1568, "secret": 3168},
            "note": "Production: use liboqs-python for actual Kyber implementation",
            "nist_standard": "FIPS 203"
        }

    def kyber_encapsulate(self, public_key_pem: str) -> Dict:
        """Simulate Kyber key encapsulation"""
        shared_secret = os.urandom(32)
        ciphertext = os.urandom(1568)  # Kyber-1024 ciphertext size
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret_hash": hashlib.sha256(shared_secret).hexdigest(),
            "algorithm": "CRYSTALS-Kyber-1024 (simulated)",
            "ciphertext_size": 1568
        }

    def dilithium_keygen(self) -> Dict:
        """Simulate Dilithium key generation"""
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        priv = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
        pub = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return {
            "algorithm": "CRYSTALS-Dilithium3 (simulated)",
            "public_key": pub,
            "secret_key": priv,
            "key_size_bytes": {"public": 1952, "secret": 4016},
            "note": "Production: use liboqs-python for actual Dilithium implementation",
            "nist_standard": "FIPS 204"
        }

    def dilithium_sign(self, message: str, private_key_pem: str) -> Dict:
        """Simulate Dilithium signature"""
        key = serialization.load_pem_private_key(
            private_key_pem.encode(), None, default_backend())
        msg_bytes = message.encode()
        signature = key.sign(msg_bytes, ec.ECDSA(hashes.SHA384()))
        return {
            "message_hash": hashlib.sha3_256(msg_bytes).hexdigest(),
            "signature": base64.b64encode(signature).decode(),
            "algorithm": "CRYSTALS-Dilithium3 (simulated)",
            "signature_size": 3293,
            "timestamp": datetime.utcnow().isoformat()
        }

    def dilithium_verify(self, message: str, signature: str, public_key_pem: str) -> Dict:
        try:
            key = serialization.load_pem_public_key(
                public_key_pem.encode(), default_backend())
            key.verify(base64.b64decode(signature),
                       message.encode(), ec.ECDSA(hashes.SHA384()))
            return {"valid": True, "algorithm": "CRYSTALS-Dilithium3 (simulated)"}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def get_algorithm_info(self) -> Dict:
        return self.ALGORITHMS


# Singleton instances
forensics = ForensicsEngine()
malware_vault = MalwareVault()
threat_intel = ThreatIntelEngine()
password_lab = PasswordSecurityLab()
ransomware_analyzer = RansomwareCryptoAnalyzer()
crypto_detector = CryptoThreatDetector()
pqc = PostQuantumCrypto()
