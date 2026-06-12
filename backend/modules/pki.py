"""
AegisXDR PKI Infrastructure
Root CA, Intermediate CA, Client/Server Certificates
Features: CSR generation, issuance, revocation lists, OCSP simulation
"""
import os
import uuid
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder

from core.config import settings


class PKIError(Exception):
    pass


class PKIInfrastructure:
    """Full PKI: Root CA → Intermediate CA → End-Entity Certs"""

    def __init__(self):
        self.root_path = Path(settings.PKI_ROOT_CA_PATH)
        self.intermediate_path = Path(settings.PKI_INTERMEDIATE_CA_PATH)
        self.certs_path = Path(settings.PKI_CERTS_PATH)
        for p in [self.root_path, self.intermediate_path, self.certs_path]:
            p.mkdir(parents=True, exist_ok=True)
        self._crl_serial = 1

    # ─── Key Generation ────────────────────────────────────────────────────────

    def _gen_rsa_key(self, bits: int = 4096):
        return rsa.generate_private_key(65537, bits, default_backend())

    def _gen_ec_key(self):
        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    def _pem_private(self, key) -> str:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()

    def _pem_public(self, key) -> str:
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # ─── Root CA ───────────────────────────────────────────────────────────────

    def create_root_ca(self, org: str = "AegisXDR", country: str = "IN",
                       valid_days: int = 3650) -> Dict:
        key = self._gen_rsa_key(4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{org} Root CA"),
        ])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=valid_days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                              crl_sign=True, content_commitment=False,
                                              key_encipherment=False, data_encipherment=False,
                                              key_agreement=False, encipher_only=False,
                                              decipher_only=False), critical=True)
                .sign(key, hashes.SHA256(), default_backend()))

        cert_id = str(uuid.uuid4())
        key_pem = self._pem_private(key)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        (self.root_path / "root_ca.key").write_text(key_pem)
        (self.root_path / "root_ca.crt").write_text(cert_pem)
        os.chmod(self.root_path / "root_ca.key", 0o600)

        return {"id": cert_id, "type": "root_ca", "common_name": f"{org} Root CA",
                "pem_cert": cert_pem, "not_after": cert.not_valid_after_utc.isoformat(),
                "serial": str(cert.serial_number)}

    def create_intermediate_ca(self, org: str = "AegisXDR", valid_days: int = 1825) -> Dict:
        root_key_path = self.root_path / "root_ca.key"
        root_cert_path = self.root_path / "root_ca.crt"
        if not root_key_path.exists():
            raise PKIError("Root CA not initialized. Call create_root_ca first.")

        root_key = serialization.load_pem_private_key(
            root_key_path.read_bytes(), None, default_backend())
        root_cert = x509.load_pem_x509_certificate(
            root_cert_path.read_bytes(), default_backend())

        int_key = self._gen_rsa_key(4096)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{org} Intermediate CA"),
        ])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(root_cert.subject)
                .public_key(int_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=valid_days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(root_key, hashes.SHA256(), default_backend()))

        key_pem = self._pem_private(int_key)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        (self.intermediate_path / "intermediate_ca.key").write_text(key_pem)
        (self.intermediate_path / "intermediate_ca.crt").write_text(cert_pem)
        os.chmod(self.intermediate_path / "intermediate_ca.key", 0o600)

        return {"type": "intermediate_ca", "common_name": f"{org} Intermediate CA",
                "pem_cert": cert_pem, "not_after": cert.not_valid_after_utc.isoformat()}

    def issue_certificate(self, common_name: str, cert_type: str = "server",
                          san_dns: List[str] = None, san_ip: List[str] = None,
                          valid_days: int = 365) -> Dict:
        int_key_path = self.intermediate_path / "intermediate_ca.key"
        int_cert_path = self.intermediate_path / "intermediate_ca.crt"
        if not int_key_path.exists():
            raise PKIError("Intermediate CA not initialized.")

        signing_key = serialization.load_pem_private_key(
            int_key_path.read_bytes(), None, default_backend())
        signing_cert = x509.load_pem_x509_certificate(
            int_cert_path.read_bytes(), default_backend())

        end_key = self._gen_ec_key()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        now = datetime.now(timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(signing_cert.subject)
                   .public_key(end_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now)
                   .not_valid_after(now + timedelta(days=valid_days))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))

        # SAN
        san_list = []
        for dns in (san_dns or [common_name]):
            san_list.append(x509.DNSName(dns))
        for ip in (san_ip or []):
            try:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        if san_list:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

        # EKU
        if cert_type == "server":
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        elif cert_type == "client":
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        else:
            eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                          ExtendedKeyUsageOID.CLIENT_AUTH])
        builder = builder.add_extension(eku, critical=False)

        cert = builder.sign(signing_key, hashes.SHA256(), default_backend())
        cert_id = str(uuid.uuid4())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = self._pem_private(end_key)

        (self.certs_path / f"{cert_id}.crt").write_text(cert_pem)
        (self.certs_path / f"{cert_id}.key").write_text(key_pem)
        os.chmod(self.certs_path / f"{cert_id}.key", 0o600)

        return {"id": cert_id, "common_name": common_name, "cert_type": cert_type,
                "pem_cert": cert_pem, "pem_key": key_pem,
                "serial": str(cert.serial_number),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat()}

    def generate_csr(self, common_name: str, org: str = "AegisXDR") -> Dict:
        key = self._gen_ec_key()
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                   x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
               ]))
               .sign(key, hashes.SHA256(), default_backend()))
        return {
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "private_key": self._pem_private(key),
            "common_name": common_name
        }

    def revoke_certificate(self, cert_id: str, reason: str = "unspecified") -> Dict:
        cert_path = self.certs_path / f"{cert_id}.crt"
        if not cert_path.exists():
            raise PKIError(f"Certificate {cert_id} not found")
        revoked_path = self.certs_path / f"{cert_id}.revoked"
        cert_path.rename(revoked_path)
        revoke_info = {"cert_id": cert_id, "reason": reason,
                       "revoked_at": datetime.utcnow().isoformat()}
        with open(self.certs_path / f"{cert_id}.revoke_info", "w") as f:
            import json; json.dump(revoke_info, f)
        return revoke_info

    def get_crl(self) -> List[Dict]:
        revoked = []
        for f in self.certs_path.glob("*.revoke_info"):
            try:
                import json
                with open(f) as fp:
                    revoked.append(json.load(fp))
            except Exception:
                pass
        return revoked

    def ocsp_check(self, cert_id: str) -> Dict:
        revoke_info_path = self.certs_path / f"{cert_id}.revoke_info"
        cert_path = self.certs_path / f"{cert_id}.crt"
        if revoke_info_path.exists():
            import json
            with open(revoke_info_path) as f:
                info = json.load(f)
            return {"status": "revoked", "cert_id": cert_id, "reason": info.get("reason"),
                    "revoked_at": info.get("revoked_at")}
        if cert_path.exists():
            return {"status": "good", "cert_id": cert_id}
        return {"status": "unknown", "cert_id": cert_id}

    def is_initialized(self) -> bool:
        return (self.root_path / "root_ca.crt").exists()


# Singleton
pki = PKIInfrastructure()
