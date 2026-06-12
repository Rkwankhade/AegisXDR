"""
AegisXDR Authentication + Multi-Tenant Security
JWT, MFA (TOTP), Argon2id passwords, tenant isolation
"""
import uuid
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict

from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from core.config import settings
from modules.zero_trust import zero_trust

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, hash_str: str) -> bool:
    try:
        return ph.verify(hash_str, password)
    except VerifyMismatchError:
        return False


def create_access_token(data: Dict, expires_minutes: int = None) -> str:
    to_encode = data.copy()
    exp = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": exp, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> Dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET,
                          algorithms=[settings.JWT_ALGORITHM])
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid token: {str(e)}")


def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def get_mfa_qr(username: str, secret: str) -> str:
    """Generate QR code as base64 PNG"""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name="AegisXDR")
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


async def get_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    return payload


async def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    if user.get("role") not in ["admin", "soc_l3"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_analyst(user: Dict = Depends(get_current_user)) -> Dict:
    if user.get("role") not in ["admin", "soc_l3", "soc_l2", "analyst"]:
        raise HTTPException(status_code=403, detail="Analyst access required")
    return user


class TenantManager:
    """Cryptographic tenant isolation"""

    def __init__(self):
        self._tenants: Dict[str, Dict] = {}
        self._ensure_default_tenant()

    def _ensure_default_tenant(self):
        if "default" not in self._tenants:
            self.create_tenant("default", "Default Organization")

    def create_tenant(self, tenant_id: str, name: str) -> Dict:
        from modules.kms import kms
        # Generate tenant-specific encryption key
        try:
            tenant_key = kms.generate_key(
                name=f"tenant_{tenant_id}_key",
                algorithm="AES-256-GCM",
                purpose="tenant_encryption",
                tenant_id=tenant_id
            )
            key_id = tenant_key["id"]
        except Exception:
            key_id = None

        tenant = {
            "id": tenant_id,
            "name": name,
            "tenant_key_id": key_id,
            "created_at": datetime.utcnow().isoformat(),
            "active": True
        }
        self._tenants[tenant_id] = tenant
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> list:
        return list(self._tenants.values())

    def validate_tenant_access(self, user_tenant: str, resource_tenant: str) -> bool:
        if user_tenant == "default":
            return True  # Default tenant is super-tenant
        return user_tenant == resource_tenant


tenant_manager = TenantManager()
