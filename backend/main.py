"""
AegisXDR - Main FastAPI Application
Complete Security Platform: SIEM + XDR + SOAR + KMS + PKI + Vault + Forensics + ...
"""
import uuid
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from core.config import settings
from db.models import init_db
from modules.auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_admin, require_analyst,
    generate_mfa_secret, get_mfa_qr, verify_totp,
    tenant_manager
)
from modules.kms import kms
from modules.vault import vault
from modules.pki import pki
from modules.zero_trust import zero_trust
from modules.blockchain import blockchain
from modules.security_modules import (
    forensics, malware_vault, threat_intel,
    password_lab, ransomware_analyzer, crypto_detector, pqc
)
from modules.siem_xdr import siem, ueba

# ─── App Init ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AegisXDR",
    description="Research-Scale Security Platform: SIEM + XDR + KMS + PKI + Vault + Forensics",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB on startup
@app.on_event("startup")
async def startup():
    init_db()
    # Create default admin if not exists
    admin_file = Path("./data/admin.json")
    if not admin_file.exists():
        import json
        admin_file.parent.mkdir(exist_ok=True)
        admin_data = {
            "id": str(uuid.uuid4()),
            "username": settings.ADMIN_USERNAME,
            "password_hash": hash_password(settings.ADMIN_PASSWORD),
            "role": "admin",
            "tenant_id": "default",
            "mfa_secret": generate_mfa_secret(),
            "created_at": datetime.utcnow().isoformat()
        }
        with open(admin_file, "w") as f:
            json.dump(admin_data, f)
        print(f"✅ Admin created: {settings.ADMIN_USERNAME}")

    # Initialize PKI if needed
    if not pki.is_initialized():
        try:
            pki.create_root_ca()
            pki.create_intermediate_ca()
            print("✅ PKI Infrastructure initialized")
        except Exception as e:
            print(f"⚠️  PKI init failed: {e}")
    print("🛡️  AegisXDR started successfully")


# ─── Pydantic Models ────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class KeyGenRequest(BaseModel):
    name: str
    algorithm: str  # AES-256-GCM, RSA-4096, ECC-P256, ECC-X25519
    purpose: str = "encrypt"
    rotation_days: int = 90

class EncryptRequest(BaseModel):
    key_id: str
    data: str  # base64 encoded

class SignRequest(BaseModel):
    key_id: str
    data: str  # base64 encoded

class VerifyRequest(BaseModel):
    key_id: str
    data: str
    signature: str

class SecretStoreRequest(BaseModel):
    name: str
    value: str
    secret_type: str = "custom"
    lease_duration: int = 3600
    auto_rotate: bool = False
    access_policy: Optional[Dict] = None

class CertRequest(BaseModel):
    common_name: str
    cert_type: str = "server"  # server, client
    san_dns: Optional[List[str]] = None
    san_ip: Optional[List[str]] = None
    valid_days: int = 365

class ZeroTrustRequest(BaseModel):
    user_id: str
    device_fingerprint: str
    ip_address: str
    resource: str
    action: str
    context: Optional[Dict] = None

class EventIngestRequest(BaseModel):
    events: List[Dict]

class IOCRequest(BaseModel):
    ioc_type: str  # ip, domain, hash, url, email
    value: str
    severity: str = "medium"
    confidence: float = 0.7
    source: str = "manual"
    tags: Optional[List[str]] = None
    mitre_tactics: Optional[List[str]] = None

class PasswordAnalyzeRequest(BaseModel):
    password: str

class CryptoAnalysisRequest(BaseModel):
    network_events: List[Dict]

class DetectionRuleRequest(BaseModel):
    name: str
    rule_type: str  # sigma, yara, custom
    content: str

class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    false_positive: Optional[bool] = None

# ─── Auth Routes ───────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    import json
    admin_file = Path("./data/admin.json")
    if not admin_file.exists():
        raise HTTPException(400, "System not initialized")
    with open(admin_file) as f:
        admin = json.load(f)

    if req.username != admin["username"] or not verify_password(req.password, admin["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    # MFA check
    if admin.get("mfa_secret") and req.mfa_code:
        if not verify_totp(admin["mfa_secret"], req.mfa_code):
            raise HTTPException(401, "Invalid MFA code")

    token = create_access_token({
        "sub": admin["id"],
        "username": admin["username"],
        "role": admin["role"],
        "tenant_id": admin.get("tenant_id", "default")
    })

    # Audit
    blockchain.add_entry(
        {"action": "login", "user": req.username, "timestamp": datetime.utcnow().isoformat()},
        data_type="audit"
    )

    return {"access_token": token, "token_type": "bearer",
            "role": admin["role"], "username": admin["username"]}


@app.get("/api/auth/mfa/setup")
async def setup_mfa(user=Depends(get_current_user)):
    import json
    admin_file = Path("./data/admin.json")
    with open(admin_file) as f:
        admin = json.load(f)
    qr = get_mfa_qr(admin["username"], admin["mfa_secret"])
    return {"qr_code": qr, "secret": admin["mfa_secret"]}


@app.get("/api/auth/me")
async def get_me(user=Depends(get_current_user)):
    return user


# ─── KMS Routes ────────────────────────────────────────────────────────────────

@app.post("/api/kms/keys")
async def create_key(req: KeyGenRequest, user=Depends(require_analyst)):
    key = kms.generate_key(req.name, req.algorithm, req.purpose,
                            user["tenant_id"], req.rotation_days)
    blockchain.add_entry({"action": "key_created", "key_id": key["id"],
                           "algorithm": req.algorithm}, "kms_audit", user["tenant_id"])
    return key


@app.get("/api/kms/keys")
async def list_keys(user=Depends(require_analyst)):
    return {"keys": kms.list_keys(user["tenant_id"])}


@app.post("/api/kms/keys/{key_id}/rotate")
async def rotate_key(key_id: str, user=Depends(require_admin)):
    result = kms.rotate_key(key_id)
    blockchain.add_entry({"action": "key_rotated", **result}, "kms_audit", user["tenant_id"])
    return result


@app.post("/api/kms/keys/{key_id}/revoke")
async def revoke_key(key_id: str, reason: str = "manual", user=Depends(require_admin)):
    result = kms.revoke_key(key_id, reason)
    blockchain.add_entry({"action": "key_revoked", **result}, "kms_audit", user["tenant_id"])
    return result


@app.post("/api/kms/encrypt")
async def encrypt_data(req: EncryptRequest, user=Depends(require_analyst)):
    import base64
    data = base64.b64decode(req.data)
    return kms.encrypt_data(req.key_id, data)


@app.post("/api/kms/sign")
async def sign_data(req: SignRequest, user=Depends(require_analyst)):
    import base64
    data = base64.b64decode(req.data)
    return kms.sign_data(req.key_id, data)


@app.post("/api/kms/verify")
async def verify_signature(req: VerifyRequest, user=Depends(require_analyst)):
    import base64
    data = req.data.encode()
    valid = kms.verify_signature(req.key_id, data, req.signature)
    return {"valid": valid}


# ─── Vault Routes ──────────────────────────────────────────────────────────────

@app.post("/api/vault/secrets")
async def store_secret(req: SecretStoreRequest, user=Depends(require_analyst)):
    secret = vault.store_secret(
        req.name, req.value, req.secret_type,
        user["tenant_id"], req.access_policy,
        req.lease_duration, req.auto_rotate
    )
    blockchain.add_entry({"action": "secret_stored", "secret_id": secret["id"],
                           "name": req.name}, "vault_audit", user["tenant_id"])
    return secret


@app.get("/api/vault/secrets")
async def list_secrets(user=Depends(require_analyst)):
    return {"secrets": vault.list_secrets(user["tenant_id"])}


@app.get("/api/vault/secrets/{secret_id}")
async def get_secret(secret_id: str, user=Depends(require_analyst)):
    return vault.get_secret(secret_id, user.get("role", "analyst"), user.get("sub"))


@app.post("/api/vault/secrets/{secret_id}/rotate")
async def rotate_secret(secret_id: str, new_value: str, user=Depends(require_admin)):
    return vault.rotate_secret(secret_id, new_value)


@app.post("/api/vault/secrets/{secret_id}/revoke")
async def revoke_secret(secret_id: str, reason: str = "manual", user=Depends(require_admin)):
    return vault.revoke_secret(secret_id, reason)


@app.post("/api/vault/emergency-revoke")
async def emergency_revoke(user=Depends(require_admin)):
    return vault.emergency_revoke_all(user["tenant_id"])


# ─── PKI Routes ────────────────────────────────────────────────────────────────

@app.post("/api/pki/root-ca")
async def create_root_ca(org: str = "AegisXDR", user=Depends(require_admin)):
    return pki.create_root_ca(org)


@app.post("/api/pki/intermediate-ca")
async def create_intermediate_ca(org: str = "AegisXDR", user=Depends(require_admin)):
    return pki.create_intermediate_ca(org)


@app.post("/api/pki/certificates")
async def issue_certificate(req: CertRequest, user=Depends(require_analyst)):
    cert = pki.issue_certificate(req.common_name, req.cert_type,
                                  req.san_dns, req.san_ip, req.valid_days)
    blockchain.add_entry({"action": "cert_issued", "cert_id": cert["id"],
                           "cn": req.common_name}, "pki_audit", user["tenant_id"])
    return cert


@app.get("/api/pki/crl")
async def get_crl(user=Depends(require_analyst)):
    return {"crl": pki.get_crl()}


@app.get("/api/pki/ocsp/{cert_id}")
async def ocsp_check(cert_id: str, user=Depends(require_analyst)):
    return pki.ocsp_check(cert_id)


@app.post("/api/pki/certificates/{cert_id}/revoke")
async def revoke_certificate(cert_id: str, reason: str = "unspecified",
                              user=Depends(require_admin)):
    return pki.revoke_certificate(cert_id, reason)


@app.post("/api/pki/csr")
async def generate_csr(common_name: str, org: str = "AegisXDR",
                        user=Depends(require_analyst)):
    return pki.generate_csr(common_name, org)


# ─── Zero Trust Routes ─────────────────────────────────────────────────────────

@app.post("/api/zerotrust/evaluate")
async def evaluate_access(req: ZeroTrustRequest, user=Depends(require_analyst)):
    return zero_trust.evaluate_access(
        req.user_id, req.device_fingerprint, req.ip_address,
        req.resource, req.action, req.context or {}
    )


@app.post("/api/zerotrust/devices")
async def register_device(device_fingerprint: str, owner: str,
                           device_name: str = None, trusted: bool = False,
                           user=Depends(require_analyst)):
    return zero_trust.register_device(device_fingerprint, owner, device_name, trusted)


@app.get("/api/zerotrust/users/{user_id}/risk")
async def user_risk_profile(user_id: str, user=Depends(require_analyst)):
    return zero_trust.get_user_risk_profile(user_id)


# ─── SIEM/XDR Routes ──────────────────────────────────────────────────────────

@app.post("/api/siem/events")
async def ingest_events(req: EventIngestRequest, user=Depends(require_analyst)):
    all_alerts = []
    for event in req.events:
        event["tenant_id"] = user["tenant_id"]
        alerts = siem.ingest_event(event)
        all_alerts.extend(alerts)
        # UEBA
        if event.get("user_id"):
            ueba.update_baseline(event["user_id"], event)
            anomaly = ueba.detect_anomaly(event["user_id"], event)
            if anomaly:
                all_alerts.append({"type": "ueba_anomaly", "data": anomaly})
    return {"processed": len(req.events), "alerts_generated": len(all_alerts),
            "alerts": all_alerts}


@app.get("/api/siem/alerts")
async def get_alerts(status: str = None, severity: str = None,
                      limit: int = 100, user=Depends(require_analyst)):
    return {"alerts": siem.get_alerts(user["tenant_id"], status, severity, limit)}


@app.patch("/api/siem/alerts/{alert_id}")
async def update_alert(alert_id: str, req: AlertUpdateRequest,
                        user=Depends(require_analyst)):
    updates = {k: v for k, v in req.dict().items() if v is not None}
    result = siem.update_alert(alert_id, updates)
    if not result:
        raise HTTPException(404, "Alert not found")
    return result


@app.post("/api/siem/correlate")
async def correlate_alerts(window_minutes: int = 30, user=Depends(require_analyst)):
    return {"incidents": siem.correlate_alerts(window_minutes)}


@app.get("/api/siem/stats")
async def siem_stats(user=Depends(require_analyst)):
    return siem.get_stats(user["tenant_id"])


# ─── Threat Intelligence Routes ────────────────────────────────────────────────

@app.post("/api/threat-intel/indicators")
async def add_indicator(req: IOCRequest, user=Depends(require_analyst)):
    return threat_intel.add_indicator(
        req.ioc_type, req.value, req.severity, req.confidence,
        req.source, tags=req.tags, mitre_tactics=req.mitre_tactics,
        tenant_id=user["tenant_id"]
    )


@app.get("/api/threat-intel/indicators")
async def get_indicators(ioc_type: str = None, severity: str = None,
                          user=Depends(require_analyst)):
    return {"indicators": threat_intel.get_feed(ioc_type, severity, user["tenant_id"])}


@app.get("/api/threat-intel/lookup/{value}")
async def lookup_ioc(value: str, user=Depends(require_analyst)):
    results = threat_intel.lookup_ioc(value)
    return {"value": value, "found": len(results) > 0, "indicators": results}


# ─── Forensics Routes ──────────────────────────────────────────────────────────

@app.post("/api/forensics/artifacts")
async def collect_artifact(
        file: UploadFile = File(...),
        incident_id: Optional[str] = Form(None),
        artifact_type: str = Form("file"),
        user=Depends(require_analyst)):
    data = await file.read()
    artifact = forensics.collect_artifact(
        data, file.filename, user["username"],
        incident_id, user["tenant_id"], artifact_type
    )
    blockchain.add_entry(
        {"action": "artifact_collected", "artifact_id": artifact["id"],
         "sha256": artifact["sha256"], "analyst": user["username"]},
        "forensics", user["tenant_id"]
    )
    return artifact


@app.get("/api/forensics/artifacts")
async def list_artifacts(user=Depends(require_analyst)):
    return {"artifacts": forensics.list_artifacts(user["tenant_id"])}


@app.get("/api/forensics/artifacts/{artifact_id}/verify")
async def verify_artifact(artifact_id: str, user=Depends(require_analyst)):
    return forensics.verify_artifact_integrity(artifact_id)


@app.post("/api/forensics/artifacts/{artifact_id}/transfer")
async def transfer_custody(artifact_id: str, to_analyst: str,
                            reason: str = "transfer", user=Depends(require_analyst)):
    return forensics.transfer_custody(artifact_id, user["username"], to_analyst, reason)


# ─── Malware Vault Routes ──────────────────────────────────────────────────────

@app.post("/api/malware/samples")
async def upload_malware(
        file: UploadFile = File(...),
        tags: str = Form(""),
        user=Depends(require_admin)):
    data = await file.read()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    sample = malware_vault.upload_sample(data, file.filename, user["username"],
                                          user["tenant_id"], tag_list)
    return sample


@app.get("/api/malware/samples")
async def list_malware(user=Depends(require_admin)):
    return {"samples": malware_vault.list_samples(user["tenant_id"])}


@app.post("/api/malware/analyze")
async def analyze_malware(file: UploadFile = File(...), user=Depends(require_admin)):
    data = await file.read()
    return ransomware_analyzer.analyze_sample(data, file.filename)


# ─── Password Lab Routes ───────────────────────────────────────────────────────

@app.post("/api/password/analyze")
async def analyze_password(req: PasswordAnalyzeRequest):
    return password_lab.analyze_password(req.password)


@app.post("/api/password/hash")
async def hash_password_route(req: PasswordAnalyzeRequest, user=Depends(require_analyst)):
    return password_lab.hash_password(req.password)


# ─── Crypto Detection Routes ───────────────────────────────────────────────────

@app.post("/api/crypto-detect/scan")
async def scan_crypto_threats(req: CryptoAnalysisRequest, user=Depends(require_analyst)):
    return crypto_detector.scan_bulk(req.network_events)


@app.post("/api/crypto-detect/event")
async def analyze_single_event(event: Dict, user=Depends(require_analyst)):
    return crypto_detector.analyze_network_event(event)


# ─── Post-Quantum Crypto Routes ────────────────────────────────────────────────

@app.post("/api/pqc/kyber/keygen")
async def kyber_keygen(user=Depends(require_analyst)):
    return pqc.kyber_keygen()


@app.post("/api/pqc/dilithium/keygen")
async def dilithium_keygen(user=Depends(require_analyst)):
    return pqc.dilithium_keygen()


@app.post("/api/pqc/dilithium/sign")
async def dilithium_sign(message: str, private_key: str, user=Depends(require_analyst)):
    return pqc.dilithium_sign(message, private_key)


@app.get("/api/pqc/algorithms")
async def pqc_algorithms():
    return pqc.get_algorithm_info()


# ─── Blockchain Audit Routes ───────────────────────────────────────────────────

@app.get("/api/blockchain/chain")
async def get_chain(data_type: str = None, limit: int = 50,
                     user=Depends(require_analyst)):
    return {"blocks": blockchain.get_chain(user["tenant_id"], data_type, limit)}


@app.get("/api/blockchain/verify")
async def verify_chain(user=Depends(require_analyst)):
    return blockchain.verify_chain()


@app.get("/api/blockchain/stats")
async def blockchain_stats(user=Depends(require_analyst)):
    return blockchain.get_stats()


# ─── UEBA Routes ──────────────────────────────────────────────────────────────

@app.get("/api/ueba/anomalies")
async def get_anomalies(limit: int = 100, user=Depends(require_analyst)):
    return {"anomalies": ueba.get_all_anomalies(limit)}


@app.get("/api/ueba/users/{user_id}/risk")
async def ueba_user_risk(user_id: str, user=Depends(require_analyst)):
    return ueba.get_user_risk(user_id)


# ─── Tenant Routes ─────────────────────────────────────────────────────────────

@app.get("/api/tenants")
async def list_tenants(user=Depends(require_admin)):
    return {"tenants": tenant_manager.list_tenants()}


@app.post("/api/tenants")
async def create_tenant(tenant_id: str, name: str, user=Depends(require_admin)):
    return tenant_manager.create_tenant(tenant_id, name)


# ─── Dashboard/Health Routes ───────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "modules": {
            "kms": "active",
            "vault": "active",
            "pki": "active" if pki.is_initialized() else "not_initialized",
            "zero_trust": "active",
            "blockchain": "active",
            "siem": "active",
            "threat_intel": "active",
            "forensics": "active",
            "malware_vault": "active",
            "password_lab": "active",
            "ransomware_analyzer": "active",
            "crypto_detector": "active",
            "pqc": "active",
            "ueba": "active"
        }
    }


@app.get("/api/dashboard/stats")
async def dashboard_stats(user=Depends(get_current_user)):
    siem_data = siem.get_stats(user["tenant_id"])
    bc_data = blockchain.get_stats()
    keys = kms.list_keys(user["tenant_id"])
    secrets = vault.list_secrets(user["tenant_id"])
    indicators = threat_intel.get_feed(tenant_id=user["tenant_id"])

    return {
        "alerts": {
            "total": siem_data["total_alerts"],
            "open": siem_data["by_status"].get("open", 0),
            "by_severity": siem_data["by_severity"]
        },
        "incidents": siem_data["total_incidents"],
        "keys": {"total": len(keys),
                  "active": sum(1 for k in keys if k.get("status") == "active")},
        "secrets": {"total": len(secrets),
                     "active": sum(1 for s in secrets if not s.get("revoked"))},
        "threat_indicators": len(indicators),
        "blockchain_blocks": bc_data["total_blocks"],
        "blockchain_valid": bc_data["chain_valid"],
        "artifacts": len(forensics.list_artifacts(user["tenant_id"])),
        "malware_samples": len(malware_vault.list_samples(user["tenant_id"])),
        "pki_initialized": pki.is_initialized()
    }


# Serve frontend for all non-API routes
@app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
async def serve_frontend(full_path: str):
    frontend_path = Path("../frontend/build/index.html")
    if frontend_path.exists():
        return HTMLResponse(frontend_path.read_text())
    return HTMLResponse("""
    <html><body style="background:#0a0e1a;color:#00ff88;font-family:monospace;padding:40px">
    <h1>🛡️ AegisXDR Backend Running</h1>
    <p>API: <a href="/api/docs" style="color:#00aaff">/api/docs</a></p>
    <p>Build frontend: cd frontend && npm install && npm run build</p>
    </body></html>
    """)
