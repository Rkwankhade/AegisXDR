"""AegisXDR Database Models"""
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    tenant_key_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="analyst")
    tenant_id = Column(String, ForeignKey("tenants.id"))
    mfa_secret = Column(String)
    mfa_enabled = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    last_login = Column(DateTime)
    last_ip = Column(String)
    failed_logins = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class CryptoKey(Base):
    __tablename__ = "crypto_keys"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)  # AES-256-GCM, RSA-4096, ECC
    purpose = Column(String)  # encrypt, sign, exchange
    tenant_id = Column(String, ForeignKey("tenants.id"))
    status = Column(String, default="active")  # active, rotated, revoked
    key_material = Column(Text)  # encrypted key material
    public_key = Column(Text)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    rotated_at = Column(DateTime)
    revoked_at = Column(DateTime)
    next_rotation = Column(DateTime)
    meta_data = Column(JSON, default={})


class Secret(Base):
    __tablename__ = "secrets"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    secret_type = Column(String)  # api_key, db_password, cert, ssh_key, jwt
    tenant_id = Column(String, ForeignKey("tenants.id"))
    encrypted_value = Column(Text)
    access_policy = Column(JSON, default={})
    lease_duration = Column(Integer, default=3600)
    last_accessed = Column(DateTime)
    last_rotated = Column(DateTime)
    auto_rotate = Column(Boolean, default=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Certificate(Base):
    __tablename__ = "certificates"
    id = Column(String, primary_key=True)
    common_name = Column(String, nullable=False)
    cert_type = Column(String)  # root_ca, intermediate_ca, client, server
    tenant_id = Column(String, ForeignKey("tenants.id"))
    pem_cert = Column(Text)
    pem_key = Column(Text)
    issuer_id = Column(String)
    serial_number = Column(String)
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime)
    csr = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(String, primary_key=True)
    ioc_type = Column(String)  # ip, domain, hash, url, email
    value = Column(String, nullable=False)
    severity = Column(String, default="medium")
    confidence = Column(Float, default=0.5)
    source = Column(String)
    publisher = Column(String)
    signature = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=False)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    tags = Column(JSON, default=[])
    ttl = Column(DateTime)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, default="medium")
    category = Column(String)
    source = Column(String)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    status = Column(String, default="open")
    assigned_to = Column(String)
    mitre_tactics = Column(JSON, default=[])
    mitre_techniques = Column(JSON, default=[])
    raw_event = Column(JSON, default={})
    risk_score = Column(Float, default=0.0)
    false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, default="medium")
    status = Column(String, default="open")
    tenant_id = Column(String, ForeignKey("tenants.id"))
    assigned_to = Column(String)
    alert_ids = Column(JSON, default=[])
    timeline = Column(JSON, default=[])
    artifacts = Column(JSON, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)


class ForensicArtifact(Base):
    __tablename__ = "forensic_artifacts"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    artifact_type = Column(String)
    sha256 = Column(String)
    sha512 = Column(String)
    file_size = Column(Integer)
    analyst = Column(String)
    analyst_signature = Column(Text)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    incident_id = Column(String, ForeignKey("incidents.id"))
    storage_path = Column(String)
    chain_of_custody = Column(JSON, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)


class MalwareSample(Base):
    __tablename__ = "malware_samples"
    id = Column(String, primary_key=True)
    name = Column(String)
    original_name = Column(String)
    sha256 = Column(String, unique=True)
    md5 = Column(String)
    file_type = Column(String)
    file_size = Column(Integer)
    encrypted_path = Column(String)
    version = Column(Integer, default=1)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    tags = Column(JSON, default=[])
    analysis_results = Column(JSON, default={})
    yara_matches = Column(JSON, default=[])
    uploaded_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class BlockchainBlock(Base):
    __tablename__ = "blockchain_blocks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    block_hash = Column(String, unique=True, nullable=False)
    previous_hash = Column(String, nullable=False)
    data = Column(JSON, nullable=False)
    data_type = Column(String)  # alert, incident, forensics, evidence
    nonce = Column(Integer, default=0)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True)
    action = Column(String, nullable=False)
    resource_type = Column(String)
    resource_id = Column(String)
    user_id = Column(String)
    tenant_id = Column(String)
    ip_address = Column(String)
    details = Column(JSON, default={})
    success = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ZeroTrustSession(Base):
    __tablename__ = "zero_trust_sessions"
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"))
    device_id = Column(String)
    device_fingerprint = Column(String)
    ip_address = Column(String)
    location = Column(String)
    risk_score = Column(Float, default=0.0)
    trust_level = Column(String, default="none")  # none, low, medium, high
    verified = Column(Boolean, default=False)
    last_verified = Column(DateTime)
    behavior_score = Column(Float, default=1.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    rule_type = Column(String)  # sigma, yara, custom
    content = Column(Text, nullable=False)
    signature = Column(Text)
    author = Column(String)
    tenant_id = Column(String, ForeignKey("tenants.id"))
    enabled = Column(Boolean, default=True)
    last_modified = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class NetworkEvent(Base):
    __tablename__ = "network_events"
    id = Column(String, primary_key=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    bytes_sent = Column(Integer, default=0)
    bytes_recv = Column(Integer, default=0)
    tenant_id = Column(String)
    tls_version = Column(String)
    cipher_suite = Column(String)
    cert_subject = Column(String)
    cert_issuer = Column(String)
    cert_valid = Column(Boolean)
    weak_tls = Column(Boolean, default=False)
    self_signed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)
