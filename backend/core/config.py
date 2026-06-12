"""AegisXDR Core Configuration"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).parent.parent


class Settings(BaseSettings):
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    SECRET_KEY: str = "aegisxdr-super-secret-key-change-in-production"
    DEBUG: bool = True

    DATABASE_URL: str = "sqlite:///./aegisxdr.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    JWT_SECRET: str = "aegisxdr-jwt-secret"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    KMS_MASTER_KEY_PATH: str = "./data/kms/master.key"
    KMS_KEY_STORE_PATH: str = "./data/kms/keys/"

    VAULT_STORAGE_PATH: str = "./data/vault/"
    VAULT_MASTER_PASSWORD: str = "change-this"

    PKI_ROOT_CA_PATH: str = "./data/pki/root/"
    PKI_INTERMEDIATE_CA_PATH: str = "./data/pki/intermediate/"
    PKI_CERTS_PATH: str = "./data/pki/certs/"

    MALWARE_VAULT_PATH: str = "./data/malware/"
    MALWARE_VAULT_KEY: str = "change-this-malware-vault-key"

    THREAT_INTEL_FEEDS: str = "./data/threat_intel/"
    FORENSICS_PATH: str = "./data/forensics/"
    BLOCKCHAIN_STORE_PATH: str = "./data/blockchain/"
    SANDBOX_PATH: str = "./data/sandbox/"
    SANDBOX_TIMEOUT: int = 30

    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "AegisXDR@2024!"

    DEFAULT_TENANT: str = "default"

    class Config:
        env_file = ".env"
        extra = "ignore"

    @property
    def cors_origins(self):
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]


settings = Settings()

# Ensure data directories exist
DATA_DIRS = [
    "./data/kms/keys",
    "./data/vault",
    "./data/pki/root",
    "./data/pki/intermediate",
    "./data/pki/certs",
    "./data/malware",
    "./data/threat_intel",
    "./data/forensics",
    "./data/blockchain",
    "./data/sandbox",
    "./data/keys",
    "./data/logs",
]

for d in DATA_DIRS:
    Path(d).mkdir(parents=True, exist_ok=True)
