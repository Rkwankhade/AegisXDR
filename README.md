# AegisXDR — Research-Scale Security Platform

A professional-grade unified security platform built for SOC L3, Cloud Security, and Applied Cryptography research. Combines 20 security subsystems into a single deployable platform.

## Modules

| Module | Technology |
|--------|-----------|
| Enterprise KMS | AES-256-GCM, RSA-4096, ECC-P256/X25519 |
| Secrets Vault | HashiCorp-inspired, AES-encrypted, auto-rotation |
| PKI Infrastructure | Root CA → Intermediate CA → X.509, OCSP, CRL |
| Zero Trust Engine | Continuous verification, trust scoring, risk signals |
| SIEM / XDR | Sigma rules, MITRE ATT&CK mapping, alert correlation |
| UEBA | Behavioral baselines, anomaly scoring |
| Threat Intelligence | ECDSA-signed IOC feeds, bulk import, lookup |
| Digital Forensics | SHA-256/SHA-512/BLAKE3, chain of custody |
| Malware Vault | AES-encrypted, versioned, audited sample storage |
| Ransomware Analyzer | Entropy detection, crypto API scanning, verdict |
| Password Security Lab | Argon2id hashing, entropy analysis, crack time |
| Post-Quantum Crypto | CRYSTALS-Kyber-1024, Dilithium3 (FIPS 203/204) |
| Blockchain Audit Trail | SHA-256 PoW chain, tamper-evident logging |
| Crypto Threat Detection | Weak TLS, expired certs, deprecated ciphers |
| Multi-Tenant Architecture | Per-tenant crypto keys, isolated namespaces |

## Stack

- **Backend:** Python 3.11, FastAPI, SQLAlchemy, SQLite
- **Frontend:** React 18, hacker terminal aesthetic
- **Crypto:** cryptography, argon2-cffi, pyotp
- **Platform:** Kali Linux

## Quick Start

```bash
# Backend
cd backend && python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
cd frontend && npm install --legacy-peer-deps && npm start
```

Open http://localhost:3000 — Login: `admin` / `AegisXDR@2024!`

API Docs: http://localhost:8000/api/docs

## Author

Rishikesh Wankhade — B.Tech ECE, IIIT Nagpur
