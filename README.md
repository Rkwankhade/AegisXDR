# 🛡 AegisXDR — Research-Scale Security Platform

> **SOC L3 + Cloud Security + Applied Cryptography**  
> Full-stack security platform for Kali Linux

---

## 🏗 Architecture

```
AegisXDR/
├── backend/              # Python FastAPI
│   ├── core/             # Config
│   ├── db/               # SQLAlchemy models
│   ├── modules/          # All security engines
│   │   ├── kms.py        # Enterprise KMS (AES-256-GCM, RSA-4096, ECC)
│   │   ├── vault.py      # Secrets Vault (HashiCorp-like)
│   │   ├── pki.py        # PKI (Root CA → Intermediate → End-Entity)
│   │   ├── zero_trust.py # Zero Trust Identity Engine
│   │   ├── blockchain.py # Immutable Audit Blockchain
│   │   ├── auth.py       # JWT + TOTP MFA + Argon2id
│   │   ├── siem_xdr.py   # SIEM + UEBA
│   │   └── security_modules.py  # Forensics, Malware, ThreatIntel,
│   │                              # PQC, PasswordLab, Ransomware, CryptoDetect
│   └── main.py           # FastAPI app + all routes
├── frontend/             # React 18 (hacker aesthetic)
│   └── src/
│       ├── pages/        # All UI pages
│       └── components/   # Sidebar, etc.
└── scripts/              # install.sh, run.sh, test_api.sh
```

---

## ⚡ QUICK START (Copy-Paste)

### Step 1 — Clone / navigate to project
```bash
cd ~/aegisxdr
```

### Step 2 — Install everything
```bash
chmod +x scripts/*.sh
bash scripts/install.sh
```

### Step 3 — Run
```bash
bash scripts/run.sh
```

### Step 4 — Open browser
```
http://localhost:3000
```
Login: `admin` / `AegisXDR@2024!`

---

## 📋 ALL COMMANDS

### Installation
```bash
# Full install (first time)
bash scripts/install.sh

# Or manually step by step:
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install argon2-cffi qrcode pillow pyotp

cd ../frontend
npm install --legacy-peer-deps
```

### Running
```bash
# Start both backend + frontend (recommended)
bash scripts/run.sh

# Development mode with tmux split panes
bash scripts/dev.sh

# Backend only
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend only
cd frontend
npm start

# Stop everything
bash scripts/stop.sh
```

### Testing
```bash
# Run full API test suite (after server is up)
bash scripts/test_api.sh
```

### Logs
```bash
# View live backend logs
tail -f logs/backend.log

# View frontend logs
tail -f logs/frontend.log
```

---

## 🌐 Endpoints

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Swagger Docs | http://localhost:8000/api/docs |
| ReDoc | http://localhost:8000/api/redoc |

---

## 🔐 Security Modules

### 1. Enterprise KMS
```bash
# Generate AES-256-GCM key
curl -X POST http://localhost:8000/api/kms/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"prod-key","algorithm":"AES-256-GCM","purpose":"encrypt"}'

# Generate RSA-4096 signing key
curl -X POST http://localhost:8000/api/kms/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"sign-key","algorithm":"RSA-4096","purpose":"sign"}'

# Rotate key
curl -X POST http://localhost:8000/api/kms/keys/{key_id}/rotate \
  -H "Authorization: Bearer $TOKEN"

# Revoke key
curl -X POST "http://localhost:8000/api/kms/keys/{key_id}/revoke?reason=compromised" \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Secrets Vault
```bash
# Store secret
curl -X POST http://localhost:8000/api/vault/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"db-password","value":"s3cr3t!","secret_type":"db_password","auto_rotate":true}'

# Emergency revoke ALL secrets
curl -X POST http://localhost:8000/api/vault/emergency-revoke \
  -H "Authorization: Bearer $TOKEN"
```

### 3. PKI Infrastructure
```bash
# Initialize full PKI chain
curl -X POST "http://localhost:8000/api/pki/root-ca?org=MyOrg" \
  -H "Authorization: Bearer $TOKEN"

curl -X POST "http://localhost:8000/api/pki/intermediate-ca?org=MyOrg" \
  -H "Authorization: Bearer $TOKEN"

# Issue server certificate
curl -X POST http://localhost:8000/api/pki/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"api.myorg.internal","cert_type":"server","valid_days":365}'

# OCSP check
curl http://localhost:8000/api/pki/ocsp/{cert_id} \
  -H "Authorization: Bearer $TOKEN"

# Get CRL
curl http://localhost:8000/api/pki/crl \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Zero Trust
```bash
# Evaluate access request
curl -X POST http://localhost:8000/api/zerotrust/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice",
    "device_fingerprint": "fp-macbook-001",
    "ip_address": "192.168.1.50",
    "resource": "/api/financial-data",
    "action": "READ",
    "context": {"mfa_verified": true, "certificate_auth": true}
  }'
```

### 5. SIEM Events
```bash
# Inject security events
curl -X POST http://localhost:8000/api/siem/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"events":[
    {"event_type":"process_injection","pid":1234,"source":"edr"},
    {"event_type":"auth_failure","user_id":"admin","ip":"10.0.0.99","source":"auth"},
    {"event_type":"auth_failure","user_id":"admin","ip":"10.0.0.99","source":"auth"},
    {"event_type":"auth_failure","user_id":"admin","ip":"10.0.0.99","source":"auth"},
    {"event_type":"auth_failure","user_id":"admin","ip":"10.0.0.99","source":"auth"},
    {"event_type":"auth_failure","user_id":"admin","ip":"10.0.0.99","source":"auth"}
  ]}'

# Get alerts
curl "http://localhost:8000/api/siem/alerts?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Auto-correlate into incidents
curl -X POST http://localhost:8000/api/siem/correlate \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Threat Intelligence
```bash
# Add signed IOC
curl -X POST http://localhost:8000/api/threat-intel/indicators \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ioc_type":"ip","value":"185.220.101.1","severity":"critical","confidence":0.95}'

# Lookup IOC
curl "http://localhost:8000/api/threat-intel/lookup/185.220.101.1" \
  -H "Authorization: Bearer $TOKEN"
```

### 7. Forensics
```bash
# Collect artifact (SHA-256 + SHA-512 + analyst signature)
curl -X POST http://localhost:8000/api/forensics/artifacts \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/evidence.bin" \
  -F "artifact_type=memory_dump" \
  -F "incident_id=INC-001"

# Verify artifact integrity
curl http://localhost:8000/api/forensics/artifacts/{id}/verify \
  -H "Authorization: Bearer $TOKEN"
```

### 8. Malware Vault
```bash
# Upload malware sample (AES-256 encrypted at rest)
curl -X POST http://localhost:8000/api/malware/samples \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample.exe" \
  -F "tags=ransomware,apt"

# Ransomware crypto analysis
curl -X POST http://localhost:8000/api/malware/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@suspicious.exe"
```

### 9. Password Lab
```bash
# Analyze password entropy
curl -X POST http://localhost:8000/api/password/analyze \
  -H "Content-Type: application/json" \
  -d '{"password":"YourPasswordHere"}'

# Hash with Argon2id
curl -X POST http://localhost:8000/api/password/hash \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"YourPasswordHere"}'
```

### 10. Post-Quantum Cryptography
```bash
# Generate Kyber-1024 keypair
curl -X POST http://localhost:8000/api/pqc/kyber/keygen \
  -H "Authorization: Bearer $TOKEN"

# Generate Dilithium3 keypair
curl -X POST http://localhost:8000/api/pqc/dilithium/keygen \
  -H "Authorization: Bearer $TOKEN"
```

### 11. Blockchain Audit
```bash
# Get full chain
curl http://localhost:8000/api/blockchain/chain \
  -H "Authorization: Bearer $TOKEN"

# Verify chain integrity
curl http://localhost:8000/api/blockchain/verify \
  -H "Authorization: Bearer $TOKEN"
```

### 12. Cryptographic Threat Detection
```bash
curl -X POST http://localhost:8000/api/crypto-detect/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"network_events":[{
    "src_ip":"10.0.0.1",
    "dst_ip":"1.2.3.4",
    "tls_version":"TLSv1.0",
    "cipher_suite":"TLS_RSA_WITH_RC4_128_MD5",
    "cert_subject":"CN=evil.com",
    "cert_issuer":"CN=evil.com",
    "cert_valid":true
  }]}'
```

---

## 🔑 Get JWT Token (for curl commands)
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AegisXDR@2024!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: $TOKEN"
```

---

## 🔧 Troubleshooting

```bash
# Port already in use
sudo lsof -i :8000
sudo lsof -i :3000
pkill -f uvicorn
pkill -f "react-scripts"

# Python dependency issues
cd backend && source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall

# Node issues
cd frontend
rm -rf node_modules package-lock.json
npm install --legacy-peer-deps

# Reset all data (WARNING: deletes keys, certs, secrets)
rm -rf backend/data/
bash scripts/install.sh

# Check backend logs
cat logs/backend.log | tail -50

# Test Redis
redis-cli ping
```

---

## 📚 Technologies

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, SQLAlchemy, SQLite |
| Frontend | React 18, Zustand, Recharts, Axios |
| Symmetric Crypto | AES-256-GCM (cryptography lib) |
| Asymmetric Crypto | RSA-4096, ECDSA P-256, X25519 |
| PKI | cryptography.x509, X.509 v3 |
| Password Hashing | Argon2id (argon2-cffi) |
| JWT | python-jose |
| MFA | TOTP (pyotp) |
| PQC (simulated) | CRYSTALS-Kyber, CRYSTALS-Dilithium |
| Hashing | SHA-256, SHA-512, BLAKE3 (simulated) |
| Audit Chain | Custom PoW blockchain |
| Auth | JWT Bearer + TOTP MFA |

---

*AegisXDR — Built for SOC L3 + Applied Cryptography research*
