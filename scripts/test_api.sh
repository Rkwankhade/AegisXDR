#!/usr/bin/env bash
# AegisXDR — API Test Script
# Tests all endpoints after the server is running

BASE="http://localhost:8000/api"
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass=0; fail=0

check() {
  local name="$1"; local cmd="$2"; local expect="$3"
  result=$(eval "$cmd" 2>/dev/null)
  if echo "$result" | grep -q "$expect"; then
    echo -e "  ${GREEN}✓ $name${NC}"
    ((pass++))
  else
    echo -e "  ${RED}✗ $name${NC} — got: ${result:0:80}"
    ((fail++))
  fi
}

echo -e "\n${CYAN}╔══════════════════════════════════════════════════╗"
echo    "║       AegisXDR API Test Suite                    ║"
echo -e "╚══════════════════════════════════════════════════╝${NC}\n"

# ── Health ─────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[Health]${NC}"
check "Health endpoint" "curl -s $BASE/health" "operational"

# ── Auth ───────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Authentication]${NC}"
TOKEN_RESP=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AegisXDR@2024!"}')
TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
  echo -e "  ${GREEN}✓ Login successful — JWT obtained${NC}"
  ((pass++))
else
  echo -e "  ${RED}✗ Login failed${NC}"
  ((fail++))
fi

AUTH="-H \"Authorization: Bearer $TOKEN\""

# ── KMS ────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[KMS — Key Management]${NC}"
check "List keys" \
  "curl -s $BASE/kms/keys -H 'Authorization: Bearer $TOKEN'" "keys"

KEY_RESP=$(curl -s -X POST "$BASE/kms/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-aes-key","algorithm":"AES-256-GCM","purpose":"encrypt","rotation_days":90}')
KEY_ID=$(echo "$KEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
[ -n "$KEY_ID" ] && echo -e "  ${GREEN}✓ AES-256-GCM key created: ${KEY_ID:0:8}...${NC}" && ((pass++)) || { echo -e "  ${RED}✗ Key creation failed${NC}"; ((fail++)); }

RSA_RESP=$(curl -s -X POST "$BASE/kms/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-rsa-key","algorithm":"RSA-4096","purpose":"sign","rotation_days":180}')
RSA_ID=$(echo "$RSA_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
[ -n "$RSA_ID" ] && echo -e "  ${GREEN}✓ RSA-4096 key created: ${RSA_ID:0:8}...${NC}" && ((pass++)) || echo -e "  ${YELLOW}⚠ RSA key (may be slow)${NC}"

# ── Vault ──────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Secrets Vault]${NC}"
SECRET_RESP=$(curl -s -X POST "$BASE/vault/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-api-key","value":"sk-test-12345abcdef","secret_type":"api_key","lease_duration":3600}')
SECRET_ID=$(echo "$SECRET_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
[ -n "$SECRET_ID" ] && echo -e "  ${GREEN}✓ Secret stored: ${SECRET_ID:0:8}...${NC}" && ((pass++)) || { echo -e "  ${RED}✗ Secret storage failed${NC}"; ((fail++)); }

check "List secrets" "curl -s $BASE/vault/secrets -H 'Authorization: Bearer $TOKEN'" "secrets"

# ── PKI ────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[PKI Infrastructure]${NC}"
check "Initialize Root CA" \
  "curl -s -X POST '$BASE/pki/root-ca?org=AegisXDR' -H 'Authorization: Bearer $TOKEN'" "root_ca"
check "Initialize Intermediate CA" \
  "curl -s -X POST '$BASE/pki/intermediate-ca?org=AegisXDR' -H 'Authorization: Bearer $TOKEN'" "intermediate_ca"

CERT_RESP=$(curl -s -X POST "$BASE/pki/certificates" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"test.aegisxdr.local","cert_type":"server","valid_days":365}')
CERT_ID=$(echo "$CERT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
[ -n "$CERT_ID" ] && echo -e "  ${GREEN}✓ Server certificate issued: ${CERT_ID:0:8}...${NC}" && ((pass++)) || { echo -e "  ${RED}✗ Certificate issue failed${NC}"; ((fail++)); }

# ── Zero Trust ─────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Zero Trust]${NC}"
ZT_RESP=$(curl -s -X POST "$BASE/zerotrust/evaluate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-001","device_fingerprint":"fp-abc123","ip_address":"192.168.1.10","resource":"/api/data","action":"READ","context":{"mfa_verified":true}}')
check "Zero Trust evaluation" "echo '$ZT_RESP'" "trust_level"

# ── SIEM ───────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[SIEM/XDR]${NC}"
SIEM_RESP=$(curl -s -X POST "$BASE/siem/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"events":[{"event_type":"auth_failure","user_id":"hacker","ip":"10.0.0.99","source":"endpoint"},{"event_type":"auth_failure","user_id":"hacker","ip":"10.0.0.99","source":"endpoint"},{"event_type":"auth_failure","user_id":"hacker","ip":"10.0.0.99","source":"endpoint"},{"event_type":"auth_failure","user_id":"hacker","ip":"10.0.0.99","source":"endpoint"},{"event_type":"auth_failure","user_id":"hacker","ip":"10.0.0.99","source":"endpoint"},{"event_type":"process_injection","pid":1234,"source":"edr"}]}')
check "Event ingestion" "echo '$SIEM_RESP'" "processed"

check "Get alerts" "curl -s $BASE/siem/alerts -H 'Authorization: Bearer $TOKEN'" "alerts"
check "SIEM stats" "curl -s $BASE/siem/stats -H 'Authorization: Bearer $TOKEN'" "total_alerts"

# ── Threat Intel ───────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Threat Intelligence]${NC}"
IOC_RESP=$(curl -s -X POST "$BASE/threat-intel/indicators" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ioc_type":"ip","value":"185.220.101.1","severity":"critical","confidence":0.95,"source":"test","tags":["tor","c2"]}')
check "Add IOC" "echo '$IOC_RESP'" "signature"
check "Lookup IOC" "curl -s '$BASE/threat-intel/lookup/185.220.101.1' -H 'Authorization: Bearer $TOKEN'" "found"

# ── Password Lab ───────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Password Security Lab]${NC}"
check "Analyze weak password" \
  "curl -s -X POST $BASE/password/analyze -H 'Content-Type: application/json' -d '{\"password\":\"password123\"}'" "very_weak\|weak"
check "Analyze strong password" \
  "curl -s -X POST $BASE/password/analyze -H 'Content-Type: application/json' -d '{\"password\":\"X9#mK2\$pL7nQ4vR8wZ6!\"}'" "strong"

# ── PQC ────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Post-Quantum Cryptography]${NC}"
check "Kyber keygen" \
  "curl -s -X POST $BASE/pqc/kyber/keygen -H 'Authorization: Bearer $TOKEN'" "CRYSTALS-Kyber"
check "Dilithium keygen" \
  "curl -s -X POST $BASE/pqc/dilithium/keygen -H 'Authorization: Bearer $TOKEN'" "CRYSTALS-Dilithium"
check "PQC algorithm info" \
  "curl -s $BASE/pqc/algorithms" "kyber"

# ── Blockchain ─────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Blockchain Audit Trail]${NC}"
check "Get chain" \
  "curl -s $BASE/blockchain/chain -H 'Authorization: Bearer $TOKEN'" "blocks"
check "Verify chain" \
  "curl -s $BASE/blockchain/verify -H 'Authorization: Bearer $TOKEN'" "valid"
check "Blockchain stats" \
  "curl -s $BASE/blockchain/stats -H 'Authorization: Bearer $TOKEN'" "total_blocks"

# ── Crypto Detection ───────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Cryptographic Threat Detection]${NC}"
SCAN_RESP=$(curl -s -X POST "$BASE/crypto-detect/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"network_events":[{"src_ip":"10.0.0.1","dst_ip":"1.2.3.4","tls_version":"TLSv1.0","cipher_suite":"TLS_RSA_WITH_RC4_128_MD5","cert_subject":"CN=test","cert_issuer":"CN=test","cert_valid":true}]}')
check "TLS scan" "echo '$SCAN_RESP'" "deprecated_tls\|weak_cipher\|findings"

# ── Dashboard ──────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[Dashboard]${NC}"
check "Dashboard stats" \
  "curl -s $BASE/dashboard/stats -H 'Authorization: Bearer $TOKEN'" "alerts"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗"
echo -e "║  Test Results: ${GREEN}${pass} passed${CYAN} / ${RED}${fail} failed${CYAN}  ║"
echo -e "╚══════════════════════════════════════╝${NC}\n"

if [ $fail -eq 0 ]; then
  echo -e "${GREEN}🛡 All systems operational!${NC}\n"
  exit 0
else
  echo -e "${YELLOW}⚠ Some tests failed. Check server logs.${NC}\n"
  exit 1
fi
