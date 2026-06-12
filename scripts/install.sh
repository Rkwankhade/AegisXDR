#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         AegisXDR — Kali Linux Setup Script                  ║
# ║  SOC L3 + Cloud Security + Applied Cryptography Platform    ║
# ╚══════════════════════════════════════════════════════════════╝
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

banner() {
  echo -e "\n${GREEN}"
  echo "  █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗  ██╗██████╗ ██████╗ "
  echo " ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚██╗██╔╝██╔══██╗██╔══██╗"
  echo " ███████║█████╗  ██║  ███╗██║███████╗     ╚███╔╝ ██║  ██║██████╔╝"
  echo " ██╔══██║██╔══╝  ██║   ██║██║╚════██║     ██╔██╗ ██║  ██║██╔══██╗"
  echo " ██║  ██║███████╗╚██████╔╝██║███████║    ██╔╝ ██╗██████╔╝██║  ██║"
  echo " ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝"
  echo -e "${CYAN}     Research-Scale Security Platform — Kali Linux Edition${NC}"
  echo -e "${YELLOW}     SIEM · XDR · KMS · PKI · Vault · PQC · Forensics · Blockchain${NC}\n"
}

step() { echo -e "\n${BOLD}${BLUE}[*] $1${NC}"; }
ok()   { echo -e "  ${GREEN}✓ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠ $1${NC}"; }
err()  { echo -e "  ${RED}✗ $1${NC}"; }

# ── Detect project root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND="$PROJECT_ROOT/backend"
FRONTEND="$PROJECT_ROOT/frontend"

banner

# ── Check Kali / Debian ───────────────────────────────────────────────────────
step "Checking system"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  ok "OS: $PRETTY_NAME"
else
  warn "Could not detect OS — continuing anyway"
fi

if ! command -v python3 &>/dev/null; then
  err "Python3 not found — install with: sudo apt install python3"
  exit 1
fi
PY_VER=$(python3 --version)
ok "Python: $PY_VER"

# ── System dependencies ───────────────────────────────────────────────────────
step "Installing system dependencies"
sudo apt-get update -q
sudo apt-get install -y -q \
  python3-pip python3-venv python3-dev \
  build-essential libssl-dev libffi-dev \
  libmagic1 libmagic-dev \
  redis-server \
  nodejs npm \
  curl wget git 2>/dev/null || warn "Some packages may already be installed"
ok "System packages installed"

# Check redis
if systemctl is-active --quiet redis-server 2>/dev/null; then
  ok "Redis already running"
else
  sudo systemctl start redis-server 2>/dev/null || warn "Could not start Redis (optional)"
fi

# ── Python Virtual Environment ────────────────────────────────────────────────
step "Setting up Python virtual environment"
cd "$BACKEND"
if [ ! -d "venv" ]; then
  python3 -m venv venv
  ok "Virtual environment created"
else
  ok "Virtual environment exists"
fi

source venv/bin/activate
pip install --upgrade pip -q

step "Installing Python dependencies (this may take 2-5 minutes...)"
pip install -r requirements.txt -q 2>&1 | tail -5
ok "Python dependencies installed"

# Install argon2-cffi separately (sometimes needs special handling)
pip install argon2-cffi argon2-cffi-bindings -q 2>/dev/null || warn "argon2-cffi already installed"
pip install qrcode pillow pyotp -q 2>/dev/null || warn "QR packages already installed"

# ── Environment config ────────────────────────────────────────────────────────
step "Setting up environment configuration"
if [ ! -f "$BACKEND/.env" ]; then
  cp "$BACKEND/.env.example" "$BACKEND/.env"
  # Generate a random secret key
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/aegisxdr-super-secret-key-change-in-production-32chars/$SECRET/" "$BACKEND/.env"
  sed -i "s/aegisxdr-jwt-secret-change-me/$JWT_SECRET/" "$BACKEND/.env"
  ok ".env created with secure random keys"
else
  ok ".env already exists"
fi

# ── Create data directories ───────────────────────────────────────────────────
step "Creating data directories"
mkdir -p "$BACKEND/data"/{kms/keys,vault,pki/{root,intermediate,certs},malware,threat_intel,forensics,blockchain,sandbox,keys,logs}
ok "Data directories created"

# ── Frontend setup ────────────────────────────────────────────────────────────
step "Setting up React frontend"
cd "$FRONTEND"
if command -v node &>/dev/null; then
  NODE_VER=$(node --version)
  ok "Node.js: $NODE_VER"
  npm install --legacy-peer-deps -q 2>&1 | tail -3
  ok "Frontend npm packages installed"
else
  err "Node.js not found — run: sudo apt install nodejs npm"
  exit 1
fi

echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════╗"
echo    "║          ✓ AegisXDR Installation Complete!           ║"
echo -e "╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}To start AegisXDR, run:${NC}"
echo -e "  ${YELLOW}cd $PROJECT_ROOT && bash scripts/run.sh${NC}"
echo ""
