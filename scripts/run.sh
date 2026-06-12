#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║              AegisXDR — Start Script                        ║
# ╚══════════════════════════════════════════════════════════════╝
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND="$PROJECT_ROOT/backend"
FRONTEND="$PROJECT_ROOT/frontend"

echo -e "${GREEN}"
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║     🛡  AegisXDR Security Platform Starting       ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check venv
if [ ! -f "$BACKEND/venv/bin/activate" ]; then
  echo -e "${RED}✗ Virtual environment not found. Run install.sh first.${NC}"
  exit 1
fi

# Start Redis if needed
if ! redis-cli ping &>/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Starting Redis...${NC}"
  sudo systemctl start redis-server 2>/dev/null || redis-server --daemonize yes 2>/dev/null || true
fi

# ── Kill any existing instances ───────────────────────────────────────────────
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "react-scripts start" 2>/dev/null || true
sleep 1

# ── Start Backend ─────────────────────────────────────────────────────────────
echo -e "${BLUE}[*] Starting AegisXDR Backend (FastAPI)...${NC}"
cd "$BACKEND"
source venv/bin/activate

mkdir -p data/{kms/keys,vault,pki/{root,intermediate,certs},malware,threat_intel,forensics,blockchain,sandbox,keys,logs}

# Copy .env if missing
[ -f .env ] || cp .env.example .env

nohup uvicorn main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --log-level info \
  > "$PROJECT_ROOT/logs/backend.log" 2>&1 &

BACKEND_PID=$!
echo -e "${GREEN}  ✓ Backend PID: $BACKEND_PID${NC}"
sleep 3

# Verify backend started
if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
  echo -e "${GREEN}  ✓ Backend healthy at http://localhost:8000${NC}"
else
  echo -e "${YELLOW}  ⚠ Backend still starting... check logs/backend.log${NC}"
fi

# ── Start Frontend ────────────────────────────────────────────────────────────
echo -e "${BLUE}[*] Starting AegisXDR Frontend (React)...${NC}"
cd "$FRONTEND"

nohup npm start \
  > "$PROJECT_ROOT/logs/frontend.log" 2>&1 &

FRONTEND_PID=$!
echo -e "${GREEN}  ✓ Frontend PID: $FRONTEND_PID${NC}"

# Save PIDs
mkdir -p "$PROJECT_ROOT/logs"
echo "$BACKEND_PID" > "$PROJECT_ROOT/logs/backend.pid"
echo "$FRONTEND_PID" > "$PROJECT_ROOT/logs/frontend.pid"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗"
echo    "║           🛡  AegisXDR is Starting Up!                   ║"
echo    "╠═══════════════════════════════════════════════════════════╣"
echo -e "║  Frontend:   ${CYAN}http://localhost:3000${GREEN}                       ║"
echo -e "║  Backend:    ${CYAN}http://localhost:8000${GREEN}                       ║"
echo -e "║  API Docs:   ${CYAN}http://localhost:8000/api/docs${GREEN}              ║"
echo    "╠═══════════════════════════════════════════════════════════╣"
echo -e "║  Login:  ${YELLOW}admin${GREEN} / ${YELLOW}AegisXDR@2024!${GREEN}                       ║"
echo    "╠═══════════════════════════════════════════════════════════╣"
echo -e "║  Logs:  logs/backend.log  |  logs/frontend.log           ║"
echo    "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${CYAN}Frontend takes ~30 seconds to compile on first run.${NC}"
echo -e "${CYAN}Press Ctrl+C or run scripts/stop.sh to stop.${NC}\n"

# Tail logs
mkdir -p "$PROJECT_ROOT/logs"
sleep 5
echo -e "${BLUE}Backend logs:${NC}"
tail -f "$PROJECT_ROOT/logs/backend.log" &
TAIL_PID=$!

# Wait for user interrupt
trap "kill $TAIL_PID 2>/dev/null; echo -e '\n${YELLOW}Use scripts/stop.sh to cleanly stop services.${NC}'" EXIT
wait $BACKEND_PID 2>/dev/null || true
