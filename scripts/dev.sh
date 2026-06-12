#!/usr/bin/env bash
# AegisXDR — Development Mode (foreground, live logs)
# Uses tmux or two terminals

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND="$PROJECT_ROOT/backend"
FRONTEND="$PROJECT_ROOT/frontend"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}[AegisXDR Dev Mode]${NC}"

# If tmux available, open side-by-side
if command -v tmux &>/dev/null; then
  echo -e "${CYAN}Opening tmux with split panes...${NC}"
  SESSION="aegisxdr"
  tmux kill-session -t $SESSION 2>/dev/null || true
  tmux new-session -d -s $SESSION -x 220 -y 50

  # Left pane — backend
  tmux send-keys -t $SESSION "cd $BACKEND && source venv/bin/activate && uvicorn main:app --host 0.0.0.0 --port 8000 --reload" Enter

  # Right pane — frontend
  tmux split-window -h -t $SESSION
  tmux send-keys -t $SESSION "cd $FRONTEND && npm start" Enter

  tmux attach -t $SESSION
else
  echo -e "${YELLOW}tmux not found — starting backend in background, frontend in foreground${NC}"
  echo -e "${YELLOW}Install tmux for split-pane dev: sudo apt install tmux${NC}\n"

  cd "$BACKEND"
  source venv/bin/activate

  mkdir -p data/{kms/keys,vault,pki/{root,intermediate,certs},malware,threat_intel,forensics,blockchain,sandbox,keys,logs}
  mkdir -p "$PROJECT_ROOT/logs"

  uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
  BACKEND_PID=$!
  echo -e "${GREEN}  ✓ Backend started (PID: $BACKEND_PID)${NC}"
  echo -e "${CYAN}  → API docs: http://localhost:8000/api/docs${NC}"

  sleep 2

  cd "$FRONTEND"
  echo -e "${GREEN}  ✓ Starting frontend...${NC}"
  npm start

  # Kill backend on exit
  trap "kill $BACKEND_PID 2>/dev/null" EXIT
fi
