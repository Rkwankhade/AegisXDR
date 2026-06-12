#!/usr/bin/env bash
# AegisXDR — Stop Script
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}[*] Stopping AegisXDR...${NC}"

pkill -f "uvicorn main:app" 2>/dev/null && echo -e "${GREEN}  ✓ Backend stopped${NC}" || echo "  Backend was not running"
pkill -f "react-scripts start" 2>/dev/null && echo -e "${GREEN}  ✓ Frontend stopped${NC}" || echo "  Frontend was not running"

# Clean up PID files
rm -f "$PROJECT_ROOT/logs/backend.pid" "$PROJECT_ROOT/logs/frontend.pid"

echo -e "${GREEN}  ✓ AegisXDR stopped${NC}"
