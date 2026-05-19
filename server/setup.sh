#!/bin/bash
# Bug Bounty MCP Server — Setup Script
# Run once to install dependencies and configure permissions.
# Usage: bash setup.sh

set -euo pipefail

MCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BB_ROOT="$(dirname "$MCP_DIR")"
VAULT_DIR="$HOME/.hive"
WORK_DIR="/tmp/bb_working"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Bug Bounty MCP Server — Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Python check ────────────────────────────────────────────────────────────
info "Checking Python version..."
python3 --version | grep -E "3\.(1[0-9]|[2-9][0-9])" > /dev/null 2>&1 \
  || error "Python 3.10+ required. Found: $(python3 --version)"
info "Python OK: $(python3 --version)"

# ── 2. Install dependencies ────────────────────────────────────────────────────
info "Installing Python dependencies..."
pip3 install -r "$MCP_DIR/requirements.txt" --quiet
info "Dependencies installed."

# ── 3. Audit dependencies ──────────────────────────────────────────────────────
info "Auditing dependencies for known CVEs..."
if pip3 show pip-audit > /dev/null 2>&1; then
    pip-audit -r "$MCP_DIR/requirements.txt" || warn "pip-audit found issues — review before use."
else
    warn "pip-audit not installed. Install with: pip3 install pip-audit"
    warn "Skipping dependency audit."
fi

# ── 4. Create vault directory ──────────────────────────────────────────────────
info "Creating vault directory: $VAULT_DIR"
mkdir -p "$VAULT_DIR"
chmod 700 "$VAULT_DIR"
info "Vault permissions set (700)."

# ── 5. Create working directory ────────────────────────────────────────────────
info "Creating working directory: $WORK_DIR"
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"

# ── 6. Set permissions on mcp_server files ────────────────────────────────────
info "Setting file permissions..."
find "$MCP_DIR" -name "*.py" -exec chmod 640 {} \;
chmod 750 "$MCP_DIR/setup.sh"

# ── 7. Register with Claude Code ──────────────────────────────────────────────
info "Registering MCP server with Claude Code..."
CLAUDE_MCP_CMD="claude mcp add bb-hunter python3 $MCP_DIR/server.py \
  --env BB_ROOT=$BB_ROOT \
  --env BB_VAULT=$VAULT_DIR \
  --env BB_SCRIPTS=$HOME/Documents/Scripts"

if command -v claude > /dev/null 2>&1; then
    eval "$CLAUDE_MCP_CMD" && info "MCP server registered." \
      || warn "Registration failed — run manually: $CLAUDE_MCP_CMD"
else
    warn "Claude Code CLI not found in PATH."
    warn "Register manually with:"
    echo ""
    echo "  $CLAUDE_MCP_CMD"
    echo ""
    warn "Or copy .mcp.json to your project root:"
    echo ""
    echo "  cp $MCP_DIR/.mcp.json $BB_ROOT/.mcp.json"
fi

# ── 8. Firejail (optional) ─────────────────────────────────────────────────────
if command -v firejail > /dev/null 2>&1; then
    info "firejail found — sandbox available."
    info "To run sandboxed: firejail --noprofile --net=none python3 $MCP_DIR/server.py"
else
    warn "firejail not installed. Install for extra isolation:"
    echo "  sudo apt install firejail"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " ${GREEN}Setup complete.${NC}"
echo ""
echo " To start the server:"
echo "   python3 $MCP_DIR/server.py"
echo ""
echo " To start sandboxed (if firejail installed):"
echo "   firejail --noprofile --net=none python3 $MCP_DIR/server.py"
echo ""
echo " Vault location: $VAULT_DIR"
echo " Verify audit log: use verify_audit_log tool in Claude"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
