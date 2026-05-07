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

# ── 7. Smoke test — fail fast on syntax / import errors ───────────────────────
info "Running MCP server smoke test (config + server import)..."
if (cd "$MCP_DIR" && python3 -c "import config, server" > /dev/null 2>&1); then
    info "Smoke test passed."
else
    error "MCP server failed to import. Check syntax in $MCP_DIR/config.py and $MCP_DIR/server.py"
fi

# ── 8. Make launcher executable ───────────────────────────────────────────────
if [[ -f "$MCP_DIR/launch.sh" ]]; then
    chmod 750 "$MCP_DIR/launch.sh"
    info "Launcher ready: $MCP_DIR/launch.sh"
else
    warn "launch.sh not found at $MCP_DIR/launch.sh — server will run without firejail."
fi

# ── 9. Register with Claude Code ──────────────────────────────────────────────
info "Registering MCP server with Claude Code..."
CLAUDE_MCP_CMD="claude mcp add bb-hunter $MCP_DIR/launch.sh \
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
    warn "Or copy .mcp.example.json to .mcp.json in your project root and adjust paths."
fi

# ── 10. Firejail (optional, used by launch.sh) ────────────────────────────────
# launch.sh detects firejail at runtime and wraps the server with: caps dropped,
# seccomp on, filesystem narrowed to BB_ROOT + BB_VAULT + BB_SCRIPTS + skills
# dir + pip user-site. Network access is preserved — the server has to launch
# curl/nmap/etc — only filesystem and capabilities are restricted.
if command -v firejail > /dev/null 2>&1; then
    info "firejail $(firejail --version 2>/dev/null | head -1 | awk '{print $3}') found — server will run sandboxed via launch.sh."
else
    warn "firejail not installed — server will run unsandboxed."
    warn "Install for filesystem + capability isolation:"
    echo "  sudo apt install firejail"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e " ${GREEN}Setup complete.${NC}"
echo ""
echo " To start the server (firejail-wrapped if installed):"
echo "   $MCP_DIR/launch.sh"
echo ""
echo " To start unwrapped (debugging only):"
echo "   python3 $MCP_DIR/server.py"
echo ""
echo " Vault location: $VAULT_DIR"
echo " Verify audit log: use verify_audit_log tool in Claude"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
