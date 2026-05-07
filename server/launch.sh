#!/bin/bash
# bb-hunter MCP launcher.
#
# Called from .mcp.json so Claude Code spawns the server through this script
# instead of plain `python3`. Wraps the server in firejail when available so
# the MCP process can only touch BB_ROOT, the vault, the scripts dir, and the
# skills dir. Network access is preserved (the server has to launch
# curl/nmap/etc); only filesystem and Linux capabilities are restricted.
#
# Falls back to plain python3 if firejail is missing — install it with:
#     sudo apt install firejail
#
# Environment variables expected (set in .mcp.json `env` block):
#   BB_ROOT     workspace root (programs/, recon/, findings/, loot/)
#   BB_VAULT    sensitive-value vault (defaults to ~/.hive)
#   BB_SCRIPTS  scripts dir for two-step approval (optional)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$SCRIPT_DIR/server.py"

BB_ROOT="${BB_ROOT:-$HOME/Documents/BugBounty}"
BB_VAULT="${BB_VAULT:-$HOME/.hive}"
BB_SCRIPTS="${BB_SCRIPTS:-$HOME/Documents/Scripts}"
SKILLS_DIR="$HOME/.claude/skills"
PY_USER_SITE="$HOME/.local"   # pip-installed packages live here (mcp etc.)

# Paths must exist before firejail tries to whitelist them — firejail refuses
# to whitelist a missing path and aborts the whole sandbox.
mkdir -p "$BB_VAULT" "$BB_ROOT" /tmp/bb_working
[[ -d "$BB_SCRIPTS" ]]    || BB_SCRIPTS=""
[[ -d "$SKILLS_DIR" ]]    || SKILLS_DIR=""
[[ -d "$PY_USER_SITE" ]]  || PY_USER_SITE=""

if command -v firejail >/dev/null 2>&1; then
  ARGS=(
    --quiet
    --noprofile
    --caps.drop=all
    --nonewprivs
    --seccomp
    --private-dev
    # bb-mcp-server install dir — read-only so the server can't modify its
    # own code at runtime. Required when bb-mcp-server lives outside BB_ROOT
    # (the normal install pattern).
    --whitelist="$SCRIPT_DIR"
    --read-only="$SCRIPT_DIR"
    --whitelist="$BB_ROOT"
    --whitelist="$BB_VAULT"
  )
  [[ -n "$BB_SCRIPTS" ]]    && ARGS+=( --whitelist="$BB_SCRIPTS"    --read-only="$BB_SCRIPTS" )
  [[ -n "$SKILLS_DIR" ]]    && ARGS+=( --whitelist="$SKILLS_DIR"    --read-only="$SKILLS_DIR" )
  [[ -n "$PY_USER_SITE" ]]  && ARGS+=( --whitelist="$PY_USER_SITE"  --read-only="$PY_USER_SITE" )
  exec firejail "${ARGS[@]}" python3 "$SERVER"
else
  exec python3 "$SERVER"
fi
