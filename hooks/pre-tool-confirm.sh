#!/usr/bin/env python3
"""
PreToolUse hook — pre-tool confirmation gate.

For every outbound (target-touching) MCP tool call, force a user approval
prompt — even for tools already in `permissions.allow`. The prompt's reason
text contains a structured summary of what's about to fire: tool, program,
target, key args. Operator sees exactly the resolved request before yes/no.

Local-only tools (consult_skill, vault_lookup, save_note, grep_file,
read_filtered, list_recon_files, count_lines, check_scope, create_report,
verify_audit_log, request_script_approval, confirm_script_execution) are
NOT gated — they don't touch the target.

Disable temporarily by setting env BB_NO_PRE_CONFIRM=1.
"""

import json, os, sys

if os.environ.get('BB_NO_PRE_CONFIRM') == '1':
    sys.exit(0)

try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(0)

tool_name = payload.get('tool_name', '')
ti = payload.get('tool_input', {}) or {}

# ── Tools that touch the target (or third-party intel APIs) — gate every call ─
TARGET_TOUCHING = {
    # Active web/recon
    'mcp__bb-hunter__run_curl',
    'mcp__bb-hunter__run_httpx',
    'mcp__bb-hunter__run_nmap',
    'mcp__bb-hunter__run_whatweb',
    'mcp__bb-hunter__run_feroxbuster',
    'mcp__bb-hunter__run_ffuf',
    'mcp__bb-hunter__run_katana',
    # Vuln testing (high blast radius)
    'mcp__bb-hunter__run_nuclei',
    'mcp__bb-hunter__run_sqlmap',
    'mcp__bb-hunter__run_dalfox',
    # Passive recon (third-party APIs, still external)
    'mcp__bb-hunter__run_subfinder',
    'mcp__bb-hunter__run_amass',
    'mcp__bb-hunter__run_assetfinder',
    'mcp__bb-hunter__run_dig',
    'mcp__bb-hunter__run_whois',
}

if tool_name not in TARGET_TOUCHING:
    sys.exit(0)


def short(s, n=200):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + '…'


# ── Build the structured summary ──────────────────────────────────────────────
short_name = tool_name.replace('mcp__bb-hunter__', '')

target = (ti.get('target') or ti.get('url') or ti.get('domain') or
          ti.get('input_file') or '(see args)')
program = ti.get('program', '(no program arg)')

lines = [
    '═══════ PRE-TOOL CONFIRMATION ═══════',
    f'Tool:     {short_name}',
    f'Program:  {program}',
    f'Target:   {short(target)}',
]

extra_keys = [k for k in ti.keys()
              if k not in ('program', 'target', 'url', 'domain', 'input_file')]
if extra_keys:
    lines.append('Args:')
    for k in extra_keys:
        v = ti[k]
        if isinstance(v, (list, dict)):
            v = json.dumps(v, default=str)
        if isinstance(v, str) and len(v) > 200:
            lines.append(f'  {k}: <{len(v)} chars> {short(v)}')
        else:
            lines.append(f'  {k}: {short(v)}')

if short_name in ('run_nuclei', 'run_sqlmap', 'run_dalfox', 'run_feroxbuster', 'run_ffuf'):
    lines.append('⚠ ACTIVE SCANNER — confirm program permits automated scanning '
                 '(rate-capped to 5 rps server-side).')
if short_name == 'run_sqlmap':
    lines.append('⚠ sqlmap — destructive flags blocked; detection-only mode.')

lines.append('Approve to send. Cancel to revise.')
lines.append('═════════════════════════════════════')

reason = '\n'.join(lines)

output = {
    'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'permissionDecision': 'ask',
        'permissionDecisionReason': reason,
    }
}
print(json.dumps(output))
