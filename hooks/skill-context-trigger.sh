#!/usr/bin/env python3
"""
PostToolUse hook — auto-injects skill / reference loads when relevant context
appears in tool input or output.

Goal: zero-friction skill use. The moment a cloud asset / contract / browser
flow / payload-tool finding / CVSS vector / report-drafting call shows up,
the relevant skill or reference is in context without the operator having
to ask.

Each trigger fires once per session per skill. Self-suppresses on
consult_skill calls (no infinite loops).

Required env (set by .mcp.json):
  BB_ROOT  — path to bug bounty workspace (where reference/ + programs/ live)
"""

import json, os, re, sys
from pathlib import Path

BB_ROOT = Path(os.environ.get('BB_ROOT', os.getcwd()))

try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(0)

session = payload.get('session_id', 'none')
tool_name = payload.get('tool_name', '')

if tool_name == 'mcp__bb-hunter__consult_skill':
    sys.exit(0)

resp = payload.get('tool_response', '')
if isinstance(resp, dict):
    resp = json.dumps(resp, default=str)
elif not isinstance(resp, str):
    resp = str(resp)

ti = payload.get('tool_input', {}) or {}
ti_str = ' '.join(str(v) for v in ti.values() if isinstance(v, (str, int, float)))
blob = (resp + '\n' + ti_str)[:50_000]

# ── Skill triggers ────────────────────────────────────────────────────────────
SKILL_TRIGGERS = {
    'cloud-security': [
        r'\b169\.254\.169\.254\b',
        r'\bmetadata\.google\.internal\b',
        r'\bAKIA[0-9A-Z]{16}\b',
        r'\bASIA[0-9A-Z]{16}\b',
        r'\.s3[.\-][a-z0-9\-]*\.amazonaws\.com\b',
        r'\bs3://[a-z0-9.\-]+',
        r'\.blob\.core\.windows\.net\b',
        r'\.azurewebsites\.net\b',
        r'\.azure-api\.net\b',
        r'\bAWS4-HMAC-SHA256\b',
        r'\bAIza[0-9A-Za-z_\-]{35}\b',
        r'\.appspot\.com\b',
        r'\.cloudfunctions\.net\b',
        r'\.run\.app\b',
        r'\bcognito-idp\.[a-z0-9\-]+\.amazonaws\.com\b',
    ],
    'secure-contracts': [
        r'\bpragma\s+solidity\b',
        r'\b(?:contract|interface|library)\s+[A-Z]\w*\s*\{',
        r'\.sol(?:[:\b]|$)',
        r'\b(?:msg\.sender|tx\.origin|block\.timestamp)\b',
    ],
    'yara-authoring': [
        r'^\s*rule\s+\w+\s*\{',
        r'\.yar(?:a)?\b',
        r'\bcondition:\s*\n',
    ],
    'webapp-testing': [
        r'\bfrom\s+playwright',
        r'\brequire\([\'"]playwright',
        r'\bpage\.goto\(',
    ],
    'awesome-security': [
        r'\bnuclei\b.*(?:findings|matched|critical|high)',
        r'\bdalfox\b.*\[(?:VULN|POC)\]',
        r'\bsqlmap\b.*(?:injection|vulnerable|payload)',
    ],
}
SKILL_REASONS = {
    'cloud-security':   'cloud asset detected (AWS/Azure/GCP)',
    'secure-contracts': 'smart-contract context (Solidity)',
    'yara-authoring':   'YARA rule context',
    'webapp-testing':   'browser / Playwright context',
    'awesome-security': 'payload-tool output — SecLists variants relevant',
}

# ── Reference triggers ────────────────────────────────────────────────────────
REFERENCE_TRIGGERS = {
    'cvss_guide': [
        r'\bCVSS:3\.\d+/AV:',
        r'\bcvss[-_ ]?(?:vector|score)\b',
    ],
    'cwe_map': [
        r'\bCWE-\d+\b',
    ],
    'payloads': [
        r'<script[\s>]', r'javascript:alert\(',
        r"['\"]?\s*OR\s+'?1'?\s*=\s*'?1'?",
        r'\bUNION\s+SELECT\b',
        r'\bSLEEP\(\d+\)',
        r'\{\{\s*\d+\s*\*\s*\d+\s*\}\}',
    ],
    'tools': [
        r'\bferoxbuster\s+-u\b',
        r'\bnuclei\s+-u\b',
        r'\bffuf\s+-u\b',
        r'\bnmap\s+-sC\s+-sV\b',
    ],
}
REFERENCE_REASONS = {
    'cvss_guide':       'CVSS vector / score being drafted',
    'cwe_map':          'CWE identifier referenced — confirm correct mapping',
    'payloads':         'PoC payload context — use safe canonical variants',
    'tools':            'scanner invocation drafted — confirm syntax & wordlist',
}

# ── Platform detection ────────────────────────────────────────────────────────
PLATFORM_FILES = {
    'intigriti': 'intigriti_taxonomy',
    'bugcrowd':  'bugcrowd_vrt',
    'hackerone': 'hackerone_taxonomy',
    'h1':        'hackerone_taxonomy',
}

def detect_platform(program: str) -> str | None:
    if not program:
        return None
    brief = BB_ROOT / 'programs' / program / 'brief.md'
    if not brief.exists():
        return None
    try:
        text = brief.read_text(errors='replace').lower()
    except Exception:
        return None
    for key in PLATFORM_FILES:
        if re.search(rf'\bplatform[:\s\*]+\s*\*?\*?\s*{key}\b', text, re.IGNORECASE):
            return key
    for key in PLATFORM_FILES:
        if re.search(rf'\b{key}\b', text):
            return key
    return None

triggered_skills = []
triggered_refs = []
triggered_platform = None

for skill, patterns in SKILL_TRIGGERS.items():
    gate = Path(f'/tmp/.bb_trigger_{session}_skill_{skill}')
    if gate.exists():
        continue
    for pat in patterns:
        if re.search(pat, blob, re.MULTILINE | re.IGNORECASE):
            gate.touch()
            triggered_skills.append((skill, SKILL_REASONS[skill]))
            break

for ref, patterns in REFERENCE_TRIGGERS.items():
    gate = Path(f'/tmp/.bb_trigger_{session}_ref_{ref}')
    if gate.exists():
        continue
    for pat in patterns:
        if re.search(pat, blob, re.MULTILINE | re.IGNORECASE):
            gate.touch()
            triggered_refs.append((ref, REFERENCE_REASONS[ref]))
            break

if tool_name == 'mcp__bb-hunter__create_report':
    program = ti.get('program', '')
    plat = detect_platform(program)
    bundle_gate = Path(f'/tmp/.bb_trigger_{session}_report_{program}')
    if not bundle_gate.exists():
        bundle_gate.touch()
        triggered_platform = (program, plat)

if not (triggered_skills or triggered_refs or triggered_platform):
    sys.exit(0)

ref_dir = BB_ROOT / 'reference'
skills_dir = Path.home() / '.claude' / 'skills'

print()
print('=== AUTO-TRIGGER: context-relevant files detected ===')
print('Read the files below NOW (or call consult_skill) before your next step. '
      'Do not just acknowledge — open them.')
print()

for skill, reason in triggered_skills:
    print(f'  • SKILL  {skill}.md — {reason}')
    print(f'    file: {skills_dir / (skill + ".md")}')
    print(f'    or:   consult_skill(name="{skill}")')

for ref, reason in triggered_refs:
    target = ref_dir / f'{ref}.md'
    if target.exists():
        print(f'  • REF    reference/{ref}.md — {reason}')
        print(f'    file: {target}')
        print(f'    or:   consult_skill(name="{ref}")')

if triggered_platform is not None:
    program, plat = triggered_platform
    print()
    print(f'  • REPORT BUNDLE for program "{program}":')
    if plat is None:
        print(f'    ⚠ platform not detected from programs/{program}/brief.md')
        print(f'    Add a "Platform: Intigriti|Bugcrowd|HackerOne" line to the brief.')
    else:
        plat_file = PLATFORM_FILES[plat]
        plat_path = ref_dir / f'{plat_file}.md'
        platform_label = {
            'intigriti': 'Intigriti', 'bugcrowd': 'Bugcrowd',
            'hackerone': 'HackerOne', 'h1': 'HackerOne',
        }[plat]
        print(f'    Platform: {platform_label}')
        if plat_path.exists():
            print(f'    Mandatory: reference/{plat_file}.md  → consult_skill(name="{plat_file}")')
        else:
            print(f'    ⚠ reference/{plat_file}.md MISSING — author it before submitting.')
    print(f'    Mandatory: reference/report_template.md → consult_skill(name="report_template")')
    print(f'    Mandatory: reference/cvss_guide.md      → consult_skill(name="cvss_guide")')
    print(f'    Mandatory: reference/cwe_map.md         → consult_skill(name="cwe_map")')

print()
print('(Each trigger fires once per session. Full map → CLAUDE.md '
      '"Skill & Reference Triggers".)')
print('=====================================================')
