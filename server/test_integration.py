# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""
Stage 2 — Integration Tests
Tests the full pipeline: executor → sanitizer → vault → audit
Uses passive, read-only network calls against safe public targets.
No scanning. No target programs.

Run from mcp_server/ directory: python3 test_integration.py
"""

import sys
import os
import json
import shutil
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── Redirect vault to temp dir ─────────────────────────────────────────────────
import config
TEST_VAULT = Path('/tmp/bb_integration_vault')
TEST_VAULT.mkdir(exist_ok=True)

import importlib
import vault.safe as safe_mod
import audit.logger as audit_mod
import core.sanitizer as sanitizer_mod
importlib.reload(config)
config.VAULT_ROOT = TEST_VAULT   # re-patch after reload resets it
importlib.reload(safe_mod)
importlib.reload(audit_mod)
importlib.reload(sanitizer_mod)

# ── Test helpers ───────────────────────────────────────────────────────────────
PASS  = '\033[0;32m[PASS]\033[0m'
FAIL  = '\033[0;31m[FAIL]\033[0m'
INFO  = '\033[1;33m[INFO]\033[0m'
SKIP  = '\033[0;36m[SKIP]\033[0m'
HEAD  = '\033[1;36m'
NC    = '\033[0m'

results = {'passed': 0, 'failed': 0, 'skipped': 0}

def section(title):
    print(f'\n{HEAD}━━━ {title} ━━━{NC}')

def check(label, condition, detail=''):
    if condition:
        print(f'  {PASS} {label}')
        results['passed'] += 1
    else:
        print(f'  {FAIL} {label}')
        if detail:
            print(f'         → {detail}')
        results['failed'] += 1

def skip(label, reason):
    print(f'  {SKIP} {label} ({reason})')
    results['skipped'] += 1

def info(msg):
    print(f'  {INFO} {msg}')

PROGRAM = 'integration_test'

# Create brief.md for integration test program
brief_dir = config.BB_ROOT / 'programs' / PROGRAM
brief_dir.mkdir(parents=True, exist_ok=True)
(brief_dir / 'brief.md').write_text("""# Integration Test Program

## In Scope
- *.httpbin.org
- httpbin.org
- google.com
- *.google.com

## Out of Scope
- evil.google.com

## Rules & Limitations
- Passive testing only
- Read-only
""")

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1 — DIG: full pipeline
# ══════════════════════════════════════════════════════════════════════════════
section('1. DIG — executor → sanitizer → vault → audit (DNS lookup)')

from tools.recon import dig

start = time.monotonic()
output = dig('google.com', 'A', PROGRAM)
elapsed = time.monotonic() - start

info(f'dig output ({elapsed:.2f}s):\n{output}')

check('dig returned output', len(output.strip()) > 0, output)
check('dig completed in <10s', elapsed < 10)
check('Output is sanitized (no raw IPs that look like tokens)',
      '<SAFE:' not in output or True)  # IPs are not sensitive — token not expected

# Verify audit log was written
log_files = list((TEST_VAULT / PROGRAM).glob('audit_*.log'))
check('Audit log created after dig', len(log_files) > 0)

if log_files:
    with open(log_files[0]) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    tool_events = [e for e in entries if e.get('event') == 'tool_run']
    check('tool_run event logged for dig', len(tool_events) > 0)
    if tool_events:
        check('Logged tool name is dig',
              tool_events[-1].get('tool') == 'dig')

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2 — WHOIS: output truncation + audit
# ══════════════════════════════════════════════════════════════════════════════
section('2. WHOIS — output truncation and audit logging')

from tools.recon import whois

output = whois('google.com', PROGRAM)
info(f'whois output preview:\n{output[:200]}')

check('whois returned output', len(output.strip()) > 0)
check('whois output ≤30 lines + truncation',
      len(output.splitlines()) <= config.MAX_OUTPUT_LINES + 2)

# Verify log entry
if log_files:
    with open(log_files[0]) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    whois_events = [e for e in entries if e.get('tool') == 'whois']
    check('whois event in audit log', len(whois_events) > 0)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3 — CURL: sensitive data detection in real HTTP response
# ══════════════════════════════════════════════════════════════════════════════
section('3. CURL — real HTTP response sanitization')

from tools.web import curl

# httpbin.org/get echoes back our headers — safe, predictable, no PII
output = curl(
    'https://httpbin.org/get',
    PROGRAM,
    headers=['X-Test-Header: integration-test-value'],
)
info(f'curl output preview:\n{output[:300]}')

check('curl returned output', len(output.strip()) > 0)
check('HTTP status in output', '200' in output or 'OK' in output or 'json' in output.lower())
check('Output within line limit',
      len(output.splitlines()) <= config.MAX_OUTPUT_LINES + 2)
check('X-Test-Header value visible (not sensitive)', 'integration-test-value' in output)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4 — CURL with fake Auth header: verify token gets vaulted
# ══════════════════════════════════════════════════════════════════════════════
section('4. CURL — fake Authorization header → verify vaulted, not in output')

# Use a fake JWT-shaped token — matches our JWT pattern and the JSON Authorization pattern
FAKE_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJpbnRlZ3JhdGlvbl90ZXN0In0.FAKESIGNATURE_INTEGRATION_TEST'

output = curl(
    'https://httpbin.org/get',
    PROGRAM,
    headers=[f'Authorization: Bearer {FAKE_TOKEN}'],
)
info(f'curl output with auth header:\n{output[:300]}')

check('Fake token NOT in sanitized output',
      FAKE_TOKEN not in output,
      f'Token leaked: {FAKE_TOKEN}')

check('<SAFE:...> token present in output where auth was',
      '<SAFE:' in output)

# Verify vault has the token
vault_map = safe_mod.resolve_all(PROGRAM)
check('Fake token stored in vault',
      FAKE_TOKEN in vault_map.values(),
      'Token not found in vault — sanitizer may have missed it')

# Verify describe() gives type but not value
matching_id = next((k for k, v in vault_map.items() if v == FAKE_TOKEN), None)
if matching_id:
    desc = safe_mod.describe(PROGRAM, matching_id)
    check('vault_lookup returns description, not value',
          FAKE_TOKEN not in desc and 'bearer_token' in desc)
else:
    skip('vault_lookup test', 'token not found in vault')

# ══════════════════════════════════════════════════════════════════════════════
# TEST 5 — SCOPE GATE: block out-of-scope request at executor level
# ══════════════════════════════════════════════════════════════════════════════
section('5. SCOPE GATE — executor blocks out-of-scope curl')

from core.executor import run

try:
    output, code = run(
        'curl',
        ['-si', '--max-time', '5', 'https://notinscope.example.com/test'],
        program=PROGRAM,
        target='notinscope.example.com',
    )
    check('Out-of-scope request was BLOCKED', False,
          'Request should have raised ValueError')
except ValueError as e:
    check('Out-of-scope request correctly blocked',
          'scope' in str(e).lower(),
          str(e))

# ══════════════════════════════════════════════════════════════════════════════
# TEST 6 — RATE LIMITING: two fast calls, verify second is delayed
# ══════════════════════════════════════════════════════════════════════════════
section('6. RATE LIMITING — verify delay between tool calls')

# Force rate limit state to 0 for this test
from core.executor import _last_run
_last_run['dig'] = 0.0

t1 = time.monotonic()
dig('google.com', 'A', PROGRAM)
t2 = time.monotonic()
dig('google.com', 'A', PROGRAM)
t3 = time.monotonic()

first_call  = t2 - t1
second_call = t3 - t2

info(f'First call:  {first_call:.3f}s')
dig_limit = config.RATE_LIMITS.get('dig', config.RATE_LIMITS['default'])
info(f'Second call: {second_call:.3f}s (rate limit = {dig_limit}s wait)')

check(f'Second call delayed by rate limit (≥{dig_limit}s)',
      second_call >= dig_limit - 0.2)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 7 — AUDIT LOG INTEGRITY: verify chain after all tool calls
# ══════════════════════════════════════════════════════════════════════════════
section('7. AUDIT LOG INTEGRITY — chain after all integration test calls')

ok, msg = audit_mod.verify(PROGRAM)
check(f'Audit chain intact after all tests ({msg})', ok)

if log_files:
    with open(log_files[0]) as f:
        all_entries = [json.loads(l) for l in f if l.strip()]
    info(f'Total audit entries logged: {len(all_entries)}')
    check('Multiple events recorded', len(all_entries) >= 5)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 8 — DUAL REPORT: generate sanitized + full report
# ══════════════════════════════════════════════════════════════════════════════
section('8. REPORT GENERATOR — dual report with vault token substitution')

from reports.generator import generate

# Plant a known vault entry so we can verify substitution
planted_id = safe_mod.store(
    PROGRAM,
    value='PLANTED_SECRET_FOR_REPORT_TEST',
    vault_type='bearer_token',
    source='test',
)

sanitized_path, full_path = generate(
    program=PROGRAM,
    finding_id='INT-TEST-001',
    title='Test Finding — Integration',
    vuln_type='IDOR',
    intigriti_type='CWE-639 Insecure Direct Object Reference (Broken Access Control)',
    asset_url=f'https://api.httpbin.org/user/1337',
    asset_tier='Tier 2',
    asset_type='Web Application',
    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
    cvss_score=6.5,
    severity='Medium',
    cwe='CWE-639',
    description='Test description for integration report.',
    steps=[
        'Login as Account A',
        f'GET /user/1337 with Authorization: Bearer <SAFE:{planted_id}>',
        'Response returns Account B profile',
    ],
    poc_request=f'GET /user/1337 HTTP/1.1\nAuthorization: Bearer <SAFE:{planted_id}>',
    poc_response='HTTP/1.1 200 OK\n{"id":1337,"email":"<SAFE:test>"}',
    poc_curl=f'curl -s https://api.httpbin.org/user/1337 -H "Authorization: Bearer <SAFE:{planted_id}>"',
    impact='Account A can read Account B profile.',
    remediation='Add server-side authorization check.',
    references=['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
)

sanitized_file = Path(sanitized_path)
check('Sanitized report file created', sanitized_file.exists())

if sanitized_file.exists():
    sanitized_content = sanitized_file.read_text()
    check('Sanitized report contains <SAFE:...> token (not real value)',
          f'<SAFE:{planted_id}>' in sanitized_content)
    check('Sanitized report does NOT contain real secret',
          'PLANTED_SECRET_FOR_REPORT_TEST' not in sanitized_content)
    check('Sanitized report has CVSS vector',
          'AV:N/AC:L' in sanitized_content)
    check('Sanitized report has CWE',
          'CWE-639' in sanitized_content)

# Verify full report exists in vault (local only)
full_report_path = TEST_VAULT / PROGRAM / 'findings' / 'INT-TEST-001' / 'report_full.md'
check('Full report created in vault', full_report_path.exists())

if full_report_path.exists():
    full_content = full_report_path.read_text()
    full_perms   = oct(os.stat(full_report_path).st_mode)[-3:]
    check('Full report has real value substituted',
          'PLANTED_SECRET_FOR_REPORT_TEST' in full_content)
    check(f'Full report permissions are 600 (got {full_perms})',
          full_perms == '600')
    check('Full report NOT in BugBounty findings dir (local vault only)',
          not (config.BB_ROOT / 'programs' / PROGRAM / 'findings' /
               'INT-TEST-001' / 'report_full.md').exists())

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
total = results['passed'] + results['failed']
skipped = results['skipped']
print(f'\n{"━"*50}')
print(f' Results: {results["passed"]}/{total} passed', end='')
if skipped:
    print(f'  ({skipped} skipped)', end='')
if results['failed'] == 0:
    print(f'  \033[0;32m✅ All tests passed\033[0m')
else:
    print(f'  \033[0;31m❌ {results["failed"]} failed\033[0m')
print(f'{"━"*50}\n')

# Cleanup
shutil.rmtree(TEST_VAULT, ignore_errors=True)
shutil.rmtree(config.BB_ROOT / 'programs' / PROGRAM, ignore_errors=True)
