"""
Integration test — validator gate end-to-end.
Exercises validate_finding → record_verdict → create_report gate logic.
Run from mcp_server/ directory: python3 test_validator_gate.py
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

PASS = '\033[0;32m[PASS]\033[0m'
FAIL = '\033[0;31m[FAIL]\033[0m'
HEAD = '\033[1;36m'
NC   = '\033[0m'

results = {'passed': 0, 'failed': 0}


def section(t): print(f'\n{HEAD}━━━ {t} ━━━{NC}')
def check(label, cond, detail=''):
    if cond:
        print(f'  {PASS} {label}')
        results['passed'] += 1
    else:
        print(f'  {FAIL} {label}')
        if detail: print(f'         → {detail}')
        results['failed'] += 1


# ── Fixtures ───────────────────────────────────────────────────────────────────
TEST_BB_ROOT = Path('/tmp/bb_test_validator_gate_root')
TEST_VAULT   = Path('/tmp/bb_test_validator_gate_vault')

shutil.rmtree(TEST_BB_ROOT, ignore_errors=True)
shutil.rmtree(TEST_VAULT,   ignore_errors=True)
TEST_BB_ROOT.mkdir(parents=True)
TEST_VAULT.mkdir(parents=True)

# Make a test program with an In Scope section the parser will accept
PROGRAM = 'gate_test'
prog_dir = TEST_BB_ROOT / 'programs' / PROGRAM
(prog_dir / 'recon').mkdir(parents=True)
(prog_dir / 'findings').mkdir(parents=True)
(prog_dir / 'brief.md').write_text(
    '# Program Brief: gate_test\n'
    '## Platform\nIntigriti\n'
    '## In Scope\n'
    '| Asset | Type |\n|-|-|\n'
    '| `target.test` | URL |\n'
    '| `*.target.test` | Wildcard |\n'
    '## Out of Scope\n'
    '- `oos.target.test`\n',
    encoding='utf-8',
)
# Reference dir and minimal payloads.md so the brief builder doesn't error
(TEST_BB_ROOT / 'reference').mkdir()
(TEST_BB_ROOT / 'reference' / 'payloads.md').write_text(
    '# Safe payloads\n- SQLi: `\' OR 1=1--`\n- XSS: `<script>alert(1)</script>`\n',
    encoding='utf-8',
)

# Patch config BEFORE importing modules that use BB_ROOT/VAULT_ROOT
import config
config.BB_ROOT    = TEST_BB_ROOT
config.VAULT_ROOT = TEST_VAULT

import importlib
import core.scope
import core.verdicts as verdicts
import core.validator_brief
importlib.reload(core.scope)
importlib.reload(verdicts)
importlib.reload(core.validator_brief)

# Bind module attributes after reload to keep call sites short while
# satisfying the import-and-import-from CodeQL hygiene rule.
scope_check = core.scope.check
build_brief = core.validator_brief.build_brief

# ══════════════════════════════════════════════════════════════════════════════
section('1. validate_finding logic — scope gate rejects OOS')

in_scope, _ = scope_check('oos.target.test', PROGRAM)
check('scope_check rejects OOS target', not in_scope)

in_scope, _ = scope_check('api.target.test', PROGRAM)
check('scope_check accepts in-scope target', in_scope)

# ══════════════════════════════════════════════════════════════════════════════
section('2. validate_finding logic — safety_check rejects destructive PoC')

ok, reason = verdicts.safety_check("'; DROP TABLE users--")
check('destructive PoC rejected at gate', not ok)

ok, _ = verdicts.safety_check("curl 'https://api.target.test/?id=1%27%20OR%201=1--'")
check('safe SQLi PoC accepted at gate', ok)

# ══════════════════════════════════════════════════════════════════════════════
section('3. happy path — open verdict, record EXPLOITABLE, gate passes')

vid = verdicts.create(
    program=PROGRAM,
    hypothesis='SSRF via /api/proxy?url=',
    target='api.target.test',
    evidence='Internal IMDS reachable, returns metadata JSON',
    proposed_poc="curl 'https://api.target.test/api/proxy?url=http://169.254.169.254/'",
)
ok, _ = verdicts.record(vid, verdicts.VERDICT_EXPLOITABLE,
                        reasoning='IMDS read confirmed, no destructive ops')
check('record EXPLOITABLE succeeds', ok)

v = verdicts.get(vid)
# Simulate create_report's gate logic
gate_ok = (
    v is not None
    and v.get('program') == PROGRAM
    and v.get('status') == verdicts.VERDICT_EXPLOITABLE
)
check('create_report gate would PASS for happy path', gate_ok)

# ══════════════════════════════════════════════════════════════════════════════
section('4. gate rejects: missing verdict_id')

v = verdicts.get('00000000-0000-0000-0000-000000000000')
check('unknown verdict_id → not found', v is None)

# ══════════════════════════════════════════════════════════════════════════════
section('5. gate rejects: verdict from another program (cross-program reuse)')

# Set up a second program
PROG2 = 'gate_test_2'
prog2_dir = TEST_BB_ROOT / 'programs' / PROG2
prog2_dir.mkdir(parents=True)
(prog2_dir / 'brief.md').write_text(
    '## In Scope\n| Asset | Type |\n|-|-|\n| `other.test` | URL |\n## Out of Scope\n',
    encoding='utf-8',
)
vid_p2 = verdicts.create(PROG2, 'XSS', 'other.test', 'reflected', 'curl https://other.test/?q=<svg/onload=alert(1)>')
verdicts.record(vid_p2, verdicts.VERDICT_EXPLOITABLE, reasoning='reflected XSS')

v = verdicts.get(vid_p2)
# Simulate cross-program gate check (passing PROGRAM but verdict belongs to PROG2)
cross_program_blocked = v is not None and v.get('program') != PROGRAM
check('cross-program reuse blocked by gate', cross_program_blocked)

# ══════════════════════════════════════════════════════════════════════════════
section('6. gate rejects: AWAITING verdict (validator did not finalize)')

vid_pending = verdicts.create(PROGRAM, 'lead', 'api.target.test', 'partial evidence', 'curl https://api.target.test/')
v = verdicts.get(vid_pending)
gate_blocks_awaiting = v is not None and v.get('status') != verdicts.VERDICT_EXPLOITABLE
check('AWAITING verdict blocked by gate', gate_blocks_awaiting)

# ══════════════════════════════════════════════════════════════════════════════
section('7. gate rejects: THEORETICAL verdict')

vid_theo = verdicts.create(PROGRAM, 'XSS via Referer', 'api.target.test',
                           'header reflected', 'craft a referer header')
verdicts.record(vid_theo, verdicts.VERDICT_THEORETICAL,
                reasoning='referer not user-controlled in modern browsers')

v = verdicts.get(vid_theo)
gate_blocks_theoretical = v is not None and v.get('status') != verdicts.VERDICT_EXPLOITABLE
check('THEORETICAL verdict blocked by gate', gate_blocks_theoretical)

# ══════════════════════════════════════════════════════════════════════════════
section('8. brief builder — produces a non-empty brief that includes program rules')

brief = build_brief(
    program=PROGRAM,
    hypothesis='IDOR on /accounts/{id}',
    target='api.target.test',
    evidence='Reading another account 200 OK',
    proposed_poc='curl https://api.target.test/accounts/1',
    verdict_id=vid,
)
check('brief contains verdict_id', vid in brief)
check('brief embeds program brief.md content', 'gate_test' in brief)
check('brief embeds payloads reference', 'Safe payloads' in brief)
check('brief instructs EXPLOITABLE/THEORETICAL output format',
      'EXPLOITABLE:' in brief and 'THEORETICAL — DROP' in brief)

# ══════════════════════════════════════════════════════════════════════════════
total = results['passed'] + results['failed']
print(f'\n{"━"*45}')
print(f' Results: {results["passed"]}/{total} passed', end='')
if results['failed'] == 0:
    print(f'  \033[0;32m✅ All tests passed\033[0m')
else:
    print(f'  \033[0;31m❌ {results["failed"]} failed\033[0m')
print(f'{"━"*45}\n')

shutil.rmtree(TEST_BB_ROOT, ignore_errors=True)
shutil.rmtree(TEST_VAULT,   ignore_errors=True)

sys.exit(0 if results['failed'] == 0 else 1)
