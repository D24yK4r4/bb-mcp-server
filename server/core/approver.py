# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""
Script approval — two-step MCP flow.

Step 1: request_approval()  → shows operator the risk analysis, returns it
Step 2: confirm_execution()  → operator passes approved=True/False
                               executes if approved, logs either way

Approval decisions persist for the session only (never written to disk).
"""

import subprocess
import time

from config import SCRIPTS_DIR, WORK_DIR
from core.analyzer import analyze, format_approval_request
from core.sanitizer import sanitize
from vault import safe as vault
from vault.safe import resolve_args
from audit import logger as audit

# Session-only approval cache: {script_name: {reason, timestamp}}
_approved_this_session: dict[str, dict] = {}


def request_approval(script_name: str, reason: str, program: str) -> str:
    """
    Analyze a script and return a formatted approval request.
    Claude shows this to the operator. Operator replies with
    approve/deny, then calls confirm_execution().
    """
    analysis = analyze(script_name)

    audit.log(program, 'script_approval_requested', {
        'script':       script_name,
        'reason':       reason,
        'verdict':      analysis['verdict'],
        'damage_score': analysis['damage_score'],
        'blocked':      analysis['blocked'],
    })

    return format_approval_request(script_name, reason, analysis)


def confirm_execution(
    script_name: str,
    reason: str,
    program: str,
    approved: bool,
    script_args: list[str] | None = None,
) -> str:
    """
    Execute the script if the operator approved.
    Always logs the decision.
    """
    audit.log(program, 'script_approval_decision', {
        'script':   script_name,
        'reason':   reason,
        'approved': approved,
    })

    if not approved:
        return f'Script execution denied by operator. {script_name} was not run.'

    # Re-analyze at execution time — no trusting stale analysis
    analysis = analyze(script_name)
    if analysis['blocked']:
        audit.log(program, 'script_blocked_at_execution', {
            'script': script_name, 'reason': 'blocked verdict at execution time'
        })
        return (
            f'BLOCKED: {script_name} cannot be executed. '
            f'Verdict at execution time: {analysis["verdict"]}.'
        )

    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        return f'Script not found: {script_path}'

    # Determine interpreter
    suffix = script_path.suffix.lower()
    interpreter_map = {
        '.py':  'python3',
        '.sh':  None,        # shell scripts not executed via MCP
        '.php': None,
        '.rb':  None,
    }

    if suffix not in interpreter_map or interpreter_map[suffix] is None:
        return (
            f'Script type {suffix!r} is not executable via MCP server. '
            f'Only Python scripts (.py) are supported.'
        )

    import shutil
    interp = shutil.which(interpreter_map[suffix])
    if not interp:
        return f'Interpreter not found for {suffix}'

    CLEAN_ENV = {
        'PATH':     '/usr/local/bin:/usr/bin:/bin',
        'HOME':     str(WORK_DIR),
        'USER':     'bbhunter',
        'TERM':     'xterm',
        'BB_VAULT': str(vault.VAULT_ROOT),
    }

    try:
        # Resolve any <SAFE:id> tokens in args before execution
        cmd = [interp, str(script_path)] + resolve_args(script_args or [], program)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env=CLEAN_ENV,
            cwd=str(WORK_DIR),
            shell=False,
        )
        output = result.stdout
        if result.stderr:
            output += '\n[stderr]\n' + result.stderr

        _approved_this_session[script_name] = {
            'reason':    reason,
            'timestamp': time.time(),
        }

        audit.log(program, 'script_executed', {
            'script':     script_name,
            'returncode': result.returncode,
        })

        return sanitize(output, program, f'python3 {script_name}')

    except subprocess.TimeoutExpired:
        audit.log(program, 'script_timeout', {'script': script_name})
        return f'Script timed out after 120 seconds: {script_name}'
    except Exception as e:
        audit.log(program, 'script_error', {'script': script_name, 'error': str(e)})
        return f'Script execution error: {e}'
