# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""
Safe subprocess executor.
- shell=False always
- Tool allowlist enforced
- Argument validation (metacharacters, traversal, null bytes)
- Clean environment (no inherited secrets)
- Per-tool MCP-side cooldown (coarse — guards against runaway agent loops)
- Global rate ceiling across ALL bb-hunter tools (hard cap on outbound rate)
- Forbidden payload patterns blocked
- Scope gate for network tools
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

from config import (
    ALLOWED_TOOLS,
    BLOCKED_TOOLS,
    FORBIDDEN_PAYLOAD_PATTERNS,
    GLOBAL_RATE_LIMIT,
    RATE_LIMITS,
    SHELL_METACHARACTERS,
    WORK_DIR,
)
from core import circuit_breaker as cb
from core import scope as scope_mod

# Track last execution time per tool for rate limiting
_last_run: dict[str, float] = {}

# Tools that make network calls — always scope-checked
NETWORK_TOOLS = {
    'subfinder', 'amass', 'assetfinder',
    'nmap', 'httpx', 'whatweb', 'dig',
    'curl', 'ffuf', 'feroxbuster', 'katana',
    'gospider', 'nuclei', 'sqlmap', 'dalfox',
}

CLEAN_ENV = {
    'PATH':     '/usr/local/bin:/usr/bin:/bin:/usr/local/sbin',
    'HOME':     str(WORK_DIR),
    'USER':     'bbhunter',
    'TERM':     'xterm-256color',
    'LANG':     'en_US.UTF-8',
    'BB_VAULT': os.environ.get('BB_VAULT', str(Path.home() / '.hive')),
}


def _rate_limit(tool: str) -> None:
    limit = RATE_LIMITS.get(tool, RATE_LIMITS['default'])
    now   = time.monotonic()
    last  = _last_run.get(tool, 0.0)
    wait  = limit - (now - last)
    if wait > 0:
        time.sleep(wait)
    _last_run[tool] = time.monotonic()


def _validate_tool(tool: str) -> str:
    """Return full path to tool or raise ValueError."""
    if tool in BLOCKED_TOOLS:
        raise ValueError(f'Tool "{tool}" is explicitly blocked.')
    if tool not in ALLOWED_TOOLS:
        raise ValueError(
            f'Tool "{tool}" is not on the allowlist. '
            f'Allowed: {sorted(ALLOWED_TOOLS)}'
        )
    full_path = shutil.which(tool)
    if not full_path:
        raise FileNotFoundError(f'Tool "{tool}" not found in PATH.')
    return full_path


def _validate_args(args: list[str]) -> None:
    """Raise ValueError if any argument is unsafe."""
    for arg in args:
        if '\x00' in arg:
            raise ValueError('Null byte detected in argument.')
        if '../' in arg or '..\\' in arg:
            raise ValueError(f'Path traversal detected in argument: {arg!r}')
        for meta in SHELL_METACHARACTERS:
            if meta in arg:
                raise ValueError(
                    f'Shell metacharacter {meta!r} detected in argument: {arg!r}'
                )

    # Check entire command string for forbidden payload patterns
    cmd_str = ' '.join(args)
    for pattern in FORBIDDEN_PAYLOAD_PATTERNS:
        if pattern.search(cmd_str):
            raise ValueError(
                f'Forbidden payload pattern detected: {pattern.pattern!r}'
            )


def _validate_path(path: str, mode: str = 'read') -> None:
    """Raise ValueError if path is outside allowed directories."""
    from config import ALLOWED_READ_PATHS, ALLOWED_WRITE_PATHS
    allowed = ALLOWED_READ_PATHS if mode == 'read' else ALLOWED_WRITE_PATHS
    resolved = str(Path(path).resolve())
    if not any(resolved.startswith(p) for p in allowed):
        raise ValueError(
            f'Path "{resolved}" is outside allowed {mode} directories.'
        )


# Per-tool expected outbound request rate (req/sec) used for the global budget
# reservation. Single-shot tools count as 1; fan-out tools reserve their
# expected --rate-limit value. Defaults to 1 if unlisted.
TOOL_EXPECTED_RPS = {
    'subfinder':   1, 'amass':       1, 'assetfinder': 1,
    'dig':         1, 'whois':       1, 'whatweb':     1,
    'curl':        1, 'nmap':        2,
    'httpx':       2, 'ffuf':        2, 'feroxbuster': 2,
    'katana':      2, 'nuclei':      2, 'sqlmap':      2,
    'dalfox':      2,
}


def run(
    tool: str,
    args: list[str],
    program: str,
    target: str | None = None,
    timeout: int = 120,
    cwd: str | None = None,
    expected_request_per_sec: int | None = None,
) -> tuple[str, int]:
    """
    Execute a tool safely.

    Args:
        tool:    Tool name (must be in ALLOWED_TOOLS)
        args:    Argument list (passed directly to subprocess, shell=False)
        program: Program name (for scope check + rate limiting)
        target:  Target domain/IP (required for network tools)
        timeout: Max execution time in seconds
        cwd:     Working directory (defaults to WORK_DIR)
        expected_request_per_sec: Budget to reserve against the global cap.
                 Defaults to TOOL_EXPECTED_RPS[tool] or 1.

    Returns:
        (stdout_output, return_code)

    Raises:
        ValueError:      Allowlist, arg validation, scope, payload, or global
                         rate violation
        FileNotFoundError: Tool not found
        subprocess.TimeoutExpired: Execution exceeded timeout
    """
    # Ensure work dir exists
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Validate tool
    tool_path = _validate_tool(tool)

    # 2. Validate arguments
    _validate_args(args)

    # 3. Scope check for network tools
    if tool in NETWORK_TOOLS and target:
        allowed, reason = scope_mod.check(target, program)
        if not allowed:
            raise ValueError(f'Scope violation: {reason}')

    # 4. Per-tool cooldown (coarse — guards against runaway agent loops)
    _rate_limit(tool)

    # 5. Global rate cap. Total outbound across ALL bb-hunter tools (every
    #    zone, every program, every concurrent invocation) must stay
    #    <= GLOBAL_RATE_LIMIT per second. Local file utilities don't count.
    if tool in NETWORK_TOOLS:
        budget = expected_request_per_sec
        if budget is None:
            budget = TOOL_EXPECTED_RPS.get(tool, 1)
        acquired, waited = cb.acquire_global_budget(budget)
        if not acquired:
            raise ValueError(
                f'Global rate cap reached ({GLOBAL_RATE_LIMIT} req/s across all '
                f'bb-hunter tools). Waited {waited:.1f}s for budget — refusing '
                f'{tool} launch. Pause other running scans and retry.'
            )

    # 6. Execute
    cmd = [tool_path] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=CLEAN_ENV,
        cwd=cwd or str(WORK_DIR),
        shell=False,
    )

    output = result.stdout
    if result.stderr:
        output += '\n[stderr]\n' + result.stderr

    return output, result.returncode
