"""Vulnerability scanning tool wrappers — nuclei, sqlmap, dalfox."""

import re

from config import BB_ROOT
from core.executor import run
from core.sanitizer import sanitize
from core import circuit_breaker as cb
from audit import logger as audit
from vault.safe import resolve_args


def _breaker_check(program: str, host: str, tool: str, target: str,
                   expected_duration_sec: int = 300) -> str | None:
    """Return a refusal message if breaker is open OR aggregate cap would be exceeded.
    For long-running tools (nuclei/ffuf), also reserves their expected request budget."""
    from config import TOOL_RATE_LIMIT
    tripped, remaining = cb.is_tripped(host)
    if tripped:
        audit.log(program, 'circuit_breaker_blocked', {
            'tool': tool, 'host': host, 'target': target,
            'cooldown_remaining_sec': remaining,
        })
        return (f"⛔ CIRCUIT BREAKER OPEN — host '{host}' returned 429 recently. "
                f"Refusing {tool} run to avoid IP ban. Cooldown: {remaining}s.")

    expected_reqs = TOOL_RATE_LIMIT * expected_duration_sec
    would_exceed, current_rate = cb.aggregate_rate_check(host, expected_request_count=TOOL_RATE_LIMIT)
    if would_exceed:
        audit.log(program, 'aggregate_rate_blocked', {
            'tool': tool, 'host': host, 'current_rate': current_rate,
        })
        return (f"⛔ AGGREGATE RATE CAP — zone is at {current_rate:.1f} req/s across "
                f"all bb-hunter tools. Cap is {cb.SAFE_RATE_PER_ZONE} req/s. "
                f"Wait ~1s for the window to clear, or pause other running scans.")
    # Reserve the budget for the bulk tool's expected duration
    cb.record_request(host, expected_request_count=expected_reqs)
    return None

_SAFE_TOKEN_RE = re.compile(r'<SAFE:(?:[^:>]+:)?[0-9a-f]{8}>')


def _resolve_safe(values: list[str], program: str) -> tuple[list[str], int]:
    """Substitute <SAFE:id> tokens with vault values. Returns (resolved, count_of_tokens_seen)."""
    if not values:
        return [], 0
    seen = sum(len(_SAFE_TOKEN_RE.findall(v)) for v in values)
    resolved = resolve_args(list(values), program)
    return resolved, seen


def _out(program: str, filename: str) -> str:
    p = BB_ROOT / 'programs' / program / 'recon'
    p.mkdir(parents=True, exist_ok=True)
    return str(p / filename)


def _host(url: str) -> str:
    for proto in ('https://', 'http://'):
        if url.startswith(proto):
            url = url[len(proto):]
    return url.split('/')[0].split(':')[0]


def nuclei(
    target: str,
    program: str,
    templates: list[str] | None = None,
    severity: str = 'high,critical',
    headers: list[str] | None = None,
) -> str:
    from config import TOOL_RATE_LIMIT
    out_file = _out(program, 'nuclei.txt')
    args = [
        '-u', target,
        '-severity', severity,
        '-o', out_file,
        '-silent',
        '-rate-limit', str(TOOL_RATE_LIMIT),
    ]
    if templates:
        for t in templates:
            args += ['-t', t]
    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    for h in resolved_headers:
        args += ['-H', h]

    target_host = _host(target)
    blocked = _breaker_check(program, target_host, 'nuclei', target)
    if blocked:
        return blocked

    raw, code = run('nuclei', args, program=program,
                    target=target_host, timeout=300)
    lines = [l for l in raw.splitlines() if l.strip()]
    result = f'nuclei: {len(lines)} findings → saved to recon/nuclei.txt'
    if lines:
        result += '\n' + '\n'.join(lines[:20])
    audit.log(program, 'tool_run', {
        'tool': 'nuclei', 'target': target,
        'findings': len(lines), 'returncode': code,
        'safe_tokens_resolved': hdr_tokens,
    })
    return sanitize(result, program, f'nuclei -u {target}')


def sqlmap(
    url: str,
    program: str,
    params: str | None = None,
    data: str | None = None,
    headers: list[str] | None = None,
    level: int = 1,
    risk: int = 1,
) -> str:
    """
    Safe sqlmap — detection only. Never --dump, never --os-shell.
    """
    out_dir = _out(program, 'sqlmap')
    args = [
        '-u', url,
        '--level', str(level),
        '--risk', str(risk),
        '--batch',                  # no interactive prompts
        '--output-dir', out_dir,
        '--technique', 'BET',       # Boolean, Error, Time — no UNION (noisier)
        '--no-cast',
        '--smart',
    ]
    if params:
        args += ['-p', params]
    resolved_data, data_tokens = _resolve_safe([data] if data else [], program)
    if resolved_data:
        args += ['--data', resolved_data[0]]
    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    for h in resolved_headers:
        args += ['-H', h]

    # Safety: explicitly block destructive flags in args
    for blocked in ('--dump', '--dump-all', '--os-shell', '--os-cmd',
                    '--sql-shell', '--file-write', '--file-dest'):
        if blocked in args:
            return f'ERROR: {blocked} is not allowed in bug bounty mode.'

    target_host = _host(url)
    refusal = _breaker_check(program, target_host, 'sqlmap', url)
    if refusal:
        return refusal

    raw, code = run('sqlmap', args, program=program,
                    target=target_host, timeout=300)
    lines = [l for l in raw.splitlines()
             if any(k in l.lower() for k in ('inject', 'vulnerab', 'parameter',
                                              'payload', 'error', 'warning'))]
    result = '\n'.join(lines[:20]) if lines else 'sqlmap: no injection detected.'
    audit.log(program, 'tool_run', {
        'tool': 'sqlmap', 'url': url, 'returncode': code,
        'safe_tokens_resolved': hdr_tokens + data_tokens,
    })
    return sanitize(result, program, f'sqlmap -u {url}')


def dalfox(
    url: str,
    program: str,
    headers: list[str] | None = None,
    params: str | None = None,
) -> str:
    from config import TOOL_RATE_LIMIT
    out_file = _out(program, 'dalfox.txt')
    # dalfox has no rps flag; --delay is ms between requests. 5 rps → 200 ms.
    delay_ms = max(1, int(1000 / TOOL_RATE_LIMIT))
    args = ['url', url, '--output', out_file, '--silence',
            '--delay', str(delay_ms)]
    if params:
        args += ['--param', params]
    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    for h in resolved_headers:
        args += ['--header', h]

    target_host = _host(url)
    refusal = _breaker_check(program, target_host, 'dalfox', url)
    if refusal:
        return refusal

    raw, code = run('dalfox', args, program=program,
                    target=_host(url), timeout=180)
    lines = [l for l in raw.splitlines()
             if any(k in l.lower() for k in ('[vuln]', '[poc]', '[info]', 'xss'))]
    result = '\n'.join(lines[:20]) if lines else 'dalfox: no XSS detected.'
    audit.log(program, 'tool_run', {
        'tool': 'dalfox', 'url': url, 'returncode': code,
        'safe_tokens_resolved': hdr_tokens,
    })
    return sanitize(result, program, f'dalfox url {url}')
