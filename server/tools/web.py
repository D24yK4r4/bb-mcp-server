"""Web testing tool wrappers — curl, ffuf, feroxbuster, whatweb, katana."""

import re

from config import BB_ROOT
from core.executor import run
from core.sanitizer import sanitize
from core import circuit_breaker as cb
from audit import logger as audit
from vault.safe import resolve_args

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


def curl(
    url: str,
    program: str,
    method: str = 'GET',
    headers: list[str] | None = None,
    data: str | dict | None = None,
    flags: list[str] | None = None,
) -> str:
    """
    Run curl against a target URL.
    headers: list of 'Header: value' strings
    data:    POST body (string or dict — dict is auto-serialized as JSON)
    flags:   extra curl flags (from allowlist only)
    """
    if isinstance(data, dict):
        import json
        data = json.dumps(data, separators=(',', ':'))

    target_host = _extract_host(url)

    # Guard 1: 429 circuit breaker (cooldown after a previous 429)
    tripped, remaining = cb.is_tripped(target_host)
    if tripped:
        audit.log(program, 'circuit_breaker_blocked', {
            'tool': 'curl', 'url': url, 'host': target_host,
            'cooldown_remaining_sec': remaining,
        })
        return (f"⛔ CIRCUIT BREAKER OPEN — host '{target_host}' (or its zone) returned 429 "
                f"recently. Refusing to fire to avoid IP ban. Cooldown remaining: "
                f"{remaining} seconds. To override (only if you're certain), call "
                f"core.circuit_breaker.reset() — operator-only.")

    # Guard 2: aggregate rate cap across ALL bb-hunter tools to this zone
    would_exceed, current_rate = cb.aggregate_rate_check(target_host, expected_request_count=1)
    if would_exceed:
        audit.log(program, 'aggregate_rate_blocked', {
            'tool': 'curl', 'host': target_host, 'current_rate': current_rate,
        })
        return (f"⛔ AGGREGATE RATE CAP — zone '{cb._zone(target_host)}' is currently at "
                f"{current_rate:.1f} req/s across all bb-hunter tools. Cap is "
                f"{cb.SAFE_RATE_PER_ZONE} req/s. Refusing to add another request. "
                f"Wait ~1s and retry, or pause other running scans.")
    cb.record_request(target_host, expected_request_count=1)

    args = ['-si', '--max-time', '15']

    if method.upper() != 'GET':
        args += ['-X', method.upper()]

    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    resolved_data, data_tokens = _resolve_safe([data] if data else [], program)
    resolved_url_list, url_tokens = _resolve_safe([url], program)
    resolved_url = resolved_url_list[0] if resolved_url_list else url

    for h in resolved_headers:
        args += ['-H', h]

    if resolved_data:
        args += ['-d', resolved_data[0]]

    for f in (flags or []):
        args.append(f)

    args.append(resolved_url)

    raw, code = run('curl', args, program=program, target=target_host)

    # Trip the breaker if response shows throttle signals
    throttled = cb.detect_throttle_in_response(raw)
    if throttled:
        cb.trip(target_host, reason='429/503/Retry-After detected')
        audit.log(program, 'circuit_breaker_tripped', {
            'tool': 'curl', 'url': url, 'host': target_host,
        })

    audit.log(program, 'tool_run', {
        'tool': 'curl', 'url': url, 'method': method, 'returncode': code,
        'safe_tokens_resolved': hdr_tokens + data_tokens + url_tokens,
        'throttled': throttled,
    })
    return sanitize(raw, program, f'curl {method} {url}')


def ffuf(
    url: str,
    wordlist: str,
    program: str,
    headers: list[str] | None = None,
    extensions: str = '',
    rate: int | None = None,
) -> str:
    from config import TOOL_RATE_LIMIT
    if rate is None:
        rate = TOOL_RATE_LIMIT
    out_file = _out(program, 'ffuf.json')
    args = [
        '-u', url,
        '-w', wordlist,
        '-o', out_file,
        '-of', 'json',
        '-rate', str(rate),
        '-mc', 'all',
        '-fc', '404',
        '-silent',
    ]
    if extensions:
        args += ['-e', extensions]
    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    for h in resolved_headers:
        args += ['-H', h]

    raw, code = run('ffuf', args, program=program, target=_extract_host(url))
    lines = [l for l in raw.splitlines() if l.strip()]
    result = '\n'.join(lines[:30])
    if len(lines) > 30:
        result += f'\n[... {len(lines)-30} more — see recon/ffuf.json]'
    audit.log(program, 'tool_run', {
        'tool': 'ffuf', 'url': url, 'wordlist': wordlist, 'returncode': code,
        'safe_tokens_resolved': hdr_tokens,
    })
    return sanitize(result, program, f'ffuf -u {url}')


def feroxbuster(
    url: str,
    program: str,
    wordlist: str = '/usr/share/wordlists/dirb/common.txt',
    headers: list[str] | None = None,
    extensions: str = 'php,html,txt,js,json,bak,conf',
    depth: int = 1,
) -> str:
    from config import TOOL_RATE_LIMIT
    out_file = _out(program, 'ferox.txt')
    args = [
        '-u', url,
        '-w', wordlist,
        '-x', extensions,
        '-o', out_file,
        '-q',
        '--no-recursion',
        '--depth', str(depth),
        '--rate-limit', str(TOOL_RATE_LIMIT),
    ]
    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    for h in resolved_headers:
        args += ['-H', h]

    raw, code = run('feroxbuster', args, program=program,
                    target=_extract_host(url), timeout=180)
    lines = [l for l in raw.splitlines() if l.strip()]
    result = '\n'.join(lines[:30])
    if len(lines) > 30:
        result += f'\n[... {len(lines)-30} more — see recon/ferox.txt]'
    audit.log(program, 'tool_run', {
        'tool': 'feroxbuster', 'url': url, 'returncode': code,
        'safe_tokens_resolved': hdr_tokens,
    })
    return sanitize(result, program, f'feroxbuster -u {url}')


def katana(
    url: str,
    program: str,
    depth: int = 2,
    headers: list[str] | None = None,
) -> str:
    from config import TOOL_RATE_LIMIT
    out_file = _out(program, 'katana.txt')
    args = ['-u', url, '-d', str(depth), '-o', out_file, '-silent',
            '-rate-limit', str(TOOL_RATE_LIMIT)]
    resolved_headers, hdr_tokens = _resolve_safe(headers or [], program)
    for h in resolved_headers:
        args += ['-H', h]

    raw, code = run('katana', args, program=program,
                    target=_extract_host(url), timeout=120)
    lines = [l for l in raw.splitlines() if l.strip()]
    result = f'katana: {len(lines)} URLs crawled → saved to recon/katana.txt'
    audit.log(program, 'tool_run', {
        'tool': 'katana', 'url': url, 'returncode': code,
        'safe_tokens_resolved': hdr_tokens,
    })
    return sanitize(result, program, f'katana -u {url}')


def _extract_host(url: str) -> str:
    """Pull just the hostname from a URL for scope checking."""
    for proto in ('https://', 'http://'):
        if url.startswith(proto):
            url = url[len(proto):]
    return url.split('/')[0].split(':')[0]
