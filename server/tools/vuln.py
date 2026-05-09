# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""Vulnerability scanning tool wrappers — nuclei, sqlmap, dalfox."""

from config import BB_ROOT
from core.executor import run
from core.sanitizer import sanitize
from audit import logger as audit


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
    for h in (headers or []):
        args += ['-H', h]

    raw, code = run('nuclei', args, program=program,
                    target=_host(target), timeout=300)
    lines = [l for l in raw.splitlines() if l.strip()]
    result = f'nuclei: {len(lines)} findings → saved to recon/nuclei.txt'
    if lines:
        result += '\n' + '\n'.join(lines[:20])
    audit.log(program, 'tool_run', {
        'tool': 'nuclei', 'target': target,
        'findings': len(lines), 'returncode': code
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
    if data:
        args += ['--data', data]
    for h in (headers or []):
        args += ['-H', h]

    # Safety: explicitly block destructive flags in args
    for blocked in ('--dump', '--dump-all', '--os-shell', '--os-cmd',
                    '--sql-shell', '--file-write', '--file-dest'):
        if blocked in args:
            return f'ERROR: {blocked} is not allowed in bug bounty mode.'

    raw, code = run('sqlmap', args, program=program,
                    target=_host(url), timeout=300)
    lines = [l for l in raw.splitlines()
             if any(k in l.lower() for k in ('inject', 'vulnerab', 'parameter',
                                              'payload', 'error', 'warning'))]
    result = '\n'.join(lines[:20]) if lines else 'sqlmap: no injection detected.'
    audit.log(program, 'tool_run', {
        'tool': 'sqlmap', 'url': url, 'returncode': code
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
    for h in (headers or []):
        args += ['--header', h]

    raw, code = run('dalfox', args, program=program,
                    target=_host(url), timeout=180)
    lines = [l for l in raw.splitlines()
             if any(k in l.lower() for k in ('[vuln]', '[poc]', '[info]', 'xss'))]
    result = '\n'.join(lines[:20]) if lines else 'dalfox: no XSS detected.'
    audit.log(program, 'tool_run', {
        'tool': 'dalfox', 'url': url, 'returncode': code
    })
    return sanitize(result, program, f'dalfox url {url}')
