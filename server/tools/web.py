"""Web testing tool wrappers — curl, ffuf, feroxbuster, whatweb, katana."""

from config import BB_ROOT
from core.executor import run
from core.sanitizer import sanitize
from audit import logger as audit


def _out(program: str, filename: str) -> str:
    p = BB_ROOT / 'programs' / program / 'recon'
    p.mkdir(parents=True, exist_ok=True)
    return str(p / filename)


def curl(
    url: str,
    program: str,
    method: str = 'GET',
    headers: list[str] | None = None,
    data: str | None = None,
    flags: list[str] | None = None,
) -> str:
    """
    Run curl against a target URL.
    headers: list of 'Header: value' strings
    data:    POST body (string)
    flags:   extra curl flags (from allowlist only)
    """
    args = ['-si', '--max-time', '15']

    if method.upper() != 'GET':
        args += ['-X', method.upper()]

    for h in (headers or []):
        args += ['-H', h]

    if data:
        args += ['-d', data]

    for f in (flags or []):
        args.append(f)

    args.append(url)

    raw, code = run('curl', args, program=program, target=_extract_host(url))
    audit.log(program, 'tool_run', {
        'tool': 'curl', 'url': url, 'method': method, 'returncode': code
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
    for h in (headers or []):
        args += ['-H', h]

    raw, code = run('ffuf', args, program=program, target=_extract_host(url))
    lines = [l for l in raw.splitlines() if l.strip()]
    result = '\n'.join(lines[:30])
    if len(lines) > 30:
        result += f'\n[... {len(lines)-30} more — see recon/ffuf.json]'
    audit.log(program, 'tool_run', {
        'tool': 'ffuf', 'url': url, 'wordlist': wordlist, 'returncode': code
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
    for h in (headers or []):
        args += ['-H', h]

    raw, code = run('feroxbuster', args, program=program,
                    target=_extract_host(url), timeout=180)
    lines = [l for l in raw.splitlines() if l.strip()]
    result = '\n'.join(lines[:30])
    if len(lines) > 30:
        result += f'\n[... {len(lines)-30} more — see recon/ferox.txt]'
    audit.log(program, 'tool_run', {
        'tool': 'feroxbuster', 'url': url, 'returncode': code
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
    for h in (headers or []):
        args += ['-H', h]

    raw, code = run('katana', args, program=program,
                    target=_extract_host(url), timeout=120)
    lines = [l for l in raw.splitlines() if l.strip()]
    result = f'katana: {len(lines)} URLs crawled → saved to recon/katana.txt'
    audit.log(program, 'tool_run', {
        'tool': 'katana', 'url': url, 'returncode': code
    })
    return sanitize(result, program, f'katana -u {url}')


def _extract_host(url: str) -> str:
    """Pull just the hostname from a URL for scope checking."""
    for proto in ('https://', 'http://'):
        if url.startswith(proto):
            url = url[len(proto):]
    return url.split('/')[0].split(':')[0]
