# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""Passive and active recon tool wrappers."""

from pathlib import Path
from config import BB_ROOT
from core.executor import run
from core.sanitizer import sanitize
from audit import logger as audit


def _out(program: str, filename: str) -> str:
    p = BB_ROOT / 'programs' / program / 'recon'
    p.mkdir(parents=True, exist_ok=True)
    return str(p / filename)


def subfinder(domain: str, program: str) -> str:
    out_file = _out(program, 'subfinder.txt')
    raw, code = run('subfinder', ['-d', domain, '-silent', '-o', out_file],
                    program=program, target=domain)
    # Summary only to Claude
    lines = [l for l in raw.splitlines() if l.strip()]
    summary = f'subfinder: {len(lines)} subdomains found → saved to recon/subfinder.txt'
    audit.log(program, 'tool_run', {'tool': 'subfinder', 'target': domain,
                                     'returncode': code, 'lines': len(lines)})
    return sanitize(summary, program, f'subfinder -d {domain}')


def amass(domain: str, program: str) -> str:
    out_file = _out(program, 'amass.txt')
    raw, code = run('amass', ['enum', '-passive', '-d', domain, '-o', out_file],
                    program=program, target=domain, timeout=300)
    lines = [l for l in raw.splitlines() if l.strip()]
    summary = f'amass: {len(lines)} results → saved to recon/amass.txt'
    audit.log(program, 'tool_run', {'tool': 'amass', 'target': domain,
                                     'returncode': code})
    return sanitize(summary, program, f'amass enum -passive -d {domain}')


def assetfinder(domain: str, program: str) -> str:
    out_file = _out(program, 'assetfinder.txt')
    raw, code = run('assetfinder', ['--subs-only', domain],
                    program=program, target=domain)
    lines = [l for l in raw.splitlines() if l.strip()]
    # Write output manually since assetfinder uses stdout
    Path(out_file).write_text('\n'.join(lines), encoding='utf-8')
    summary = f'assetfinder: {len(lines)} subdomains → saved to recon/assetfinder.txt'
    audit.log(program, 'tool_run', {'tool': 'assetfinder', 'target': domain,
                                     'returncode': code})
    return sanitize(summary, program, f'assetfinder --subs-only {domain}')


def httpx(input_file: str, program: str) -> str:
    from config import TOOL_RATE_LIMIT
    out_file = _out(program, 'alive.txt')
    raw, code = run('httpx',
                    ['-l', input_file, '-silent', '-status-code',
                     '-title', '-tech-detect', '-rate-limit', str(TOOL_RATE_LIMIT),
                     '-o', out_file],
                    program=program)
    lines = [l for l in raw.splitlines() if l.strip()]
    # Return first 30 alive hosts — sanitized
    preview = '\n'.join(lines[:30])
    if len(lines) > 30:
        preview += f'\n[... {len(lines)-30} more — see recon/alive.txt]'
    audit.log(program, 'tool_run', {'tool': 'httpx', 'input': input_file,
                                     'alive': len(lines), 'returncode': code})
    return sanitize(preview, program, f'httpx -l {input_file}')


def nmap(target: str, program: str,
         ports: str = '--top-ports 1000', flags: str = '-sC -sV') -> str:
    out_base = _out(program, 'nmap')
    port_args = ports.split() if ports else ['--top-ports', '1000']
    flag_args = flags.split() if flags else ['-sC', '-sV']
    raw, code = run('nmap', flag_args + port_args + [target, '-oA', out_base],
                    program=program, target=target, timeout=300)
    # Filter to open ports only
    open_lines = [l for l in raw.splitlines() if 'open' in l.lower()]
    result = '\n'.join(open_lines[:30]) if open_lines else 'No open ports found.'
    if len(open_lines) > 30:
        result += f'\n[... {len(open_lines)-30} more — see recon/nmap.*]'
    audit.log(program, 'tool_run', {'tool': 'nmap', 'target': target,
                                     'open_ports': len(open_lines), 'returncode': code})
    return sanitize(result, program, f'nmap {target}')


def whatweb(target: str, program: str) -> str:
    raw, code = run('whatweb', [target, '--color=never'],
                    program=program, target=target)
    result = '\n'.join(raw.splitlines()[:10])
    audit.log(program, 'tool_run', {'tool': 'whatweb', 'target': target,
                                     'returncode': code})
    return sanitize(result, program, f'whatweb {target}')


def dig(domain: str, record_type: str, program: str) -> str:
    raw, code = run('dig', [domain, record_type, '+short'],
                    program=program, target=domain)
    result = '\n'.join(raw.splitlines()[:20])
    audit.log(program, 'tool_run', {'tool': 'dig', 'domain': domain,
                                     'type': record_type, 'returncode': code})
    return sanitize(result, program, f'dig {domain} {record_type}')


def whois(domain: str, program: str) -> str:
    raw, code = run('whois', [domain], program=program, target=domain)
    # Limit to first 30 lines — whois can be very verbose
    result = '\n'.join(raw.splitlines()[:30])
    audit.log(program, 'tool_run', {'tool': 'whois', 'domain': domain,
                                     'returncode': code})
    return sanitize(result, program, f'whois {domain}')
