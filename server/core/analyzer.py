"""
Script analyzer — scans a script's source code before the approval
request is shown to the operator. Produces a risk score and verdict.
"""

import ast
import re
from pathlib import Path

from config import SCRIPTS_BLOCKED, SCRIPTS_DIR

# Risk indicators — category → list of patterns to search for
RISK_INDICATORS: dict[str, list[str]] = {
    'reverse_shell': [
        r'/dev/tcp',
        r'nc\s+-e',
        r'bash\s+-i',
        r'python[23]?\s+-c\s+["\']import socket',
        r'socket\.connect\(',
        r'SOCK_STREAM.*connect',
    ],
    'destructive': [
        r'\brm\s+-[rf]+\b',
        r'\bshutil\.rmtree\b',
        r'\bos\.remove\b',
        r'\bDROP\s+TABLE\b',
        r'\bDELETE\s+FROM\b',
        r'\bTRUNCATE\b',
        r'\bdd\s+if=',
    ],
    'privilege': [
        r'\bos\.setuid\b',
        r'\bos\.setgid\b',
        r'\bctypes.*root\b',
        r'\bsudo\b',
        r'\bchmod\s+[0-7]*[67]\b',
    ],
    'shell_spawn': [
        r'subprocess.*shell\s*=\s*True',
        r'\bos\.system\b',
        r'\bos\.popen\b',
        r'\beval\s*\(',
        r'\bexec\s*\(',
    ],
    'code_download': [
        r'wget\s+http',
        r'curl\s+.*\|\s*(ba)?sh',
        r'urllib.*download',
        r'requests\.get.*write',
    ],
    'outbound_connection': [
        r'\brequests\.',
        r'\burllib\b',
        r'\bhttpx\b',
        r'\baiohttp\b',
        r'socket\.socket',
    ],
    'file_write': [
        r'open\([^)]+["\'][wa]["\']',
        r'\.write\(',
        r'shutil\.copy',
        r'shutil\.move',
        r'os\.rename',
    ],
}

RISK_WEIGHTS: dict[str, int] = {
    'reverse_shell':      10,
    'destructive':         8,
    'privilege':           7,
    'shell_spawn':         3,
    'code_download':       4,
    'outbound_connection': 1,
    'file_write':          1,
}


def analyze(script_name: str) -> dict:
    """
    Analyze a script and return a risk assessment dict.

    Returns:
        {
            'script':        str,
            'path':          str | None,
            'blocked':       bool,
            'verdict':       'BLOCKED' | 'REVIEW' | 'SAFE',
            'damage_score':  int (0–10),
            'findings':      dict[category, bool],
            'lines':         int,
            'error':         str | None,
        }
    """
    result: dict = {
        'script':       script_name,
        'path':         None,
        'blocked':      False,
        'verdict':      'BLOCKED',
        'damage_score': 10,
        'findings':     {},
        'lines':        0,
        'error':        None,
    }

    # Hardcoded block list — no analysis needed
    if script_name in SCRIPTS_BLOCKED:
        result['blocked'] = True
        result['verdict'] = 'BLOCKED'
        result['damage_score'] = 10
        return result

    # Find the script
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        result['error'] = f'Script not found: {script_path}'
        result['verdict'] = 'BLOCKED'
        return result

    result['path'] = str(script_path)

    try:
        source = script_path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        result['error'] = f'Could not read script: {e}'
        result['verdict'] = 'BLOCKED'
        return result

    result['lines'] = len(source.splitlines())

    # Run pattern checks
    findings: dict[str, bool] = {}
    for category, patterns in RISK_INDICATORS.items():
        findings[category] = any(
            re.search(p, source, re.IGNORECASE | re.MULTILINE)
            for p in patterns
        )

    result['findings'] = findings

    # Calculate damage score (capped at 10)
    score = sum(
        RISK_WEIGHTS[cat] for cat, found in findings.items() if found
    )
    result['damage_score'] = min(score, 10)

    # Verdict thresholds
    if result['damage_score'] >= 10 or findings.get('reverse_shell'):
        result['verdict'] = 'BLOCKED'
        result['blocked'] = True
    elif result['damage_score'] >= 3:
        result['verdict'] = 'REVIEW'
    else:
        result['verdict'] = 'SAFE'

    return result


def format_approval_request(script_name: str, reason: str, analysis: dict) -> str:
    """Format the approval request shown to the operator via Claude."""
    if analysis['blocked']:
        return (
            f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
            f' SCRIPT APPROVAL REQUEST\n'
            f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
            f' Script: {script_name}\n\n'
            f' AUTO-VERDICT: 🚫 BLOCKED\n'
            f' Reason: Script is on the blocked list or contains\n'
            f'         reverse shell / destructive patterns.\n'
            f'         This script cannot be executed by the MCP server.\n'
            f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
        )

    f = analysis['findings']
    verdict_icon = '✅' if analysis['verdict'] == 'SAFE' else '⚠️ '

    lines = [
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        ' SCRIPT APPROVAL REQUEST',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        f' Script:  {script_name}',
        f' Lines:   {analysis["lines"]}',
        '',
        ' WHY the AI wants to run it:',
        f'   {reason}',
        '',
        ' WHAT IT DOES (auto-analyzed):',
        f'   Network calls:       {"YES" if f.get("outbound_connection") else "NO"}',
        f'   File writes:         {"YES" if f.get("file_write") else "NO"}',
        f'   Shell spawn:         {"YES" if f.get("shell_spawn") else "NO"}',
        f'   Code download:       {"YES" if f.get("code_download") else "NO"}',
        f'   Reverse connection:  {"YES ⚠️" if f.get("reverse_shell") else "NO"}',
        f'   Destructive ops:     {"YES ⚠️" if f.get("destructive") else "NO"}',
        f'   Privilege ops:       {"YES ⚠️" if f.get("privilege") else "NO"}',
        '',
        f' DAMAGE SCORE: {analysis["damage_score"]} / 10',
        '',
        f' AUTO-VERDICT: {verdict_icon} {analysis["verdict"]}',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        '',
        ' ⚡ Respond with:',
        '   "approve" — to allow execution',
        '   "deny"    — to block execution',
    ]
    return '\n'.join(lines)
