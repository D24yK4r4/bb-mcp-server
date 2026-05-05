"""
Scope gate — every network command must pass this check
before execution. Reads brief.md for each program.
"""

import re
from pathlib import Path
from config import BB_ROOT


def _load_brief(program: str) -> str:
    brief_path = BB_ROOT / 'programs' / program / 'brief.md'
    if not brief_path.exists():
        raise FileNotFoundError(
            f'brief.md not found for program "{program}". '
            f'Run program setup first.'
        )
    return brief_path.read_text(encoding='utf-8')


def _extract_scope_lists(brief: str) -> tuple[list[str], list[str]]:
    """
    Parse in-scope and out-of-scope domain/IP lists from brief.md.
    Looks for sections headed by 'In Scope' and 'Out of Scope'.
    """
    in_scope:  list[str] = []
    out_scope: list[str] = []

    current = None
    for line in brief.splitlines():
        lower = line.lower().strip()
        if 'in scope' in lower and 'out' not in lower:
            current = 'in'
            continue
        if 'out of scope' in lower or 'out-of-scope' in lower:
            current = 'out'
            continue
        # New section resets context
        if lower.startswith('#') and current is not None:
            if 'in scope' not in lower and 'out' not in lower:
                current = None

        if current and line.strip():
            # Extract domain/IP-like tokens from bullet points and table rows
            tokens = re.findall(
                r'[\w*][\w.*-]*\.[\w.]{2,}|(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?',
                line
            )
            if current == 'in':
                in_scope.extend(t.lower() for t in tokens)
            elif current == 'out':
                out_scope.extend(t.lower() for t in tokens)

    return in_scope, out_scope


def _matches(target: str, pattern: str) -> bool:
    """
    Check if target matches a scope pattern.
    Supports wildcards: *.example.com matches sub.example.com
    """
    target  = target.lower().strip().rstrip('/')
    pattern = pattern.lower().strip().rstrip('/')

    # Strip protocol
    for proto in ('https://', 'http://'):
        if target.startswith(proto):
            target = target[len(proto):]
        if pattern.startswith(proto):
            pattern = pattern[len(proto):]

    # Strip path for domain matching
    target_host = target.split('/')[0].split(':')[0]

    if pattern.startswith('*.'):
        base = pattern[2:]
        return target_host == base or target_host.endswith('.' + base)

    return target_host == pattern or target_host == pattern.split('/')[0]


def check(target: str, program: str) -> tuple[bool, str]:
    """
    Verify target is in scope for program.
    Returns (allowed: bool, reason: str).
    """
    try:
        brief = _load_brief(program)
    except FileNotFoundError as e:
        return False, str(e)

    in_scope, out_scope = _extract_scope_lists(brief)

    if not in_scope:
        return False, (
            'Could not parse in-scope list from brief.md. '
            'Verify brief.md has an "In Scope" section.'
        )

    # Out-of-scope check first — explicit exclusions win
    for pattern in out_scope:
        if _matches(target, pattern):
            return False, f'Target "{target}" is explicitly out of scope ({pattern}).'

    # In-scope check
    for pattern in in_scope:
        if _matches(target, pattern):
            return True, f'Target "{target}" is in scope ({pattern}).'

    return False, (
        f'Target "{target}" does not match any in-scope pattern. '
        f'In scope: {in_scope}. '
        f'If this should be in scope, update brief.md and confirm with operator.'
    )
