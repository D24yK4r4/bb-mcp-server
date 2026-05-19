"""
Scope gate — every network command must pass this check
before execution. Reads brief.md for each program.
"""

import re
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
        # New section resets context — only h1/h2 ends a scope block;
        # h3+ (### Tier 1, etc.) are subsections of the current scope section.
        if (lower.startswith('# ') or lower.startswith('## ')) and current is not None:
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


def _normalize_pattern(pattern: str) -> str:
    """Strip protocol/path/port from a scope pattern, leaving just the host(-pattern)."""
    pattern = pattern.lower().strip().rstrip('/')
    for proto in ('https://', 'http://'):
        if pattern.startswith(proto):
            pattern = pattern[len(proto):]
    return pattern.split('/')[0].split(':')[0]


def _matches(target: str, pattern: str) -> bool:
    """
    Check if target matches a scope pattern.
    Supports wildcards: *.example.com matches sub.example.com (and example.com).
    """
    target = target.lower().strip().rstrip('/')
    for proto in ('https://', 'http://'):
        if target.startswith(proto):
            target = target[len(proto):]
    target_host = target.split('/')[0].split(':')[0]

    pattern_host = _normalize_pattern(pattern)

    if pattern_host.startswith('*.'):
        base = pattern_host[2:]
        return target_host == base or target_host.endswith('.' + base)

    return target_host == pattern_host


def _specificity(pattern: str) -> int:
    """
    Higher score = more specific match. Used to resolve in-scope vs out-of-scope
    conflicts: the more-specific pattern wins. Exact host always beats any
    wildcard; among wildcards, longer base wins.

    Example: with in-scope=auth2.example.com and out-of-scope=*.example.com,
    the exact host wins, so auth2.example.com is allowed (matches the carve-out
    semantics where wildcard OOS is a catch-all for unlisted subdomains).
    """
    host = _normalize_pattern(pattern)
    if host.startswith('*.'):
        return len(host[2:])
    return 1000 + len(host)


def check(target: str, program: str) -> tuple[bool, str]:
    """
    Verify target is in scope for program.
    Returns (allowed: bool, reason: str).

    Precedence: the most-specific matching pattern wins (across both in- and
    out-of-scope lists). On an exact specificity tie, deny wins (fail-safe).
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

    best_score = -1
    best_allow = False
    best_pattern = ''

    for pattern in in_scope:
        if _matches(target, pattern):
            score = _specificity(pattern)
            if score > best_score:
                best_score, best_allow, best_pattern = score, True, pattern

    for pattern in out_scope:
        if _matches(target, pattern):
            score = _specificity(pattern)
            # Strictly greater wins; on tie, deny takes precedence (fail-safe)
            if score > best_score or (score == best_score and best_allow):
                best_score, best_allow, best_pattern = score, False, pattern

    if best_score < 0:
        return False, (
            f'Target "{target}" does not match any in-scope pattern. '
            f'In scope: {in_scope}. '
            f'If this should be in scope, update brief.md and confirm with operator.'
        )

    if best_allow:
        return True, f'Target "{target}" is in scope ({best_pattern}).'
    return False, f'Target "{target}" is explicitly out of scope ({best_pattern}).'
