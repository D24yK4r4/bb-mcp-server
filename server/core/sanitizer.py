"""
Output sanitizer — scans tool output for sensitive patterns,
vaults the values locally, and replaces them with <SAFE:type:id> tokens.
Claude only ever sees the sanitized version.

Three-pass design:
  1. Per-program patterns (loaded from programs/<program>/brief.md if present)
  2. Built-in REDACT_PATTERNS from config
  3. JSON-context retagging: identify generic UUIDs in known semantic JSON keys
     (userId / programId / fileId / etc.) and re-tag for inline visibility.
"""

import re
from pathlib import Path
from config import REDACT_PATTERNS, MAX_OUTPUT_LINES, MAX_OUTPUT_BYTES, BB_ROOT
from vault import safe as vault


# ── JSON-context UUID retagging ───────────────────────────────────────────────
# Map from JSON key name (lowercase, no underscores/dashes) to a more specific vault type.
# Order matters: more specific keys first.
_UUID_CONTEXT_KEYS: list[tuple[str, str]] = [
    ('userid',         'userid_uuid'),
    ('researcherid',   'userid_uuid'),
    ('ownerid',        'userid_uuid'),
    ('createdby',      'userid_uuid'),
    ('updatedby',      'userid_uuid'),
    ('programid',      'programid_uuid'),
    ('companyid',      'companyid_uuid'),
    ('groupid',        'groupid_uuid'),
    ('fileid',         'fileid_uuid'),
    ('attachmentid',   'fileid_uuid'),
    ('avatarid',       'fileid_uuid'),
    ('submissionid',   'submissionid_uuid'),
    ('clientid',       'clientid_uuid'),
    ('tenantid',       'tenantid_uuid'),
    ('subscriptionid', 'subscriptionid_uuid'),
    ('identityid',     'identityid_uuid'),
    ('sessionid',      'sessionid_uuid'),
    ('roleid',         'roleid_uuid'),
]

# Build retag patterns: "userId":"<SAFE:uuid:abc12345>" -> retag the SAFE token type
_RETAG_PATTERNS: list[tuple[re.Pattern, str]] = []
for key_norm, new_type in _UUID_CONTEXT_KEYS:
    # Match "<key>":"<SAFE:uuid:id>" where <key> may have underscores/dashes/case variants
    key_chars = ''.join(f'[{c.upper()}{c.lower()}][_-]?' for c in key_norm)
    # Tighten: just allow case variants and optional separators
    pat = rf'("(?:[A-Za-z]+[_-]?)*?{key_norm}"|"{key_norm}"|"{key_norm.upper()}")\s*:\s*"<SAFE:uuid:([0-9a-f]{{8}})>"'
    # Simpler & faster: just case-insensitive direct key match
    pat = rf'(?i)("[A-Za-z_]*{key_norm}"\s*:\s*")<SAFE:uuid:([0-9a-f]{{8}})>(")'
    _RETAG_PATTERNS.append((re.compile(pat), new_type))


# ── Per-program patterns from brief.md ────────────────────────────────────────
# Cache: program -> list of (compiled_pattern, replacement_template, vault_type)
_PROGRAM_PATTERN_CACHE: dict[str, list] = {}


def _load_program_patterns(program: str) -> list:
    """
    Read programs/<program>/brief.md and parse a `## Vault Patterns` section if present.
    Format expected:
        ## Vault Patterns
        - type: TYPE_NAME, regex: `REGEX_PATTERN`
        - type: TYPE_NAME2, regex: `REGEX_PATTERN2`

    Patterns are compiled with re.MULTILINE | re.IGNORECASE.
    Returns [] if no brief.md or no Vault Patterns section.
    """
    if program in _PROGRAM_PATTERN_CACHE:
        return _PROGRAM_PATTERN_CACHE[program]

    patterns: list = []
    brief_path = BB_ROOT / 'programs' / program / 'brief.md'
    if not brief_path.exists():
        _PROGRAM_PATTERN_CACHE[program] = patterns
        return patterns

    try:
        text = brief_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        _PROGRAM_PATTERN_CACHE[program] = patterns
        return patterns

    # Find the Vault Patterns section
    section_match = re.search(
        r'^##\s+Vault Patterns\s*\n(.*?)(?=^##\s+|\Z)',
        text, re.MULTILINE | re.DOTALL
    )
    if not section_match:
        _PROGRAM_PATTERN_CACHE[program] = patterns
        return patterns

    section = section_match.group(1)
    # Parse each "- type: NAME, regex: `PATTERN`" line
    for m in re.finditer(
        r'^[-*]\s+type:\s*([A-Za-z_][A-Za-z_0-9]*)\s*,\s*regex:\s*`(.+?)`\s*$',
        section, re.MULTILINE
    ):
        try:
            vtype = m.group(1)
            raw   = m.group(2)
            compiled = re.compile(raw, re.MULTILINE | re.IGNORECASE)
            patterns.append((compiled, f'<SAFE:{{id}}>', vtype))
        except re.error:
            continue  # skip malformed regex silently

    _PROGRAM_PATTERN_CACHE[program] = patterns
    return patterns


_SAFE_TOKEN_RE = re.compile(r'<SAFE:[^>]+>')


def sanitize(output: str, program: str, source: str) -> str:
    """
    Scan output for sensitive patterns.
    Vault each match, replace with <SAFE:type:id>.
    Truncate to safe size limits.
    Returns the sanitized string.

    Protection against re-vaulting existing SAFE tokens is enforced at the
    pattern level (see config.py — patterns with greedy value matchers all
    use `(?!<SAFE:)` negative lookahead or exclude `<` from their character
    class). No mask/unmask layer is needed here.
    """
    result = output

    # Pass 0: program-specific patterns (from brief.md), applied first
    program_patterns = _load_program_patterns(program)
    all_patterns = program_patterns + REDACT_PATTERNS

    for pattern, _replacement_template, vault_type in all_patterns:
        def replace_match(m: re.Match, _vtype: str = vault_type) -> str:
            groups = m.lastindex or 0

            if groups >= 3:
                # 3-group pattern: prefix, sensitive_value, suffix (e.g. JSON closing quote)
                prefix          = m.group(1)
                sensitive_value = m.group(2)
                suffix          = m.group(3)
            elif groups >= 1:
                # 1-group pattern: prefix only, sensitive value is remainder
                prefix          = m.group(1)
                sensitive_value = m.group(0)[len(prefix):]
                suffix          = ''
            else:
                # No groups: entire match is the sensitive value
                prefix          = ''
                sensitive_value = m.group(0)
                suffix          = ''

            safe_id = vault.store(
                program=program,
                value=sensitive_value,
                vault_type=_vtype,
                source=source,
            )

            # Type-prefixed SAFE token so context is visible inline.
            # Format: <SAFE:type:id> (e.g. <SAFE:cookie:a3f9c2b1>).
            # The id is always the last colon-delimited segment for backward-compat parsing.
            return f'{prefix}<SAFE:{_vtype}:{safe_id}>{suffix}'

        result = pattern.sub(replace_match, result)

    # Pass 2: JSON-context UUID retagging — promote generic <SAFE:uuid:..> tokens
    # to typed <SAFE:userid_uuid:..>, <SAFE:programid_uuid:..>, etc. based on the
    # JSON key they appear after. The vault entry retains its original generic type;
    # we update the displayed token only (and call vault.attach_context if available).
    for pat, new_type in _RETAG_PATTERNS:
        def _retag(m: re.Match, _t: str = new_type) -> str:
            prefix  = m.group(1)
            safe_id = m.group(2)
            suffix  = m.group(3)
            try:
                vault.attach_context(program, safe_id, _t)
            except (AttributeError, Exception):
                pass  # vault may not have attach_context yet; best-effort
            return f'{prefix}<SAFE:{_t}:{safe_id}>{suffix}'
        result = pat.sub(_retag, result)

    return _truncate(result)


def _truncate(output: str) -> str:
    lines = output.splitlines()
    truncated = False

    if len(lines) > MAX_OUTPUT_LINES:
        kept   = lines[:MAX_OUTPUT_LINES]
        dropped = len(lines) - MAX_OUTPUT_LINES
        kept.append(f'[... {dropped} lines truncated — full output saved to recon/ file]')
        output = '\n'.join(kept)
        truncated = True

    if len(output.encode()) > MAX_OUTPUT_BYTES and not truncated:
        output = output.encode()[:MAX_OUTPUT_BYTES].decode(errors='ignore')
        output += '\n[... output truncated — full output saved to recon/ file]'

    return output
