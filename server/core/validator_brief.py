"""
Builds the markdown brief that the operator hands to an Opus Agent for verdict.
Pulls program rules from brief.md and safe-payload patterns from reference/payloads.md.

v0.4.0: also auto-injects reference/disclosed_patterns/hunt-<class>.md when the
hypothesis names a known vuln class — gives the validator concrete prior-art
examples instead of relying on abstract criteria alone.
"""

from pathlib import Path

from config import BB_ROOT
from core import next_action

# Cap for disclosed-pattern injection. Keeps Opus brief tight; the validator
# only needs representative examples, not the whole catalog.
_DISCLOSED_PATTERN_CAP = 8000


def _read_optional(path: Path, max_chars: int = 8000) -> str:
    if not path.exists():
        return f'(file not found: {path})'
    try:
        text = path.read_text(encoding='utf-8')
        return text[:max_chars] + ('\n…[truncated]' if len(text) > max_chars else '')
    except Exception as e:
        return f'(error reading {path}: {e})'


def _disclosed_patterns_section(class_name: str | None) -> str:
    """
    Return a markdown section with disclosed-report prior art for the given
    vuln class, or an empty string when class_name is None or the file is
    missing.
    """
    if not class_name:
        return ''
    path = BB_ROOT / 'reference' / 'disclosed_patterns' / f'hunt-{class_name}.md'
    if not path.exists():
        return ''
    content = _read_optional(path, _DISCLOSED_PATTERN_CAP)
    return (
        f'\n---\n\n'
        f'## Disclosed-report prior art — {class_name}\n\n'
        f'The hypothesis matched the **{class_name}** class. The following '
        f'patterns are extracted from public disclosed bug-bounty reports. '
        f'Use them as concrete prior-art when judging EXPLOITABLE vs '
        f'THEORETICAL — if the operator\'s evidence matches one of these '
        f'patterns, the burden of proof for THEORETICAL increases.\n\n'
        f'{content}\n'
    )


def build_brief(
    program: str,
    hypothesis: str,
    target: str,
    evidence: str,
    proposed_poc: str,
    verdict_id: str,
    class_hint: str | None = None,
) -> str:
    brief_md    = _read_optional(BB_ROOT / 'programs' / program / 'brief.md', 8000)
    payloads_md = _read_optional(BB_ROOT / 'reference' / 'payloads.md',       8000)

    # v0.4.0 — auto-detect vuln class from hypothesis (overridden by class_hint
    # when the operator passes it explicitly).
    detected_class = class_hint or next_action.detect_class(hypothesis)
    patterns_section = _disclosed_patterns_section(detected_class)

    return f'''# Validator-Agent Brief — {program}

**verdict_id:** `{verdict_id}`

You are a bug-bounty PoC validator. Your job: decide whether the hypothesis below
can be **safely exploited** within program rules to produce a working,
non-destructive PoC.

**Output format — line 1 must be exactly one of:**
- `EXPLOITABLE: <one-line summary>` followed by a copy-pasteable safe PoC
  (curl/HTTP request/payload) that proves impact without violating program rules.
- `THEORETICAL — DROP: <one-line reason>` if you cannot construct a safe
  exploit within the rules. Be honest — do not stretch.

**Do not actually execute the PoC.** Design it and verify against rules only.

---

## Hypothesis
{hypothesis}

## Target
{target}

## Evidence so far
```
{(evidence or "(none provided)")[:3000]}
```

## Operator's proposed safe PoC (review and refine)
```
{(proposed_poc or "(none provided)")[:3000]}
```

---

## Program rules (from brief.md)
{brief_md}

---

## Safe-payload reference
{payloads_md}
{patterns_section}
---

## Offensive Posture (project-wide rule — bias the THEORETICAL/EXPLOITABLE call honestly)

The main thread operates under a project rule that **a defensive control is the
start of the lane, not the end**. "WAF detected, moved on" / "endpoint returned
403, marked hardened" is the failure mode to fight, not the conclusion to
accept. Apply this lens to your own verdict:

Before answering THEORETICAL, ask yourself:
1. How many payload variants are conceivable here? (target ≥5 — encoding,
   case, comment-injection, alternate-payload-class, parser-differential)
2. Could a WAF-bypass technique (URL/Unicode/HTML-entity encode, content-type
   confusion, parser differential, version-pinned endpoint, header injection)
   land where the operator's first payload didn't?
3. Could a different endpoint / API version / auth state / role / mobile API /
   internal route expose the same surface less defended?
4. Did the operator's evidence include the *response*, not just the request?
   THEORETICAL-on-no-response is premature.

## Burden of proof for THEORETICAL

A THEORETICAL verdict **must explicitly justify all three** of the following
in the reasoning section of your response:

a. **Payload-variant exhaustion** — name at least 2 concrete payload variants
   (encoding, case, comment, alternate class) that would not change the outcome
   here, and why.
b. **Bypass-technique exhaustion** — name at least 1 vendor-bypass / parser-
   differential / origin-IP-discovery angle that would not apply, and why.
c. **Endpoint/auth-state exhaustion** — name the alternative endpoint, API
   version, role, or auth state you considered and why each would not unlock
   the lane.

A THEORETICAL verdict with **fewer than 3 explicit justifications is
insufficient** — return `THEORETICAL — INSUFFICIENT JUSTIFICATION` and let the
operator re-spawn you with more evidence.

## Decision criteria

Answer EXPLOITABLE only if **all** of these hold:
1. The PoC respects the program's rate cap and required headers.
2. The PoC does not touch out-of-scope assets (verify against the OOS list above).
3. The PoC reads/proves impact rather than modifying state — no destructive
   operations (DELETE, DROP, file uploads beyond proof, account modifications
   beyond your own test accounts).
4. The PoC could realistically reach Medium severity or higher (this program's
   floor — verify in brief).
5. You can write the exact request/payload — no hand-waving like "send a
   crafted X" or "manipulate the parameter Y somehow".

Otherwise return THEORETICAL — DROP with the three-part justification above.
The operator will not draft a report on a THEORETICAL verdict, but they will
re-spawn you if the justification is insufficient.
'''
