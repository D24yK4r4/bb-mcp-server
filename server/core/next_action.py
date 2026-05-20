"""
v0.4.0 — Workflow-nudge suggestion generator.

Pure function: given a (tool_name, outcome) pair, return the single most useful
next slash-command / Skill / Agent call. The operator (via Claude) decides
whether to follow it. The server does NOT block subsequent calls if the
suggestion is ignored.

Stable command vocabulary (the contract — renaming any of these breaks the
suggestion strings; treat as a stable interface):

  /report  /triage  /pickup  /scope  /validate  /chain  /recon  /hunt  /surface

These must exist as `.md` files in
`~/Documents/BugBounty/.claude/commands/` for the operator to fire them.
"""

from __future__ import annotations


# ── Outcome constants (string-typed so unknown values degrade gracefully) ──
VALIDATE_OPENED       = 'validate.opened'
VERDICT_EXPLOITABLE   = 'verdict.exploitable'
VERDICT_THEORETICAL   = 'verdict.theoretical'
VERDICT_INSUFFICIENT  = 'verdict.insufficient'
REPORT_CREATED        = 'report.created'
SCOPE_DRIFT           = 'scope.drift'
SCOPE_REJECTED        = 'scope.rejected'
RATE_LIMIT_TRIPPED    = 'circuit.rate_limited'
SAFETY_REJECTED       = 'safety.rejected'
FINGERPRINT_JWT       = 'fingerprint.jwt'
FINGERPRINT_GRAPHQL   = 'fingerprint.graphql'
FINGERPRINT_SAML      = 'fingerprint.saml'


def suggest(outcome: str, *, verdict_id: str | None = None,
            target: str | None = None) -> str | None:
    """
    Return a one-line next-action suggestion, or None if no suggestion applies.

    The string is plain operator-facing English with embedded slash-commands
    where applicable. Claude surfaces it; the operator approves or ignores.
    """
    if outcome == VALIDATE_OPENED:
        return (
            'Spawn an Opus Agent with the brief below as the prompt. '
            'Read line 1 of the agent\'s reply (EXPLOITABLE / THEORETICAL / '
            'INSUFFICIENT), then call '
            f'record_verdict(verdict_id={verdict_id!r}, ...).'
        )

    if outcome == VERDICT_EXPLOITABLE:
        return (
            f'Run /report to draft the submission. '
            f'Pass validator_verdict_id={verdict_id!r} when calling '
            f'create_report.'
        )

    if outcome == VERDICT_THEORETICAL:
        pivot = f'/pickup {target}' if target else '/pickup <other-target>'
        return (
            f'Archive the lead in notes.md per CLAUDE.md THEORETICAL gate, '
            f'then {pivot} on a different lane. Do not draft a report.'
        )

    if outcome == VERDICT_INSUFFICIENT:
        return (
            'Add the missing payload-variant / bypass-technique / endpoint-state '
            'evidence to the brief and re-spawn the Opus Agent. Do NOT '
            'call record_verdict yet — re-justify first.'
        )

    if outcome == REPORT_CREATED:
        return (
            'Spawn the program-manager subagent for Phase 4 QA '
            '(independent CVSS + duplicate-risk re-score). One revision '
            'round max. If the subagent downgrades severity below the '
            'program\'s policy floor, surface that to the operator before '
            'submitting.'
        )

    if outcome == SCOPE_REJECTED:
        return (
            'Re-check the target against brief.md. If brief.md is stale, '
            f'/scope {target or "<target>"} to re-sync; otherwise pivot.'
        )

    if outcome == SCOPE_DRIFT:
        return (
            f'brief.md hash changed since session start. /scope {target or "<target>"} '
            f'to re-sync before continuing — scope may have moved.'
        )

    if outcome == RATE_LIMIT_TRIPPED:
        return (
            'Circuit breaker tripped — 2 req/s + 5-min cooldown active on this '
            'zone. /pickup a different target or lane while the breaker recovers; '
            'do NOT attempt rate-limit evasion (forbidden bypass per CLAUDE.md).'
        )

    if outcome == SAFETY_REJECTED:
        return (
            'Replace the destructive payload with a safe equivalent from '
            'reference/payloads.md (e.g. SLEEP() instead of DROP TABLE, '
            'id/whoami instead of installing a shell). Re-call validate_finding '
            'with the safe PoC.'
        )

    if outcome == FINGERPRINT_JWT:
        return (
            'Response contains a JWT (`eyJ...`). Consult auth-attacks.md + '
            'reference/disclosed_patterns/hunt-oauth.md before treating the '
            'lane as exhausted (alg=none, weak HMAC, kid traversal, JWK '
            'injection, etc.).'
        )

    if outcome == FINGERPRINT_GRAPHQL:
        return (
            'GraphQL endpoint observed. Consult graphql-hunting.md + '
            'reference/disclosed_patterns/hunt-graphql.md (introspection '
            'bypass, alias/batch, mutation IDOR, persisted-query).'
        )

    if outcome == FINGERPRINT_SAML:
        return (
            'SAML endpoint observed. Consult auth-attacks.md + '
            'reference/disclosed_patterns/hunt-saml.md (XSW1-XSW8, '
            'NameID comment injection, signature stripping).'
        )

    return None


# ── Vuln-class detection for validator_brief auto-injection ──────────────────

# Order matters: longer / more-specific keys first so 'http smuggling' beats 'http'.
_CLASS_KEYWORDS: tuple[tuple[str, str], ...] = (
    ('http smuggling', 'http-smuggling'),
    ('request smuggling', 'http-smuggling'),
    ('http-smuggling', 'http-smuggling'),
    ('cache poison', 'cache-poison'),
    ('cache-poison', 'cache-poison'),
    ('cache deception', 'cache-poison'),
    ('file upload', 'file-upload'),
    ('file-upload', 'file-upload'),
    ('mass assignment', 'idor'),
    ('business logic', 'business-logic'),
    ('business-logic', 'business-logic'),
    ('workflow bypass', 'business-logic'),
    ('mfa bypass', 'mfa-bypass'),
    ('mfa-bypass', 'mfa-bypass'),
    ('2fa bypass', 'mfa-bypass'),
    ('race condition', 'idor'),  # races usually surface via idor disclosed
    ('graphql', 'graphql'),
    ('oauth', 'oauth'),
    ('openid', 'oauth'),
    ('oidc',  'oauth'),
    ('saml',  'saml'),
    ('idor',  'idor'),
    ('broken access control', 'idor'),
    ('bac',   'idor'),
    ('privilege escalation', 'idor'),
    ('privesc', 'idor'),
    ('ssrf',  'ssrf'),
    ('server-side request forgery', 'ssrf'),
    ('ssti',  'ssti'),
    ('template injection', 'ssti'),
    ('sqli',  'sqli'),
    ('sql injection', 'sqli'),
    ('xxe',   'xxe'),
    ('xml external entity', 'xxe'),
    ('rce',   'rce'),
    ('remote code execution', 'rce'),
    ('command injection', 'rce'),
    ('csrf',  'csrf'),
    ('cross-site request forgery', 'csrf'),
    ('xss',   'xss'),
    ('cross-site scripting', 'xss'),
)


def detect_class(hypothesis: str) -> str | None:
    """
    Return the disclosed-patterns class name matching the hypothesis text,
    or None when no keyword matches.

    Used by validator_brief to decide whether to inject
    reference/disclosed_patterns/hunt-<class>.md into the brief.
    """
    if not hypothesis:
        return None
    needle = hypothesis.lower()
    for keyword, cls in _CLASS_KEYWORDS:
        if keyword in needle:
            return cls
    return None
