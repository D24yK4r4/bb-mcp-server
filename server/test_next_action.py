"""
Tests for core/next_action.py — the v0.4.0 workflow-nudge generator.

Covers:
  • suggest() returns the expected string per outcome
  • suggest() returns None for unknown outcomes
  • detect_class() finds the right disclosed-pattern class for hypothesis text
  • detect_class() returns None when nothing matches
  • build_brief() injects the disclosed_patterns/hunt-<class>.md content
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core import next_action
from core.validator_brief import build_brief


# ── suggest() ─────────────────────────────────────────────────────────────────

def test_suggest_validate_opened_mentions_record_verdict():
    out = next_action.suggest(next_action.VALIDATE_OPENED, verdict_id='abc-123')
    assert out is not None
    assert 'record_verdict' in out
    assert 'abc-123' in out


def test_suggest_exploitable_mentions_report():
    out = next_action.suggest(next_action.VERDICT_EXPLOITABLE, verdict_id='v-1')
    assert out is not None
    assert '/report' in out
    assert 'v-1' in out


def test_suggest_theoretical_mentions_pickup_and_target():
    out = next_action.suggest(
        next_action.VERDICT_THEORETICAL, target='example.com',
    )
    assert out is not None
    assert '/pickup' in out
    assert 'example.com' in out
    assert 'notes.md' in out


def test_suggest_theoretical_without_target_uses_placeholder():
    out = next_action.suggest(next_action.VERDICT_THEORETICAL)
    assert out is not None
    assert '/pickup' in out
    assert '<other-target>' in out


def test_suggest_insufficient_warns_against_record_verdict():
    out = next_action.suggest(next_action.VERDICT_INSUFFICIENT)
    assert out is not None
    assert 'record_verdict' in out
    assert 'NOT' in out or 'not' in out


def test_suggest_report_created_mentions_phase4():
    out = next_action.suggest(next_action.REPORT_CREATED)
    assert out is not None
    assert 'program-manager' in out
    assert 'Phase 4' in out


def test_suggest_scope_drift_recommends_scope_resync():
    out = next_action.suggest(next_action.SCOPE_DRIFT, target='target.com')
    assert out is not None
    assert '/scope' in out
    assert 'target.com' in out


def test_suggest_rate_limit_forbids_evasion():
    out = next_action.suggest(next_action.RATE_LIMIT_TRIPPED)
    assert out is not None
    assert '/pickup' in out
    assert 'evasion' in out  # explicit reminder per CLAUDE.md forbidden bypass


def test_suggest_jwt_fingerprint_points_to_auth_attacks():
    out = next_action.suggest(next_action.FINGERPRINT_JWT)
    assert out is not None
    assert 'auth-attacks' in out


def test_suggest_unknown_outcome_returns_none():
    assert next_action.suggest('not.a.real.outcome') is None


# ── detect_class() ────────────────────────────────────────────────────────────

def test_detect_class_xss():
    assert next_action.detect_class('Stored XSS in /comments') == 'xss'
    assert next_action.detect_class('reflected cross-site scripting') == 'xss'


def test_detect_class_sqli():
    assert next_action.detect_class('SQLi via id parameter') == 'sqli'
    assert next_action.detect_class('SQL injection in search') == 'sqli'


def test_detect_class_idor_family():
    assert next_action.detect_class('IDOR on /api/users/{id}') == 'idor'
    assert next_action.detect_class('broken access control') == 'idor'
    assert next_action.detect_class('privilege escalation via role param') == 'idor'
    assert next_action.detect_class('mass assignment of is_admin') == 'idor'


def test_detect_class_oauth_family():
    assert next_action.detect_class('OAuth redirect_uri bypass') == 'oauth'
    assert next_action.detect_class('OpenID Connect flow') == 'oauth'
    assert next_action.detect_class('OIDC bypass') == 'oauth'


def test_detect_class_specificity():
    # 'http smuggling' must beat 'http' (not in keyword list anyway, but smuggling specifically)
    assert next_action.detect_class('HTTP request smuggling') == 'http-smuggling'
    # 'cache poison' must beat any 'poison' shortcut
    assert next_action.detect_class('cache poison via X-Forwarded-Host') == 'cache-poison'


def test_detect_class_unknown_returns_none():
    assert next_action.detect_class('something completely unrelated') is None
    assert next_action.detect_class('') is None
    assert next_action.detect_class(None) is None


# ── validator_brief integration ───────────────────────────────────────────────

def test_brief_injects_disclosed_patterns_when_class_detected():
    brief = build_brief(
        program='__test__',
        hypothesis='Stored XSS in /comments allows session hijack',
        target='example.com',
        evidence='reflected canary in response body',
        proposed_poc='<script>alert(document.domain)</script>',
        verdict_id='test-verdict-1',
    )
    # Brief should contain the disclosed-patterns marker section header.
    assert 'Disclosed-report prior art' in brief, \
        'XSS hypothesis should trigger disclosed_patterns injection'
    assert 'xss' in brief.lower()


def test_brief_omits_disclosed_patterns_when_no_class_match():
    brief = build_brief(
        program='__test__',
        hypothesis='Something completely unrelated to any vuln class',
        target='example.com',
        evidence='',
        proposed_poc='id',
        verdict_id='test-verdict-2',
    )
    # No class detected → no prior-art section.
    assert 'Disclosed-report prior art' not in brief


def test_brief_class_hint_overrides_detection():
    # Hypothesis says nothing about idor, but class_hint forces it.
    brief = build_brief(
        program='__test__',
        hypothesis='generic test hypothesis',
        target='example.com',
        evidence='',
        proposed_poc='GET /api/users/2',
        verdict_id='test-verdict-3',
        class_hint='idor',
    )
    assert 'Disclosed-report prior art' in brief
    assert 'idor' in brief.lower()


if __name__ == '__main__':
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f'  ✓ {t.__name__}')
        except AssertionError as e:
            failed += 1
            print(f'  ✗ {t.__name__}: {e}')
        except Exception:
            failed += 1
            print(f'  ✗ {t.__name__}: unexpected error')
            traceback.print_exc()
    print(f'\n{passed} passed, {failed} failed (out of {len(tests)})')
    sys.exit(0 if failed == 0 else 1)
