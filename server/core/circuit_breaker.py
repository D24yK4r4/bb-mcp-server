"""
Per-host 429 circuit breaker.
HARD OPERATOR RULE: never trigger 429 on any program. If a tool sees a true
throttle signal (429, or 503 with Retry-After) from host X, all subsequent
requests to X are refused for COOLDOWN_AFTER_429 seconds. State is persisted
to /tmp so it survives MCP process restarts within the cooldown window.

Scoping: the breaker is HOST-scoped, not zone-scoped. A 5xx on rs-open-api.x
must not lock cmapi.x — many "5xx" responses are static fallback pages
(Akamai NetStorage default 503, etc.) that signal a dead host, not zone-wide
rate limiting. Zone-level rate accounting still happens via the separate
aggregate-rate tracker below.

Throttle-signal definition (detect_throttle_in_response):
  • Status 429 → trip (always — explicit rate-limit response)
  • Status 503 + Retry-After header → trip (real upstream throttle)
  • Status 503 without Retry-After → DO NOT trip (likely static fallback / dead host)
  • Any status + Retry-After header → trip (rare but valid; respect server's hint)
"""
import json
import time
from pathlib import Path

from config import COOLDOWN_AFTER_429, BREAKER_STATE_FILE


def _load_state() -> dict:
    p = Path(BREAKER_STATE_FILE)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    Path(BREAKER_STATE_FILE).write_text(json.dumps(state))


def _zone(host: str) -> str:
    """Return the eTLD+1-ish parent zone. Best-effort: takes the last 2 labels.
    For *.intigriti.rocks → 'intigriti.rocks'. Good enough for CF aggregation."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def is_tripped(host: str) -> tuple[bool, int]:
    """Returns (tripped, seconds_remaining). Host-scoped only — siblings on the
    same registrable domain are NOT affected by this host's cooldown."""
    state = _load_state()
    now = int(time.time())
    last = state.get(host, 0)
    remaining = COOLDOWN_AFTER_429 - (now - int(last))
    if remaining > 0:
        return True, remaining
    return False, 0


def trip(host: str, reason: str = "429") -> None:
    """Record a true throttle signal (429 or 503-with-Retry-After) for the
    exact host. Host-scoped only — does NOT lock siblings on the parent zone."""
    state = _load_state()
    now = int(time.time())
    state[host] = now
    _save_state(state)


def reset(host: str | None = None) -> None:
    """Clear the breaker for one host (or all if None). Operator-only."""
    state = _load_state()
    if host is None:
        _save_state({})
    else:
        for c in (host, _zone(host)):
            state.pop(c, None)
        _save_state(state)


def detect_throttle_in_response(raw_response: str) -> bool:
    """Inspect a curl `-si` response (headers+body) for TRUE throttle signals.

    Trips on:
      • Status 429 (explicit rate-limit, always)
      • Status 503 + Retry-After header (real upstream throttle)
      • Any status + Retry-After header (server explicitly asks for backoff)

    Does NOT trip on:
      • Bare 503 without Retry-After — these are commonly static fallback
        pages (e.g. Akamai NetStorage default 503 for dead hosts) and don't
        indicate rate limiting.
    """
    head = raw_response[:2048].lower()
    status_line = head.split("\n", 1)[0]
    has_retry_after = "retry-after:" in head

    # 429 always trips
    if "http/" in head and " 429" in status_line:
        return True
    # 503 only trips if Retry-After is present (real throttle vs static fallback)
    if "http/" in head and " 503" in status_line:
        return has_retry_after
    # Any other status: trip only if Retry-After is set (rare but valid)
    if has_retry_after:
        return True
    return False


# ── Aggregate rate tracker ────────────────────────────────────────────────────
# Hard rule from operator: total requests across ALL bb-hunter tools to a single
# zone must stay under SAFE_RATE_PER_ZONE per second. If a new request would
# push the trailing-1s window over the limit, refuse it.

SAFE_RATE_PER_ZONE = 2  # req/sec aggregate cap per zone (intigriti.rocks, etc.)
RATE_TRACKER_FILE = "/tmp/bb_rate_tracker.json"


def _load_tracker() -> dict:
    p = Path(RATE_TRACKER_FILE)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_tracker(state: dict) -> None:
    Path(RATE_TRACKER_FILE).write_text(json.dumps(state))


def record_request(host: str, expected_request_count: int = 1) -> None:
    """Record outbound request(s) for aggregate-rate accounting. Long-running tools
    (nuclei, ffuf) should call this with expected_request_count = req_per_sec * duration_sec."""
    state = _load_tracker()
    z = _zone(host)
    now = time.time()
    bucket = state.get(z, [])
    # Each entry is a single timestamp — for batch tools, append `count` entries
    bucket.extend([now] * expected_request_count)
    # Keep only last 60 seconds
    bucket = [t for t in bucket if now - t < 60]
    state[z] = bucket
    _save_tracker(state)


def aggregate_rate_check(host: str, expected_request_count: int = 1) -> tuple[bool, float]:
    """Returns (would_exceed_safe_rate, current_rate_per_sec).
    Checks the trailing 1-second window and projects expected_request_count."""
    state = _load_tracker()
    z = _zone(host)
    now = time.time()
    bucket = [t for t in state.get(z, []) if now - t < 1.0]
    projected_rate = len(bucket) + expected_request_count  # within 1s window
    return projected_rate > SAFE_RATE_PER_ZONE, len(bucket) / 1.0


# ── Global rate cap ───────────────────────────────────────────────────────────
# Hard rule from operator: total outbound across ALL bb-hunter tools (every
# zone, every program, every concurrent invocation) must stay ≤ GLOBAL_RATE_LIMIT
# per second. Persisted in /tmp so it survives MCP process restarts within a
# 1-second window.

from config import GLOBAL_RATE_LIMIT, GLOBAL_RATE_FILE, GLOBAL_BUDGET_MAX_WAIT


def _load_global() -> list[float]:
    p = Path(GLOBAL_RATE_FILE)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text())
    except Exception:
        return []


def _save_global(bucket: list[float]) -> None:
    Path(GLOBAL_RATE_FILE).write_text(json.dumps(bucket))


def _trim_global(bucket: list[float], now: float) -> list[float]:
    return [t for t in bucket if now - t < 1.0]


def global_rate_check(expected_request_count: int = 1) -> tuple[bool, float]:
    """Returns (would_exceed_global_cap, current_global_rate_per_sec)."""
    now = time.time()
    bucket = _trim_global(_load_global(), now)
    projected = len(bucket) + expected_request_count
    return projected > GLOBAL_RATE_LIMIT, float(len(bucket))


def record_global(expected_request_count: int = 1) -> None:
    """Record outbound request(s) against the global 1-second window."""
    now = time.time()
    bucket = _trim_global(_load_global(), now)
    bucket.extend([now] * expected_request_count)
    _save_global(bucket)


def acquire_global_budget(expected_request_count: int = 1,
                          max_wait: float = GLOBAL_BUDGET_MAX_WAIT) -> tuple[bool, float]:
    """
    Block until the global 1-second window has room for `expected_request_count`
    more requests, then record them. Returns (acquired, waited_seconds).

    If `max_wait` elapses without the budget freeing up, returns (False, waited)
    without recording — caller should refuse the request.
    """
    if expected_request_count > GLOBAL_RATE_LIMIT:
        # Cap a single tool's reservation at the global limit so it doesn't
        # starve everyone else. Tool will run, but its --rate-limit flag is
        # what actually shapes its outbound traffic.
        expected_request_count = GLOBAL_RATE_LIMIT

    start = time.time()
    while True:
        now = time.time()
        bucket = _trim_global(_load_global(), now)
        if len(bucket) + expected_request_count <= GLOBAL_RATE_LIMIT:
            bucket.extend([now] * expected_request_count)
            _save_global(bucket)
            return True, now - start
        if now - start >= max_wait:
            return False, now - start
        # Sleep until the oldest entry in the window expires, capped at 200ms
        oldest = min(bucket) if bucket else now
        sleep_for = max(0.05, min(0.2, 1.0 - (now - oldest)))
        time.sleep(sleep_for)


def reset_global() -> None:
    """Operator-only: clear the global rate window."""
    _save_global([])
