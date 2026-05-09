# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""
Per-host 429 circuit breaker + global rate ceiling.

Two layers of throttling, both persisted to /tmp so they survive MCP process
restarts within their respective windows:

1. Per-host breaker — once a host returns 429, refuse further requests to that
   host (and its parent zone) for COOLDOWN_AFTER_429 seconds. Hard rule:
   never trigger 429 on any program, on any day.

2. Per-zone aggregate cap — total requests across all bb-hunter tools to a
   single zone (e.g. *.example.com) must stay under SAFE_RATE_PER_ZONE per
   second. Trailing 1-second window. Tool wrappers can opt in via
   `aggregate_rate_check` + `record_request`.

3. Global ceiling — total outbound across ALL bb-hunter tools (every zone,
   every program, every concurrent invocation) must stay <= GLOBAL_RATE_LIMIT
   per second. Enforced inside the executor for every network-tool launch
   via `acquire_global_budget`.
"""
import json
import time
from pathlib import Path

from config import (
    BREAKER_STATE_FILE,
    COOLDOWN_AFTER_429,
    GLOBAL_BUDGET_MAX_WAIT,
    GLOBAL_RATE_FILE,
    GLOBAL_RATE_LIMIT,
    RATE_TRACKER_FILE,
    SAFE_RATE_PER_ZONE,
)


# ── Per-host 429 breaker ──────────────────────────────────────────────────────

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
    Good enough for CDN/WAF aggregation (Cloudflare, Akamai, etc.)."""
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def is_tripped(host: str) -> tuple[bool, int]:
    """Returns (tripped, seconds_remaining). Checks both exact host and parent zone."""
    state = _load_state()
    now = int(time.time())
    candidates = {host, _zone(host)}
    worst_remaining = 0
    tripped = False
    for c in candidates:
        last = state.get(c, 0)
        remaining = COOLDOWN_AFTER_429 - (now - int(last))
        if remaining > 0:
            tripped = True
            worst_remaining = max(worst_remaining, remaining)
    return tripped, worst_remaining


def trip(host: str, reason: str = '429') -> None:
    """Record a 429 (or related throttle) for host AND its parent zone."""
    state = _load_state()
    now = int(time.time())
    state[host] = now
    state[_zone(host)] = now
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
    """Inspect a curl `-si` response (headers+body) for throttle signals.
    Returns True if any 429 / 503 / Retry-After / 'rate limit' header found."""
    head = raw_response[:2048].lower()
    if 'http/' in head and ' 429' in head.split('\n', 1)[0]:
        return True
    if 'http/' in head and ' 503' in head.split('\n', 1)[0]:
        return True
    if 'retry-after:' in head:
        return True
    return False


# ── Per-zone aggregate rate tracker ───────────────────────────────────────────

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
    """Record outbound request(s) for aggregate-rate accounting. Long-running
    tools (nuclei, ffuf) should call this with
    `expected_request_count = req_per_sec * duration_sec`."""
    state = _load_tracker()
    z = _zone(host)
    now = time.time()
    bucket = state.get(z, [])
    bucket.extend([now] * expected_request_count)
    bucket = [t for t in bucket if now - t < 60]
    state[z] = bucket
    _save_tracker(state)


def aggregate_rate_check(host: str, expected_request_count: int = 1) -> tuple[bool, float]:
    """Returns (would_exceed_safe_rate, current_rate_per_sec) for the trailing
    1-second window."""
    state = _load_tracker()
    z = _zone(host)
    now = time.time()
    bucket = [t for t in state.get(z, []) if now - t < 1.0]
    projected = len(bucket) + expected_request_count
    return projected > SAFE_RATE_PER_ZONE, len(bucket) / 1.0


# ── Global rate cap ───────────────────────────────────────────────────────────

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
        # starve other concurrent calls. The tool's --rate-limit flag is what
        # actually shapes its outbound traffic past this point.
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
        oldest = min(bucket) if bucket else now
        sleep_for = max(0.05, min(0.2, 1.0 - (now - oldest)))
        time.sleep(sleep_for)


def reset_global() -> None:
    """Operator-only: clear the global rate window."""
    _save_global([])
