"""
Validator-gate verdict store.

Hash-chained append-only JSONL log under VAULT_ROOT/<program>/verdicts/verdicts.jsonl.
Every entry links to the previous via SHA-256 — tampering is detectable, same model
as audit/logger.py.

Lifecycle:
  create()  → opens an AWAITING entry, returns verdict_id (UUID)
  record()  → appends a finalizing entry with EXPLOITABLE or THEORETICAL
  get()     → returns the latest entry for a verdict_id (the finalized one if recorded)
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from config import VAULT_ROOT, FORBIDDEN_PAYLOAD_PATTERNS

VERDICT_AWAITING    = 'AWAITING'
VERDICT_EXPLOITABLE = 'EXPLOITABLE'
VERDICT_THEORETICAL = 'THEORETICAL'


def _verdicts_log(program: str) -> Path:
    log_dir = VAULT_ROOT / program / 'verdicts'
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / 'verdicts.jsonl'


def _last_hash(log_path: Path) -> str:
    if not log_path.exists():
        return hashlib.sha256(b'genesis').hexdigest()
    try:
        with open(log_path, 'rb') as f:
            lines = f.read().splitlines()
        for line in reversed(lines):
            line = line.strip()
            if line:
                entry = json.loads(line)
                return entry.get('hash', hashlib.sha256(b'genesis').hexdigest())
    except Exception:
        pass
    return hashlib.sha256(b'genesis').hexdigest()


def _hash_entry(entry: dict) -> str:
    serialized = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _append(program: str, entry: dict) -> None:
    log_path = _verdicts_log(program)
    entry['prev_hash'] = _last_hash(log_path)
    entry['hash'] = _hash_entry({k: v for k, v in entry.items() if k != 'hash'})
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    os.chmod(log_path, 0o600)


def safety_check(proposed_poc: str) -> tuple[bool, str]:
    """
    Reject PoCs that contain forbidden destructive patterns
    (DROP TABLE, rm -rf, reverse shells, etc. — see config.FORBIDDEN_PAYLOAD_PATTERNS).
    """
    if not proposed_poc or not proposed_poc.strip():
        return False, 'proposed_poc is empty — describe the safe PoC you intend to run'
    for pat in FORBIDDEN_PAYLOAD_PATTERNS:
        m = pat.search(proposed_poc)
        if m:
            return False, (
                f'proposed_poc contains forbidden destructive pattern: {m.group(0)!r}. '
                f'Validator gate rejects destructive PoCs by design.'
            )
    return True, 'ok'


def create(
    program: str,
    hypothesis: str,
    target: str,
    evidence: str,
    proposed_poc: str,
) -> str:
    """Open a new AWAITING verdict. Returns verdict_id (UUID)."""
    verdict_id = str(uuid.uuid4())
    entry = {
        'verdict_id':    verdict_id,
        'program':       program,
        'hypothesis':    hypothesis[:1000],
        'target':        target[:500],
        'evidence':      (evidence or '')[:4000],
        'proposed_poc':  (proposed_poc or '')[:4000],
        'status':        VERDICT_AWAITING,
        'verdict':       None,
        'reasoning':     None,
        'validated_poc': None,
        'ts_created':    datetime.now(timezone.utc).isoformat(),
        'ts_recorded':   None,
    }
    _append(program, entry)
    return verdict_id


def record(
    verdict_id: str,
    verdict: str,
    reasoning: str,
    validated_poc: str = '',
) -> tuple[bool, str]:
    """
    Finalize a verdict. Returns (ok, message).
    A verdict can only be recorded once — second attempts are rejected.
    """
    if verdict not in (VERDICT_EXPLOITABLE, VERDICT_THEORETICAL):
        return False, (
            f'verdict must be {VERDICT_EXPLOITABLE!r} or {VERDICT_THEORETICAL!r}, '
            f'got {verdict!r}'
        )

    existing = get(verdict_id)
    if existing is None:
        return False, f'verdict_id {verdict_id!r} not found'
    if existing['status'] != VERDICT_AWAITING:
        return False, (
            f'verdict {verdict_id!r} is already finalized '
            f'(status={existing["status"]!r}) — cannot record twice'
        )

    entry = {k: v for k, v in existing.items() if k not in ('hash', 'prev_hash')}
    entry['status']        = verdict
    entry['verdict']       = verdict
    entry['reasoning']     = (reasoning or '')[:2000]
    entry['validated_poc'] = (validated_poc or '')[:4000]
    entry['ts_recorded']   = datetime.now(timezone.utc).isoformat()

    _append(existing['program'], entry)
    return True, f'verdict {verdict_id} recorded as {verdict}'


def get(verdict_id: str) -> dict | None:
    """
    Return the latest entry for a verdict_id (final state if recorded, else AWAITING).
    Searches across all programs under VAULT_ROOT.
    """
    if not VAULT_ROOT.exists():
        return None

    latest: dict | None = None
    latest_ts = ''

    for program_dir in VAULT_ROOT.iterdir():
        if not program_dir.is_dir():
            continue
        log_path = program_dir / 'verdicts' / 'verdicts.jsonl'
        if not log_path.exists():
            continue
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get('verdict_id') != verdict_id:
                        continue
                    ts = entry.get('ts_recorded') or entry.get('ts_created', '')
                    if ts >= latest_ts:
                        latest = entry
                        latest_ts = ts
        except Exception:
            continue

    return latest


def verify(program: str) -> tuple[bool, str]:
    """
    Verify the hash chain of the verdicts log for one program.
    Mirrors audit.logger.verify().
    """
    log_path = _verdicts_log(program)
    if not log_path.exists():
        return True, 'No verdicts log found — nothing to verify.'

    prev = hashlib.sha256(b'genesis').hexdigest()
    with open(log_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f'Line {line_num}: invalid JSON'

            if entry.get('prev_hash') != prev:
                return False, f'Line {line_num}: hash chain broken (tampering detected)'

            expected = _hash_entry({k: v for k, v in entry.items() if k != 'hash'})
            if entry.get('hash') != expected:
                return False, f'Line {line_num}: entry hash mismatch (tampering detected)'

            prev = entry['hash']

    return True, 'Verdicts log integrity verified.'
