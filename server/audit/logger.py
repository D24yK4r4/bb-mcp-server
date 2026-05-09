# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""
Append-only audit logger with SHA-256 hash chain.
Every entry links to the previous — tampering is detectable.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from config import VAULT_ROOT


def _today_log(program: str) -> Path:
    log_dir = VAULT_ROOT / program
    log_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    return log_dir / f'audit_{date_str}.log'


def _last_hash(log_path: Path) -> str:
    """Return the hash of the last entry, or genesis hash if empty."""
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
        # Graceful degradation: a missing or malformed audit log file means we
        # haven't written any entries yet (or the file was tampered/deleted).
        # Fall back to the genesis hash; verify_audit_log will surface any
        # subsequent chain inconsistency on demand.
        pass
    return hashlib.sha256(b'genesis').hexdigest()


def _hash_entry(entry: dict) -> str:
    serialized = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


def log(program: str, event: str, data: dict) -> None:
    """Append one entry to the audit log for this program."""
    log_path = _today_log(program)
    prev = _last_hash(log_path)

    entry: dict = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event':     event,
        'prev_hash': prev,
        **data,
    }
    entry['hash'] = _hash_entry({k: v for k, v in entry.items() if k != 'hash'})

    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    # Owner read/write only
    os.chmod(log_path, 0o600)


def verify(program: str) -> tuple[bool, str]:
    """
    Verify the hash chain for today's log.
    Returns (ok, message).
    """
    log_path = _today_log(program)
    if not log_path.exists():
        return True, 'No log file found — nothing to verify.'

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

    return True, 'Audit log integrity verified.'
