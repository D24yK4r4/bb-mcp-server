"""Safe file utilities — grep, filtered reads, note saving."""

import os
from pathlib import Path

from config import BB_ROOT, MAX_OUTPUT_LINES
from core.executor import _validate_path
from core.sanitizer import sanitize
from audit import logger as audit


def grep_file(file_path: str, pattern: str, program: str) -> str:
    """
    Grep a file for a pattern. Never reads the full file.
    Safe for files that may contain sensitive data.
    """
    _validate_path(file_path, mode='read')

    path = Path(file_path)
    if not path.exists():
        return f'File not found: {file_path}'

    try:
        import re
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f'Invalid regex pattern: {e}'

    matches: list[str] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if compiled.search(line):
                matches.append(f'{line_num}: {line.rstrip()}')
            if len(matches) >= MAX_OUTPUT_LINES:
                matches.append(f'[... stopped at {MAX_OUTPUT_LINES} matches]')
                break

    result = '\n'.join(matches) if matches else f'No matches for pattern: {pattern}'
    audit.log(program, 'file_grep', {
        'file': file_path, 'pattern': pattern, 'matches': len(matches)
    })
    return sanitize(result, program, f'grep {pattern!r} {file_path}')


def read_filtered(file_path: str, program: str, head: int = 30) -> str:
    """
    Read first N lines of a file — for recon output files only.
    Sanitized before returning.
    """
    _validate_path(file_path, mode='read')

    path = Path(file_path)
    if not path.exists():
        return f'File not found: {file_path}'

    lines: list[str] = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= head:
                break
            lines.append(line.rstrip())

    result = '\n'.join(lines)
    audit.log(program, 'file_read', {
        'file': file_path, 'lines_read': len(lines)
    })
    return sanitize(result, program, f'head -{head} {file_path}')


def count_lines(file_path: str, program: str) -> str:
    """Count lines in a file — safe, no content returned."""
    _validate_path(file_path, mode='read')

    path = Path(file_path)
    if not path.exists():
        return f'File not found: {file_path}'

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        count = sum(1 for _ in f)
    audit.log(program, 'file_count', {'file': file_path, 'lines': count})
    return f'{file_path}: {count} lines'


def save_note(content: str, program: str, filename: str = 'notes.md') -> str:
    """Append content to a notes file in the program directory."""
    notes_path = BB_ROOT / 'programs' / program / filename
    notes_path.parent.mkdir(parents=True, exist_ok=True)

    with open(notes_path, 'a', encoding='utf-8') as f:
        f.write(content + '\n')

    os.chmod(notes_path, 0o600)
    audit.log(program, 'note_saved', {'file': filename, 'bytes': len(content)})
    return f'Saved to {filename}'


def list_recon(program: str) -> str:
    """List recon output files for a program — names and sizes only."""
    recon_dir = BB_ROOT / 'programs' / program / 'recon'
    if not recon_dir.exists():
        return 'No recon directory found.'

    lines = []
    for f in sorted(recon_dir.iterdir()):
        if f.is_file():
            size = f.stat().st_size
            lines.append(f'{f.name} ({size} bytes)')

    return '\n'.join(lines) if lines else 'Recon directory is empty.'
