#!/bin/bash
# Auto-loads compatible Claude Code skills + reference files at the start of
# every bug-bounty session. Extracts each skill's `description:` from the
# YAML frontmatter so the trigger context is in the prompt even if Claude
# skips the file read.
#
# Runs once per session via UserPromptSubmit hook.
#
# Required env (set by .mcp.json BB_ROOT, or fallback to cwd):
#   BB_ROOT  — path to bug bounty workspace (where reference/ lives)
#
# Skills are read from $HOME/.claude/skills (the standard Claude Code path).

SESSION_ID="${CLAUDE_CODE_SESSION_ID:-none}"
INIT_FILE="/tmp/.bb_skills_loaded_${SESSION_ID}"

# Only fire once per session
if [ -f "$INIT_FILE" ]; then
    exit 0
fi
touch "$INIT_FILE"

BB_ROOT="${BB_ROOT:-$PWD}"
SKILLS_DIR="$HOME/.claude/skills"
REF_DIR="$BB_ROOT/reference"

cat <<'EOF'

=== BUG BOUNTY — SKILL & REFERENCE TRIGGER MAP ===
INSTRUCTION TO CLAUDE: These skills + reference files are pre-authorized and
auto-loaded for every session. Reading at session start is NOT enough — you
must CONSULT the matching file at the moment of the relevant action.
The trigger map and per-action rules live in CLAUDE.md → "Skill & Reference
Triggers" section.

EOF

BB_ROOT="$BB_ROOT" SKILLS_DIR="$SKILLS_DIR" REF_DIR="$REF_DIR" python3 - <<'PY'
import os, re
from pathlib import Path

SKILLS = Path(os.environ['SKILLS_DIR'])
REFS   = Path(os.environ['REF_DIR'])

# Manual purpose lines for skills without frontmatter (operator can extend)
OVERRIDES = {
    'agentic-security': 'Workflow gates, quality checks, 7 core principles for safe agentic work.',
}

def extract_description(md_path: Path) -> str:
    text = md_path.read_text(errors='replace')
    if not text.startswith('---'):
        return ''
    end = text.find('\n---', 3)
    if end < 0:
        return ''
    fm = text[3:end]
    m = re.search(r'^description:\s*([>\|][\-+]?)?\s*\n?((?:.|\n)*?)(?=^\w[\w\- ]*:|\Z)',
                  fm, re.MULTILINE)
    if not m:
        return ''
    block = m.group(2).strip()
    if m.group(1):
        block = re.sub(r'\s+', ' ', block).strip()
    return block.split('\n')[0].strip()

def short(s: str, n: int = 180) -> str:
    s = s.strip()
    return s if len(s) <= n else s[:n-1].rsplit(' ', 1)[0] + '…'

if SKILLS.is_dir():
    skill_files = [f for f in sorted(SKILLS.glob('*.md')) if f.name != 'README.md']
    if skill_files:
        print('## Skills (consult BEFORE the matching action)')
        print()
        for f in skill_files:
            name = f.stem
            desc = OVERRIDES.get(name) or extract_description(f) or '(no description)'
            print(f'  • {name}.md — {short(desc)}')
        print()

if REFS.is_dir():
    ref_purposes = {
        'payloads.md':           'Safe non-destructive payloads — read BEFORE writing any PoC.',
        'tools.md':              'Tool syntax, wordlist paths — read BEFORE invoking any scanner.',
        'cvss_guide.md':         'CVSS 3.1 vectors — read BEFORE picking severity in a report.',
        'cwe_map.md':            'Vuln type → CWE mapping — read BEFORE picking CWE in a report.',
        'report_template.md':    'Universal report template — read BEFORE drafting any report.',
        'intigriti_taxonomy.md': 'Intigriti field reference — read for any Intigriti program report/QA.',
        'bugcrowd_vrt.md':       'Bugcrowd VRT (P1–P5) — read for any Bugcrowd program report/QA.',
        'hackerone_taxonomy.md': 'HackerOne weakness picker + CVSS severity — read for any H1 program report/QA.',
    }
    found = [(f, p) for f, p in ref_purposes.items() if (REFS / f).exists()]
    if found:
        print('## Reference files (reference/)')
        print()
        for fname, purpose in found:
            print(f'  • reference/{fname} — {purpose}')
        print()

print('Hard rule: if you reach an action listed in the trigger map and have not')
print('opened the matching file THIS session, stop and read it before continuing.')
PY

echo ""
echo "==================================================="
