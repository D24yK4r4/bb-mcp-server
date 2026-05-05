# Bug Bounty MCP Server — Architecture & Workflow Plan

A privacy-first MCP (Model Context Protocol) server designed for bug bounty
hunting with Claude Code. Built around one core principle: **sensitive data
never reaches the AI model.**

> **Build status:** Phases 1–9 implemented. Phase 10 (sandbox hardening) is
> opt-in via the `firejail` hook in `setup.sh`. Everything below reflects the
> code that is actually in the tree, not aspirational design.

---

## The Problem This Solves

Standard bug bounty + AI workflows have a critical gap:

```
Tool runs → Raw output → AI model → Cloud LLM provider
                ↑
         Tokens, cookies, API keys,
         PII all travel here
```

This server adds a sanitization + vault layer so the AI only ever sees clean
output. It also closes the *workflow* gap — automatic skill consultation when
context warrants it, severity-gated reporting, and per-tool confirmation
prompts.

```
Tool runs → Sanitization layer → AI model → Cloud LLM provider
                ↓
         Sensitive values
         stored locally only
         (never reach AI)
```

---

## Project Structure (as built)

The repository is split between two cooperating components:

```
bb-mcp-server/                    ← The MCP server (Python)
├── server.py                     # MCP entry point (FastMCP), tool registration
├── config.py                     # Allowlists, paths, redaction patterns, limits
├── requirements.txt              # Pinned dependencies
├── setup.sh                      # Install + permissions + Claude Code registration
├── .mcp.json                     # Claude Code registration manifest
├── test_server.py                # Unit tests
├── test_integration.py           # End-to-end integration tests
│
├── core/
│   ├── executor.py               # Safe subprocess (shell=False, clean env, rate limit)
│   ├── sanitizer.py              # 60+ regex patterns + vault writer
│   ├── scope.py                  # Scope gate — reads brief.md before every command
│   ├── approver.py               # Two-step approval: request → confirm
│   └── analyzer.py               # regex-based script analysis before approval
│
├── tools/
│   ├── recon.py                  # subfinder, amass, assetfinder, httpx, nmap,
│   │                             # whatweb, dig, whois
│   ├── web.py                    # curl, ffuf, feroxbuster, katana
│   ├── vuln.py                   # nuclei, sqlmap, dalfox
│   └── utils.py                  # grep_file, read_filtered, count_lines, save_note,
│                                 # list_recon_files, consult_skill
│
├── vault/
│   └── safe.py                   # Vault writer, hash chain, chmod 600,
│                                 # describe() returns type+source only
│
├── audit/
│   └── logger.py                 # Append-only log, hash chain, verify()
│
└── reports/
    └── generator.py              # Dual report: sanitized (AI/repo) + full (local)
                                  # Backstop sanitization on free-text inputs.

.claude/                          ← Claude Code-side glue
├── settings.json                 # Hook registration + permission allowlist
└── hooks/
    ├── autoload-skills.sh        # UserPromptSubmit → injects skill+ref index
    ├── pre-tool-confirm.sh       # PreToolUse  → forces confirm prompt
    └── skill-context-trigger.sh  # PostToolUse → auto-loads skill on context match
```

---

## Local Vault Structure

Sensitive data is stored here. The MCP server writes to it but **never reads
it back to the AI.** Only the operator has access.

```
~/.<vault-dir>/                   ← Operator-chosen path via BB_VAULT env
└── <program-name>/
    ├── safe_YYYY-MM-DD.jsonl     # Vaulted values, hash-chained, chmod 600
    ├── audit_YYYY-MM-DD.log      # Every command + result, append-only
    └── findings/
        └── <finding-id>/
            ├── report_full.md    # Report with real values, chmod 600
            └── repro_full.sh     # Working PoC with real credentials, chmod 600
```

The vault path is fully configurable. Operators set `BB_VAULT=/path/of/choice`
in their MCP server registration — the server defaults to `~/.<vault-dir>/`
but does not assume any specific name.

---

## Data Flow

### Tool Execution Flow

```
Claude requests a tool call
         ↓
    PreToolUse hook fires
    (target-touching tools only — silent on local-only tools)
         ↓
    Forces approval prompt with structured summary:
      Tool: run_curl
      Program: <name>
      Target: <resolved URL>
      Args: method/headers/data
      ⚠ ACTIVE SCANNER if applicable
         ↓ DENY → Stop.
         ↓ APPROVE
    scope.check(target, program)
    Is target in program scope (brief.md)?
         ↓ NO  → Reject. Explain why. Stop.
         ↓ YES
    executor.run(...)
    Is binary in ALLOWED_TOOLS? Not in BLOCKED_TOOLS?
         ↓ NO  → Reject. Stop.
         ↓ YES
    Validate args (no null bytes, no path traversal, no shell metachars)
         ↓ FAIL → Reject. Stop.
         ↓ PASS
    Per-tool MCP cooldown (RATE_LIMITS, default 0.2 s)
         ↓ Wait if needed
    Per-tool TOOL_RATE_LIMIT injected as native flag (5 req/sec default)
         ↓
    Forbidden-payload-pattern check on full argv
         ↓ FAIL → Reject. Log attempt. Stop.
         ↓ PASS
    subprocess.run([...], shell=False, env=CLEAN_ENV)
         ↓
    sanitizer.sanitize(output)
    60+ compiled regex patterns scan output
         ↓
    safe.store(value)  →  ~/.<vault-dir>/<program>/safe_YYYY-MM-DD.jsonl
    Replace each sensitive match with <SAFE:type:id> token
         ↓
    audit.logger.append(entry)
    Hash-chained log per program per day
         ↓
    Truncate to MAX_OUTPUT_LINES / MAX_OUTPUT_BYTES
         ↓
    Claude receives clean output with <SAFE:type:id> tokens only
         ↓
    PostToolUse hook scans output for context signals
    (cloud / smart-contract / browser / payload-tool / CVSS / CWE / etc.)
         ↓ Match → inject skill/ref load reminder (once per skill per session)
         ↓ No match → silent
```

### Script Execution Flow (two-step)

```
Claude calls request_script_approval(script, reason, program)
         ↓
    analyzer.analyze(script_path)
    regex-based scan of script source
         ↓
    In SCRIPTS_BLOCKED list?  (reverse_shell_*, webshell.*, exfil_*, etc.)
    → BLOCKED. Never runs. Log attempt.
         ↓ NO
    Generate approval request shown to operator:
      - Why Claude wants to run it
      - What the script does (auto-analyzed)
      - Network calls? File writes? Shell spawns?
      - Damage score 0–10
      - Verdict: SAFE / REVIEW / BLOCKED
         ↓
    Operator approves or denies (out-of-band)
         ↓
Claude calls confirm_script_execution(..., approved=True/False)
         ↓ approved=False → Log attempt. Stop.
         ↓ approved=True
    Re-analyze (defence in depth — script may have changed)
         ↓ FAIL → Stop.
         ↓ PASS
    executor → sanitizer → vault → audit
    Claude receives clean output
```

### Report Generation Flow

```
Finding confirmed by operator
         ↓
    create_report(...)  →  reports.generator.generate(...)
         ↓
    Severity gate
    severity ∈ {high, critical, exceptional} OR force=True ?
         ↓ NO  → Reject. Bug bounty mission is impact-only.
         ↓ YES
    Backstop sanitization on free-text fields
    (description, steps, poc_*, impact, remediation — ensures any
     accidentally-pasted PII is also vaulted)
         ↓
    ┌────────────────────────┐     ┌─────────────────────────────┐
    │  report.md             │     │  report_full.md             │
    │  (sanitized)           │     │  (full — local only)        │
    │                        │     │                             │
    │  programs/<prog>/      │     │  ~/.<vault-dir>/<prog>/     │
    │  findings/<id>/        │     │  findings/<id>/             │
    │  report.md             │     │  report_full.md             │
    │                        │     │                             │
    │  <SAFE:bearer:t001>    │     │  Bearer eyJhbGc...          │
    │  <SAFE:email:e004>     │     │  victim@example.com         │
    │                        │     │                             │
    │  Claude reads this     │     │  Operator reads this        │
    │  Platform receives     │     │  Never leaves machine       │
    └────────────────────────┘     └─────────────────────────────┘
         ↓
    PostToolUse fires
    Reads programs/<prog>/brief.md for "Platform:" line
         ↓
    Injects platform-specific report bundle:
      Platform: Intigriti  → reference/intigriti_taxonomy.md
      Platform: Bugcrowd   → reference/bugcrowd_vrt.md
      Platform: HackerOne  → reference/hackerone_taxonomy.md
      Plus always:           reference/report_template.md
                             reference/cvss_guide.md
                             reference/cwe_map.md
```

---

## Security Layers

### Layer 1 — Process Isolation (operator-configured)

```
- Run as a low-privilege user (no login shell, no sudo)
- firejail sandbox: --net=none for the server process itself
- Optional systemd hardening:
    NoNewPrivileges=true
    PrivateTmp=true
    CapabilityBoundingSet=        ← empty, no capabilities
    ProtectSystem=strict
    ProtectHome=true
    ReadWritePaths=<explicit list only>
```

`setup.sh` detects `firejail` and prints the sandboxed launch command.

### Layer 2 — Filesystem: Principle of Least Privilege

```
CAN READ:                            CANNOT ACCESS:
✓ Project root (BB_ROOT)             ✗ Home directory (~/)
✓ Scripts dir (read-only)            ✗ /etc/, /var/, /sys/
✓ /usr/share/wordlists/              ✗ SSH keys (~/.ssh/)
✓ /usr/share/seclists/               ✗ Browser data
✓ /usr/share/nmap/                   ✗ Other projects
✓ /tmp/bb_working/                   ✗ System configuration

CAN WRITE:                           CANNOT WRITE:
✓ programs/ findings, notes          ✗ Anywhere not listed
✓ recon/ output files                ✗ System directories
✓ ~/.<vault-dir>/ (vault root)       ✗ Other user dirs
✓ /tmp/bb_working/
```

Allowed paths are declared in `config.py`:
`ALLOWED_READ_PATHS`, `ALLOWED_WRITE_PATHS`.

### Layer 3 — Tool Allowlist

```python
ALLOWED_TOOLS = {
    # Passive recon
    'subfinder', 'amass', 'assetfinder',
    # Active recon
    'nmap', 'httpx', 'whatweb', 'dig', 'whois',
    # Web
    'curl', 'ffuf', 'feroxbuster', 'katana', 'gospider',
    # Vuln
    'nuclei', 'sqlmap', 'dalfox',
    # Safe utilities
    'grep', 'jq', 'head', 'wc', 'sort', 'uniq', 'cut',
}

BLOCKED_TOOLS = {
    'sudo', 'su', 'bash', 'sh', 'zsh', 'fish', 'dash',
    'python3', 'python', 'perl', 'ruby', 'php',
    'gcc', 'make', 'pip', 'apt', 'apt-get', 'npm', 'yarn',
    'docker', 'kubectl', 'systemctl', 'service',
    'nc', 'netcat', 'socat', 'ncat',
    'iptables', 'ip', 'ufw', 'firewalld',
    'passwd', 'useradd', 'usermod', 'chmod', 'chown', 'chattr',
    'mount', 'umount', 'dd', 'mkfs', 'fdisk',
    'crontab', 'at', 'batch',
    'ssh', 'scp', 'sftp', 'rsync',
    'curl | bash', 'wget',
}

SCRIPTS_BLOCKED = {
    'reverse_shell_nc.py', 'webshell.php', 'venom_macro.vba',
    'ligolo-agent.exe', 'exfil_exploit.html', 'exfil_xss.html',
    'cors_exfil.html',
}
```

### Layer 4 — Argument Validation

```python
SHELL_METACHARACTERS = [';', '&&', '||', '`', '$(', '${',
                        '>(', '<(', '\n', '\r', '\x00']

# Blocked in any argument that reaches the executor.
# Plus: null-byte check, path-traversal check, unexpected-flag check.

# Environment is wiped clean — no inherited secrets
CLEAN_ENV = {
    'PATH': '/usr/local/bin:/usr/bin:/bin',
    'HOME': '/tmp/bb_working',
    'USER': 'bbhunter',
    'TERM': 'xterm',
    # Nothing else. No API keys. No tokens. No secrets.
}
```

### Layer 5 — Sanitization Patterns

Compiled once at import. Order matters: high-specificity SaaS patterns run
**before** generic `key=` / `token=` / `secret=` to avoid mistagging.

| Category | Examples |
|----------|----------|
| Auth headers | `Authorization: Bearer/Basic/Token`, JSON-echoed equivalents |
| Cookies | `Set-Cookie`, `Cookie:`, follow-on cookies ≥20-char value |
| SaaS tokens | GitHub PAT, Slack `xox*`, Slack webhook URLs, Stripe `sk/rk/pk_live/test`, Twilio Account SID, SendGrid `SG.*`, Mailgun `key-*`, DigitalOcean `dop_v1_*`, npm, Discord, Telegram |
| Cloud creds | AWS `AKIA*`/`ASIA*`, AWS secret/session/SigV4, Azure SAS `sig=`, Azure storage key, GCP `private_key_id`, GCP/Firebase/Maps `AIza*` |
| Crypto | `-----BEGIN ... PRIVATE KEY-----`, JWTs, ASP.NET Data Protection `CfDJ8*` blobs, generic 64-char hex (AES-256/HMAC), `sign_id`/`aes_key`/`hmac_secret` fields |
| Generic | `api_key=`, `secret=`, `token=`, `password=` (JSON or query) |
| DB conn strings | `postgres://`, `mysql://`, `mongodb://`, `redis://` with embedded creds |
| Long base64 | ≥40 chars (catches session IDs not caught above) |
| PII | `firstName/lastName/displayName/fullName` JSON keys, phone numbers (E.164), and three email tiers below |
| Email — researcher aliases | Configurable platform alias domains. Username vaulted, platform suffix preserved (e.g. `<SAFE:id>@<platform>`). Runs first. |
| Email — consumer/webmail | Public webmail domains (gmail, outlook, hotmail, yahoo, icloud, proton, aol, gmx, yandex, etc.). Username vaulted, suffix preserved (`<SAFE:id>@gmail.com`) — domain is a useful severity signal and not itself sensitive. Runs second. |
| Email — generic | Anything else (corporate, target, unknown). **Whole address collapsed** to `<SAFE:id>` — the domain itself may identify a target, acquisition, or customer sector. Operators can promote a specific corporate domain to "preserve suffix" via the `## Vault Patterns` section of `brief.md`. |
| 3rd-party SDK | Segment, Mixpanel, LaunchDarkly, Zendesk |
| Identifiers | UUIDs (catches OAuth client_ids, product IDs) |
| CTF / program | Common CTF flag formats, generic submission codes |
| Observability | Sentry DSN |

Each match is replaced with `<SAFE:type:id>`; the original is stored locally
and typed (`bearer_token`, `cookie`, `jwt`, `aws_access_key`, `email`, etc.).
The token format `<SAFE:type:id>` is recognized by both the vault and the
report substitution layer (which restores real values into the local-only
`report_full.md`).

### Layer 6 — Vault Integrity

```python
# Every vault entry is hash-chained — tampering is detectable
{
    "timestamp": "...",
    "id":        "t001",
    "type":      "bearer_token",
    "source":    "curl https://api.example.com/user",
    "prev_hash": "a3f9c2...",
    "hash":      "b7e1d4..."   # SHA-256 of this entry + prev_hash
}

# File permissions enforced on every write
os.chmod(vault_file, 0o600)

# Audit log is append-only (operator may also set chattr +a)
```

### Layer 7 — Script Approval

```python
# Damage scoring — auto-calculated from analyzer.py
RISK_WEIGHTS = {
    'reverse_shell':      10,   # always BLOCKED
    'destructive_ops':     8,   # rm -rf, DROP TABLE, etc.
    'privilege_ops':       7,   # setuid, sudo, etc.
    'shell_spawn':         3,   # os.system, subprocess shell=True
    'outbound_connection': 1,   # requests, socket, etc.
    'file_write':          1,   # open('w'), shutil, etc.
}

# Verdict thresholds
# score >= 10 → BLOCKED (cannot approve)
# score 3–9   → REVIEW  (approval required + warning shown)
# score 0–2   → SAFE    (approval still required — always ask)
```

The flow is **two-step** (`request_script_approval` → operator decides →
`confirm_script_execution(approved=…)`) so approval cannot be silently
inferred. The script is re-analyzed at confirm time as defence in depth.

### Layer 8 — Output & Rate Limits

```python
MAX_OUTPUT_LINES = 50
MAX_OUTPUT_BYTES = 8_000   # ~2000 tokens

# Per-tool TOOL_RATE_LIMIT — passed to the tool natively (req/sec):
#   httpx -rate-limit, ffuf -rate, feroxbuster --rate-limit,
#   nuclei -rate-limit, dalfox --delay
TOOL_RATE_LIMIT = 5        # Most programs allow 5–10/sec — stay polite

# Per-tool MCP-side cooldown (seconds between successive MCP invocations):
RATE_LIMITS = {
    'subfinder':   0.2,  'amass':       0.2,  'assetfinder': 0.2,
    'nmap':        5.0,                       # nmap is heavy
    'httpx':       0.2,
    'feroxbuster': 0.2,  'ffuf':        0.2,  'katana':      0.2,
    'nuclei':      0.2,  'sqlmap':      0.2,  'dalfox':      0.2,
    'curl':        0.2,  'default':     0.2,
}

# Truncated output tells Claude where the full file is
# so it can use grep_file() for specific lookups
```

### Layer 9 — Forbidden Payload Patterns

Blocked at the executor *regardless* of allowlist/approval:

```python
FORBIDDEN_PAYLOAD_PATTERNS = [
    DROP (TABLE|DATABASE|SCHEMA),
    DELETE FROM,
    TRUNCATE TABLE,
    rm -rf,
    shutdown, mkfs, dd if=,
    wget|sh,  curl|sh,
    /dev/tcp,  nc -e,  bash -i,
    python -c "import socket",
]
```

### Layer 10 — Dependency Security

```bash
# Dependencies pinned in requirements.txt
pip install -r requirements.txt

# setup.sh runs pip-audit if available
pip-audit -r requirements.txt
```

### Layer 11 — Report Signing (Optional)

```bash
# Sign sanitized report before submission
gpg --armor --sign --detach-sign findings/<id>/report.md

# Triager can verify with operator's public key
gpg --verify report.md.sig report.md
```

### Layer 12 — Severity Gate (Impact-Only Mission)

```python
MIN_REPORT_SEVERITY = {'high', 'critical', 'exceptional'}

# create_report rejects findings below the threshold unless
# force=True is explicitly passed. Bug bounty mission is high-impact only:
# Low/Medium findings burn time without paying out.
```

When the gate trips, the response is a clear error directing the operator
to either pivot to higher-impact targets or, if they really want to submit a
low-severity finding, re-call with `force=True` after explicit confirmation.

### Layer 13 — Hook Architecture (Claude Code-side)

Three coordinated hooks that wrap the MCP server:

| Hook | When it fires | What it does |
|------|---------------|--------------|
| `UserPromptSubmit` → `autoload-skills.sh` | Once per session, on first prompt | Injects the skill + reference index with one-line purpose for each — primes Claude with what's available |
| `PreToolUse` → `pre-tool-confirm.sh` | Before every target-touching MCP tool call | Forces an approval prompt with structured summary (tool, program, target, args, ⚠ active-scanner notice). Local-only tools (`consult_skill`, `vault_lookup`, `save_note`, etc.) are NOT gated |
| `PostToolUse` → `skill-context-trigger.sh` | After every tool call | Scans output + input for context signals (cloud, smart-contract, payload tool, CVSS, CWE, etc.) and injects skill/reference load instructions when matches appear. Each trigger fires once per session |

Each gate is independently disable-able (`BB_NO_PRE_CONFIRM=1` env var for the
confirmation gate) so heavy manual sessions can opt out.

---

## Skill Plug-in Model (Bring Your Own Skills)

This server is designed to **work alongside Claude Code skills, not bundle
them.** Skills are third-party — written by the security community and the
operator's own additions. Drop any compatible skill into `~/.claude/skills/`
and the trigger hooks pick it up automatically.

### Compatible skill areas (examples)

The trigger hooks recognize the following skill areas. Any pack — community,
vendor, or your own — that fits the area works once dropped into
`~/.claude/skills/`. Operators source skills from wherever they prefer.

| Skill area | What it covers |
|------------|----------------|
| Web app code review | OWASP Top 10 / ASVS-style checklists, auth/authz, input handling |
| Cloud attack surface | AWS / Azure / GCP — SSRF→metadata, bucket misconfig, IAM |
| UI / browser flow testing | Headless browser-driven SPA testing |
| Smart contract audit | Solidity static analysis + audit workflow |
| Malware detection rule authoring | YARA-style rule writing |
| Static code analysis | SARIF-emitting analyzers |
| Dependency hygiene | Advisory checks + automated remediation |
| Wordlists & payload variants | Injection corpus, fuzzing inputs |
| Pentest playbooks | CTF / generic web pentest checklists |

The **trigger hook** maps context signals → skill name. Adding a new skill
is two changes: drop the file, add a trigger pattern.

### Trigger Map (skill ↔ context)

| Context signal | Auto-loads |
|----------------|------------|
| AWS / Azure / GCP signal in tool output | `cloud-security` |
| Solidity / contract context | `secure-contracts` |
| YARA rule context (`rule X {`) | `yara-authoring` |
| Playwright / browser flow | `webapp-testing` |
| nuclei / dalfox / sqlmap finding output | `awesome-security` |
| `CVSS:3.x/AV:` vector drafted | `reference/cvss_guide` |
| `CWE-###` | `reference/cwe_map` |
| `<script>`, `' OR 1=1`, `UNION SELECT`, `SLEEP()`, `{{7*7}}` | `reference/payloads` |
| Scanner invocation drafted | `reference/tools` |
| `create_report` invoked | platform-specific bundle (see below) |

---

## Platform-Aware Report Routing

Each program brief includes a `Platform:` line (Intigriti / Bugcrowd /
HackerOne). When `create_report` fires, the PostToolUse hook reads the
brief, identifies the platform, and injects the platform-specific report
bundle.

```
Platform: Intigriti  → reference/intigriti_taxonomy.md
Platform: Bugcrowd   → reference/bugcrowd_vrt.md
Platform: HackerOne  → reference/hackerone_taxonomy.md

Plus always:
  reference/report_template.md   (universal template)
  reference/cvss_guide.md        (CVSS 3.1 vectors)
  reference/cwe_map.md           (vuln type → CWE)
```

If a program brief omits the `Platform:` line or names an unsupported
platform, the hook emits a warning prompting the operator to fix the brief
before submission.

---

## Script Approval — What the Operator Sees

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SCRIPT APPROVAL REQUEST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Script:    email_enum.py
 Requested: <timestamp>

 WHY the AI wants to run it:
   "Enumerate valid accounts on api.example.com
    to confirm IDOR affects real user IDs."

 WHAT IT DOES (auto-analyzed):
   - Sends HTTP GET requests to /api/user/{id}
   - Reads wordlist from /usr/share/wordlists/
   - Writes results to /tmp/bb_working/
   - No shell spawning detected
   - No reverse connection detected
   - No destructive operations detected

 WHAT YOU WILL SEE:
   - List of accessible user IDs (count only to AI)
   - Actual values stored in vault automatically

 RISK ANALYSIS:
   Network calls:       YES → api.example.com only
   File writes:         YES → /tmp/bb_working/
   Shell spawn:         NO
   Reverse connection:  NO
   Destructive ops:     NO
   Damage score:        1 / 10

 AUTO-VERDICT: ✅ SAFE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Approve? [y/N]:
```

Blocked example:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SCRIPT APPROVAL REQUEST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Script:    reverse_shell.py

 AUTO-VERDICT: 🚫 BLOCKED
 Reason: Reverse shell pattern detected.
         Out of scope for bug bounty methodology.
         Read-only reference — cannot be executed
         by the MCP server under any circumstances.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Pre-Tool Confirmation — What the Operator Sees

For every target-touching tool call (curl, httpx, nuclei, sqlmap, dalfox,
ffuf, feroxbuster, katana, nmap, whatweb, plus passive recon):

```
═══════ PRE-TOOL CONFIRMATION ═══════
Tool:     run_curl
Program:  <program-name>
Target:   https://api.example.com/v1/users/42
Args:
  method: GET
  headers: ["X-Bug-Bounty: <handle>"]
Approve to send. Cancel to revise.
═════════════════════════════════════
```

For active scanners (nuclei, sqlmap, dalfox, ffuf, feroxbuster) an extra
warning appears:

```
⚠ ACTIVE SCANNER — confirm program permits automated scanning
  (rate-capped to 5 rps server-side).
```

For sqlmap specifically:

```
⚠ sqlmap — destructive flags blocked; detection-only mode.
```

Local-only tools (`consult_skill`, `vault_lookup`, `save_note`, `grep_file`,
`read_filtered`, `check_scope`, `create_report`, `verify_audit_log`,
`request_script_approval`, `confirm_script_execution`) are NOT gated — they
fire per the existing permission allowlist.

---

## End-to-End Workflow

### Step 0 — Session Start

```bash
# Terminal 1: start MCP server (or let Claude Code launch via .mcp.json)
./start.sh
# → Sandbox active (if firejail), vault ready

# Terminal 2: start Claude Code
cd ~/path/to/project && claude
```

The `UserPromptSubmit` hook fires on the first prompt and injects the skill
+ reference index. Claude is now primed with what's available.

### Step 1 — Program Setup

```
Operator: "New program — Acme, Intigriti, scope is *.acme.example"
AI: Creates programs/acme/ structure
    Fills brief.md with scope (incl. "Platform: Intigriti" line)
    Confirms scope with operator
```

### Step 2 — Phase 1: Recon

```
AI proposes each command before running.
Pre-tool confirmation prompt appears for each target-touching call:

  ═══════ PRE-TOOL CONFIRMATION ═══════
  Tool:     run_subfinder
  Program:  acme
  Target:   acme.example
  ═════════════════════════════════════

Operator approves → MCP server runs → sanitized output returned.
PostToolUse may inject skill triggers (e.g., cloud-security if S3 buckets
appear in output).
AI checkpoints to notes.md after each command.
```

### Step 3 — Phase 1 → Phase 2 Transition

```
AI presents attack surface:
  - Subdomains alive: 12/47
  - Interesting: api.*, admin.*, dev.*
  - Proposed targets ranked by likely vulnerability

Operator approves targets → Phase 2 begins
```

### Step 4 — Phase 2: Vulnerability Testing

```
AI proposes each test:

  Pre-tool confirmation:
  ═══════ PRE-TOOL CONFIRMATION ═══════
  Tool:     run_curl
  Program:  acme
  Target:   https://api.acme.example/v1/user/1338
  Args:
    headers: ["Authorization: Bearer <SAFE:bearer:t001>"]
  Approve to send. Cancel to revise.
  ═════════════════════════════════════

MCP server runs curl → sanitizes response:
  Token → vaulted as <SAFE:bearer:t001>
  PII   → vaulted as <SAFE:email:e004>

AI sees: {"email":"<SAFE:email:e004>","id":1338}
         → POTENTIAL IDOR detected
```

### Step 5 — Script Needed

```
AI calls request_script_approval(...)
Operator sees full risk analysis
AI then calls confirm_script_execution(..., approved=True/False)
If approved: re-analyzed, runs sanitized, output vaulted
```

### Step 6 — Finding Confirmed

```
AI presents:
  ID:       ACME-IDOR-001
  Type:     IDOR
  Location: GET /v1/user/{id}
  Severity: High (estimated)
  PoC:      ready

Finding directory created automatically:
  programs/acme/findings/ACME-IDOR-001/
    poc/      repro.sh (sanitized, <SAFE:bearer:t001>)
    evidence/ response.txt (sanitized)

Full version written locally (chmod 600):
  ~/.<vault-dir>/acme/findings/ACME-IDOR-001/
    report_full.md  (real values via vault substitution)
    repro_full.sh   (working curl with real token)
```

### Step 7 — Phase 3: Report Generation

```
create_report(severity="high", ...) auto-generates both reports.

Severity gate verifies severity ∈ {high, critical, exceptional}:
  → Pass: continue
  → Fail: "ERROR: severity 'low' rejected — bug bounty mission is
          impact-only. Re-call with force=True if you really mean it."

Free-text fields run through sanitize() as a backstop, then:

report.md (sanitized — for platform):
  Title: IDOR on /v1/user/{id} exposes user profiles
  Type:  CWE-639 Insecure Direct Object Reference
         (Broken Access Control)
  CVSS:  7.5 High — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
  PoC:   GET /v1/user/1338
         Authorization: Bearer <SAFE:bearer:t001>
         → 200 OK, returns user profile

report_full.md (local only — operator only):
  Same structure, real values substituted from vault
  chmod 600, never read by AI

PostToolUse fires → reads brief.md → "Platform: Intigriti" detected →
injects: "Mandatory: reference/intigriti_taxonomy.md +
report_template.md + cvss_guide.md + cwe_map.md"
```

### Step 8 — Phase 4: QA Review

```
AI self-checks against the platform-specific QA checklist
(loaded automatically by the report bundle trigger):

  ✓ Asset in scope per brief.md
  ✓ IDOR type accepted by program
  ✓ PoC uses own test accounts only
  ✓ CVSS score matches proven impact
  ✓ CWE-639 correct
  ✓ Steps reproducible in < 5 min
  ✓ No real PII in sanitized report
  ✓ Duplicate risk: Low

VERDICT: ✅ APPROVED — ready to submit
```

### Step 9 — Submission

```
AI presents final sanitized report
Operator copies to platform of choice

If triager asks for full PoC with real values:
  → Use ~/.<vault-dir>/acme/findings/ACME-IDOR-001/repro_full.sh
  → Share only what's needed, redact the rest

tracker.md updated:
  ACME-IDOR-001 | IDOR /v1/user/{id} | High 7.5 | Submitted | <date>
```

---

## What the AI Never Sees

```
✗ Raw sensitive values        — only <SAFE:type:id> tokens
✗ Full file reads             — grep/filtered reads only
✗ Vault contents              — describe() returns type+source only
✗ Full report                 — sanitized version only
✗ Scripts without approval    — two-step flow, always asks first
✗ Anything outside allowed paths
✗ Any tool not on the allowlist
✗ Real PII from target users  — vaulted immediately
✗ Outbound requests without operator confirmation (Layer 13 PreToolUse)
```

---

## Tools Exposed to the AI (as registered in `server.py`)

```
Recon:    run_subfinder  run_amass  run_assetfinder  run_httpx  run_nmap
          run_whatweb    run_dig    run_whois
Web:      run_curl       run_ffuf   run_feroxbuster  run_katana
Vuln:     run_nuclei     run_sqlmap run_dalfox
Utils:    grep_file      read_filtered  count_lines  save_note  list_recon_files
          consult_skill                         ← load skill/ref on demand
Scope:    check_scope                           ← always call first
Scripts:  request_script_approval               ← step 1 of approval
          confirm_script_execution              ← step 2 of approval
Reports:  create_report                         ← dual output, severity-gated
Vault:    vault_lookup                          ← type+source only
Audit:    verify_audit_log                      ← hash-chain integrity
```

---

## Build Phases (status)

```
Phase 1   ✅ core/executor.py + sanitizer.py + scope.py + audit/logger.py
Phase 2   ✅ vault/safe.py — hash chain, chmod 600, append-only
Phase 3   ✅ tools/ — all tool wrappers with rate limiting per tool
Phase 4   ✅ core/analyzer.py + approver.py — two-step approval flow
Phase 5   ✅ reports/generator.py — dual report, token substitution,
              backstop sanitization on free-text inputs
Phase 6   ✅ server.py + config.py — wire everything, register MCP tools
Phase 7   ✅ setup.sh + .mcp.json — install, register with Claude Code
Phase 8   ✅ Severity gate (impact-only mission) + 5 rps default rate limit
Phase 9   ✅ Hook architecture (UserPromptSubmit / PreToolUse / PostToolUse)
              + consult_skill tool + platform-aware report routing
Phase 10  ◻ Hardening — firejail/systemd unit (operator-side, opt-in)
```

---

## Stack

```
Language:    Python 3.10+
MCP SDK:     mcp >= 1.6.0 (FastMCP, official)
Sandbox:     firejail (optional, recommended)
Process:     Operator runs as a low-privilege user (recommended)
Vault:       Flat files, chmod 600, SHA-256 hash chain
Audit log:   Append-only JSONL, hash chain
Hooks:       Bash + Python (stdlib only) — Claude Code-side
Deps:        Pinned + audited with pip-audit
Transport:   stdio (localhost only, no network port)
```

---

*This document contains no personal data, credentials, real targets, or
machine-specific paths. All paths use generic placeholders. The vault
location, project root, and platform alias domains are operator-configurable
via environment variables and `brief.md`.*
