# bb-mcp-server

A privacy-first MCP server for bug bounty hunting with Claude Code.

**One core principle:** sensitive data never reaches the AI.

```
Tool runs → Sanitization layer → AI model
                ↓
         Real values stored locally only
         (vault on disk, chmod 600, hash-chained)
```

The AI only ever sees `<SAFE:type:id>` tokens. Real cookies, bearer tokens,
API keys, PII, and findings stay on your machine. The server enforces scope,
rate-limits outbound traffic to 5 rps by default, and gates report submission
to High / Critical / Exceptional severity (the bug bounty mission is
impact-only).

---

## What you get

- **30 MCP tools** for recon (subfinder, amass, httpx, nmap, …), web testing
  (curl, ffuf, feroxbuster, katana), vuln testing (nuclei, sqlmap, dalfox),
  vault lookup, on-demand skill loading, and dual-output report generation.
- **Validator-agent gate** (`validate_finding` → spawn validator → `record_verdict`
  → `create_report`). A finding cannot be submitted until a separate agent
  has independently judged it `EXPLOITABLE` against a structured brief; the
  verdict is hash-chained to a per-program ledger and resolved server-side
  at report time. `force=True` does not bypass the gate.
- **A 60+ pattern sanitizer** that vaults bearer tokens, cookies, JWTs, AWS /
  Azure / GCP creds, SaaS keys (GitHub, Slack, Stripe, Twilio, SendGrid, …),
  PII (names, emails by tier, phone numbers), DB connection strings, private
  keys, and more — all hash-chained to detect tampering.
- **Three Claude Code hooks** that wrap the server:
  - `UserPromptSubmit` — auto-loads compatible skills + reference files at
    session start, with one-line purpose blurbs so the AI knows what to reach
    for.
  - `PreToolUse` — forces an approval prompt for every target-touching tool
    call, with a structured summary (tool, program, target, args). Active
    scanners get an extra warning.
  - `PostToolUse` — auto-injects skill / reference loads when context signals
    appear in tool output (cloud asset → cloud-security skill, Solidity →
    secure-contracts, CVSS vector → cvss_guide, etc.). Each trigger fires
    once per session.
- **Platform-aware report routing.** When `create_report` runs, the hook
  reads the program's `brief.md`, identifies the platform (Intigriti /
  Bugcrowd / HackerOne), and injects the matching taxonomy reference plus
  the universal report template, CVSS guide, and CWE map.
- **Two-step script approval** with AST + regex analysis, damage scoring,
  and a hard block list (reverse shells, webshells, exfil tools).
- **Dual-output reporting**: a sanitized chat-safe `report.md` for Claude
  and the platform; a `report_full.md` with real values via vault
  substitution, written `chmod 600` and never visible to the AI.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design.

---

## Quickstart

### Prerequisites

- Python 3.10+
- Claude Code (latest)
- The standard bug bounty toolchain on `$PATH`: `subfinder`, `amass`,
  `assetfinder`, `httpx`, `nmap`, `whatweb`, `dig`, `whois`, `curl`, `ffuf`,
  `feroxbuster`, `katana`, `nuclei`, `sqlmap`, `dalfox`
- Optional: `firejail` for sandbox isolation

### Install

```bash
git clone https://github.com/<your-handle>/bb-mcp-server.git
cd bb-mcp-server

# Server deps
pip install -r server/requirements.txt

# Pick a workspace + vault location
export BB_ROOT="$HOME/Documents/BugBounty"
export BB_VAULT="$HOME/.bb-vault"
mkdir -p "$BB_ROOT" "$BB_VAULT"
chmod 700 "$BB_VAULT"

# Drop reference templates into your workspace
cp -r reference-templates "$BB_ROOT/reference"

# Wire up Claude Code
mkdir -p "$BB_ROOT/.claude"
cp settings.example.json "$BB_ROOT/.claude/settings.json"
cp .mcp.example.json     "$BB_ROOT/.mcp.json"
# Edit both files to use absolute paths to bb-mcp-server/

# Make hooks executable
chmod +x hooks/*.sh
```

### Bring your own skills (BYOS)

This server is designed to **work alongside** Claude Code skills, not bundle
them. The trigger hooks pick up any skill dropped into `~/.claude/skills/`.

Skill areas you might want to plug in (any source — community packs,
vendor releases, your own — all work the same once they're in the skills
directory):

| Skill area | Use when |
|------------|----------|
| Web app code review | Auditing application code against OWASP Top 10 / ASVS-style checklists |
| Cloud attack surface | Target on AWS / Azure / GCP — SSRF→metadata, bucket misconfig, IAM |
| UI / browser flow testing | Driving an SPA via headless browser |
| Smart contract audit | Solidity static analysis + audit workflow |
| Malware detection rule authoring | Writing YARA-style rules |
| Static code analysis | SARIF-emitting analyzers |
| Dependency hygiene | Pinning, advisory checks, automated remediation |
| Wordlists & payload variants | Injection corpus, fuzzing inputs |
| Pentest playbooks | CTF / generic web pentest checklists |

The trigger map (which skill loads on which signal) is configured in
[`hooks/skill-context-trigger.sh`](hooks/skill-context-trigger.sh) — extend
it for your own skills.

### First session

```bash
cd "$BB_ROOT"
claude
```

Claude Code reads `.mcp.json`, launches the bb-hunter MCP server, and the
`UserPromptSubmit` hook injects the skill + reference index on your first
prompt. From there:

1. **Set up a program**: tell Claude the program name, platform, scope. It
   creates `programs/<name>/` with a `brief.md` from
   [`examples/program-brief.template.md`](examples/program-brief.template.md).
2. **Phase 1 (Recon)**: Claude proposes commands. Each target-touching tool
   call shows you the structured pre-tool confirmation. You approve.
3. **Phase 2 (Vuln Discovery)**: same gating; outputs are sanitized and
   vaulted; cloud / contract / browser context auto-loads the matching skill.
4. **Phase 3 (Reporting)**: `create_report` rejects severity below High
   unless you explicitly pass `force=True`. The platform-specific taxonomy
   + report template + CVSS / CWE refs are auto-loaded by the hook.
5. **Phase 4 (QA)**: Claude self-checks against the platform-specific QA
   list. You read the sanitized report. If approved, copy-paste to the
   platform.

---

## Repository layout

```
bb-mcp-server/
├── README.md                  ← this file
├── ARCHITECTURE.md            ← full design + data flow + security layers
├── LICENSE                    ← EUPL-1.2 (primary)
├── LICENSE-AGPL-3.0           ← AGPL-3.0 (alternative, at your option)
├── COMMERCIAL.md              ← commercial-licence option for orgs that can't use copyleft
├── TRADEMARK.md               ← name / wordmark policy (separate from code licence)
├── DCO.md                     ← Developer Certificate of Origin (contribution sign-off)
│
├── server/                    ← the MCP server (Python)
│   ├── server.py              ← FastMCP entry point + tool registration
│   ├── config.py              ← allowlists, paths, redaction patterns, limits
│   ├── core/                  ← executor, sanitizer, scope, approver, analyzer
│   ├── tools/                 ← recon, web, vuln, utils tool wrappers
│   ├── vault/                 ← hash-chained, chmod-600 vault writer
│   ├── audit/                 ← append-only audit log
│   ├── reports/               ← dual-output report generator
│   ├── requirements.txt
│   ├── setup.sh
│   └── test_*.py              ← unit + integration tests
│
├── hooks/                     ← Claude Code-side glue
│   ├── autoload-skills.sh
│   ├── pre-tool-confirm.sh
│   └── skill-context-trigger.sh
│
├── reference-templates/       ← drop into your workspace's reference/
│   ├── payloads.md
│   ├── tools.md
│   ├── cvss_guide.md
│   ├── cwe_map.md
│   ├── report_template.md
│   ├── intigriti_taxonomy.md
│   ├── bugcrowd_vrt.md
│   └── hackerone_taxonomy.md
│
├── examples/
│   └── program-brief.template.md
│
├── .mcp.example.json          ← Claude Code MCP registration
└── settings.example.json      ← Claude Code project settings (hooks + perms)
```

---

## Security model

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full breakdown. In short, 13
layers stack on top of each other:

1. Process isolation (firejail / systemd hardening, opt-in)
2. Filesystem least privilege (explicit read / write allowlists)
3. Tool allowlist + block list (no shells, no package managers, no SSH)
4. Argument validation (no shell metacharacters, no null bytes, no traversal)
5. 60+ sanitization patterns (auth headers, SaaS tokens, cloud creds, PII)
6. Vault integrity (SHA-256 hash chain, chmod 600, append-only)
7. Two-step script approval with AST analysis
8. Output + rate limits (50 lines / 8 KB output cap; 5 rps default)
9. Forbidden payload patterns (DROP, rm -rf, reverse shells, etc.)
10. Pinned deps + pip-audit
11. GPG report signing (optional)
12. Severity gate on `create_report` (impact-only mission)
13. Hook architecture (pre/post tool, prompt-submit) — context-aware skill
    loading + per-tool confirmation

---

## What this is NOT

- **Not a scanner.** It's a sanitizing wrapper around scanners.
- **Not a replacement for skills.** Skills (third-party) bring the testing
  knowledge. This server brings the safety + workflow rails.
- **Not autonomous.** Every target-touching call is gated by an operator
  approval. The AI proposes; the operator decides.
- **Not for unauthorized testing.** Scope is enforced from `brief.md` —
  out-of-scope = blocked.

---

## License

Dual-licensed under either of:

- **[European Union Public Licence v1.2](LICENSE)** (EUPL-1.2) — primary
- **[GNU Affero General Public License v3.0](LICENSE-AGPL-3.0)** (AGPL-3.0) — alternative

at your option. Both are strong copyleft licences with a network-use clause:
running a modified version as a hosted service obliges you to make the source
of your modifications available to the users of that service.

Source files carry the SPDX header
`# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0`.

### Why this licence and not MIT / Apache / GPLv3

bb-mcp-server was originally MIT, and was relicensed in 2026-05. Four reasons:

1. **It closes the SaaS loophole.** MIT lets a company take the code,
   modify it, and never share back — including running it as a hosted
   service. GPLv3 has the same problem: it only triggers on
   *distribution*, not on network use. EUPL-1.2 (Article 13) and
   AGPL-3.0 (Section 13) both treat "communication to the public" /
   network use as triggering source disclosure. For an MCP **server** —
   something explicitly designed to be run as a service — closing this
   loophole is the whole point.
2. **It matches the project's jurisdiction.** EUPL-1.2 is drafted in EU
   legal language, has 23 official translations all legally equivalent,
   and references EU law for warranty / liability — so an EU court
   doesn't have to translate or reinterpret US-style "AS-IS"
   boilerplate. AGPL-3.0 is the global fallback for users outside the
   EU who find EUPL unfamiliar.
3. **It protects the work as a security tool.** A bug-bounty MCP server
   is exactly the kind of code that gets vendored into commercial
   pentest platforms. Without copyleft, hardening work (rate caps,
   scope checks, vault, audit log, validator gate) can be silently
   absorbed into a closed product, and the next operator never sees the
   safety improvements made downstream. Copyleft + network clause means
   anyone running a modified bb-mcp-server has to expose their
   modifications — defenders win, gatekeepers don't.
4. **Dual licensing keeps it adoptable.** EUPL-1.2's Appendix
   explicitly lists AGPL-3.0, GPL-2.0/3.0, MPL-2.0, OSL, EPL and others
   as compatible, so derivative works can be relicensed without
   dead-ends. AGPL-3.0 is what many security tools already use (MISP,
   OpenCTI, BloodHound CE, parts of OWASP ZAP), so it's familiar to
   security-focused contributors. Offering both lets a contributor or
   downstream project pick whichever fits their stack.

**The honest tradeoff:** a small fraction of corporate users won't touch
AGPL / EUPL because their internal legal policy bans copyleft network-use
clauses (Google famously bans AGPL internally; many startups follow).
That adoption is intentionally given up — those are the same orgs most
likely to absorb the code into a closed product. MIT optimised for
adoption-at-any-cost; EUPL / AGPL optimises for *"the people who use this
share back."*

### Backwards compatibility for previous downloaders

bb-mcp-server v0.2.0 and earlier were released under the MIT licence.
Anyone who obtained those versions retains the MIT licence on those
copies indefinitely — the relicence applies only to commits and
releases dated 2026-05-09 or later. You don't need to re-licence or
re-download anything you already had.

### Commercial licensing

If your organisation cannot use AGPL or copyleft network-use clauses
for legal or policy reasons, a **commercial licence** is available.
Same code, same release stream, proprietary terms in place of
EUPL-1.2 / AGPL-3.0. See [`COMMERCIAL.md`](COMMERCIAL.md) for details
and contact information.

### Trademark

The name "bb-mcp-server" is a trademark of the project author. Forks
and derivatives must rename — see [`TRADEMARK.md`](TRADEMARK.md). The
licences cover the code; the trademark policy covers the name.

### Contributing

All contributions require a `Signed-off-by:` trailer
([Developer Certificate of Origin](DCO.md)). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full process and the
DCO sign-off rules.

---

## Acknowledgements

- All Claude Code skills are third-party. This server is just the harness
  around them — install the packs you need separately, and check each
  pack's license before redistributing.
- The Bugcrowd VRT (in `reference-templates/bugcrowd_vrt.md`) is sourced from
  the public taxonomy at <https://bugcrowd.com/vulnerability-rating-taxonomy>.
- HackerOne and Intigriti report field references are derived from the
  public submission UIs; check both platforms for current authoritative
  copies before submitting.
