# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-19

Validator-gate release. The biggest change: a server-enforced two-agent
workflow that catches over-stretched hypotheses *before* a report is drafted.
Reporting is no longer a single tool call — it's a four-step pipeline
(`validate_finding` → spawn validator agent → `record_verdict` → `create_report`),
and `create_report` will refuse any submission whose `validator_verdict_id`
does not resolve to an `EXPLOITABLE` verdict in the local verdicts log. The
gate is unconditional; `force=True` does not bypass it.

Three new tools, two new core modules, two new test suites, plus the
licensing work that landed after v0.2.0 was tagged (relicense to
EUPL-1.2 OR AGPL-3.0, DCO, commercial-licensing option, trademark policy).

### Added
- **Validator-agent gate — three new MCP tools** (server.py now exposes 30
  tools, up from 27 in v0.2.0):
  - **`validate_finding(program, hypothesis, target, evidence, proposed_poc)`**
    — re-runs scope check on the target, screens the proposed PoC against
    the forbidden-payload denylist, opens a verdict in `AWAITING` state,
    and returns a `verdict_id` plus a markdown brief. The brief is what
    you feed to a separately-spawned validator agent for an independent
    EXPLOITABLE / THEORETICAL judgment. Hash-chained to the verdicts log.
  - **`record_verdict(verdict_id, verdict, reasoning, validated_poc)`** —
    closes the verdict with the agent's judgment (`EXPLOITABLE` or
    `THEORETICAL`) and its safe PoC. Hash-chained.
  - **`verify_verdicts_log(program)`** — replays the hash chain on the
    per-program verdicts ledger and reports any tampering. Mirrors the
    audit-log verifier added in v0.1.0.
- **`server/core/verdicts.py`** — verdicts ledger: append-only JSON-Lines,
  SHA-256 hash chain, `AWAITING → EXPLOITABLE | THEORETICAL` state machine,
  resolution helpers used by `create_report` to enforce the gate.
- **`server/core/validator_brief.py`** — generates the markdown brief the
  validator agent receives. The brief embeds the burden-of-proof clause
  (payload-variant exhaustion + bypass-technique exhaustion + endpoint/
  auth-state exhaustion) so an under-justified THEORETICAL verdict gets
  caught and re-spawned rather than killing a real lead.
- **`server/test_validator_gate.py`** — 196 lines covering the gate
  end-to-end: AWAITING enforcement, EXPLOITABLE-only acceptance,
  THEORETICAL rejection, force-bypass refusal, verdict-id resolution
  failures.
- **`server/test_verdicts.py`** — 185 lines covering the verdicts module
  directly: state transitions, hash-chain continuity, tamper detection,
  per-program isolation.

### Changed
- **`create_report` requires `validator_verdict_id`** — the parameter is
  now mandatory for any submission. The tool resolves it against the
  per-program verdicts log; only `EXPLOITABLE` verdicts pass. Missing,
  unknown, mismatched-program, AWAITING-state, or THEORETICAL verdict
  IDs all refuse, with a clear error pointing to the validator workflow.
  `force=True` continues to bypass the severity floor (Medium+) but
  **does not** bypass the validator gate.
- **`server/launch.sh`** — firejail whitelist extended to include
  `~/go/bin` (read-only) so ProjectDiscovery binaries (`httpx`, `nuclei`,
  `katana`, `subfinder`) installed via `go install` remain executable
  inside the sandbox. Existing installs continue to work; this only
  matters if your binaries live under `~/go/bin` rather than
  `/usr/local/bin`.
- **Validator brief routing in the autoloader hook** — when
  `validate_finding` fires, the hook surfaces the validator-agent
  spawn instructions alongside the brief text, so the operator sees
  the full four-step protocol inline.

### Licensing & governance (carried over from post-v0.2.0 work)
- **Relicensed from MIT to EUPL-1.2 OR AGPL-3.0** (dual-license, recipient
  picks). Both are strong copyleft with a network-use clause: running a
  modified version as a hosted service obliges the operator to make the
  source of those modifications available to its users. This is deliberate
  — bb-mcp-server is a security tool, and the project does not want forks
  re-emerging as closed-source SaaS. Versions 0.2.0 and earlier remain
  available under MIT for anyone who downloaded them under those terms;
  the relicense applies to all future commits and releases.
- **`DCO.md`** — Developer Certificate of Origin v1.1 (Linux Foundation).
  Every contribution from now on requires a `Signed-off-by:` trailer
  matching the commit author.
- **`.github/workflows/dco.yml`** — CI check that blocks PRs whose
  commits are missing or have mismatched `Signed-off-by:` trailers.
- **`COMMERCIAL.md`** — commercial-licence option for organisations
  that cannot use AGPL / copyleft network-use clauses. Same code,
  proprietary terms, contact for a quote.
- **`TRADEMARK.md`** — explicit name / wordmark policy. Forks and
  derivatives must rename; the licences cover the code, not the name.
- **`CONTRIBUTING.md`** — added DCO sign-off section + commercial-licensing
  note (contributors accept that their DCO-signed contributions can be
  included in commercial dual-licensing).
- **`README.md`** — added "Why this licence" rationale, commercial
  licensing summary, trademark summary, and contributing pointer.
- Added `LICENSE-AGPL-3.0` (canonical GNU text); replaced `LICENSE` with
  the canonical EUPL-1.2 text from the European Commission.
- Added `# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0` headers to all
  Python source files in `server/`.
- Updated `README.md`, `CONTRIBUTING.md`, and `SECURITY.md` to reflect the
  new licence terms.

### Compatibility
- **`create_report` callers must update.** Code that previously called
  `create_report(...)` without a `validator_verdict_id` will now fail
  with a structured error. The full four-step flow is the only supported
  path. There is no migration shim — the gate exists precisely to prevent
  unverified submissions.
- All existing v0.2.0 tools continue to work unchanged. The validator
  gate is additive: it sits in front of `create_report` and does not
  affect the recon / web / vuln tool surface.
- Sanitizer, vault, audit log, scope gate, circuit breaker, rate caps,
  and firejail wrapper are unchanged from v0.2.0.

## [0.2.0] - 2026-05-07

Hardening release. Three layers added on top of v0.1.0: a global outbound
rate ceiling, optional firejail sandboxing of the MCP process, and a
hard-block deny list that prevents Claude from bypassing the MCP via raw
`Bash` invocations of the wrapped tools.

### Added
- **Global rate ceiling — `GLOBAL_RATE_LIMIT = 5` req/sec across ALL
  bb-hunter tools** (every zone, every program, every concurrent
  invocation). Implemented as a token bucket persisted to
  `/tmp/bb_global_rate.json` so it survives MCP process restarts within
  the 1-second window. Enforced inside `core/executor.run()` for every
  network-tool launch via the new `circuit_breaker.acquire_global_budget()`.
  Single-shot tools reserve 1 token; fan-out tools (nuclei, ffuf, sqlmap,
  etc.) reserve 2. Saturation blocks the launch up to `GLOBAL_BUDGET_MAX_WAIT`
  seconds (default 10), then refuses with a clear error.
- **`server/core/circuit_breaker.py`** — new module providing three throttle
  layers as a library:
  - Per-host 429 breaker — once a host returns 429, refuse further requests
    to that host *and* its parent zone for `COOLDOWN_AFTER_429` seconds
    (default 300). Persisted across process restarts.
  - Per-zone aggregate cap — `SAFE_RATE_PER_ZONE` (default 5) requests/sec
    across all bb-hunter tools to a single zone. Trailing 1-second window.
  - Global cap (above).
  Plus `detect_throttle_in_response()` to inspect raw curl `-si` output for
  429 / 503 / Retry-After headers.
- **Optional firejail sandboxing** — `server/launch.sh` (new) wraps the MCP
  process with `--caps.drop=all --nonewprivs --seccomp --private-dev` and a
  filesystem whitelist narrowed to `BB_ROOT`, `BB_VAULT`, `BB_SCRIPTS`
  (read-only), the skills dir (read-only), and the pip user-site (read-only).
  Network access is preserved — the server has to launch curl/nmap/etc.
  Falls back to plain `python3` if firejail is missing.
- **Bash bypass deny list** — `settings.example.json` now hard-blocks direct
  `Bash(<tool>:*)` invocations of every tool the MCP wraps plus common
  alternates (33 entries: curl, wget, subfinder, amass, assetfinder, httpx,
  nmap, masscan, rustscan, naabu, whatweb, wappalyzer, dig, whois, host,
  nslookup, ffuf, feroxbuster, gobuster, dirb, dirsearch, katana, gospider,
  hakrawler, waybackurls, gau, nuclei, sqlmap, dalfox, xsstrike, nikto,
  wpscan, testssl, sslscan). Forces every target-touching operation through
  `mcp__bb-hunter__*` — which means scope check, sanitization, vault, audit
  log, and the global rate cap. Individual entries can be removed for
  legitimate non-target uses.
- **Pre-flight smoke test** — `server/setup.sh` now runs
  `python3 -c "import config, server"` before completing, so syntax errors
  in `config.py` or `server.py` fail fast at install time instead of on the
  first tool call.
- **CHANGELOG entries from prior unreleased work** — SSH-based commit
  signing, CodeQL static analysis workflow, branch protection on `main`,
  repository security features (secret scanning, push protection, Dependabot
  alerts and updates), and `CHANGELOG.md` itself.

### Changed
- **Tightened default rate limits.** `TOOL_RATE_LIMIT` lowered from 5 to 2
  req/sec, and `SAFE_RATE_PER_ZONE` set to 2 req/sec to match. Rationale:
  CDN/WAF aggregate per-zone limits (Cloudflare, Akamai) are usually lower
  than the per-app stated limit, and a single 429 risks an IP ban. Programs
  that explicitly allow higher rates can override per-program. Comment on
  the constant marks 3 req/sec as the upper bound that should not be raised
  without operator review.
- **`.mcp.example.json`** — `command` now points to `server/launch.sh` so
  Claude Code spawns the server through the firejail wrapper. Existing
  installs that have already copied to `.mcp.json` should re-copy.
- **`server/setup.sh`** — corrected the misleading `firejail --net=none`
  advice from v0.1.0. `--net=none` would have broken the server (every tool
  needs outbound network); the launcher uses filesystem + capability
  isolation only. Setup also now `chmod 750`'s `launch.sh` and registers
  Claude Code with the launcher path instead of plain `python3`.
- **`server/requirements.txt`** — `mcp>=1.6.0` → `mcp>=1.6.0,<2.0.0` to
  prevent surprise major-version upgrades.
- **Generalized third-party skill references** in `README.md` and
  `ARCHITECTURE.md`. The harness is skill-pack agnostic; specific pack
  names removed in favour of skill-area descriptions. (Carried over from
  prior unreleased work.)

### Fixed
- **`server/setup.sh` printed an unrunnable command** as the
  recommended sandboxing invocation. The `firejail --noprofile --net=none`
  command was repeated twice in the output and would have left the server
  unable to make any outbound request. Replaced with the launcher path.

### Security
- The Bash bypass deny list closes a previously implicit assumption: that
  Claude would *prefer* `mcp__bb-hunter__*` over raw `Bash`. With v0.1.0
  there was no enforcement — an agent could route around scope checks,
  sanitization, the vault, the audit log, and rate limits by reaching for
  `Bash curl` instead. v0.2.0 makes the MCP path the only path.
- The global rate cap closes a related gap: even with all calls going
  through the MCP, two concurrent fan-out scans against different
  programs could collectively exceed the per-tool limit. The cap is a
  hard ceiling regardless of how many tools are running.

### Compatibility
- All 41 unit tests pass against v0.2.0.
- Existing `.mcp.json` files keep working but lose firejail isolation
  until they re-copy from the new example. The legacy `python3 server.py`
  path is still functional.
- `core/circuit_breaker.py` is wired into `executor.run()` for the global
  cap only. The per-host breaker and per-zone aggregate cap are exposed
  as a library so tool wrappers can opt in; v0.2.0 does not auto-enable
  them. Tool authors can integrate by calling `cb.is_tripped()`,
  `cb.aggregate_rate_check()`, and `cb.record_request()` from their
  wrappers — see `circuit_breaker.py` docstrings.

## [0.1.0] - 2026-05-05

Initial public release.

### Added
- **MCP server (`server/`):** 27 tools across recon, web testing, vuln
  testing, vault operations, scope checking, two-step script approval,
  on-demand skill loading (`consult_skill`), and dual-output report
  generation.
- **60+ sanitization patterns** covering auth headers (Bearer/Basic/Token),
  cookies, SaaS tokens (GitHub/Slack/Stripe/Twilio/SendGrid/Mailgun/
  DigitalOcean/npm/Discord/Telegram), AWS/Azure/GCP credentials,
  cryptographic material (private keys, JWTs, ASP.NET Data Protection
  blobs, AES/HMAC keys), DB connection strings with embedded creds,
  PII (names, emails by tier, phone numbers), CTF flags, observability
  DSNs, third-party SDK keys.
- **Vault** (`server/vault/`) — hash-chained, `chmod 600`, append-only.
- **Audit log** (`server/audit/`) — append-only with SHA-256 hash chain,
  tamper-evident.
- **Dual-output report generator** (`server/reports/`) — produces a
  sanitized report (chat-safe, with `<SAFE:type:id>` tokens) and a
  full report (local-only, with real values substituted from the vault).
- **Severity gate** on `create_report` — rejects findings below High
  unless `force=True` is explicitly passed.
- **Three Claude Code hooks** (`hooks/`):
  - `UserPromptSubmit` autoloader injects skill + reference index at
    session start.
  - `PreToolUse` confirmation gate forces an approval prompt on every
    target-touching tool with a structured summary of what's about to
    fire. Local-only tools are not gated.
  - `PostToolUse` context trigger auto-injects skill / reference loads
    when context signals appear (cloud asset → cloud-security skill,
    Solidity → secure-contracts, CVSS vector → cvss_guide, etc.). Each
    trigger fires once per session.
- **Platform-aware report routing** — when `create_report` fires, the
  hook reads the program's `brief.md`, identifies the platform
  (Intigriti / Bugcrowd / HackerOne), and injects the matching
  taxonomy reference plus the universal report template, CVSS guide,
  and CWE map.
- **Reference templates** (`reference-templates/`): payloads, tools,
  CVSS guide, CWE map, universal report template, Intigriti taxonomy,
  Bugcrowd VRT (v1.18, March 2026), HackerOne field reference.
- **13 security layers** — see `ARCHITECTURE.md`.
- **Tests** — 41 unit tests + 30 integration tests, all green.

### Security
- The masking strategy in `core/sanitizer.py` was found to leak existing
  `<SAFE:...>` tokens to re-vaulting via greedy-match patterns. Fixed by
  removing the broken mask layer and adding `(?!<SAFE:)` negative
  lookaheads to all greedy value matchers (auth headers, AWS secret
  fields, cookie values, JSON-quoted bearer/token values, JSON-keyed
  PII names, DB connection-string passwords). Discovered and fixed
  pre-publication.

[Unreleased]: https://github.com/D24yK4r4/bb-mcp-server/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/D24yK4r4/bb-mcp-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/D24yK4r4/bb-mcp-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/D24yK4r4/bb-mcp-server/releases/tag/v0.1.0
