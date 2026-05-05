# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SSH-based commit signing for all commits going forward.
- CodeQL static analysis workflow on push, PR, and weekly schedule.
- Branch protection on `main`: force-push and deletion blocked, linear
  history required.
- Repository security features: secret scanning, push protection,
  Dependabot vulnerability alerts, Dependabot automated security updates.
- `CHANGELOG.md` (this file).

### Changed
- Generalized third-party skill references in `README.md` and
  `ARCHITECTURE.md`. The harness is skill-pack agnostic; specific pack
  names removed in favour of skill-area descriptions.

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

[Unreleased]: https://github.com/D24yK4r4/bb-mcp-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/D24yK4r4/bb-mcp-server/releases/tag/v0.1.0
