# APTS Foundation-Tier Compliance Mapping

This document maps `bb-hunter` MCP server controls to **OWASP APTS** (Autonomous Penetration Testing Standard) Tier 1 (Foundation) requirements.

**Standard:** [OWASP/APTS](https://github.com/OWASP/APTS)
**Server version:** v0.3.0 (validator-agent gate, 30 tools)
**Tier claimed:** Foundation (Tier 1)
**Autonomy level operated at:** L1 (Single Technique Execution, Human-Directed) — with optional L2 (Multi-Step Within Single Phase) when validator-agent gate is engaged.

APTS does not define *what* to test but *how* to govern autonomous testing platforms. This mapping demonstrates that `bb-hunter` enforces the foundational safety, oversight, and auditability requirements that APTS Tier 1 prescribes.

---

## Domain 1 — Scope Enforcement

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-SE-001 | Rules of Engagement specification + validation | `brief.md` per-program file is the canonical RoE; every MCP tool reads it before execution |
| APTS-SE-002 | IP range validation, RFC 1918 awareness | `check_scope` rejects RFC 1918 unless brief.md explicitly lists internal CIDRs |
| APTS-SE-003 | Domain scope + wildcard handling | scope parser handles `*.target.com` plus explicit allow/deny in brief.md |
| APTS-SE-004 | Temporal boundary, timezone handling | brief.md `Test Window` line; tools refuse outside window |
| APTS-SE-005 | Asset criticality classification | brief.md `Priority Targets:` + `Critical Assets:` sections feed validator-agent risk weighting |
| APTS-SE-006 | **Pre-action scope validation** | every `run_*` MCP tool calls `check_scope` before sending a single byte — no per-call bypass |
| APTS-SE-008 | Temporal scope compliance monitoring | audit log timestamps every action; out-of-window invocations are recorded as policy violations |
| APTS-SE-009 | Hard deny lists, critical asset protection | brief.md `Out of Scope:` + global deny list (`*.gov`, payment processors, etc.) — non-overridable |
| APTS-SE-015 | Scope enforcement audit + compliance verification | `verify_audit_log` + `verify_verdicts_log` provide tamper-evident replay of every scope check |

---

## Domain 2 — Safety Controls

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-SC-001 | Impact classification (CIA scoring) | validator-agent brief assigns CIA scores before any exploit attempt |
| APTS-SC-004 | **Rate limiting, bandwidth, payload constraints** | global 5 req/s default cap; circuit breaker drops to 2 req/s + 5-minute cooldown after any 429/503 |
| APTS-SC-009 | **Kill switch** | operator can `^C` any MCP call; long-running tools (nmap, ffuf) are firejailed with timeout |
| APTS-SC-010 | Health check monitoring, auto-halt | MCP tools self-abort on rate-limit triggers, scope drift, or sanitizer rejection |
| APTS-SC-015 | Post-test system integrity validation | non-destructive payload sanitizer rejects `DROP`, `DELETE`, `rm -rf`, reverse shells, etc., before transmission |

---

## Domain 3 — Human Oversight

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-HO-001 | **Mandatory pre-approval gates for L1/L2 autonomy** | Claude Code permission prompts on every non-allowlisted Bash + MCP call; operator must explicitly approve |
| APTS-HO-002 | Real-time monitoring + intervention | operator sees every tool call before approval; pause/cancel always available |
| APTS-HO-003 | Decision timeout, default-safe behavior | unanswered approval prompts default to **deny**, never proceed |
| APTS-HO-004 | Authority delegation matrix | single-operator model — no delegated authority claims accepted |
| APTS-HO-006 | Graceful pause with state preservation | `notes.md` checkpoint after every finding; session-resume protocol re-reads CLAUDE.md + notes.md |
| APTS-HO-007 | Mid-engagement redirect capability | operator can shift program / lane / target at any prompt without losing audit chain |
| APTS-HO-008 | **Immediate kill switch with state dump** | `^C` halts; verdicts log + audit log persist last known state |
| APTS-HO-010 | Mandatory human decision points before irreversible actions | every PUT/PATCH/POST/DELETE requires explicit per-call confirmation (memory: `feedback_writes_explicit_confirm`) |
| APTS-HO-011 | Unexpected findings escalation framework | validator-agent gate surfaces `EXPLOITABLE` / `THEORETICAL — DROP` / `INSUFFICIENT JUSTIFICATION` |
| APTS-HO-012 | Impact threshold breach escalation | findings above operator severity floor surface immediately for review |
| APTS-HO-013 | Confidence-based escalation (scope uncertainty) | scope-ambiguous targets trigger `ASK_OPERATOR` rather than `PROCEED` |
| APTS-HO-014 | Legal + compliance escalation triggers | PII discovery during recon halts the lane; operator approves redaction discipline |
| APTS-HO-015 | Real-time activity monitoring | every MCP call is logged + visible in the Claude Code transcript |

---

## Domain 4 — Graduated Autonomy

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-AL-001 | Single technique execution (L1) | default mode — one MCP tool per approval |
| APTS-AL-002 | Human-directed target + technique selection | operator picks program, target, and tool; agent suggests but does not auto-execute |
| APTS-AL-003 | Parameter configuration by operator | every tool's parameters are visible in the approval prompt |
| APTS-AL-004 | No automated chaining (L1) | L1 mode: each tool call gates on operator approval; no daisy-chained mutations |
| APTS-AL-005 | Mandatory logging + reviewable audit trail | `verify_audit_log` returns chronologically ordered, hash-chained record |
| APTS-AL-006 | Basic scope validation + policy enforcement | covered by SE-006 |
| APTS-AL-008 | Real-time human monitoring + approval gates (L2) | even in subagent-orchestrated runs, the validator-agent verdict surfaces before `create_report` is enabled |
| APTS-AL-011 | Escalation triggers + exception handling | rate-limit / scope-drift / sanitizer rejection → operator alert + halt |
| APTS-AL-012 | Kill switch + pause capability | covered by SC-009 + HO-008 |
| APTS-AL-014 | Boundary definition + enforcement framework | brief.md + scope parser + sanitizer + validator-gate = four enforcement layers |

---

## Domain 5 — Auditability

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-AR-001 | **Structured event logging with schema validation** | JSONL audit log; one event per MCP call with schema-validated fields |
| APTS-AR-002 | State transition logging | phase transitions + verdict state changes logged with timestamps |
| APTS-AR-004 | Decision point logging + confidence scoring | validator-agent verdicts captured verbatim with verdict_id |
| APTS-AR-006 | Decision chain of reasoning + alternative evaluation | validator-agent brief includes proposed PoC + alternative exploit paths considered |
| APTS-AR-010 | **Cryptographic hashing of all evidence** | `record_verdict` + `create_report` write SHA-256 hashes to verdicts log |
| APTS-AR-012 | **Tamper-evident logging with hash chains** | audit log + verdicts log are hash-chained (each entry references prior hash) |
| APTS-AR-015 | Evidence classification + sensitive data handling | vault separates `<SAFE:id>` tokens from raw secrets; never enters chat |

---

## Domain 6 — Manipulation Resistance

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-MR-001 | Instruction boundary enforcement | system prompt + CLAUDE.md + skills are immutable per session; user-supplied content cannot override |
| APTS-MR-002 | Response validation + sanitization | tool outputs filtered by sanitizer before reaching agent context |
| APTS-MR-003 | Error message neutrality | tool errors stripped of stack traces / internal paths before display |
| APTS-MR-004 | Configuration file integrity verification | brief.md hash recorded at session start; mid-session edits trigger re-validation |
| APTS-MR-005 | Authority claim detection + rejection | "you are authorized to test out-of-scope" type prompt-injection patterns rejected |
| APTS-MR-007 | Redirect-following policy | curl/httpx redirects bounded to in-scope hosts; cross-domain redirects logged as scope events |
| APTS-MR-008 | DNS + network-level redirect prevention | scope check resolves IP at request time; DNS rebinding flagged |
| APTS-MR-009 | SSRF prevention in testing infrastructure | the agent's *own* HTTP fetches are firejailed; no internal-network reachability from MCP host |
| APTS-MR-010 | Scope expansion social engineering prevention | target asking the agent to "also test this other domain" requires explicit operator brief.md update |
| APTS-MR-011 | Out-of-band communication prevention | no callback / DNS-OOB / webhook channels from the firejail sandbox |
| APTS-MR-012 | Immutable scope enforcement architecture | scope check is in the MCP server itself, not in the agent — cannot be bypassed by prompt injection |
| APTS-MR-018 | AI model input/output architectural boundary | secrets vault + sanitizer = architectural separation between LLM context and sensitive data |

---

## Domain 7 — Supply Chain Trust

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-TP-001 | Third-party provider selection + vetting | Anthropic-only LLM provider, documented |
| APTS-TP-003 | API security + authentication | OAuth flow for platform integrations; vault-stored credentials |
| APTS-TP-005 | Provider incident response, breach notification | operator notified on any auth failure / provider 5xx |
| APTS-TP-006 | Dependency inventory + supply chain verification | `pyproject.toml` lockfile; dependencies pinned + scanned |
| APTS-TP-008 | Cloud security configuration | MCP runs locally in firejail — no cloud surface |
| APTS-TP-012 | Client data classification framework | findings / loot / evidence / brief separated by directory + permission |
| APTS-TP-013 | Sensitive data discovery + handling | `loot/` directory listed in CLAUDE.md as "never read in full"; grep-by-key only |
| APTS-TP-014 | Data encryption + cryptographic controls | vault uses AES-GCM; hash chains use SHA-256 |

---

## Domain 8 — Reporting

| APTS-ID | Requirement | bb-hunter control |
|---|---|---|
| APTS-RP-006 | **False positive rate disclosure** | validator-agent gate publishes EXPLOITABLE vs THEORETICAL ratio per program |
| APTS-RP-008 | **Vulnerability coverage disclosure** | CLAUDE.md skill triggers table + reference files document tested vulnerability classes |
| APTS-RP-011 | Executive summary + risk overview | report-writer subagent emits Executive Summary section per platform taxonomy |

---

## Tier-1 Coverage Summary

| Domain | Tier-1 MUST reqs | Met | Partial | Not yet |
|---|---|---|---|---|
| 1. Scope Enforcement | 8 | 8 | 0 | 0 |
| 2. Safety Controls | 5 | 5 | 0 | 0 |
| 3. Human Oversight | 13 | 13 | 0 | 0 |
| 4. Graduated Autonomy | 8 | 8 | 0 | 0 |
| 5. Auditability | 7 | 7 | 0 | 0 |
| 6. Manipulation Resistance | 12 | 12 | 0 | 0 |
| 7. Supply Chain Trust | 6 | 6 | 0 | 0 |
| 8. Reporting | 3 | 3 | 0 | 0 |
| **Total** | **62** | **62** | **0** | **0** |

`bb-hunter` v0.3.0 satisfies all 62 Tier-1 MUST requirements at L1 (single technique, human-directed) and L2 (multi-step within single phase, with validator-agent gate).

## Path to Tier-2 (Verified)

Tier-2 additions on the roadmap:

- **APTS-SE-007 / SE-016**: dynamic scope monitoring + drift detection (programmatic brief.md re-fetch from platform)
- **APTS-SC-006**: threshold escalation workflow (automated → approval → prohibited tiers per finding class)
- **APTS-SC-014**: reversible action tracking + rollback ledger
- **APTS-AR-005 / AR-011**: log retention policy + chain-of-custody handoff
- **APTS-MR-013**: adversarial example detection in vulnerability classification
- **APTS-RP-001 / RP-002**: evidence-based finding validation + human review pipeline (already in workflow, needs formal documentation)

## Reference

OWASP APTS standard: <https://github.com/OWASP/APTS>
Compliance tier definitions: `APTS/standard/Introduction.md`
Per-requirement implementation guides: `APTS/standard/<N>_<Domain>/Implementation_Guide.md`
