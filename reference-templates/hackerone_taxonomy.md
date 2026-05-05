# HackerOne Report Field Reference

> **Status:** Form fields verified from the H1 submission UI as of 2026-05-05.
> Weakness picker labels are best-effort (HackerOne maintains an internal list
> mapped to CWE — exact labels can drift across program scopes). The Description
> + Impact templates are **program-customizable** — what each program shows can
> differ from the generic template captured here.

---

## Severity Scale (CVSS-derived)

HackerOne severity is set per report. You can either:
- Provide a **CVSS 3.1 vector** → severity is auto-mapped from the score
- Or set severity manually from None / Low / Medium / High / Critical

| Severity | CVSS 3.1 score |
|----------|----------------|
| Critical | 9.0 – 10.0 |
| High     | 7.0 – 8.9 |
| Medium   | 4.0 – 6.9 |
| Low      | 0.1 – 3.9 |
| None     | 0.0 |

If the program publishes a severity-to-bounty mapping, the CVSS-derived
severity is what they use to pick the band.

---

## Report Form Fields (HackerOne UI)

The form auto-saves as you type ("Last saved at HH:MM"). The minimum required
fields before submission are: **Asset**, **Weakness**, **Severity**.

| Field | Required | Notes |
|-------|----------|-------|
| **Title** | Yes | One-line summary at the top of the report |
| **Asset** | Yes | Picked from the program's scope dropdown (URL / Domain / IP / CIDR / Source code / Mobile package / Other / Hardware — per program) |
| **Weakness** | Yes | Single dropdown — pick the most-specific CWE-mapped item (see common labels below) |
| **Severity** | Yes | CVSS 3.1 vector OR manual None/Low/Medium/High/Critical |
| **Description** | Yes | Markdown body — programs publish custom templates (see below) |
| **Impact** | Yes | Markdown body — what the attacker can realistically achieve |
| **Attachments** | Optional | Screenshots, videos, PoC files — drag/drop or paste |

### Default Description template (CTF / common form)

```markdown
## Summary:
[add summary of how you captured the flag]

## What is the bad poetry?:        ← program-specific prompt; usually replaced
[insert the flag/bad poetry here]

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. [add step]
  1. [add step]
  1. [add step]

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]
```

### Default Impact template

```markdown
## Summary:
```

> **Note:** the Description template above came from a CTF program (the
> "bad poetry" prompt is a CTF-specific replacement). Standard programs
> typically show a similar `Summary / Steps To Reproduce / Supporting
> Material/References` skeleton in Description and a `Summary:` line in
> Impact. Each program can customize.

---

## Common Weakness picker labels (best-effort → CWE)

> H1 maintains the canonical list internally; this table covers the most
> frequent picks. Always select the most-specific match from the live picker.

| H1 weakness label | CWE |
|-------------------|-----|
| Cross-site Scripting (XSS) — Reflected | CWE-79 |
| Cross-site Scripting (XSS) — Stored    | CWE-79 |
| Cross-site Scripting (XSS) — DOM       | CWE-79 |
| Cross-site Scripting (XSS) — Generic   | CWE-79 |
| SQL Injection                          | CWE-89 |
| Server-Side Request Forgery (SSRF)     | CWE-918 |
| Server-Side Template Injection (SSTI)  | CWE-1336 / CWE-94 |
| Insecure Direct Object Reference (IDOR)| CWE-639 |
| Improper Authorization                 | CWE-285 |
| Improper Access Control — Generic      | CWE-284 |
| Broken Authentication                  | CWE-287 |
| Privilege Escalation                   | CWE-269 |
| Cross-site Request Forgery (CSRF)      | CWE-352 |
| Open Redirect                          | CWE-601 |
| Information Disclosure                 | CWE-200 |
| Sensitive Information Disclosure       | CWE-200 |
| Cryptographic Issues — Generic         | CWE-310 |
| Use of Hard-coded Credentials          | CWE-798 |
| Code Injection                         | CWE-94 |
| Command Injection — Generic            | CWE-77 |
| OS Command Injection                   | CWE-78 |
| Path Traversal                         | CWE-22 |
| Unrestricted File Upload               | CWE-434 |
| Race Condition                         | CWE-362 |
| XML External Entity (XXE)              | CWE-611 |
| Business Logic Errors                  | CWE-840 |
| Memory Corruption — Generic            | CWE-119 |
| Use After Free                         | CWE-416 |
| Buffer Overflow                        | CWE-120 |
| Integer Overflow / Underflow           | CWE-190 / CWE-191 |
| Misconfiguration                       | CWE-16 |
| Denial of Service                      | CWE-400 |
| Improper Input Validation              | CWE-20 |
| Improper Authentication — Generic      | CWE-287 |
| Use of Default Credentials             | CWE-1392 |
| Brute Force                            | CWE-307 |
| Improper Restriction of Auth Attempts  | CWE-307 |
| Server Misconfiguration — Generic      | CWE-16 |

---

## Phase 4 QA Checklist (HackerOne-specific)

- [ ] CVSS vector valid; auto-mapped severity matches the impact you can demonstrate
- [ ] Weakness is the most-specific available label (not "Other")
- [ ] Asset matches an in-scope item exactly (specific subdomain, not the wildcard)
- [ ] Title is specific — programs read titles first when triaging
- [ ] Description follows the program's template (don't strip the `## Summary` / `## Steps To Reproduce` headers — triagers expect them)
- [ ] Steps To Reproduce numbered (use the `1. 1. 1.` pattern — H1 markdown auto-renumbers)
- [ ] Impact section describes a *realistic* attacker scenario, not theoretical maximum
- [ ] PII (other users' emails, names, IDs) redacted in attachments
- [ ] Sensitive data attached as a file — not pasted into Description body
- [ ] No mention of testing on out-of-scope assets

---

## Common reasons reports get N/A on HackerOne

- Self-XSS without a victim path
- Missing security headers with no exploit chain
- "Default credentials" on an exposed dev/staging asset that's not in scope
- Email enumeration (often program-specific — check brief)
- Outdated software with no proven exploitation path
- CSRF on actions that don't change state
- Clickjacking on pages with no sensitive action
- Open redirects without a phishing chain (often Low or N/A)

---

## Tips

- **Asset matching:** if the program scope is `*.example.com`, your asset
  identifier must be the *specific subdomain* you exploited, not the wildcard.
- **CVSS Calculator:** [first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1) or H1's inline picker — both produce the same vector.
- **Weakness drift:** if your finding is a chain (e.g., SSRF → cloud creds →
  RCE), pick the *initial* weakness for the picker, then describe the chain in
  the body.
- **Auto-save:** the form auto-saves so you can close and resume — but copy
  the report to a local file before submitting in case the draft is lost.
- **Attachment taxonomy:** H1 has no formal attachment-type field. Common
  practice: put screenshots inline (drag/drop into Description), and use
  the file attachment area for PoC scripts, larger videos, and HAR files.
