# Security Policy

## Reporting a vulnerability

**Do not** open a public issue for security vulnerabilities in
**bb-mcp-server itself**. Instead, email the maintainer (see the GitHub
profile of the repository owner) with:

- A description of the issue
- Steps to reproduce
- Affected versions
- (Optional) suggested fix

You should receive an acknowledgement within 7 days. We aim to ship a fix
within 30 days for high-severity issues.

If you find a vulnerability in a **target you're testing** while using
bb-mcp-server, that report goes to that target's program (Intigriti,
Bugcrowd, HackerOne, etc.) — not here.

## What constitutes a security issue here

| In scope | Out of scope |
|----------|--------------|
| Sensitive value leaking into AI-visible output | Bugs in third-party skills |
| Sanitization pattern that fails to vault a real-world token format | Issues in scanners (nuclei, sqlmap, etc.) — report upstream |
| Vault entry not chmod 600 | Behavior of Claude Code itself |
| Audit log hash chain not actually verifying | Performance issues without security impact |
| Scope check bypass | Style / cosmetic issues |
| Script approval bypass | Documentation typos |
| Pre-tool confirmation gate bypass | |
| Severity gate bypass | |

## What we do NOT do

- We do not host a vulnerability disclosure program with bounties.
- We do not run third-party scans against the project on behalf of
  reporters.
- We do not provide indemnification for users of the project.

Both licences under which bb-mcp-server is distributed
([EUPL-1.2](LICENSE) and [AGPL-3.0](LICENSE-AGPL-3.0)) disclaim all
warranties — see Articles 7–8 of the EUPL and Sections 15–17 of the AGPL.

## Supported versions

Only the latest tagged release receives security fixes. There are no LTS
branches.

## Hardening recommendations for operators

Even with all 13 layers active, operators should:

1. Run as a low-privilege user with no login shell.
2. Wrap the server launch in `firejail --net=none` (the server itself
   needs no outbound network — only the tools it spawns do, which run
   under their own scope checks).
3. Set `chmod 700` on the vault directory.
4. Set `chattr +a` on audit logs if your filesystem supports it.
5. Use `pip-audit` regularly on `server/requirements.txt`.
6. Periodically run `verify_audit_log` to confirm hash-chain integrity.
7. Never disable the pre-tool confirmation gate (`BB_NO_PRE_CONFIRM=1`)
   in long-running unattended sessions.

## Threat model

- **Trusted:** the operator running Claude Code locally.
- **Adversarial-but-cooperative:** the AI model. We assume the AI may try
  to exfiltrate sensitive data through tool output paths if not gated, but
  is not actively malicious.
- **Adversarial:** the testing target. Output may contain attacker-
  controlled content designed to evade sanitization or trigger
  destructive actions.
- **Out of scope:** local OS compromise. If the operator's machine is
  rooted, the vault and audit log are gone too.
