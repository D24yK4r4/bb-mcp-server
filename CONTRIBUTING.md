# Contributing

Thanks for the interest. This project takes contributions in three forms:

1. **Bug reports** — open an issue with: what you ran, what you expected, what
   happened. If a sensitive value leaked into the AI's view, mark the issue
   `security` and follow [`SECURITY.md`](SECURITY.md) instead.
2. **New sanitization patterns** — edit `server/config.py` `RAW_REDACT_PATTERNS`,
   add a test case in `server/test_server.py`, run the full suite.
3. **New tool wrappers** — add to `server/tools/`, register in `server/server.py`,
   include rate-limit + scope-check + sanitization just like the existing wrappers.

## Development setup

```bash
git clone https://github.com/<your-handle>/bb-mcp-server.git
cd bb-mcp-server/server
pip install -r requirements.txt
```

## Running tests

```bash
cd server
python3 test_server.py        # 41 unit tests, no network
python3 test_integration.py   # 30 integration tests, hits httpbin.org
```

Both must be green before submitting a PR.

## Pattern contributions — the rules

When adding a new sanitization pattern to `RAW_REDACT_PATTERNS` in
`server/config.py`:

1. **High-specificity patterns go BEFORE generic ones.** A SaaS-specific
   pattern (Stripe, GitHub, Slack, …) must run before the generic
   `api_key=` / `token=` / `secret=` patterns; otherwise the generic ones
   consume the value first and re-tag it with the wrong type.
2. **Use the 3-group form `(prefix)(value)(suffix)`** for value-bracketed
   matches (JSON quotes, separators). The sanitizer uses `group(1)` as the
   preserved prefix, vaults `group(2)`, and emits `prefix + <SAFE:type:id> +
   suffix`.
3. **Greedy value matchers (`\S+`, `[^"]+`, `[^@\s]+`, etc.) MUST exclude or
   reject `<SAFE:`.** Use either:
   - Negative lookahead at the start: `(?!<SAFE:)\S+`
   - Per-character lookahead inside a `(?:(?!<SAFE:)[^"])+` group, or
   - Add `<` to the character class: `[^"<]+`
   Skipping this lets the pattern re-vault tokens already produced by an
   earlier pattern, breaking report substitution.
4. **Add a test case** in `test_server.py` section 1 (sanitizer tests).
   Both: (a) a positive case (real value gets vaulted), and (b) a
   re-vaulting protection case (existing `<SAFE:type:id>` survives).

## Hook contributions

Hooks live in `hooks/`. They run inside Claude Code's runtime, receive JSON
on stdin, and emit JSON or plain text on stdout. Keep them dependency-free
(stdlib Python or Bash only) — they need to start fast and run anywhere.

When adding a new context trigger to `skill-context-trigger.sh`:
- Add the regex set + reason text under `SKILL_TRIGGERS` (or
  `REFERENCE_TRIGGERS`).
- Use a tight, low-false-positive pattern. Match a syntactic marker, not a
  general keyword (e.g. `pragma\s+solidity` not just `solidity`).
- Test it with the smoke-test pattern in the file's `if __name__` section
  (operators run hooks via the Claude Code lifecycle; for unit testing,
  pipe a JSON payload to the script and check the output).

## Commit messages

Conventional-style is fine but not required. Keep the subject under 72
characters; include a short body explaining *why* if non-obvious.

## Sign-off — Developer Certificate of Origin (DCO)

**Every commit in a pull request must include a `Signed-off-by:`
trailer matching the commit author.** This is a CI-enforced check; PRs
without sign-offs are blocked.

By adding `Signed-off-by:` you certify the contents of
[`DCO.md`](DCO.md) — the
[Developer Certificate of Origin v1.1](https://developercertificate.org/) —
which states (paraphrased): you wrote this code or have the right to
contribute it under the project's licence.

The trailer must be added by `git`, not typed manually:

```bash
# Sign new commits:
git commit -s -m "Your commit message"

# Sign the most recent commit retroactively:
git commit --amend --signoff

# Sign the last N commits in a branch:
git rebase HEAD~N --signoff
```

This produces a trailer like:

```
Signed-off-by: Your Name <your.email@example.com>
```

The CI check verifies (a) every commit in the PR has the trailer, and
(b) the sign-off email matches the commit author email.

**Why DCO and not a CLA?** A DCO is a lightweight, in-band signoff that
doesn't require contributors to sign a separate document. It's
sufficient for this project's licensing model and matches the practice
used by the Linux kernel, Docker, GitLab, and many other strong-copyleft
projects.

## License

By contributing (and by signing off via DCO) you agree to license your
contribution under the same terms as the rest of the repo:
dual-licensed under [EUPL-1.2](LICENSE) or [AGPL-3.0](LICENSE-AGPL-3.0)
at the recipient's option. Both are strong copyleft with a network-use
clause — please make sure you understand them before contributing.

The project author retains the right to dual-license bb-mcp-server
under additional commercial terms (see [`COMMERCIAL.md`](COMMERCIAL.md)).
By signing off your contribution under DCO, you accept that this
relicensing right extends to your contribution.
