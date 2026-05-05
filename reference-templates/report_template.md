# Universal Bug Bounty Report Template

This template works for HackerOne, Bugcrowd, and Intigriti.
Fill in the sections below. Remove any sections that don't apply.

---

## Report Structure

```markdown
# [Vulnerability Type] in [Component/Feature] allows [Impact]

## Summary

[One paragraph: What is the vulnerability, where is it, and what can an attacker do with it. Written so a triager understands the issue in 30 seconds.]

**Affected Asset:** `https://target.com/endpoint`
**Vulnerability Type:** [e.g., Stored XSS, SQL Injection, IDOR]
**CWE:** [CWE-XXX — Full Name]
**CVE:** [CVE-XXXX-XXXXX or N/A]
**CVSS 3.1:** [X.X (Rating)] — `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`

---

## Description

[Detailed explanation of the vulnerability. Include:
- What the vulnerable component does
- Why it's vulnerable (root cause)
- What an attacker could achieve
- Any preconditions or requirements]

---

## Steps to Reproduce

1. Navigate to `https://target.com/page`
2. Log in with credentials: `testuser:testpassword` (or create a new account)
3. [Exact step with exact input]
4. [Exact step — include full URLs, parameters, headers]
5. [Exact step]
6. Observe: [what proves the vulnerability — exact response, behavior, output]

**Expected behavior:** [What should happen if the app were secure]
**Actual behavior:** [What actually happens — the vulnerability]

---

## Proof of Concept

### HTTP Request
```http
POST /api/endpoint HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer eyJ...
Cookie: session=abc123

{"parameter": "malicious_value"}
```

### HTTP Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"result": "proves_the_vulnerability"}
```

### cURL Command (copy-paste ready)
```bash
curl -s -X POST 'https://target.com/api/endpoint' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer eyJ...' \
  -d '{"parameter": "malicious_value"}'
```

### PoC Script (if applicable)
```python
#!/usr/bin/env python3
"""PoC for [vulnerability description]"""
import requests

TARGET = "https://target.com"
# ... minimal script that demonstrates the issue
```

### Screenshots
[Attach screenshots with timestamps showing:
1. The malicious request being sent
2. The vulnerable response
3. The impact demonstrated]

---

## Impact

[Describe the realistic impact. Be specific, not hypothetical.

Good: "An attacker with a low-privileged account can read any user's private messages by changing the message_id parameter, exposing PII including email addresses and phone numbers."

Bad: "An attacker could potentially compromise the entire system and steal all data." (too vague, inflated)]

### Attack Scenario

1. Attacker [does X]
2. This causes [Y]
3. Result: attacker gains [Z]

### Affected Users/Data
- [Who is affected: all users, admins only, specific role]
- [What data is at risk: PII, financial, credentials, etc.]

---

## Remediation

[Actionable fix — not just "sanitize input" but HOW.

Good:
- "Use parameterized queries instead of string concatenation for SQL queries"
- "Implement server-side authorization checks in the `/api/messages/{id}` endpoint to verify the requesting user owns the message"
- "Add Content-Security-Policy header with `script-src 'self'` to prevent inline script execution"

Include code example if possible:]

```python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE id = '{user_input}'"

# After (fixed)
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
```

---

## References

- [OWASP: relevant page]
- [CWE-XXX: https://cwe.mitre.org/data/definitions/XXX.html]
- [HackTricks: relevant technique]
- [Related CVE or advisory if applicable]
- [Blog post or research paper if applicable]

---

## Supporting Materials / Attachments

- [ ] Screenshot(s) with timestamps
- [ ] HTTP request/response logs
- [ ] PoC script (if applicable)
- [ ] Video recording (for complex multi-step bugs)
```

---

## Platform-Specific Notes

### HackerOne
- Select the correct **Weakness** (maps to CWE)
- Set **Severity** using their CVSS calculator
- **Asset** must match one from the program scope
- Use markdown formatting — HackerOne renders it well
- Attach files directly, don't use external links

### Bugcrowd
- Select the correct **VRT category** (Vulnerability Rating Taxonomy)
- Bugcrowd may override your severity with their P-scale (P1-P5)
- Keep the report concise — Bugcrowd triagers handle high volume
- Technical PoC is more valued than long descriptions

### Intigriti
Full field reference: `reference/intigriti_taxonomy.md`

**Required fields (in order):**
1. **Title** — `[Vuln Type] in [Component] allows [Impact]`
2. **Asset: Tier** — from program scope page
3. **Asset: Type** — Web Application / API / Mobile / Other
4. **Asset: Endpoint / Vulnerable Component** — exact URL
5. **Type** — select from Intigriti taxonomy (see intigriti_taxonomy.md)
6. **Severity** — CVSS 3.1 calculator (AV / AC / PR / UI / S / C / I / A)
7. **Details** — PoC + numbered reproduction steps + HTTP request/response
8. **Impact** — realistic attack scenario, specific not theoretical
9. **Recommended Solution** — optional but valued by triagers

**Key rules:**
- Type field must match Intigriti's exact taxonomy — use the quick mapping table in `intigriti_taxonomy.md`
- Severity comes from CVSS calculator, not a dropdown — fill all 8 fields
- Video PoC is especially valued for complex multi-step bugs
- Self-XSS without victim path = N/A
- Check program-specific severity guidelines — some programs override CVSS

---

## Report Writing Tips

1. **Title matters.** "[Vuln Type] in [Component] allows [Impact]" — a triager reads 100 titles a day. Make yours clear.

2. **Steps must be copy-paste-able.** If a triager can't reproduce in 5 minutes, it gets closed as "Needs More Info" or "N/A."

3. **Don't oversell.** Claiming Critical for a Low issue damages your reputation. Honest, accurate severity builds trust.

4. **One report per vulnerability.** Don't bundle multiple findings unless they're part of the same exploit chain.

5. **Provide the fix.** Triagers prioritize reports that include remediation guidance — it saves their engineers time.

6. **Check for duplicates.** If the program has public disclosures, check if your finding is already reported.

7. **Timestamp everything.** Screenshots should show browser URL bar, time, and the vulnerable response.

8. **Redact other users' data.** If you find an IDOR and see someone else's PII, redact it in your report. Mention that PII was visible but don't include it.
