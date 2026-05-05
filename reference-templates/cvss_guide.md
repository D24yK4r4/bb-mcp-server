# CVSS 3.1 Scoring Guide for Bug Bounty

**Rule: Score what you PROVED, not what's theoretically possible.**

---

## CVSS 3.1 Vector String Format

```
CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
```

## Base Metrics

### Attack Vector (AV)
| Value | Code | Description |
|-------|------|-------------|
| Network | N | Exploitable over the network (most web vulns) |
| Adjacent | A | Requires same network segment |
| Local | L | Requires local access |
| Physical | P | Requires physical access |

### Attack Complexity (AC)
| Value | Code | Description |
|-------|------|-------------|
| Low | L | No special conditions needed |
| High | H | Requires specific conditions (race, MitM, specific config) |

### Privileges Required (PR)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No auth needed |
| Low | L | Normal user account needed |
| High | H | Admin/privileged account needed |

### User Interaction (UI)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No user interaction (SSRF, SQLi, IDOR) |
| Required | R | Victim must click/visit (XSS, CSRF, phishing) |

### Scope (S)
| Value | Code | Description |
|-------|------|-------------|
| Unchanged | U | Impact limited to vulnerable component |
| Changed | C | Can affect components beyond the vulnerable one (XSS: browser scope ≠ server scope) |

### Confidentiality Impact (C)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No confidentiality impact |
| Low | L | Some data disclosed (non-sensitive, limited) |
| High | H | All data or critical data disclosed |

### Integrity Impact (I)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No integrity impact |
| Low | L | Some data can be modified (limited) |
| High | H | All data or critical data can be modified |

### Availability Impact (A)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No availability impact |
| Low | L | Reduced performance or partial disruption |
| High | H | Complete denial of service |

---

## Common Vulnerability CVSS Vectors

### Critical (9.0-10.0)

**Unauthenticated RCE**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
```

**Unauthenticated SQLi → Full DB Access**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
```

**Auth Bypass → Admin Access**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1
```

**SSRF → AWS Credentials via Metadata**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N → 9.3
```

### High (7.0-8.9)

**Stored XSS → Session Hijacking (any user)**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N → 7.6
```

**IDOR → Read Any User's Data**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5
# Bumped to High if data is sensitive (PII, financial)
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N → 7.1
```

**IDOR → Modify Any User's Data**
```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N → 6.5
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N → 8.1
```

**Blind SQLi (time-based)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5
```

**LFI → Read Sensitive Files**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5
```

### Medium (4.0-6.9)

**Reflected XSS**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1
```

**CSRF → State-Changing Action**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N → 4.3
# With high impact (password change, email change):
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N → 6.5
```

**Open Redirect (standalone)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1
```

**Information Disclosure (non-sensitive)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3
```

**CORS Misconfiguration**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N → 6.5
```

### Low (0.1-3.9)

**Self-XSS (no victim path)**
```
Usually N/A — most programs don't accept this
```

**Missing Security Headers (no demonstrated impact)**
```
CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N → 3.1
```

**Clickjacking (non-sensitive page)**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N → 4.3
```

---

## Scoring Principles for Bug Bounty

1. **Be honest about Privileges Required.** If the attacker needs a user account, it's PR:L not PR:N.

2. **User Interaction matters.** XSS requires a victim to visit a page → UI:R. SQLi doesn't → UI:N.

3. **Scope changes are rare.** Only use S:C when the vulnerable component is genuinely different from the impacted component (e.g., XSS: vuln is in server, impact is in browser).

4. **Don't double-count.** If you proved read access (C:H), don't also claim write (I:H) unless you proved that too.

5. **Context matters.** An IDOR leaking public profile info is C:L. An IDOR leaking SSN/payment info is C:H.

6. **Programs have their own severity scales.** Some programs override CVSS with their own severity ratings. Note this in the report if applicable.

---

## Quick Reference — Severity Ranges

| Score | Rating | Typical Bounty Range |
|-------|--------|---------------------|
| 9.0-10.0 | Critical | $2,000-$50,000+ |
| 7.0-8.9 | High | $1,000-$15,000 |
| 4.0-6.9 | Medium | $500-$5,000 |
| 0.1-3.9 | Low | $100-$1,000 |

*Ranges vary wildly by program. Check the program's bounty table.*
