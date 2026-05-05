# Intigriti Report Field Reference

Complete field reference for Intigriti report submission.
Use this when generating reports in Phase 3.

---

## Report Fields (in order)

| Field | Required | Notes |
|-------|----------|-------|
| Title | Yes | Clear, specific — "[Vuln] in [Component] allows [Impact]" |
| Asset: Tier | Yes | From program scope (e.g. Tier 1, Tier 2) |
| Asset: Type | Yes | Web, Mobile, API, etc. |
| Asset: Endpoint / Vulnerable Component | Yes | Exact URL or component |
| Type | Yes | Select from taxonomy below |
| Severity | Yes | CVSS calculator (fields below) |
| Details / PoC | Yes | Full reproduction steps + proof |
| Impact | Yes | Realistic attack scenario |
| Recommended Solution | Optional | Actionable fix |

---

## CVSS 3.1 Fields (Intigriti Calculator)

```
Attack Vector (AV)        Network / Adjacent / Local / Physical
Attack Complexity (AC)    Low / High
Privileges Required (PR)  None / Low / High
User Interaction (UI)     None / Required
Scope (S)                 Unchanged / Changed
Confidentiality (C)       None / Low / High
Integrity (I)             None / Low / High
Availability (A)          None / Low / High
```

Score ranges:
- Critical: 9.0 – 10.0
- High:     7.0 – 8.9
- Medium:   4.0 – 6.9
- Low:      0.1 – 3.9

---

## Vulnerability Type Taxonomy

Format: `[CWE/CAPEC] Name (Category)`
Select the most specific match from the list below.

### Other (Web / Generic)
```
Remote Code Execution
Email Spoofing
Homograph Attack
CWE-918  Server-Side Request Forgery
CWE-352  Cross-Site Request Forgery
CAPEC-101 Server-Side Include Injection
Fingerprinting
Banner Grabbing
CWE-98   Local File Inclusion
CWE-98   Remote File Inclusion
Buffer Overflow
CWE-400  Denial of Service
Reflected File Download
CWE-601  Open Redirect
Weak or Default Credentials
CWE-203  Information Exposure Through Discrepancy (Enumeration)
Missing Cookie Flag
CAPEC-103 UI Redressing (Clickjacking)
No Rate Limiting
Missing Security Header
CAPEC-148 Content Injection
Web Cache Poisoning
CAPEC-460 HTTP Parameter Pollution
CWE-434  Unrestricted File Upload
CWE-362  Race Condition
CWE-444  HTTP Request Smuggling
CWE-300  Man-in-the-Middle
CWE-840  Business Logic Error
CRLF Injection
CWE-121  Stack Overflow Disclosure
Subdomain Takeover
Web Cache Deception
Host Header Injection
HTML Injection
CWE-602  Client-Side Enforcement of Server-Side Security
CWE-776  XML Entity Expansion
CWE-125  Out-of-bounds Read
CWE-122  Heap Overflow
CAPEC-549 Malware
CWE-426  Untrusted Search Path
CWE-427  Uncontrolled Search Path Element
```

### Mobile
```
CWE-96   Server-Side Template Injection
CAPEC-233 Horizontal Privilege Escalation
CAPEC-233 Vertical Privilege Escalation
CWE-639  Insecure Direct Object Reference
CWE-79   Blind Cross-Site Scripting
CWE-79   Reflected Cross-Site Scripting
CWE-79   Stored Cross-Site Scripting
CWE-79   DOM-Based Cross-Site Scripting
CWE-79   Self Cross-Site Scripting
CWE-77   Command Injection (Generic)
CWE-89   SQL Injection
CWE-613  Insufficient Session Expiration
CWE-640  Weak Password Recovery Mechanism for Forgotten Password
CWE-200  Information Disclosure (Generic)
CWE-285  Improper Authorization
CWE-287  Improper Authentication (Generic)
CWE-22   Path Traversal
CWE-798  Use of Hard-coded Credentials
CWE-215  Information Exposure Through a Debug Message
CWE-548  Information Exposure Through Directory Listing
CWE-209  Information Exposure Through an Error Message
CWE-327  Use of a Broken or Risky Cryptographic Algorithm
CWE-312  Cleartext Storage of Sensitive Information
CWE-502  Deserialization of Untrusted Data
CWE-256  Plaintext Storage of a Password
CWE-91   XML Injection
CSV Injection
CWE-284  Improper Access Control (Generic)
CWE-319  Cleartext Transmission of Sensitive Information
CWE-425  Forced Browsing
CWE-307  Brute Force
CWE-657  Violation of Secure Design Principles
CWE-620  Unverified Password Change
CWE-922  Insecure Storage of Sensitive Information
CWE-325  Missing Required Cryptographic Step
CWE-613  Insufficient Session Expiration
CWE-190  Integer Overflow
Injection (Generic)
Security Misconfiguration (Generic)
No/Bypass SSL Certificate Pinning
Mobile Security Misconfiguration (Generic)
```

### Misconfiguration
```
CWE-548  Information Exposure Through Directory Listing
CWE-209  Information Exposure Through an Error Message
Security Misconfiguration (Generic)
```

### Broken Access Control
```
CAPEC-233 Horizontal Privilege Escalation
CAPEC-233 Vertical Privilege Escalation
CWE-639  Insecure Direct Object Reference
CWE-285  Improper Authorization
CWE-22   Path Traversal
CWE-284  Improper Access Control (Generic)
CWE-425  Forced Browsing
```

### Injection
```
CWE-96   Client-Side Template Injection
CWE-96   Server-Side Template Injection
NoSQL Injection
CWE-77   Command Injection (Generic)
CWE-90   LDAP Injection
CWE-89   SQL Injection
CAPEC-83 XPath Injection
CWE-91   XML Injection
CSV Injection
SOAP Injection
Injection (Generic)
```

### Vulnerable Components
```
CWE-327  Use of a Broken or Risky Cryptographic Algorithm
CWE-657  Violation of Secure Design Principles
CWE-190  Integer Overflow
```

### Broken Authentication
```
CWE-384  Session Fixation
CWE-613  Insufficient Session Expiration
CWE-640  Weak Password Recovery Mechanism for Forgotten Password
CWE-287  Improper Authentication (Generic)
CWE-798  Use of Hard-coded Credentials
CWE-256  Plaintext Storage of a Password
CWE-307  Brute Force
CWE-620  Unverified Password Change
CWE-613  Insufficient Session Expiration
```

### Insecure Deserialisation
```
CWE-502  Deserialization of Untrusted Data
```

### Cryptographic Issues
```
CWE-295  Improper Certificate Validation
CWE-328  Reversible One-Way Hash
CWE-296  Improper Following of a Certificate's Chain of Trust
CWE-326  Inadequate Encryption Strength
CWE-311  Missing Encryption of Sensitive Data
Cryptographic Issue (Generic)
```

### Access Control Issues
```
CWE-22   Path Traversal
CWE-200  Information Disclosure
CWE-209  Information Exposure Through an Error Message
CWE-215  Information Exposure Through Debug Information
CWE-269  Privilege Escalation
CWE-284  Improper Access Control
CWE-287  Improper Authentication
CWE-307  Brute Force
CWE-313  Insufficient Session Expiration
CWE-322  Key Exchange without Entity Authentication
CWE-359  Privacy Violation
CWE-425  Forced Browsing
CWE-639  Insecure Direct Object Reference
CWE-250  Execution with Unnecessary Privileges
CWE-276  Incorrect Default Permissions
```

### Cross-Site Scripting
```
CWE-79   Blind Cross-Site Scripting
CWE-79   Reflected Cross-Site Scripting
CWE-79   Stored Cross-Site Scripting
CWE-79   DOM-Based Cross-Site Scripting
CWE-79   Self Cross-Site Scripting
Cross-Site Script Inclusion
```

### XML External Entities
```
CWE-611  XML External Entity
```

### Generative AI & LLMs
```
Prompt Injection
Insecure Output Handling
Training Data Poisoning
Model Denial of Service
Supply Chain Vulnerabilities
Sensitive Information Disclosure
Insecure Plugin Design
Excessive Agency
Overreliance
Model Theft
```

### Memory Management
```
CWE-416  Use After Free
CWE-787  Out-of-bounds Write
CWE-824  Access of Uninitialized Pointer
CWE-119  Memory Corruption (Generic)
CWE-476  Null Pointer Dereference
CWE-415  Double Free
CWE-770  Allocation of Resources Without Limits or Throttling
```

---

## Quick Mapping — Finding Type → Intigriti Type + Category

| Our Finding Type | Intigriti Type | Category |
|-----------------|----------------|----------|
| XSS (Stored) | CWE-79 Stored Cross-Site Scripting | Cross site scripting |
| XSS (Reflected) | CWE-79 Reflected Cross-Site Scripting | Cross site scripting |
| XSS (DOM) | CWE-79 DOM-Based Cross-Site Scripting | Cross site scripting |
| XSS (Blind) | CWE-79 Blind Cross-Site Scripting | Cross site scripting |
| XSS (Self) | CWE-79 Self Cross-Site Scripting | Cross site scripting |
| SQLi | CWE-89 SQL Injection | Injection |
| IDOR | CWE-639 Insecure Direct Object Reference | Broken Access Control |
| SSRF | CWE-918 Server-Side Request Forgery | Other |
| CSRF | CWE-352 Cross-Site Request Forgery | Other |
| SSTI (server) | CWE-96 Server-Side Template Injection | Injection |
| SSTI (client) | CWE-96 Client-Side Template Injection | Injection |
| RCE | Remote Code Execution | Other |
| LFI | CWE-98 Local File Inclusion | Other |
| RFI | CWE-98 Remote File Inclusion | Other |
| Path Traversal | CWE-22 Path Traversal | Broken Access Control |
| XXE | CWE-611 XML External Entity | XML External Entities |
| Command Injection | CWE-77 Command Injection (Generic) | Injection |
| LDAP Injection | CWE-90 LDAP Injection | Injection |
| Open Redirect | CWE-601 Open Redirect | Other |
| Clickjacking | CAPEC-103 UI Redressing (Clickjacking) | Other |
| Subdomain Takeover | Subdomain Takeover | Other |
| Race Condition | CWE-362 Race Condition | Other |
| File Upload | CWE-434 Unrestricted File Upload | Other |
| Business Logic | CWE-840 Business Logic Error | Other |
| Auth Bypass | CWE-287 Improper Authentication (Generic) | Broken Authentication |
| Session Fixation | CWE-384 Session Fixation | Broken Authentication |
| Brute Force | CWE-307 Brute Force | Broken Authentication |
| Password Reset | CWE-640 Weak Password Recovery | Broken Authentication |
| Horizontal PrivEsc | CAPEC-233 Horizontal Privilege Escalation | Broken Access Control |
| Vertical PrivEsc | CAPEC-233 Vertical Privilege Escalation | Broken Access Control |
| Info Disclosure | CWE-200 Information Disclosure | Access Control Issues |
| Debug Info | CWE-215 Information Exposure Through Debug Info | Access Control Issues |
| Error Message | CWE-209 Information Exposure Through Error Message | Access Control Issues |
| Directory Listing | CWE-548 Information Exposure Through Directory Listing | Misconfiguration |
| Missing Headers | Missing Security Header | Other |
| Missing Cookie Flag | Missing Cookie Flag | Other |
| No Rate Limiting | No Rate Limiting | Other |
| CORS Misc | CWE-284 Improper Access Control (Generic) | Broken Access Control |
| HTTP Smuggling | CWE-444 HTTP Request Smuggling | Other |
| Web Cache Poisoning | Web Cache Poisoning | Other |
| CRLF Injection | CRLF Injection | Other |
| Host Header Injection | Host Header Injection | Other |
| Deserialization | CWE-502 Deserialization of Untrusted Data | Insecure Deserialisation |
| Hard-coded Creds | CWE-798 Use of Hard-coded Credentials | Broken Authentication |
| Weak Crypto | CWE-327 Use of a Broken or Risky Cryptographic Algorithm | Cryptographic Issues |
| Missing Encryption | CWE-311 Missing Encryption of Sensitive Data | Cryptographic Issues |
| Prompt Injection | Prompt Injection | Generative AI & LLMs |
| NoSQL Injection | NoSQL Injection | Injection |
| XPath Injection | CAPEC-83 XPath Injection | Injection |
| CSV Injection | CSV Injection | Injection |
| HTTP Param Pollution | CAPEC-460 HTTP Parameter Pollution | Other |
| Forced Browsing | CWE-425 Forced Browsing | Broken Access Control |
| DoS | CWE-400 Denial of Service | Other |
| Reflected File Download | Reflected File Download | Other |

---

## Intigriti Report Format (What to Fill)

```
TITLE
└── [Vuln Type] in [Component/Endpoint] allows [Impact]
    Example: "Stored XSS in comment field allows session hijacking"

ASSET
├── Tier:      [from program scope page]
├── Type:      Web Application / API / Mobile / Other
└── Endpoint:  https://target.com/vulnerable/endpoint

TYPE
└── [Select from taxonomy above — most specific match]

SEVERITY
├── AV: Network/Adjacent/Local/Physical
├── AC: Low/High
├── PR: None/Low/High
├── UI: None/Required
├── S:  Unchanged/Changed
├── C:  None/Low/High
├── I:  None/Low/High
└── A:  None/Low/High
    → Score calculates automatically

DETAILS (Proof of Concept)
├── Brief description (1 paragraph)
├── Numbered steps to reproduce
├── Full HTTP request (sanitized)
├── Full HTTP response (sanitized)
└── curl command (copy-paste ready)

IMPACT
└── Realistic attack scenario — what attacker achieves
    Reference affected users, data types, business risk

RECOMMENDED SOLUTION (optional but valued)
└── Specific fix — not just "validate input"
```

---

## Notes

- Intigriti triagers value **video PoC** for complex multi-step bugs
- **Self-XSS** is almost always N/A — must have a victim path
- **Missing headers** alone are usually Low or Informational
- **No Rate Limiting** without demonstrated impact is usually Low
- Score what you **proved**, not theoretical maximum
- Check program-specific severity guidelines — some programs override CVSS
