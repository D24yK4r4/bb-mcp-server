# CWE Mapping Reference for Bug Bounty Reports

Use the **most specific CWE** that matches the vulnerability. Don't use parent categories when a child fits.

---

## Injection

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| SQL Injection (generic) | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command |
| SQL Injection (blind) | CWE-89 | Same CWE, specify blind in description |
| NoSQL Injection | CWE-943 | Improper Neutralization of Special Elements in Data Query Logic |
| LDAP Injection | CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query |
| Command Injection (OS) | CWE-78 | Improper Neutralization of Special Elements used in an OS Command |
| Code Injection | CWE-94 | Improper Control of Generation of Code |
| SSTI | CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine |
| XPath Injection | CWE-643 | Improper Neutralization of Data within XPath Expressions |
| Header Injection (HTTP) | CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers |
| Log Injection | CWE-117 | Improper Output Neutralization for Logs |

## Cross-Site Scripting (XSS)

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| Reflected XSS | CWE-79 | Improper Neutralization of Input During Web Page Generation |
| Stored XSS | CWE-79 | Same CWE, specify stored in description |
| DOM-Based XSS | CWE-79 | Same CWE, specify DOM-based in description |

## Authentication & Session

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| Broken Authentication | CWE-287 | Improper Authentication |
| Default Credentials | CWE-1393 | Use of Default Credentials |
| Weak Password Requirements | CWE-521 | Weak Password Requirements |
| Session Fixation | CWE-384 | Session Fixation |
| Insufficient Session Expiration | CWE-613 | Insufficient Session Expiration |
| Missing MFA | CWE-308 | Use of Single-factor Authentication |
| Brute Force (no rate limit) | CWE-307 | Improper Restriction of Excessive Authentication Attempts |
| Account Takeover via Password Reset | CWE-640 | Weak Password Recovery Mechanism for Forgotten Password |

## Authorization / Access Control

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| IDOR (generic) | CWE-639 | Authorization Bypass Through User-Controlled Key |
| Horizontal Privilege Escalation | CWE-639 | Same — user A accesses user B's data |
| Vertical Privilege Escalation | CWE-269 | Improper Privilege Management |
| Missing Function Level Access Control | CWE-285 | Improper Authorization |
| Forced Browsing | CWE-425 | Direct Request (Forced Browsing) |
| CORS Misconfiguration | CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |

## Server-Side

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| SSRF | CWE-918 | Server-Side Request Forgery |
| XXE | CWE-611 | Improper Restriction of XML External Entity Reference |
| Path Traversal / LFI | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory |
| Remote File Inclusion | CWE-98 | Improper Control of Filename for Include/Require Statement |
| Unrestricted File Upload | CWE-434 | Unrestricted Upload of File with Dangerous Type |
| Deserialization | CWE-502 | Deserialization of Untrusted Data |
| Race Condition | CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization |

## Client-Side

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| CSRF | CWE-352 | Cross-Site Request Forgery |
| Clickjacking | CWE-1021 | Improper Restriction of Rendered UI Layers or Frames |
| Open Redirect | CWE-601 | URL Redirection to Untrusted Site |
| Tabnabbing | CWE-1022 | Use of Web Link to Untrusted Target with window.opener Access |
| Prototype Pollution | CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes |
| PostMessage Vulnerability | CWE-345 | Insufficient Verification of Data Authenticity |

## Cryptography

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| Weak Algorithm | CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| Hard-coded Credentials | CWE-798 | Use of Hard-coded Credentials |
| Hard-coded Crypto Key | CWE-321 | Use of Hard-coded Cryptographic Key |
| Insufficient Key Size | CWE-326 | Inadequate Encryption Strength |
| Missing Encryption | CWE-311 | Missing Encryption of Sensitive Data |
| Weak Random | CWE-330 | Use of Insufficiently Random Values |
| JWT None Algorithm | CWE-345 | Insufficient Verification of Data Authenticity |
| JWT Weak Secret | CWE-521 | Weak Password Requirements |

## Information Disclosure

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| Sensitive Data in Error Messages | CWE-209 | Generation of Error Message Containing Sensitive Information |
| Debug Information Exposed | CWE-215 | Insertion of Sensitive Information Into Debugging Code |
| Source Code Disclosure | CWE-540 | Inclusion of Sensitive Information in Source Code |
| Directory Listing | CWE-548 | Exposure of Information Through Directory Listing |
| .git Exposure | CWE-538 | Insertion of Sensitive Information into Externally-Accessible File |
| Excessive Data in API Response | CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies |
| Stack Trace Disclosure | CWE-209 | Same as error messages |

## Configuration / Deployment

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| Missing Security Headers | CWE-693 | Protection Mechanism Failure |
| Missing HSTS | CWE-319 | Cleartext Transmission of Sensitive Information |
| Missing CSP | CWE-693 | Protection Mechanism Failure |
| HTTP when HTTPS available | CWE-319 | Cleartext Transmission of Sensitive Information |
| Exposed Admin Panel | CWE-749 | Exposed Dangerous Method or Function |
| Subdomain Takeover | CWE-913 | Improper Control of Dynamically-Managed Code Resources |

## Business Logic

| Vulnerability | CWE | Description |
|--------------|-----|-------------|
| Price Manipulation | CWE-472 | External Control of Assumed-Immutable Web Parameter |
| Workflow Bypass | CWE-841 | Improper Enforcement of Behavioral Workflow |
| Mass Assignment | CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Rate Limit Bypass | CWE-770 | Allocation of Resources Without Limits or Throttling |

---

## Bugcrowd VRT Mapping

Bugcrowd uses its own Vulnerability Rating Taxonomy (VRT). Common mappings:

| Finding | VRT Category |
|---------|-------------|
| XSS (Stored) | Cross-Site Scripting (XSS) > Stored |
| XSS (Reflected) | Cross-Site Scripting (XSS) > Reflected |
| SQLi | Server Security Misconfiguration > SQL Injection |
| IDOR | Broken Access Control (BAC) > IDOR |
| SSRF | Server Security Misconfiguration > SSRF |
| Open Redirect | Unvalidated Redirects and Forwards > Open Redirect |
| CSRF | Cross-Site Request Forgery (CSRF) |

Check the current VRT at: https://bugcrowd.com/vulnerability-rating-taxonomy
