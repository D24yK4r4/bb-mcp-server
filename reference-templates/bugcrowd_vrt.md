# Bugcrowd VRT & Report Field Reference

> **VRT version:** 1.18 (current) — last updated 2026-03-09
> **Source:** <https://bugcrowd.com/vulnerability-rating-taxonomy>
> **Status:** captured 2026-05-05; verify before each submission in case of newer revision.

A submission's **Technical Severity** is *suggested* by the VRT but the program
ultimately decides. The taxonomy hierarchy is:
**VRT Category → Specific vulnerability name → Variant / Affected function → Priority (P1–P5 / Varies)**

---

## Severity Scale

| Priority | Meaning |
|----------|---------|
| **P1** | Critical |
| **P2** | High |
| **P3** | Medium |
| **P4** | Low |
| **P5** | Informational |
| **Varies** | Program-specific — depends on context, brief, or asset criticality |

---

## Report Form Fields (Bugcrowd UI)

All fields required unless marked optional.

| Field | Required | Notes |
|-------|----------|-------|
| **Submission title** | Yes | One-line summary of the vulnerability |
| **Target** | Yes | Pick from program scope dropdown. Out-of-scope targets may be ineligible. |
| **Technical severity** | Yes | VRT-suggested; program may override |
| **VRT Category** | Yes | Select vuln type (XSS, SQLi, IDOR, etc.) — drives severity suggestion |
| **URL / Location of vulnerability** | Optional | Full URL, e.g. `https://secure.server.com/some/path/file.php` |
| **Description** | Yes | Vuln + impact + PoC + repro steps. **Max 25,000 characters.** |
| **Attachments** | Optional | Up to **20 files**, **400 MiB** each. Markdown embeds for `.jpg/.gif/.png` ≤ 50 MB. |

> **Pro-tip from Bugcrowd:** new accounts and accounts with spammy behaviour
> have submission volume limits. High-quality, well-documented reports build
> reputation faster.

---

## Full VRT (v1.18) — by Priority

### P1 — Critical

| Category | Specific vulnerability | Variant |
|----------|------------------------|---------|
| AI Application Security | Model Extraction | API Query-Based Model Reconstruction |
| AI Application Security | Remote Code Execution | Full System Compromise |
| AI Application Security | Sensitive Information Disclosure | Cross-Tenant PII Leakage/Exposure |
| AI Application Security | Sensitive Information Disclosure | Key Leak |
| AI Application Security | Training Data Poisoning | Backdoor Injection / Bias Manipulation |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Sensitive data Leakage/Exposure |
| Automotive Security Misconfiguration | RF Hub | Key Fob Cloning |
| Broken Access Control (BAC) | Insecure Direct Object References (IDOR) | Modify/View Sensitive Information (Iterable Object Identifiers) |
| Broken Authentication and Session Management | Authentication Bypass | — |
| Cloud Security | Identity and Access Management (IAM) Misconfigurations | Publicly Accessible IAM Credentials |
| Decentralized Application Misconfiguration | Insecure Data Storage | Plaintext Private Key |
| Decentralized Application Misconfiguration | Marketplace Security | Orderbook Manipulation |
| Decentralized Application Misconfiguration | Marketplace Security | Signer Account Takeover |
| Decentralized Application Misconfiguration | Marketplace Security | Unauthorized Asset Transfer |
| Decentralized Application Misconfiguration | Protocol Security Misconfiguration | Node-level Denial of Service |
| Insecure OS/Firmware | Command Injection | — |
| Insecure OS/Firmware | Hardcoded Password | Privileged User |
| Sensitive Data Exposure | Disclosure of Secrets | For Publicly Accessible Asset |
| Server Security Misconfiguration | Exposed Portal | Admin Portal |
| Server Security Misconfiguration | Using Default Credentials | — |
| Server-Side Injection | File Inclusion | Local |
| Server-Side Injection | Remote Code Execution (RCE) | — |
| Server-Side Injection | SQL Injection | — |
| Server-Side Injection | XML External Entity Injection (XXE) | — |
| Smart Contract Misconfiguration | Reentrancy Attack | — |
| Smart Contract Misconfiguration | Smart Contract Owner Takeover | — |
| Smart Contract Misconfiguration | Unauthorized Transfer of Funds | — |
| Smart Contract Misconfiguration | Uninitialized Variables | — |
| Zero Knowledge Security Misconfiguration | Deanonymization of Data | — |
| Zero Knowledge Security Misconfiguration | Improper Proof Validation and Finalization Logic | — |

### P2 — High

| Category | Specific vulnerability | Variant |
|----------|------------------------|---------|
| AI Application Security | Denial-of-Service (DoS) | Application-Wide |
| AI Application Security | Prompt Injection | System Prompt Leakage |
| AI Application Security | Remote Code Execution | Sandboxed Container Code Execution |
| AI Application Security | Vector and Embedding Weaknesses | Embedding Exfiltration / Model Extraction |
| Application-Level Denial-of-Service (DoS) | Critical Impact and/or Easy Difficulty | — |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Code Execution (CAN Bus Pivot) |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | OTA Firmware Manipulation |
| Automotive Security Misconfiguration | RF Hub | CAN Injection / Interaction |
| Broken Access Control (BAC) | Insecure Direct Object References (IDOR) | Modify Sensitive Information (Iterable Object Identifiers) |
| Cloud Security | Identity and Access Management (IAM) Misconfigurations | Overly Permissive IAM Roles |
| Cloud Security | Storage Misconfigurations | Unencrypted Sensitive Data at Rest |
| Cross-Site Request Forgery (CSRF) | Application-Wide | — |
| Cross-Site Scripting (XSS) | Stored | Non-Privileged User to Anyone |
| Cryptographic Weakness | Key Reuse | Inter-Environment |
| Decentralized Application Misconfiguration | Marketplace Security | Malicious Order Offer |
| Decentralized Application Misconfiguration | Marketplace Security | Price or Fee Manipulation |
| Insecure OS/Firmware | Hardcoded Password | Non-Privileged User |
| Insecure OS/Firmware | Local Administrator on default environment | — |
| Insecure OS/Firmware | Over-Permissioned Credentials on Storage | — |
| Physical Security Issues | Weakness in physical access control | Commonly Keyed System |
| Protocol Specific Misconfiguration | Frontrunning-Enabled Attack | — |
| Protocol Specific Misconfiguration | Sandwich-Enabled Attack | — |
| Sensitive Data Exposure | Weak Password Reset Implementation | Token Leakage via Host Header Poisoning |
| Server Security Misconfiguration | OAuth Misconfiguration | Account Takeover |
| Server Security Misconfiguration | Server-Side Request Forgery (SSRF) | Internal High Impact |
| Smart Contract Misconfiguration | Integer Overflow / Underflow | — |
| Smart Contract Misconfiguration | Unauthorized Smart Contract Approval | — |

### P3 — Medium

| Category | Specific vulnerability | Variant |
|----------|------------------------|---------|
| AI Application Security | Improper Output Handling | Cross-Site Scripting (XSS) |
| AI Application Security | Vector and Embedding Weaknesses | Semantic Indexing |
| Application-Level Denial-of-Service (DoS) | High Impact and/or Medium Difficulty | — |
| Automotive Security Misconfiguration | Automatic Braking System (ABS) | Unintended Acceleration / Brake |
| Automotive Security Misconfiguration | Battery Management System | Firmware Dump |
| Automotive Security Misconfiguration | CAN | Injection (Basic Safety Message) |
| Automotive Security Misconfiguration | CAN | Injection (Battery Management System) |
| Automotive Security Misconfiguration | CAN | Injection (Headlights) |
| Automotive Security Misconfiguration | CAN | Injection (Powertrain) |
| Automotive Security Misconfiguration | CAN | Injection (Pyrotechnical Device Deployment Tool) |
| Automotive Security Misconfiguration | CAN | Injection (Sensors) |
| Automotive Security Misconfiguration | CAN | Injection (Steering Control) |
| Automotive Security Misconfiguration | CAN | Injection (Vehicle Anti-theft Systems) |
| Automotive Security Misconfiguration | Immobilizer | Engine Start |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Code Execution (No CAN Bus Pivot) |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Unauthorized Access to Services (API / Endpoints) |
| Automotive Security Misconfiguration | RF Hub | Data Leakage / Pull Encryption Mechanism |
| Broken Access Control (BAC) | Insecure Direct Object References (IDOR) | View Sensitive Information (Iterable Object Identifiers) |
| Broken Authentication and Session Management | Session Fixation | Remote Attack Vector |
| Broken Authentication and Session Management | Second Factor Authentication (2FA) Bypass | — |
| Client-Side Injection | Binary Planting | Default Folder Privilege Escalation |
| Cloud Security | Network Configuration Issues | Lack of Network Segmentation |
| Cloud Security | Network Configuration Issues | Open Management Ports to the Internet |
| Cross-Site Scripting (XSS) | Reflected | Non-Self |
| Cross-Site Scripting (XSS) | Stored | Privileged User to Privilege Elevation |
| Cross-Site Scripting (XSS) | Stored | CSRF/URL-Based |
| Cryptographic Weakness | Broken Cryptography | Use of Broken Cryptographic Primitive |
| Cryptographic Weakness | Insecure Key Generation | Insufficient Key Space |
| Decentralized Application Misconfiguration | Marketplace Security | OFAC Bypass |
| Insecure OS/Firmware | Shared Credentials on Storage | — |
| Insecure OS/Firmware | Weakness in Firmware Updates | Firmware does not validate update integrity |
| Sensitive Data Exposure | Disclosure of Secrets | For Internal Asset |
| Sensitive Data Exposure | EXIF Geolocation Data Not Stripped From Uploaded Images | Automatic User Enumeration |
| Server Security Misconfiguration | Exposed Portal | Non-Admin Portal |
| Server Security Misconfiguration | Mail Server Misconfiguration | No Spoofing Protection on Email Domain |
| Server Security Misconfiguration | Misconfigured DNS | Subdomain Takeover |
| Server Security Misconfiguration | Server-Side Request Forgery (SSRF) | Internal Scan and/or Medium Impact |
| Server-Side Injection | Content Spoofing | iframe Injection |
| Server-Side Injection | HTTP Response Manipulation | Response Splitting (CRLF) |
| Smart Contract Misconfiguration | Function-level Denial of Service | — |
| Smart Contract Misconfiguration | Improper Fee Implementation | — |
| Smart Contract Misconfiguration | Irreversible Function Call | — |
| Smart Contract Misconfiguration | Malicious Superuser Risk | — |

### P4 — Low

| Category | Specific vulnerability | Variant |
|----------|------------------------|---------|
| AI Application Security | Adversarial Example Injection | AI Misclassification Attacks |
| AI Application Security | AI Safety | Misinformation / Wrong Factual Data |
| AI Application Security | Denial-of-Service (DoS) | Tenant-Scoped |
| AI Application Security | Improper Output Handling | Markdown/HTML Injection |
| AI Application Security | Insufficient Rate Limiting | Query Flooding / API Token Abuse |
| Automotive Security Misconfiguration | Battery Management System | Fraudulent Interface |
| Automotive Security Misconfiguration | CAN | Injection (Disallowed Messages) |
| Automotive Security Misconfiguration | CAN | Injection (DoS) |
| Automotive Security Misconfiguration | GNSS / GPS | Spoofing |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Default Credentials |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Denial of Service (DoS / Brick) |
| Automotive Security Misconfiguration | Infotainment, Radio Head Unit | Source Code Dump |
| Automotive Security Misconfiguration | RF Hub | Unauthorized Access / Turn On |
| Automotive Security Misconfiguration | Roadside Unit (RSU) | Sybil Attack |
| Broken Access Control (BAC) | Bypass of Password Confirmation | Change Password |
| Broken Access Control (BAC) | Insecure Direct Object References (IDOR) | Modify/View Sensitive Information (Complex Object Identifiers GUID/UUID) |
| Broken Access Control (BAC) | Username/Email Enumeration | Non-Brute Force |
| Broken Authentication and Session Management | Cleartext Transmission of Session Token | — |
| Broken Authentication and Session Management | Failure to Invalidate Session | On Logout (Client and Server-Side) |
| Broken Authentication and Session Management | Failure to Invalidate Session | On Password Reset and/or Change |
| Broken Authentication and Session Management | Weak Login Function | Other Plaintext Protocol with no Secure Alternative |
| Broken Authentication and Session Management | Weak Login Function | Over HTTP |
| Broken Authentication and Session Management | Weak Registration Implementation | Over HTTP |
| Cloud Security | Misconfigured Services and APIs | Insecure API Endpoints |
| Cross-Site Scripting (XSS) | Off-Domain | Data URI |
| Cross-Site Scripting (XSS) | Referer | — |
| Cross-Site Scripting (XSS) | Stored | Privileged User to No Privilege Elevation |
| Cross-Site Scripting (XSS) | Universal (UXSS) | — |
| Cryptographic Weakness | Broken Cryptography | Use of Vulnerable Cryptographic Library |
| Cryptographic Weakness | Insecure Key Generation | Key Exchange Without Entity Authentication |
| Cryptographic Weakness | Insufficient Entropy | Limited Random Number Generator (RNG) Entropy Source |
| Cryptographic Weakness | Insufficient Entropy | Predictable Initialization Vector (IV) |
| Cryptographic Weakness | Insufficient Entropy | Predictable Pseudo-Random Number Generator (PRNG) Seed |
| Cryptographic Weakness | Insufficient Entropy | Small Seed Space in Pseudo-Random Number Generator (PRNG) |
| Cryptographic Weakness | Insufficient Verification of Data Authenticity | Integrity Check Value (ICV) |
| Cryptographic Weakness | Key Reuse | Lack of Perfect Forward Secrecy |
| Cryptographic Weakness | Side-Channel Attack | Padding Oracle Attack |
| Cryptographic Weakness | Side-Channel Attack | Timing Attack |
| Cryptographic Weakness | Use of Expired Cryptographic Key (or Certificate) | — |
| Insecure Data Storage | Sensitive Application Data Stored Unencrypted | On External Storage |
| Insecure Data Storage | Server-Side Credentials Storage | Plaintext |
| Insecure Data Transport | Executable Download | No Secure Integrity Check |
| Insufficient Security Configurability | No Password Policy | — |
| Insufficient Security Configurability | Weak Password Reset Implementation | Token is Not Invalidated After Use |
| Insufficient Security Configurability | Weak 2FA Implementation | 2FA Secret Cannot be Rotated |
| Insufficient Security Configurability | Weak 2FA Implementation | 2FA Secret Remains Obtainable After 2FA is Enabled |
| Privacy Concerns | Unnecessary Data Collection | WiFi SSID+Password |
| Sensitive Data Exposure | Disclosure of Secrets | Pay-Per-Use Abuse |
| Sensitive Data Exposure | EXIF Geolocation Data Not Stripped From Uploaded Images | Manual User Enumeration |
| Sensitive Data Exposure | Sensitive Token in URL | User Facing |
| Sensitive Data Exposure | Token Leakage via Referer | Over HTTP |
| Sensitive Data Exposure | Token Leakage via Referer | Untrusted 3rd Party |
| Sensitive Data Exposure | Via localStorage/sessionStorage | Sensitive Token |
| Sensitive Data Exposure | Visible Detailed Error/Debug Page | Detailed Server Configuration |
| Sensitive Data Exposure | Weak Password Reset Implementation | Password Reset Token Sent Over HTTP |
| Server Security Misconfiguration | CAPTCHA | Implementation Vulnerability |
| Server Security Misconfiguration | Clickjacking | Sensitive Click-Based Action |
| Server Security Misconfiguration | Database Management System (DBMS) Misconfiguration | Excessively Privileged User / DBA |
| Server Security Misconfiguration | Lack of Password Confirmation | Delete Account |
| Server Security Misconfiguration | Lack of Security Headers | Cache-Control for a Sensitive Page |
| Server Security Misconfiguration | Mail Server Misconfiguration | Email Spoofing to Inbox due to Missing or Misconfigured DMARC on Email Domain |
| Server Security Misconfiguration | Misconfigured DNS | Zone Transfer |
| Server Security Misconfiguration | Missing Secure or HTTPOnly Cookie Flag | Session Token |
| Server Security Misconfiguration | No Rate Limiting on Form | Email-Triggering |
| Server Security Misconfiguration | No Rate Limiting on Form | Login |
| Server Security Misconfiguration | No Rate Limiting on Form | Registration |
| Server Security Misconfiguration | No Rate Limiting on Form | SMS-Triggering |
| Server Security Misconfiguration | OAuth Misconfiguration | Account Squatting |
| Server Security Misconfiguration | Web Application Firewall (WAF) Bypass | Direct Server Access |
| Server-Side Injection | Content Spoofing | Email HTML Injection |
| Server-Side Injection | Content Spoofing | External Authentication Injection |
| Server-Side Injection | Content Spoofing | Impersonation via Broken Link Hijacking |
| Server-Side Injection | Server-Side Template Injection (SSTI) | Basic |
| Smart Contract Misconfiguration | Improper Decimals Implementation | — |
| Smart Contract Misconfiguration | Improper Use of Modifier | — |
| Unvalidated Redirects and Forwards | Open Redirect | GET-Based |

### P5 — Informational

| Category | Specific vulnerability | Variant |
|----------|------------------------|---------|
| AI Application Security | Improper Input Handling | ANSI Escape Codes |
| AI Application Security | Improper Input Handling | RTL Overrides |
| AI Application Security | Improper Input Handling | Unicode Confusables |
| Application-Level Denial-of-Service (DoS) | App Crash | Malformed Android Intents |
| Application-Level Denial-of-Service (DoS) | App Crash | Malformed iOS URL Schemes |
| Automotive Security Misconfiguration | RF Hub | Relay |
| Automotive Security Misconfiguration | RF Hub | Replay |
| Automotive Security Misconfiguration | RF Hub | Roll Jam |
| Broken Access Control (BAC) | Insecure Direct Object References (IDOR) | View Non-Sensitive Information |
| Broken Authentication and Session Management | Concurrent Logins | — |
| Broken Authentication and Session Management | Failure to Invalidate Session | Concurrent Sessions On Logout |
| Broken Authentication and Session Management | Failure to Invalidate Session | Long Timeout |
| Broken Authentication and Session Management | Failure to Invalidate Session | On Email Change |
| Broken Authentication and Session Management | Failure to Invalidate Session | On Logout (Server-Side Only) |
| Broken Authentication and Session Management | Failure to Invalidate Session | On 2FA Activation/Change |
| Broken Authentication and Session Management | SAML Replay | — |
| Broken Authentication and Session Management | Session Fixation | Local Attack Vector |
| Broken Authentication and Session Management | Weak Login Function | Not Operational or Intended Public Access |
| Client-Side Injection | Binary Planting | No Privilege Escalation |
| Client-Side Injection | Binary Planting | Non-Default Folder Privilege Escalation |
| Cloud Security | Logging and Monitoring Issues | Disabled or Insufficient Logging |
| Cross-Site Request Forgery (CSRF) | Action-Specific | Logout |
| Cross-Site Request Forgery (CSRF) | CSRF Token Not Unique Per Request | — |
| Cross-Site Request Forgery (CSRF) | Flash-Based | — |
| Cross-Site Scripting (XSS) | Cookie-Based | — |
| Cross-Site Scripting (XSS) | Flash-Based | — |
| Cross-Site Scripting (XSS) | IE-Only | — |
| Cross-Site Scripting (XSS) | Reflected | Self |
| Cross-Site Scripting (XSS) | Stored | Self |
| Cross-Site Scripting (XSS) | TRACE Method | — |
| Cryptographic Weakness | Incomplete Cleanup of Keying Material | — |
| Cryptographic Weakness | Insufficient Entropy | Initialization Vector (IV) Reuse |
| Cryptographic Weakness | Insufficient Entropy | Pseudo-Random Number Generator (PRNG) Seed Reuse |
| Cryptographic Weakness | Insufficient Entropy | Use of True Random Number Generator (TRNG) for Non-Security Purpose |
| Cryptographic Weakness | Key Reuse | Intra-Environment |
| Cryptographic Weakness | Side-Channel Attack | Emanations Attack |
| Cryptographic Weakness | Side-Channel Attack | Power Analysis Attack |
| Cryptographic Weakness | Weak Hash | Use of Predictable Salt |
| External Behavior | Browser Feature | Aggressive Offline Caching |
| External Behavior | Browser Feature | Autocomplete Enabled |
| External Behavior | Browser Feature | Autocorrect Enabled |
| External Behavior | Browser Feature | Plaintext Password Field |
| External Behavior | Browser Feature | Save Password |
| External Behavior | Captcha Bypass | Crowdsourcing |
| External Behavior | CSV Injection | — |
| External Behavior | System Clipboard Leak | Shared Links |
| External Behavior | User Password Persisted in Memory | — |
| Insecure Data Storage | Non-Sensitive Application Data Stored Unencrypted | — |
| Insecure Data Storage | Screen Caching Enabled | — |
| Insecure Data Storage | Sensitive Application Data Stored Unencrypted | On Internal Storage |
| Insecure Data Transport | Executable Download | Secure Integrity Check |
| Insecure OS/Firmware | Data not encrypted at rest | Non sensitive |
| Insecure OS/Firmware | Weakness in Firmware Updates | Firmware is not encrypted |
| Insufficient Security Configurability | Lack of Notification Email | — |
| Insufficient Security Configurability | Password Policy Bypass | — |
| Insufficient Security Configurability | Verification of Contact Method not Required | — |
| Insufficient Security Configurability | Weak Password Policy | — |
| Insufficient Security Configurability | Weak Password Reset Implementation | Token Has Long Timed Expiry |
| Insufficient Security Configurability | Weak Password Reset Implementation | Token is Not Invalidated After Email Change |
| Insufficient Security Configurability | Weak Password Reset Implementation | Token is Not Invalidated After Login |
| Insufficient Security Configurability | Weak Password Reset Implementation | Token is Not Invalidated After New Token is Requested |
| Insufficient Security Configurability | Weak Password Reset Implementation | Token is Not Invalidated After Password Change |
| Insufficient Security Configurability | Weak Registration Implementation | Allows Disposable Email Addresses |
| Insufficient Security Configurability | Weak 2FA Implementation | Missing Failsafe |
| Insufficient Security Configurability | Weak 2FA Implementation | Old 2FA Code is Not Invalidated After New Code is Generated |
| Insufficient Security Configurability | Weak 2FA Implementation | 2FA Code is Not Updated After New Code is Requested |
| Lack of Binary Hardening | Lack of Exploit Mitigations | — |
| Lack of Binary Hardening | Lack of Jailbreak Detection | — |
| Lack of Binary Hardening | Lack of Obfuscation | — |
| Lack of Binary Hardening | Runtime Instrumentation-Based | — |
| Mobile Security Misconfiguration | Auto Backup Allowed by Default | — |
| Mobile Security Misconfiguration | Clipboard Enabled | — |
| Mobile Security Misconfiguration | SSL Certificate Pinning | Absent |
| Mobile Security Misconfiguration | SSL Certificate Pinning | Defeatable |
| Mobile Security Misconfiguration | Tapjacking | — |
| Network Security Misconfiguration | Telnet Enabled | — |
| Sensitive Data Exposure | Disclosure of Known Public Information | — |
| Sensitive Data Exposure | Disclosure of Secrets | Data/Traffic Spam |
| Sensitive Data Exposure | Disclosure of Secrets | Intentionally Public, Sample or Invalid |
| Sensitive Data Exposure | Disclosure of Secrets | Non-Corporate User |
| Sensitive Data Exposure | GraphQL Introspection Enabled | — |
| Sensitive Data Exposure | Internal IP Disclosure | — |
| Sensitive Data Exposure | JSON Hijacking | — |
| Sensitive Data Exposure | Mixed Content (HTTPS Sourcing HTTP) | — |
| Sensitive Data Exposure | Non-Sensitive Token in URL | — |
| Sensitive Data Exposure | Sensitive Data Hardcoded | File Paths |
| Sensitive Data Exposure | Sensitive Data Hardcoded | OAuth Secret |
| Sensitive Data Exposure | Sensitive Token in URL | In the Background |
| Sensitive Data Exposure | Sensitive Token in URL | On Password Reset |
| Sensitive Data Exposure | Token Leakage via Referer | Password Reset Token |
| Sensitive Data Exposure | Token Leakage via Referer | Trusted 3rd Party |
| Sensitive Data Exposure | Via localStorage/sessionStorage | Non-Sensitive Token |
| Sensitive Data Exposure | Visible Detailed Error/Debug Page | Descriptive Stack Trace |
| Sensitive Data Exposure | Visible Detailed Error/Debug Page | Full Path Disclosure |
| Server Security Misconfiguration | Bitsquatting | — |
| Server Security Misconfiguration | CAPTCHA | Brute Force |
| Server Security Misconfiguration | CAPTCHA | Missing |
| Server Security Misconfiguration | Clickjacking | Form Input |
| Server Security Misconfiguration | Clickjacking | Non-Sensitive Action |
| Server Security Misconfiguration | Cookie Scoped to Parent Domain | — |
| Server Security Misconfiguration | Directory Listing Enabled | Non-Sensitive Data Exposure |
| Server Security Misconfiguration | Email Verification Bypass | — |
| Server Security Misconfiguration | Exposed Portal | Protected |
| Server Security Misconfiguration | Fingerprinting/Banner Disclosure | — |
| Server Security Misconfiguration | Insecure SSL | Certificate Error |
| Server Security Misconfiguration | Insecure SSL | Insecure Cipher Suite |
| Server Security Misconfiguration | Insecure SSL | Lack of Forward Secrecy |
| Server Security Misconfiguration | Lack of Password Confirmation | Change Email Address |
| Server Security Misconfiguration | Lack of Password Confirmation | Change Password |
| Server Security Misconfiguration | Lack of Password Confirmation | Manage 2FA |
| Server Security Misconfiguration | Lack of Security Headers | Cache-Control for a Non-Sensitive Page |
| Server Security Misconfiguration | Lack of Security Headers | Content-Security-Policy |
| Server Security Misconfiguration | Lack of Security Headers | Content-Security-Policy-Report-Only |
| Server Security Misconfiguration | Lack of Security Headers | Public-Key-Pins |
| Server Security Misconfiguration | Lack of Security Headers | Strict-Transport-Security |
| Server Security Misconfiguration | Lack of Security Headers | X-Content-Security-Policy |
| Server Security Misconfiguration | Lack of Security Headers | X-Content-Type-Options |
| Server Security Misconfiguration | Lack of Security Headers | X-Frame-Options |
| Server Security Misconfiguration | Lack of Security Headers | X-Webkit-CSP |
| Server Security Misconfiguration | Lack of Security Headers | X-XSS-Protection |
| Server Security Misconfiguration | Mail Server Misconfiguration | Email Spoofing on Non-Email Domain |
| Server Security Misconfiguration | Mail Server Misconfiguration | Email Spoofing to Spam Folder |
| Server Security Misconfiguration | Mail Server Misconfiguration | Missing or Misconfigured SPF and/or DKIM |
| Server Security Misconfiguration | Misconfigured DNS | Missing Certification Authority Authorization (CAA) Record |
| Server Security Misconfiguration | Missing DNSSEC | — |
| Server Security Misconfiguration | Missing Secure or HTTPOnly Cookie Flag | Non-Session Cookie |
| Server Security Misconfiguration | Missing Subresource Integrity | — |
| Server Security Misconfiguration | No Rate Limiting on Form | Change Password |
| Server Security Misconfiguration | Potentially Unsafe HTTP Method Enabled | OPTIONS |
| Server Security Misconfiguration | Potentially Unsafe HTTP Method Enabled | TRACE |
| Server Security Misconfiguration | Reflected File Download (RFD) | — |
| Server Security Misconfiguration | Same-Site Scripting | — |
| Server Security Misconfiguration | Server-Side Request Forgery (SSRF) | External - DNS Query Only |
| Server Security Misconfiguration | Server-Side Request Forgery (SSRF) | External - Low impact |
| Server Security Misconfiguration | Unsafe File Upload | File Extension Filter Bypass |
| Server Security Misconfiguration | Unsafe File Upload | No Antivirus |
| Server Security Misconfiguration | Unsafe File Upload | No Size Limit |
| Server Security Misconfiguration | Username/Email Enumeration | Brute Force |
| Server-Side Injection | Content Spoofing | Email Hyperlink Injection Based on Email Provider |
| Server-Side Injection | Content Spoofing | Flash Based External Authentication Injection |
| Server-Side Injection | Content Spoofing | Homograph/IDN-Based |
| Server-Side Injection | Content Spoofing | HTML Content Injection |
| Server-Side Injection | Content Spoofing | Right-to-Left Override (RTLO) |
| Server-Side Injection | Content Spoofing | Text Injection |
| Server-Side Injection | Exposed Data | Non Sensitive Data |
| Server-Side Injection | Parameter Pollution | Social Media Sharing Buttons |
| Unvalidated Redirects and Forwards | Lack of Security Speed Bump Page | — |
| Unvalidated Redirects and Forwards | Open Redirect | Flash-Based |
| Unvalidated Redirects and Forwards | Open Redirect | Header-Based |
| Unvalidated Redirects and Forwards | Open Redirect | POST-Based |
| Unvalidated Redirects and Forwards | Tabnabbing | — |
| Using Components with Known Vulnerabilities | Captcha Bypass | OCR (Optical Character Recognition) |
| Using Components with Known Vulnerabilities | Outdated Software Version | — |
| Using Components with Known Vulnerabilities | Rosetta Flash | — |

### Varies — Program-Specific (priority depends on context)

| Category | Specific vulnerability | Variant |
|----------|------------------------|---------|
| Algorithmic Biases | Aggregation Bias | — |
| Algorithmic Biases | Processing Bias | — |
| Application-Level Denial-of-Service (DoS) | Excessive Resource Consumption | Injection (Prompt) |
| Blockchain Infrastructure Misconfiguration | Improper Bridge Validation and Verification Logic | — |
| Broken Access Control (BAC) | Exposed Sensitive Android Intent | — |
| Broken Access Control (BAC) | Exposed Sensitive iOS URL Scheme | — |
| Broken Access Control (BAC) | Privilege Escalation | — |
| Broken Authentication and Session Management | Failure to Invalidate Session | On Permission Change |
| Cloud Security | Misconfigured Services and APIs | Exposed Debug or Admin Interfaces |
| Cloud Security | Storage Misconfigurations | Publicly Accessible Cloud Storage |
| Cross-Site Request Forgery (CSRF) | Action-Specific | Authenticated Action |
| Cross-Site Request Forgery (CSRF) | Action-Specific | Unauthenticated Action |
| Cryptographic Weakness | Insecure Implementation | Improper Following of Specification (Other) |
| Cryptographic Weakness | Insecure Implementation | Missing Cryptographic Step |
| Cryptographic Weakness | Insecure Key Generation | Improper Asymmetric Exponent Selection |
| Cryptographic Weakness | Insecure Key Generation | Improper Asymmetric Prime Selection |
| Cryptographic Weakness | Insecure Key Generation | Insufficient Key Stretching |
| Cryptographic Weakness | Insufficient Verification of Data Authenticity | Cryptographic Signature |
| Cryptographic Weakness | Side-Channel Attack | Differential Fault Analysis |
| Cryptographic Weakness | Weak Hash | Lack of Salt |
| Cryptographic Weakness | Weak Hash | Predictable Hash Collision |
| Data Biases | Pre-existing Bias | — |
| Data Biases | Representation Bias | — |
| Decentralized Application Misconfiguration | DeFi Security | Flash Loan Attack |
| Decentralized Application Misconfiguration | DeFi Security | Function-Level Accounting Error |
| Decentralized Application Misconfiguration | DeFi Security | Improper Implementation of Governance |
| Decentralized Application Misconfiguration | DeFi Security | Pricing Oracle Manipulation |
| Decentralized Application Misconfiguration | Improper Authorization | Insufficient Signature Validation |
| Decentralized Application Misconfiguration | Insecure Data Storage | Sensitive Information Exposure |
| Decentralized Application Misconfiguration | Marketplace Security | Denial of Service |
| Decentralized Application Misconfiguration | Marketplace Security | Improper Validation and Checks For Deposits and Withdrawals |
| Decentralized Application Misconfiguration | Marketplace Security | Miscalculated Accounting Logic |
| Developer Biases | Implicit Bias | — |
| Indicators of Compromise | — | — |
| Insecure Data Transport | Cleartext Transmission of Sensitive Data | — |
| Insecure OS/Firmware | Data not encrypted at rest | Sensitive |
| Insecure OS/Firmware | Failure to Remove Sensitive Artifacts from Disk | — |
| Insecure OS/Firmware | Kiosk Escape or Breakout | — |
| Insecure OS/Firmware | Poorly Configured Disk Encryption | — |
| Insecure OS/Firmware | Poorly Configured Operating System Security | — |
| Insecure OS/Firmware | Recovery of Disk Contains Sensitive Material | — |
| Insecure OS/Firmware | Weakness in Firmware Updates | Firmware cannot be updated |
| Misinterpretation Biases | Context Ignorance | — |
| Physical Security Issues | Bypass of physical access control | — |
| Physical Security Issues | Weakness in physical access control | Cloneable Key |
| Physical Security Issues | Weakness in physical access control | Master Key Identification |
| Protocol Specific Misconfiguration | Improper Validation and Finalization Logic | — |
| Protocol Specific Misconfiguration | Misconfigured Staking Logic | — |
| Sensitive Data Exposure | Disclosure of Secrets | PII Leakage/Exposure |
| Sensitive Data Exposure | Cross Site Script Inclusion (XSSI) | — |
| Server Security Misconfiguration | Cache Deception | — |
| Server Security Misconfiguration | Cache Poisoning | — |
| Server Security Misconfiguration | Directory Listing Enabled | Sensitive Data Exposure |
| Server Security Misconfiguration | OAuth Misconfiguration | Insecure Redirect URI |
| Server Security Misconfiguration | OAuth Misconfiguration | Missing/Broken State Parameter |
| Server Security Misconfiguration | Path Traversal | — |
| Server Security Misconfiguration | Race Condition | — |
| Server Security Misconfiguration | HTTP Request Smuggling | — |
| Server Security Misconfiguration | Software Package Takeover | — |
| Server Security Misconfiguration | SSL Attack (BREACH, POODLE etc.) | — |
| Server Security Misconfiguration | Unsafe Cross-Origin Resource Sharing | — |
| Server-Side Injection | Exposed Data | Sensitive Data |
| Server-Side Injection | LDAP Injection | — |
| Server-Side Injection | Server-Side Template Injection (SSTI) | Custom |
| Smart Contract Misconfiguration | Bypass of Function Modifiers and Checks | — |
| Smart Contract Misconfiguration | Inaccurate Rounding Calculation | — |
| Societal Biases | Confirmation Bias | — |
| Societal Biases | Systemic Bias | — |
| Zero Knowledge Security Misconfiguration | Misconfigured Trusted Setup | — |
| Zero Knowledge Security Misconfiguration | Mismatching Bit Lengths | — |
| Zero Knowledge Security Misconfiguration | Missing Constraint | — |
| Zero Knowledge Security Misconfiguration | Missing Range Check | — |

---

## Phase 4 QA Checklist (Bugcrowd-specific)

- [ ] VRT Category selected (most-specific available — drill from category → vuln name → variant)
- [ ] Technical severity matches the VRT default for the chosen variant (if arguing up/down, justify in description)
- [ ] Submission title is specific: `{vuln} in {component} → {impact}`
- [ ] Target picked from program scope dropdown — not free text
- [ ] Description ≤ 25,000 characters, includes vuln + impact + PoC + repro
- [ ] Attachments ≤ 20 files, each ≤ 400 MiB; embed images inline if ≤ 50 MB
- [ ] No out-of-scope information referenced
- [ ] PII (other users' emails/names/IDs) redacted in screenshots and PoC
- [ ] If the variant is `Varies`, justify the proposed priority based on program asset criticality
