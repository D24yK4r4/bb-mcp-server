# Bug Bounty Tools Reference

Quick syntax reference for common tools. Always check `brief.md` for program-specific scanning restrictions.

---

## Subdomain Enumeration

### Subfinder
```bash
subfinder -d target.com -silent -o subs.txt
subfinder -d target.com -silent -recursive -o subs.txt    # recursive
subfinder -d target.com -silent -sources shodan,censys     # specific sources
```

### Amass (passive only for bug bounty)
```bash
amass enum -passive -d target.com -o amass.txt
amass enum -passive -d target.com -src -o amass.txt    # show sources
```

### Assetfinder
```bash
assetfinder --subs-only target.com > assetfinder.txt
```

### httpx (probe alive hosts)
```bash
httpx -l subs.txt -silent -status-code -title -tech-detect -o alive.txt
httpx -l subs.txt -silent -status-code -content-length -follow-redirects -o alive.txt
httpx -l subs.txt -silent -json -o alive.json    # full JSON output
```

---

## Port Scanning

### Nmap
```bash
# Quick scan
nmap -sC -sV --top-ports 1000 $TARGET -oA nmap_quick

# Full scan
nmap -sC -sV -p- --open $TARGET -oA nmap_full

# UDP top ports
nmap -sU --top-ports 50 $TARGET -oA nmap_udp

# Vuln scan (specific ports only)
nmap -sV -p 80,443,8080 --script=vuln $TARGET | grep -E "VULNERABLE|CVE" | head -20

# Service version on specific port
nmap -sV -p 8443 $TARGET
```

### Masscan (fast, use with caution)
```bash
masscan -p1-65535 $TARGET --rate=1000 -oL masscan.txt
```

---

## Web Content Discovery

### Feroxbuster
```bash
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,js,json,bak,conf \
  -o ferox.txt -q --no-recursion

# With auth
feroxbuster -u https://target.com \
  -H "Authorization: Bearer <token>" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -o ferox.txt -q
```

### Ffuf
```bash
# Directory brute
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -fc 404 -o ffuf.json -of json

# Vhost discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fc 301,302,404 -o vhosts.json -of json -s

# Parameter fuzzing
ffuf -u "https://target.com/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fc 404 -fs <default-size>

# POST data fuzzing
ffuf -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/wordlists/rockyou.txt \
  -fc 401 -H "Content-Type: application/x-www-form-urlencoded"
```

### Gobuster
```bash
gobuster dir -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt -o gobuster.txt -q

gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -q
```

---

## Wordlists

### Paths
```
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv
/usr/share/seclists/Fuzzing/special-chars.txt
/usr/share/seclists/Fuzzing/SQLi/
/usr/share/seclists/Fuzzing/XSS/
/usr/share/wordlists/rockyou.txt
```

---

## Technology Fingerprinting

### Whatweb
```bash
whatweb https://target.com 2>/dev/null
whatweb -a 3 https://target.com 2>/dev/null    # aggressive
```

### Wappalyzer (CLI)
```bash
wappalyzer https://target.com 2>/dev/null
```

### Manual Headers Check
```bash
curl -si https://target.com | grep -iE "Server:|X-Powered-By:|Set-Cookie:|X-Frame|Content-Security|X-Content-Type|Strict-Transport" | head -10
```

---

## Nuclei (only if program allows automated scanning)

```bash
# Safe templates only
nuclei -u https://target.com -t exposures/ -t misconfiguration/ -silent | head -20
nuclei -u https://target.com -t cves/ -severity critical,high -silent | head -20

# Against list of URLs
nuclei -l alive.txt -t exposures/ -silent -o nuclei_results.txt
cat nuclei_results.txt | head -30

# Specific template
nuclei -u https://target.com -t cves/2024/ -silent
```

---

## SQLMap (use responsibly)

```bash
# Basic test
sqlmap -u "https://target.com/page?id=1" --batch --level 2 --risk 1

# With cookie/auth
sqlmap -u "https://target.com/page?id=1" --cookie="session=abc123" --batch

# POST request
sqlmap -u "https://target.com/api" --data="id=1&name=test" --batch

# From Burp request file
sqlmap -r request.txt --batch --level 2

# Safe options for bug bounty
sqlmap -u "URL" --batch --level 2 --risk 1 --threads 1 --delay 1 \
  --technique=BEUST --no-cast --tamper=space2comment
```

**IMPORTANT:** Never use `--os-shell`, `--file-write`, `--file-read` on real targets. Prove the injection, extract version/user/db name only.

---

## Burp Suite

### Proxy Setup
```
Proxy: 127.0.0.1:8080
Browser: configure proxy or use FoxyProxy
```

### Useful Extensions
- Autorize (IDOR/authz testing)
- JWT Editor
- Param Miner
- Turbo Intruder
- Active Scan++

---

## Curl (manual testing)

```bash
# Basic request with headers
curl -si https://target.com/api/endpoint

# POST with JSON
curl -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'

# With auth token
curl -s https://target.com/api/user \
  -H "Authorization: Bearer <token>"

# CORS check
curl -s -H "Origin: https://evil.com" -I https://target.com/api/user

# Follow redirects
curl -sL https://target.com/redirect?url=https://evil.com

# Upload file
curl -s -X POST https://target.com/upload \
  -F "file=@test.php" -H "Authorization: Bearer <token>"

# With proxy (Burp)
curl -s --proxy http://127.0.0.1:8080 -k https://target.com/api/endpoint
```

---

## Git Dumper (exposed .git)

```bash
# Check if .git is exposed
curl -s https://target.com/.git/HEAD

# Dump the repo
git-dumper https://target.com/.git/ ./git-dump
cd git-dump && git log --oneline | head -20
```

---

## JWT Tools

### jwt_tool
```bash
jwt_tool <token>                           # decode
jwt_tool <token> -C -d wordlist.txt        # crack secret
jwt_tool <token> -X a                      # alg:none attack
jwt_tool <token> -X k -pk public.pem       # key confusion
```

### Python (manual)
```python
import jwt
# Decode without verification
decoded = jwt.decode(token, options={"verify_signature": False})
# Forge with none
forged = jwt.encode({"sub": "admin"}, key="", algorithm="none")
```

---

## Netexec (nxc) — NOT crackmapexec

```bash
# SMB enumeration
nxc smb $TARGET -u '' -p '' --shares
nxc smb $TARGET -u 'guest' -p '' --shares
nxc smb $TARGET -u user -p pass --shares

# Check credentials across services
nxc smb $TARGET -u user -p pass
nxc winrm $TARGET -u user -p pass
nxc ldap $TARGET -u user -p pass
```

---

## Screenshot Tools

```bash
# Take screenshots of alive hosts
gowitness file -f alive.txt -P screenshots/
gowitness report generate    # HTML report

# Or with eyewitness
eyewitness --web -f alive.txt -d screenshots/
```
