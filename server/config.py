# SPDX-License-Identifier: EUPL-1.2 OR AGPL-3.0
"""
Central configuration for the Bug Bounty MCP Server.
All allowlists, paths, limits, and patterns live here.
"""

import os
import re
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────

BB_ROOT   = Path(os.environ.get('BB_ROOT',   Path.home() / 'Documents' / 'BugBounty'))
VAULT_ROOT = Path(os.environ.get('BB_VAULT', Path.home() / '.hive'))
SCRIPTS_DIR = Path(os.environ.get('BB_SCRIPTS', Path.home() / 'Documents' / 'Scripts'))
WORK_DIR    = Path('/tmp/bb_working')

ALLOWED_READ_PATHS = [
    str(BB_ROOT),
    str(SCRIPTS_DIR),
    '/usr/share/wordlists/',
    '/usr/share/seclists/',
    '/usr/share/nmap/',
    str(WORK_DIR),
]

ALLOWED_WRITE_PATHS = [
    str(BB_ROOT / 'programs'),
    str(BB_ROOT / 'recon'),
    str(VAULT_ROOT),
    str(WORK_DIR),
]

# ── Tool allowlist ─────────────────────────────────────────────────────────────

ALLOWED_TOOLS = {
    # Passive recon
    'subfinder', 'amass', 'assetfinder',
    # Active recon
    'nmap', 'httpx', 'whatweb', 'dig', 'whois',
    # Web
    'curl', 'ffuf', 'feroxbuster', 'katana', 'gospider',
    # Vuln
    'nuclei', 'sqlmap', 'dalfox',
    # Safe utilities
    'grep', 'jq', 'head', 'wc', 'sort', 'uniq', 'cut',
}

BLOCKED_TOOLS = {
    'sudo', 'su', 'bash', 'sh', 'zsh', 'fish', 'dash',
    'python3', 'python', 'perl', 'ruby', 'php',
    'gcc', 'make', 'pip', 'apt', 'apt-get', 'npm', 'yarn',
    'docker', 'kubectl', 'systemctl', 'service',
    'nc', 'netcat', 'socat', 'ncat',
    'iptables', 'ip', 'ufw', 'firewalld',
    'passwd', 'useradd', 'usermod', 'chmod', 'chown', 'chattr',
    'mount', 'umount', 'dd', 'mkfs', 'fdisk',
    'crontab', 'at', 'batch',
    'ssh', 'scp', 'sftp', 'rsync',
    'curl | bash', 'wget',
}

# Scripts that are read-only reference — never executed by MCP server
SCRIPTS_BLOCKED = {
    'reverse_shell_nc.py',
    'webshell.php',
    'venom_macro.vba',
    'ligolo-agent.exe',
    'exfil_exploit.html',
    'exfil_xss.html',
    'cors_exfil.html',
}

# ── Rate limits ────────────────────────────────────────────────────────────────
# Two different layers — both enforce the same 5 req/sec ceiling that most
# bug-bounty programs allow:
#   • RATE_LIMITS = MCP-side cooldown (seconds) between successive MCP calls of
#     the same tool. Coarse — guards against runaway agent loops.
#   • TOOL_RATE_LIMIT = the requests/sec cap passed via tool-native flags
#     (httpx -rate-limit, ffuf -rate, feroxbuster --rate-limit, nuclei
#     -rate-limit, dalfox --delay). This is what actually shapes outbound
#     traffic to the target.

TOOL_RATE_LIMIT = 2  # req/sec — leave headroom under program caps. NEVER raise above 3
                     # without operator review; CF/WAF aggregate per-zone limits are usually
                     # lower than the per-app stated limit, and a single 429 risks IP ban.
                     # Programs that explicitly allow 5–10/sec can override per-program.

# Per-host 429 circuit breaker. Once a host returns 429 (or related throttle
# signal), refuse further requests to that host AND its parent zone for
# COOLDOWN_AFTER_429 seconds. State persisted across process restarts.
COOLDOWN_AFTER_429 = 300            # 5 minutes — long enough for sliding-window throttles to fully reset
BREAKER_STATE_FILE = '/tmp/bb_429_breaker.json'

# Per-zone aggregate cap. Total requests across all bb-hunter tools to a single
# zone (e.g. *.example.com) must stay <= SAFE_RATE_PER_ZONE per second.
# Trailing 1-second window. Tool wrappers can opt in via aggregate_rate_check.
SAFE_RATE_PER_ZONE = 2              # req/sec aggregate per zone — match TOOL_RATE_LIMIT default
RATE_TRACKER_FILE  = '/tmp/bb_rate_tracker.json'

# Global rate ceiling. Total outbound across ALL bb-hunter tools (every zone,
# every program, every concurrent invocation) must stay <= GLOBAL_RATE_LIMIT
# per second. Enforced inside the executor for every network-tool launch.
GLOBAL_RATE_LIMIT      = 5          # req/sec aggregate across every tool, every zone
GLOBAL_RATE_FILE       = '/tmp/bb_global_rate.json'
GLOBAL_BUDGET_MAX_WAIT = 10         # max seconds to block waiting for budget before refusing

RATE_LIMITS: dict[str, float] = {
    'subfinder':    0.2,
    'amass':        0.2,
    'assetfinder':  0.2,
    'nmap':         5.0,   # nmap is heavy — keep coarse
    'httpx':        0.2,
    'feroxbuster':  0.2,
    'ffuf':         0.2,
    'katana':       0.2,
    'nuclei':       0.2,
    'sqlmap':       0.2,
    'dalfox':       0.2,
    'curl':         0.2,
    'default':      0.2,
}

# ── Report severity gate ───────────────────────────────────────────────────────
# Bug-bounty mission is high-impact only. create_report rejects findings below
# this threshold unless explicitly overridden with force=True.
MIN_REPORT_SEVERITY = {'high', 'critical', 'exceptional'}

# ── Output limits ──────────────────────────────────────────────────────────────

MAX_OUTPUT_LINES = 50
MAX_OUTPUT_BYTES = 8_000

# ── Sanitization patterns ──────────────────────────────────────────────────────
# Each entry: (compiled_pattern, replacement_template, vault_type)

RAW_REDACT_PATTERNS: list[tuple[str, str, str]] = [
    # Auth headers (plain HTTP format)
    # Negative lookahead `(?!<SAFE:)` prevents re-vaulting an existing SAFE token
    # if one was already substituted upstream (e.g. by the report generator's
    # backstop sanitize on user-pasted text fields).
    (r'(Authorization:\s*Bearer\s+)(?!<SAFE:)\S+', r'\1<SAFE:{id}>',  'bearer_token'),
    (r'(Authorization:\s*Basic\s+)(?!<SAFE:)\S+',  r'\1<SAFE:{id}>',  'basic_auth'),
    (r'(Authorization:\s*Token\s+)(?!<SAFE:)\S+',  r'\1<SAFE:{id}>',  'api_token'),
    # Auth headers in JSON response bodies (e.g. httpbin echoing headers back)
    (r'(?i)("Authorization":\s*"Bearer\s+)((?:(?!<SAFE:)[^"])+)(")',
                                                   r'\1<SAFE:{id}>\3', 'bearer_token'),
    (r'(?i)("Authorization":\s*"Token\s+)((?:(?!<SAFE:)[^"])+)(")',
                                                   r'\1<SAFE:{id}>\3', 'api_token'),
    # Cookies — vault VALUES only, keep names visible.
    # Convention: group(1) is the prefix kept verbatim; sensitive_value = rest of match.
    # Pattern A: first cookie after Set-Cookie:/Cookie: header
    (r'(?i)((?:set-cookie:|cookie:)\s*[A-Za-z_][\w.\-]{0,40}=)(?!<SAFE:)[^;\r\n]+',
                                                   r'\1<SAFE:{id}>',  'cookie'),
    # Pattern B: subsequent cookies separated by `;` or whitespace, value ≥20 chars
    (r'((?:[;\s])[A-Za-z_][\w.\-]{1,40}=)[A-Za-z0-9+/_\-=.%]{20,}',
                                                   r'\1<SAFE:{id}>',  'cookie'),
    # ── HIGH-SPECIFICITY SaaS / cloud tokens MUST come BEFORE the generic
    # token/secret/key/password patterns below — otherwise the generic ones
    # consume them first and re-tag as the wrong type.
    # GitHub PATs and tokens
    (r'\bgh[psoaur]_[A-Za-z0-9]{36,}',             '<SAFE:{id}>',     'github_token'),
    # Slack
    (r'\bxox[abprs]-[A-Za-z0-9-]{10,}',            '<SAFE:{id}>',     'slack_token'),
    (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
                                                   '<SAFE:{id}>',     'slack_webhook'),
    # Stripe
    (r'\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}',
                                                   '<SAFE:{id}>',     'stripe_key'),
    # Twilio Account SID (AC + 32 hex)
    (r'\bAC[0-9a-f]{32}\b',                        '<SAFE:{id}>',     'twilio_sid'),
    # SendGrid
    (r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b',
                                                   '<SAFE:{id}>',     'sendgrid_key'),
    # Mailgun
    (r'\bkey-[0-9a-f]{32}\b',                      '<SAFE:{id}>',     'mailgun_key'),
    # DigitalOcean
    (r'\bdop_v1_[a-f0-9]{64}\b',                   '<SAFE:{id}>',     'do_token'),
    # npm token
    (r'\bnpm_[A-Za-z0-9]{36}\b',                   '<SAFE:{id}>',     'npm_token'),
    # Discord bot token
    (r'\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b',
                                                   '<SAFE:{id}>',     'discord_token'),
    # Telegram bot token
    (r'\b[0-9]{9,10}:[A-Za-z0-9_-]{35}\b',         '<SAFE:{id}>',     'telegram_token'),

    # API keys in JSON/query params (generic — runs after specific SaaS patterns)
    (r'(?i)(["\']?api[_-]?key["\']?\s*[:=]\s*)["\']?([^\s\'"&,}\]\x00<>]+)["\']?',
                                                   r'\1<SAFE:{id}>',  'api_key'),
    (r'(?i)(["\']?secret["\']?\s*[:=]\s*)["\']?([^\s\'"&,}\]\x00<>]+)["\']?',
                                                   r'\1<SAFE:{id}>',  'secret'),
    (r'(?i)(["\']?token["\']?\s*[:=]\s*)["\']?([^\s\'"&,}\]\x00<>]+)["\']?',
                                                   r'\1<SAFE:{id}>',  'token'),
    (r'(?i)(["\']?password["\']?\s*[:=]\s*)["\']?([^\s\'"&,}\]\x00<>]+)["\']?',
                                                   r'\1<SAFE:{id}>',  'password'),
    # ── AWS credentials ───────────────────────────────────────────────────────
    (r'AKIA[0-9A-Z]{16}',                          '<SAFE:{id}>',     'aws_access_key'),
    (r'ASIA[0-9A-Z]{16}',                          '<SAFE:{id}>',     'aws_sts_key'),    # STS temp creds (Cognito uses these)
    (r'(?i)(aws_secret_access_key\s*=\s*)(?!<SAFE:)\S+', r'\1<SAFE:{id}>', 'aws_secret'),
    (r'(?i)(aws_session_token\s*=\s*)(?!<SAFE:)\S+',     r'\1<SAFE:{id}>', 'aws_session_token'),
    # AWS SigV4 Authorization header (signed request)
    (r'(?i)(Authorization:\s*AWS4-HMAC-SHA256\s+)((?:(?!<SAFE:)[^\r\n])+)',
                                                   r'\1<SAFE:{id}>',  'aws_sigv4'),
    # ── Azure ─────────────────────────────────────────────────────────────────
    # Azure SAS token (sig= ... &se= ...) — keep "?sig=" / "&sig=" visible
    (r'(?i)((?:[?&])sig=)[A-Za-z0-9%+/=]{20,}',    r'\1<SAFE:{id}>',  'azure_sas'),
    # Azure storage account key (88 chars, base64, ends ==)
    (r'\b[A-Za-z0-9+/]{86}==\B',                   '<SAFE:{id}>',     'azure_storage_key'),
    # ── GCP ───────────────────────────────────────────────────────────────────
    # GCP service account private_key_id (40 hex chars)
    (r'(?i)("private_key_id"\s*:\s*")([0-9a-f]{40})(")',
                                                   r'\1<SAFE:{id}>\3', 'gcp_sa_key_id'),
    # ── Database connection strings with embedded credentials ────────────────
    # (SaaS tokens deduplicated above — moved before generic key/token/secret/password)
    # postgres://user:pass@host  /  mysql://user:pass@host  /  mongodb://user:pass@host
    # 3-group form: prefix=protocol://user:, value=password, suffix=@
    (r'\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:)((?:(?!<SAFE:)[^@\s])+)(@)',
                                                   r'\1<SAFE:{id}>\3', 'db_password'),
    # Private keys
    (r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----',
                                                   '<SAFE:{id}>',     'private_key'),
    # JWTs
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                                                   '<SAFE:{id}>',     'jwt'),
    # ASP.NET Core Data Protection envelopes — must come BEFORE generic base64
    # CfDJ8 prefix decodes to magic bytes 09F0C9F0; always sensitive (auth tickets,
    # antiforgery tokens, encrypted error references, OAuth state)
    (r'CfDJ8[A-Za-z0-9_\-]{20,}',                  '<SAFE:{id}>',     'dataprotection_blob'),
    # Long base64 (tokens, session IDs)
    (r'[A-Za-z0-9+/]{40,}={0,2}',                 '<SAFE:{id}>',     'base64_token'),
    # Sentry DSN must come before email pattern (DSN contains key@host which email would match first)
    (r'https://[0-9a-f]+@[a-z0-9.\-]+\.sentry\.io/[0-9]+',
                                                   '<SAFE:{id}>',     'sentry_dsn'),
    # ── Bug-bounty researcher aliases — MUST run before generic email ─────────
    # Username portion is the researcher's handle on the platform; vault it but
    # keep the platform suffix visible so readers know which platform the alias
    # belongs to. 3-group form (empty prefix, sensitive, suffix) so the sanitizer
    # places <SAFE:id> *before* the kept "@platform.tld".
    (r'()([a-zA-Z0-9._%+\-]+)(@(?:intigriti\.me|bugcrowdninja\.com|wearehackerone\.com))',
                                                   r'\1<SAFE:{id}>\3', 'researcher_alias'),
    # ── Free webmail / consumer email — domain is non-sensitive public info,
    # vault the local-part but keep the suffix visible. Add target-specific
    # domains via the per-program ## Vault Patterns section in brief.md.
    (r'()([a-zA-Z0-9._%+\-]+)(@(?:gmail\.com|googlemail\.com|outlook\.com|hotmail\.com|live\.com|msn\.com|yahoo\.com|yahoo\.[a-z]{2,3}|icloud\.com|me\.com|mac\.com|protonmail\.com|proton\.me|aol\.com|gmx\.[a-z]{2,3}|web\.de|tutanota\.com|tuta\.com|fastmail\.com|zoho\.com|yandex\.(?:com|ru)|mail\.ru|qq\.com|163\.com|126\.com))',
                                                   r'\1<SAFE:{id}>\3', 'email_consumer'),
    # Email addresses (PII) — generic fallback, collapses whole address since
    # the domain itself may identify a target / acquisition / customer sector.
    (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
                                                   '<SAFE:{id}>',     'email'),

    # ── Cryptographic key fields ───────────────────────────────────────────────
    # sign_id and similar AES/HMAC key fields (32-64 char hex value)
    (r'(?i)(["\']?sign[_-]?id["\']?\s*[:=]\s*["\']?)([0-9a-fA-F]{32,64})(["\']?)',
                                                   r'\1<SAFE:{id}>\3', 'aes_key'),
    (r'(?i)(["\']?(?:aes|hmac|encrypt)[_-]?(?:key|secret)["\']?\s*[:=]\s*["\']?)([0-9a-fA-F]{32,64})(["\']?)',
                                                   r'\1<SAFE:{id}>\3', 'aes_key'),
    # Standalone 64-char hex strings (AES-256 keys, HMAC secrets not caught by above)
    (r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])',
                                                   '<SAFE:{id}>',     'hex_key_256'),

    # ── Third-party SDK keys (by key name) ────────────────────────────────────
    # Segment write key
    (r'(?i)(["\']?segment[_-]?(?:write[_-]?)?key["\']?\s*[:=]\s*["\']?)([A-Za-z0-9_-]{20,})(["\']?)',
                                                   r'\1<SAFE:{id}>\3', 'segment_key'),
    # Mixpanel token
    (r'(?i)(["\']?mixpanel[_-]?token["\']?\s*[:=]\s*["\']?)([0-9a-fA-F]{20,32})(["\']?)',
                                                   r'\1<SAFE:{id}>\3', 'mixpanel_token'),
    # LaunchDarkly client-side ID
    (r'(?i)(["\']?(?:launchdarkly|launch[_-]?darkly)[_-]?(?:client[_-]?)?(?:id|key)["\']?\s*[:=]\s*["\']?)([0-9a-fA-F]{24})(["\']?)',
                                                   r'\1<SAFE:{id}>\3', 'launchdarkly_id'),
    # Zendesk widget key
    (r'(?i)(["\']?zendesk[_-]?(?:widget[_-]?)?key["\']?\s*[:=]\s*["\']?)([A-Za-z0-9_-]{20,})(["\']?)',
                                                   r'\1<SAFE:{id}>\3', 'zendesk_key'),
    # Google Maps / Firebase / GCP API key
    (r'AIza[0-9A-Za-z_-]{35}',                    '<SAFE:{id}>',     'google_api_key'),

    # ── UUIDs — vault all occurrences ─────────────────────────────────────────
    # Catches OAuth client_ids, product UUIDs, service IDs, internal identifiers
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                                                   '<SAFE:{id}>',     'uuid'),

    # ── CTF flags — vault before they reach chat (prevents accidental echo) ───
    # Common CTF flag formats: HTB{}, flag{}, FLAG{}, picoCTF{}, plus platform-specific
    # variants — caught as a generic "<UPPER_OR_LETTERS>{...}" pattern with non-greedy body.
    (r'(?i)\b(?:INTIGRITI|HTB|FLAG|PICO(?:CTF)?|TF|CTF)\{[^}\s]{1,200}\}',
                                                   '<SAFE:{id}>',     'ctf_flag'),

    # ── Personal name fields in JSON (PII) — 3 groups so quotes are preserved ─
    # firstName / lastName / displayName / fullName as JSON keys
    (r'(?i)("(?:first|last|full|display)[_-]?name"\s*:\s*")((?:(?!<SAFE:)[^"]){1,80})(")',
                                                   r'\1<SAFE:{id}>\3', 'pii_name'),

    # ── Phone numbers (E.164 and common formats) ──────────────────────────────
    (r'(?:^|[\s>])\+?[1-9][0-9]{1,3}[-\s]?\(?[0-9]{1,4}\)?[-\s]?[0-9]{3,4}[-\s]?[0-9]{4}\b',
                                                   '<SAFE:{id}>',     'phone'),

    # ── Submission codes (program-specific identifiers) ───────────────────────
    # FLAGPROJECT-XXXXXXXX (Intigriti CTF), generic <UPPERCASE>-<ALNUM> ≥6 chars
    # Marked as 'submission_code' so vault_lookup can disambiguate from random strings
    (r'\b(?:FLAGPROJECT|FLAG|SUB|REPORT)-[A-Z0-9]{6,16}\b',
                                                   '<SAFE:{id}>',     'submission_code'),
]

# Compile patterns once at import
REDACT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(raw, re.MULTILINE), repl, vtype)
    for raw, repl, vtype in RAW_REDACT_PATTERNS
]

# ── Forbidden payload patterns (never send these to a target) ──────────────────

FORBIDDEN_PAYLOAD_PATTERNS = [
    re.compile(r'\bDROP\s+(TABLE|DATABASE|SCHEMA)\b',   re.IGNORECASE),
    re.compile(r'\bDELETE\s+FROM\b',                    re.IGNORECASE),
    re.compile(r'\bTRUNCATE\s+TABLE\b',                 re.IGNORECASE),
    re.compile(r'\brm\s+-[rf]+\b'),
    re.compile(r'\bshutdown\b',                         re.IGNORECASE),
    re.compile(r'\bmkfs\b'),
    re.compile(r'\bdd\s+if='),
    re.compile(r'wget[^\n]+\|\s*(ba)?sh'),
    re.compile(r'curl[^\n]+\|\s*(ba)?sh'),
    re.compile(r'/dev/tcp'),
    re.compile(r'nc\s+-e'),
    re.compile(r'bash\s+-i'),
    re.compile(r'python[23]?\s+-c\s+["\']import socket'),
]

# ── Shell metacharacters blocked in arguments ──────────────────────────────────

SHELL_METACHARACTERS = [';', '&&', '||', '`', '$(',  '${',  '>(', '<(', '\n', '\r', '\x00']
