"""
Bug Bounty MCP Server — main entry point.

Exposes all tools to Claude Code via the MCP protocol (stdio transport).
Every tool call passes through: scope → executor → sanitizer → vault → audit.
Claude never sees raw sensitive values.
"""

import sys
from pathlib import Path

# Add mcp_server root to path so relative imports work
sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.fastmcp import FastMCP

from tools import recon, web, vuln, utils
from core import approver, verdicts, next_action
from core.scope import check as scope_check
from core.validator_brief import build_brief as build_validator_brief
from vault.safe import describe as vault_describe
from audit.logger import verify as audit_verify
from reports.generator import generate as generate_report

mcp = FastMCP(
    name='bb-hunter',
    instructions=(
        'Bug bounty hunting co-pilot — IMPACT-FIRST mission.\n'
        'Hunt for High, Critical, or Exceptional severity findings. Mediums '
        'ship only as "free Mediums" — byproduct of in-lane hunting, <30min '
        'draft, exploitable class, validator-gate passed. Lows are dropped. '
        'Always ask "can this chain to critical?" before investing time.\n'
        'A finding without a working safe PoC is a hypothesis, not a bug. '
        'Demonstrate impact with reproducible non-destructive exploitation '
        '(alert(document.domain), \' OR 1=1, SLEEP, IMDS read, id/whoami, own '
        'test accounts). If you cannot exploit it within program rules, it is '
        'not a finding — keep digging or pivot.\n'
        'create_report rejects severity below Medium AND empty PoC fields, '
        'unless force=True is set. Noise-class Mediums (missing headers, '
        'clickjacking, self-XSS, rate-limit, SPF/DMARC, cookie flags) must '
        'still be dropped at operator level — the gate enforces the numeric '
        'floor only, not taxonomy.\n'
        'VALIDATOR GATE (mandatory, server-enforced). Before drafting any '
        'report:\n'
        '  1. call validate_finding(program, hypothesis, target, evidence, '
        'proposed_poc) — server returns verdict_id + brief.\n'
        '  2. spawn an Opus Agent (subagent_type=general-purpose, model=opus) '
        'with that brief as the prompt.\n'
        '  3. read the agent verdict (line 1 = "EXPLOITABLE: …" or '
        '"THEORETICAL — DROP: …").\n'
        '  4. call record_verdict(verdict_id, verdict, reasoning, '
        'validated_poc).\n'
        '  5. if EXPLOITABLE → run the safe PoC, then '
        'create_report(..., validator_verdict_id=verdict_id).\n'
        '  6. if THEORETICAL → archive in notes.md, drop the lead, pivot. '
        'Do not draft a report.\n'
        'create_report rejects any report without an EXPLOITABLE verdict_id; '
        'force=True does NOT bypass this gate.\n'
        'Default rate limit on automated tools is 5 req/sec (programs typically '
        'allow 5–10/sec) — stay polite, do not bypass.\n'
        'All sensitive values are vaulted locally — you receive <SAFE:id> tokens. '
        'Every command is scope-checked against brief.md before execution. '
        'Always propose commands to the operator before calling tools. '
        'Never run scripts without going through request_script_approval first.\n'
        '\n'
        'SKILL CONSULTATION (mandatory — these are pre-loaded at session start, '
        'consult the file at the moment of the matching action, not only at session '
        'start). Use the consult_skill tool to load any skill/reference on demand:\n'
        '  • before nuclei / dalfox / sqlmap / ffuf → awesome-security + reference/payloads\n'
        '  • before SSRF / S3 / Blob / GCS testing → cloud-security\n'
        '  • before any PoC drafting → reference/payloads\n'
        '  • before code review → owasp + codeql-audit + snyk-fix + snyk-learning\n'
        '  • before smart-contract audit → secure-contracts\n'
        '  • before SPA / browser flow → webapp-testing\n'
        '  • before authoring a YARA rule → yara-authoring\n'
        '  • before drafting a report → reference/report_template + reference/intigriti_taxonomy\n'
        '  • before CVSS scoring → reference/cvss_guide\n'
        '  • before CWE selection → reference/cwe_map\n'
        'Full per-phase / per-action map: CLAUDE.md → "Skill & Reference Triggers".'
    ),
)

# ── Recon tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def run_subfinder(domain: str, program: str) -> str:
    """Passive subdomain enumeration. Results saved to recon/subfinder_<domain>.txt."""
    return recon.subfinder(domain, program)


@mcp.tool()
def run_amass(domain: str, program: str) -> str:
    """Passive subdomain enumeration via amass. Results saved to recon/amass.txt."""
    return recon.amass(domain, program)


@mcp.tool()
def run_assetfinder(domain: str, program: str) -> str:
    """Subdomain enumeration via assetfinder. Results saved to recon/assetfinder.txt."""
    return recon.assetfinder(domain, program)


@mcp.tool()
def run_httpx(input_file: str, program: str) -> str:
    """Probe a list of hosts for liveness, status codes, and tech stack."""
    return recon.httpx(input_file, program)


@mcp.tool()
def run_nmap(
    target: str,
    program: str,
    ports: str = '--top-ports 1000',
    flags: str = '-sC -sV',
) -> str:
    """Port scan a target. Returns open ports only. Full output saved to recon/nmap.*"""
    return recon.nmap(target, program, ports, flags)


@mcp.tool()
def run_whatweb(target: str, program: str) -> str:
    """Technology fingerprinting."""
    return recon.whatweb(target, program)


@mcp.tool()
def run_dig(domain: str, record_type: str, program: str) -> str:
    """DNS record lookup. record_type: A, AAAA, MX, TXT, CNAME, NS, etc."""
    return recon.dig(domain, record_type, program)


@mcp.tool()
def run_whois(domain: str, program: str) -> str:
    """WHOIS lookup for a domain."""
    return recon.whois(domain, program)


# ── Web tools ──────────────────────────────────────────────────────────────────

@mcp.tool()
def run_curl(
    url: str,
    program: str,
    method: str = 'GET',
    headers: list[str] | None = None,
    data: str | None = None,
) -> str:
    """HTTP request via curl. Response is sanitized before returning."""
    return web.curl(url, program, method, headers, data)


@mcp.tool()
def run_ffuf(
    url: str,
    wordlist: str,
    program: str,
    headers: list[str] | None = None,
    extensions: str = '',
) -> str:
    """Directory/parameter fuzzing. URL must contain FUZZ keyword."""
    return web.ffuf(url, wordlist, program, headers, extensions)


@mcp.tool()
def run_feroxbuster(
    url: str,
    program: str,
    wordlist: str = '/usr/share/wordlists/dirb/common.txt',
    headers: list[str] | None = None,
) -> str:
    """Directory brute-force. Results saved to recon/ferox.txt."""
    return web.feroxbuster(url, program, wordlist, headers)


@mcp.tool()
def run_katana(url: str, program: str, depth: int = 2) -> str:
    """Web crawler. Discovered URLs saved to recon/katana.txt."""
    return web.katana(url, program, depth)


# ── Vuln tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def run_nuclei(
    target: str,
    program: str,
    templates: list[str] | None = None,
    severity: str = 'medium,high,critical',
    headers: list[str] | None = None,
) -> str:
    """Vulnerability scanning with nuclei. Detection only — no exploitation."""
    return vuln.nuclei(target, program, templates, severity, headers)


@mcp.tool()
def run_sqlmap(
    url: str,
    program: str,
    params: str | None = None,
    data: str | None = None,
    headers: list[str] | None = None,
) -> str:
    """SQL injection detection. Safe mode: no dump, no shell, no writes."""
    return vuln.sqlmap(url, program, params, data, headers)


@mcp.tool()
def run_dalfox(
    url: str,
    program: str,
    headers: list[str] | None = None,
    params: str | None = None,
) -> str:
    """XSS detection via dalfox. Detection only."""
    return vuln.dalfox(url, program, headers, params)


# ── Utility tools ──────────────────────────────────────────────────────────────

@mcp.tool()
def grep_file(file_path: str, pattern: str, program: str) -> str:
    """Grep a file for a pattern. Safe for sensitive files — never dumps full content."""
    return utils.grep_file(file_path, pattern, program)


@mcp.tool()
def read_filtered(file_path: str, program: str, head: int = 30) -> str:
    """Read first N lines of a recon output file. Sanitized before returning."""
    return utils.read_filtered(file_path, program, head)


@mcp.tool()
def count_lines(file_path: str, program: str) -> str:
    """Count lines in a file. Returns count only — no content."""
    return utils.count_lines(file_path, program)


@mcp.tool()
def save_note(content: str, program: str, filename: str = 'notes.md') -> str:
    """Append a note to the program's notes file."""
    return utils.save_note(content, program, filename)


@mcp.tool()
def list_recon_files(program: str) -> str:
    """List recon output files for a program — names and sizes only."""
    return utils.list_recon(program)


@mcp.tool()
def consult_skill(name: str) -> str:
    """
    Load a security skill or reference file on demand. Use this at the moment
    of the matching action, not only at session start. The trigger map lives
    in CLAUDE.md → "Skill & Reference Triggers".

    Args:
      name: Skill or reference file name. Accepts:
        - skill stems: 'awesome-security', 'cloud-security', 'owasp',
          'codeql-audit', 'agentic-security', 'snyk-fix', 'snyk-learning',
          'webapp-testing', 'yara-authoring', 'secure-contracts',
          'secskills-pentest'
        - reference stems: 'payloads', 'tools', 'cvss_guide', 'cwe_map',
          'report_template', 'intigriti_taxonomy'
        - or a bare 'list' to enumerate available skills + references
    """
    from pathlib import Path
    skills_dir = Path.home() / '.claude' / 'skills'
    refs_dir   = Path.home() / 'Documents' / 'BugBounty' / 'reference'

    n = name.strip().lower().removesuffix('.md')
    if n in ('list', 'index', '?'):
        skills = sorted(p.stem for p in skills_dir.glob('*.md') if p.name != 'README.md')
        refs   = sorted(p.stem for p in refs_dir.glob('*.md'))
        return ('Available skills:\n  ' + '\n  '.join(skills) +
                '\n\nAvailable references:\n  ' + '\n  '.join(refs))

    candidates = [skills_dir / f'{n}.md', refs_dir / f'{n}.md']
    for c in candidates:
        if c.exists():
            try:
                text = c.read_text(errors='replace')
            except Exception as e:
                return f'ERROR reading {c}: {type(e).__name__}: {e}'
            # Cap response — skill files can be long. Claude can re-call with
            # more if needed, but the head is usually the trigger context.
            limit = 12_000
            if len(text) > limit:
                text = text[:limit] + f'\n\n[... truncated at {limit} chars — re-call if you need the rest]'
            return f'# {c.name}  ({c})\n\n{text}'
    return (f'ERROR: skill or reference "{name}" not found. '
            f'Call consult_skill(name="list") to see available files.')


# ── Scope tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def check_scope(target: str, program: str) -> str:
    """Verify a target is in scope before testing. Always call this first."""
    allowed, reason = scope_check(target, program)
    status = '✅ IN SCOPE' if allowed else '🚫 OUT OF SCOPE'
    return f'{status}: {reason}'


# ── Script approval tools ──────────────────────────────────────────────────────

@mcp.tool()
def request_script_approval(
    script_name: str,
    reason: str,
    program: str,
) -> str:
    """
    Step 1 of script execution.
    Analyze script and return approval request for operator.
    Show this to the operator and wait for their response.
    Then call confirm_script_execution() with their decision.
    """
    return approver.request_approval(script_name, reason, program)


@mcp.tool()
def confirm_script_execution(
    script_name: str,
    reason: str,
    program: str,
    approved: bool,
    script_args: list[str] | None = None,
) -> str:
    """
    Step 2 of script execution.
    Pass approved=True if operator said yes, approved=False if no.
    Script only runs if approved=True AND re-analysis passes.
    """
    return approver.confirm_execution(
        script_name, reason, program, approved, script_args
    )


# ── Vault tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def vault_lookup(safe_id: str, program: str) -> str:
    """
    Look up what a <SAFE:id> token represents.
    Returns TYPE and SOURCE only — never the actual value.
    """
    return vault_describe(program, safe_id)


# ── Validator gate ────────────────────────────────────────────────────────────

@mcp.tool()
def validate_finding(
    program: str,
    hypothesis: str,
    target: str,
    evidence: str,
    proposed_poc: str,
    class_hint: str | None = None,
) -> str:
    """
    Open a verdict for a finding hypothesis. Returns verdict_id + a markdown
    brief that the operator must hand to an Opus Agent to obtain the verdict.

    Server-side gates run BEFORE the verdict is opened:
      • scope_check(target, program) — out-of-scope targets are rejected.
      • verdicts.safety_check(proposed_poc) — destructive payloads are rejected.

    After the Opus Agent returns its verdict, the operator must call
    record_verdict(verdict_id, ...) to finalize. create_report later requires
    a finalized EXPLOITABLE verdict_id from the same program.

    class_hint (v0.4.0, optional): explicit vuln-class name to inject the
    matching reference/disclosed_patterns/hunt-<class>.md into the brief.
    When omitted, the class is auto-detected from the hypothesis text.
    Valid values: xss, sqli, idor, ssrf, ssti, xxe, rce, oauth, saml,
    mfa-bypass, csrf, business-logic, cache-poison, file-upload,
    http-smuggling, graphql.
    """
    # Scope gate
    in_scope, scope_reason = scope_check(target, program)
    if not in_scope:
        nudge = next_action.suggest(next_action.SCOPE_REJECTED, target=target)
        return (
            f'🚫 ERROR: target "{target}" is out of scope ({scope_reason}).\n\n'
            f'💡 next: {nudge}'
        )

    # Payload-safety gate
    safe, safety_reason = verdicts.safety_check(proposed_poc)
    if not safe:
        nudge = next_action.suggest(next_action.SAFETY_REJECTED)
        return f'🚫 ERROR: {safety_reason}\n\n💡 next: {nudge}'

    # Open the verdict
    verdict_id = verdicts.create(
        program=program,
        hypothesis=hypothesis,
        target=target,
        evidence=evidence,
        proposed_poc=proposed_poc,
    )

    brief = build_validator_brief(
        program=program,
        hypothesis=hypothesis,
        target=target,
        evidence=evidence,
        proposed_poc=proposed_poc,
        verdict_id=verdict_id,
        class_hint=class_hint,
    )

    nudge = next_action.suggest(next_action.VALIDATE_OPENED, verdict_id=verdict_id)
    return (
        f'✅ Verdict opened.\n\n'
        f'verdict_id: {verdict_id}\n'
        f'status: {verdicts.VERDICT_AWAITING}\n\n'
        f'💡 next: {nudge}\n\n'
        f'━━━━━━━━ BRIEF (paste this to the Opus Agent) ━━━━━━━━\n'
        f'{brief}'
    )


@mcp.tool()
def record_verdict(
    verdict_id: str,
    verdict: str,
    reasoning: str,
    validated_poc: str = '',
) -> str:
    """
    Record the Opus validator agent's outcome.

    verdict must be exactly 'EXPLOITABLE' or 'THEORETICAL'.
    A verdict can only be recorded once.

    After EXPLOITABLE, the operator can run the validated PoC and call
    create_report with this verdict_id. After THEORETICAL, the operator must
    archive the lead in notes.md and pivot.
    """
    normalized = verdict.strip().upper()
    ok, msg = verdicts.record(
        verdict_id=verdict_id,
        verdict=normalized,
        reasoning=reasoning,
        validated_poc=validated_poc,
    )
    if not ok:
        return '🚫 ERROR: ' + msg

    # v0.4.0 — emit next-action suggestion based on outcome.
    rec = verdicts.get(verdict_id) or {}
    target = rec.get('target')
    if 'INSUFFICIENT' in (reasoning or '').upper():
        nudge_outcome = next_action.VERDICT_INSUFFICIENT
    elif normalized == verdicts.VERDICT_EXPLOITABLE:
        nudge_outcome = next_action.VERDICT_EXPLOITABLE
    else:
        nudge_outcome = next_action.VERDICT_THEORETICAL
    nudge = next_action.suggest(
        nudge_outcome, verdict_id=verdict_id, target=target,
    )
    return f'✅ {msg}\n\n💡 next: {nudge}'


@mcp.tool()
def verify_verdicts_log(program: str) -> str:
    """Verify the integrity of the verdicts log hash chain for one program."""
    ok, msg = verdicts.verify(program)
    return ('✅ ' if ok else '🚫 ') + msg


# ── Report tools ───────────────────────────────────────────────────────────────

@mcp.tool()
def create_report(
    program: str,
    finding_id: str,
    title: str,
    vuln_type: str,
    intigriti_type: str,
    asset_url: str,
    asset_tier: str,
    asset_type: str,
    cvss_vector: str,
    cvss_score: float,
    severity: str,
    cwe: str,
    description: str,
    steps: list[str],
    poc_request: str,
    poc_response: str,
    poc_curl: str,
    impact: str,
    remediation: str,
    references: list[str],
    validator_verdict_id: str,
    force: bool = False,
) -> str:
    """
    Generate dual reports for a confirmed finding.
    Sanitized report → findings/<id>/report.md (Claude can read)
    Full report      → ~/.hive/<program>/findings/<id>/report_full.md (local only)
    Returns paths to both files.

    Validator gate: rejects findings without an EXPLOITABLE verdict_id from
      validate_finding/record_verdict for THIS program. force=True does NOT
      bypass this gate.
    Severity gate: rejects findings below Medium severity unless force=True.
      Mediums must be "free" (in-lane byproduct, <30min draft, exploitable
      class). Lows are always rejected unless force=True is set.
    PoC gate: rejects findings without reproduction artifacts unless force=True.
    """
    # ── Validator gate (unconditional — force=True does not bypass) ──────────
    v = verdicts.get(validator_verdict_id)
    if v is None:
        return (
            f'🚫 ERROR: validator_verdict_id {validator_verdict_id!r} not found. '
            f'Call validate_finding first, then record_verdict, then pass the '
            f'verdict_id here.'
        )
    if v.get('program') != program:
        return (
            f'🚫 ERROR: verdict {validator_verdict_id!r} belongs to program '
            f'{v.get("program")!r}, not {program!r}. Verdicts are not '
            f'cross-program reusable.'
        )
    if v.get('status') != verdicts.VERDICT_EXPLOITABLE:
        return (
            f'🚫 ERROR: verdict {validator_verdict_id!r} status is '
            f'{v.get("status")!r}; create_report requires '
            f'{verdicts.VERDICT_EXPLOITABLE!r}. '
            f'If THEORETICAL, archive the lead in notes.md and pivot — '
            f'do not draft a report.'
        )

    from config import MIN_REPORT_SEVERITY
    sev_norm = severity.strip().lower()
    if sev_norm not in MIN_REPORT_SEVERITY and not force:
        return (
            f'ERROR: severity "{severity}" rejected — mission floor is '
            f'Medium/High/Critical/Exceptional. Lows are dropped, not reported. '
            f'If you really want to submit this anyway, re-call with force=True '
            f'after confirming with the operator.'
        )

    # PoC gate — a finding without proof is a hypothesis, not a bug.
    poc_present = any(
        s.strip() for s in (poc_request, poc_response, poc_curl)
    )
    if not poc_present and not force:
        return (
            'ERROR: no PoC provided — a finding without reproduction '
            'artifacts is a hypothesis, not a bug. Fill in poc_request, '
            'poc_response, and/or poc_curl with the working safe-exploit '
            'evidence before submitting. If you really mean to ship a '
            'theoretical-impact report, re-call with force=True after '
            'operator confirmation.'
        )
    try:
        sanitized_path, full_path = generate_report(
            program=program,
            finding_id=finding_id,
            title=title,
            vuln_type=vuln_type,
            intigriti_type=intigriti_type,
            asset_url=asset_url,
            asset_tier=asset_tier,
            asset_type=asset_type,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            severity=severity,
            cwe=cwe,
            description=description,
            steps=steps,
            poc_request=poc_request,
            poc_response=poc_response,
            poc_curl=poc_curl,
            impact=impact,
            remediation=remediation,
            references=references,
        )
    except Exception as e:
        return f'ERROR generating report: {type(e).__name__}: {e}'

    from pathlib import Path
    vault_exists = Path(full_path).exists()
    nudge = next_action.suggest(next_action.REPORT_CREATED)
    return (
        f'Reports generated:\n'
        f'  Sanitized: {sanitized_path}\n'
        f'  Full (local only): {full_path} [{"✓ written" if vault_exists else "✗ MISSING — vault write failed"}]\n\n'
        f'💡 next: {nudge}'
    )


# ── Audit tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def verify_audit_log(program: str) -> str:
    """Verify the integrity of today's audit log hash chain."""
    ok, message = audit_verify(program)
    status = '✅' if ok else '🚫'
    return f'{status} {message}'


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    mcp.run(transport='stdio')
