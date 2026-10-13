import argparse
import json
import sys
import urllib3
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from scanner.ssl_checker import check_ssl
from scanner.headers import audit_headers
from scanner.cookies import audit_raw_cookies
from scanner.scoring import calculate_score

console = Console()


def scan_target(target: str, timeout: int = 10) -> dict:
    """
    Orchestrates the security audit:
    1. TLS / SSL probe.
    2. HTTP response probe (with fallback for self-signed/expired cert inspection).
    3. Defensive header & cookie flag audit.
    4. Posture scoring and grading.
    """
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = "https://" + target
    else:
        target_url = target

    # 1. Run TLS probe
    ssl_result = check_ssl(target_url, timeout=timeout)

    # 2. Run HTTP probe
    header_audit = {"status": "NOT_RUN", "findings": [], "content_type": "unknown", "is_html": False}
    cookie_audit = []
    status_code = None

    try:
        try:
            response = requests.get(
                target_url,
                timeout=timeout,
                headers={"User-Agent": "VulnScanner-CLI/1.0 (Security Audit Tool)"},
                allow_redirects=True,
                verify=True,
            )
        except requests.exceptions.SSLError:
            # Re-try unverified so headers/cookies can still be audited despite certificate failure
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(
                target_url,
                timeout=timeout,
                headers={"User-Agent": "VulnScanner-CLI/1.0 (Security Audit Tool)"},
                allow_redirects=True,
                verify=False,
            )

        status_code = response.status_code
        header_audit = audit_headers(dict(response.headers))

        # Extract raw Set-Cookie headers
        raw_cookies = []
        if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist"):
            raw_cookies = response.raw.headers.getlist("Set-Cookie")
        elif "set-cookie" in response.headers:
            raw_cookies = [response.headers["set-cookie"]]

        cookie_audit = audit_raw_cookies(raw_cookies)

    except requests.exceptions.RequestException as e:
        header_audit = {
            "status": "FAILED",
            "error": str(e),
            "findings": [],
            "content_type": "N/A",
            "is_html": False,
        }

    # 3. Calculate score
    score_result = calculate_score(header_audit, cookie_audit, ssl_result)

    return {
        "target": target_url,
        "http_status": status_code,
        "ssl": ssl_result,
        "headers": header_audit,
        "cookies": cookie_audit,
        "assessment": score_result,
    }


def render_terminal(results: dict):
    target = results["target"]
    assessment = results["assessment"]

    # Header Summary Panel
    grade = assessment.get("grade", "N/A")
    score = assessment.get("score")
    score_str = f"{score}/100" if score is not None else "N/A"

    grade_color = "green" if grade in ("A+", "A") else ("yellow" if grade in ("B", "C") else "red")

    panel_content = Text()
    panel_content.append(f"Target: {target}\n", style="bold white")
    panel_content.append(f"HTTP Status: {results['http_status'] or 'N/A'}\n")
    panel_content.append("Security Grade: ", style="bold")
    panel_content.append(f"[{grade}]", style=f"bold {grade_color}")
    panel_content.append(f"  |  Score: {score_str}\n")
    if assessment.get("summary"):
        panel_content.append(f"Notice: {assessment['summary']}\n", style="italic yellow")

    console.print(Panel(panel_content, title="[bold cyan]Security Audit Report[/bold cyan]", expand=False))

    # SSL / TLS Table
    ssl_info = results["ssl"]
    ssl_table = Table(title="TLS / SSL Certificate Health", show_header=True)
    ssl_table.add_column("Property", style="cyan")
    ssl_table.add_column("Value", style="white")

    ssl_status = ssl_info.get("status", "UNKNOWN")
    status_style = "green" if ssl_status == "VALID" else "bold red"
    ssl_table.add_row("Status", f"[{status_style}]{ssl_status}[/]")
    if "issuer" in ssl_info:
        ssl_table.add_row("Issuer", ssl_info["issuer"])
    if "tls_version" in ssl_info:
        ssl_table.add_row("TLS Version", ssl_info["tls_version"])
    if "cipher" in ssl_info:
        ssl_table.add_row("Cipher Suite", ssl_info["cipher"])
    if "days_remaining" in ssl_info:
        days = ssl_info["days_remaining"]
        days_style = "green" if days > 30 else ("yellow" if days > 7 else "bold red")
        ssl_table.add_row("Days Remaining", f"[{days_style}]{days} days[/]")
    if "error_detail" in ssl_info:
        ssl_table.add_row("Verification Error", ssl_info["error_detail"], style="bold red")

    console.print(ssl_table)

    # Headers Findings Table
    findings = results["headers"].get("findings", [])
    hdr_status = results["headers"].get("status", "UNKNOWN")
    hdr_table = Table(title="Defensive HTTP Headers", show_header=True)
    hdr_table.add_column("Header", style="cyan")
    hdr_table.add_column("Severity", justify="center")
    hdr_table.add_column("Status", justify="center")
    hdr_table.add_column("Issue Description", style="white")

    if hdr_status == "FAILED":
        hdr_table.add_row("HTTP Probe", "[bold red]HIGH[/]", "[bold red]FAILED[/]", results["headers"].get("error", "Failed to connect to host."))
    elif not findings:
        hdr_table.add_row("All Headers", "[green]INFO[/]", "[green]PASS[/]", "All recommended security headers are present.")
    else:
        for f in findings:
            sev = f["severity"]
            sev_badge = f"[bold red]{sev}[/]" if sev == "HIGH" else (f"[yellow]{sev}[/]" if sev == "MEDIUM" else f"[cyan]{sev}[/]")
            stat_badge = f"[bold red]{f['status']}[/]" if f["status"] in ("MISSING", "MISCONFIGURED") else f"[yellow]{f['status']}[/]"
            hdr_table.add_row(f["header"], sev_badge, stat_badge, f["issue"])

    console.print(hdr_table)

    # Cookie Security Table
    cookies = results.get("cookies", [])
    if cookies:
        cookie_table = Table(title="Cookie Security Flags", show_header=True)
        cookie_table.add_column("Cookie Name", style="cyan")
        cookie_table.add_column("Secure", justify="center")
        cookie_table.add_column("HttpOnly", justify="center")
        cookie_table.add_column("SameSite", justify="center")
        cookie_table.add_column("Issues", style="white")

        for c in cookies:
            sec = "[green]YES[/]" if c["secure"] else "[bold red]NO[/]"
            http = "[green]YES[/]" if c["httponly"] else "[bold red]NO[/]"
            same = c["samesite"]
            issues = ", ".join(c["issues"]) if c["issues"] else "[green]Safe[/]"
            cookie_table.add_row(c["name"], sec, http, same, issues)

        console.print(cookie_table)
    else:
        console.print("[dim]No cookies were set by target response.[/dim]\n")


GRADE_RANKS = {"A+": 5, "A": 4, "B": 3, "C": 2, "F": 1, "N/A": 0}


def determine_exit_code(results: dict, fail_grade: str | None = None) -> int:
    """
    Computes CLI exit code:
    - 0: Passed audit requirements.
    - 1: Audit grade fell below or matched the failure threshold.
    - 2: Network, DNS, or operational failure (UNREACHABLE / ERROR / HTTP_FAILED).
    """
    assessment = results.get("assessment", {})
    status = assessment.get("status")

    if status in ("UNREACHABLE", "ERROR", "HTTP_FAILED"):
        return 2

    if fail_grade:
        actual_grade = assessment.get("grade", "N/A")
        if GRADE_RANKS.get(actual_grade, 0) <= GRADE_RANKS.get(fail_grade.upper(), 0):
            return 1

    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Automated Web Security & Vulnerability Header Scanner")
    parser.add_argument("target", help="Target URL or domain (e.g. google.com, https://example.com)")
    parser.add_argument("--json", dest="json_output", help="Path to write JSON results", default=None)
    parser.add_argument("--timeout", type=int, default=10, help="Socket and HTTP timeout in seconds (default: 10)")
    parser.add_argument(
        "--fail-grade",
        choices=["A+", "A", "B", "C", "F"],
        default=None,
        help="Exit with code 1 if the security grade is at or below this threshold (useful for CI/CD gates)",
    )

    args = parser.parse_args(argv)

    results = scan_target(args.target, timeout=args.timeout)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green][+] Results successfully exported to {args.json_output}[/green]")
    else:
        render_terminal(results)

    return determine_exit_code(results, fail_grade=args.fail_grade)


if __name__ == "__main__":
    sys.exit(main())

