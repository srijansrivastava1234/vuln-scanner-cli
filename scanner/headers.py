import re
from typing import Dict, Any


def audit_headers(response_headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Audits HTTP response headers with directive-level parsing and Content-Type awareness.
    """
    normalized = {k.lower(): v for k, v in response_headers.items()}
    content_type = normalized.get("content-type", "").lower()
    
    # Treat empty Content-Type as potentially HTML due to browser MIME sniffing
    is_html = not content_type or "text/html" in content_type or "application/xhtml+xml" in content_type

    findings = []

    # 1. Strict-Transport-Security (HSTS)
    hsts = normalized.get("strict-transport-security")
    if not hsts:
        findings.append({
            "header": "Strict-Transport-Security",
            "status": "MISSING",
            "severity": "HIGH",
            "issue": "HSTS missing: browser can be downgraded to plain HTTP via MITM.",
        })
    else:
        match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if not match or int(match.group(1)) == 0:
            findings.append({
                "header": "Strict-Transport-Security",
                "status": "MISCONFIGURED",
                "severity": "HIGH",
                "issue": "HSTS max-age is 0 or invalid (provides no protection).",
            })
        elif int(match.group(1)) < 10368000:  # < 120 days
            findings.append({
                "header": "Strict-Transport-Security",
                "status": "WEAK",
                "severity": "LOW",
                "issue": "HSTS max-age is short (< 120 days). Recommend at least 1 year (31536000).",
            })

    # 2. X-Content-Type-Options
    x_content = normalized.get("x-content-type-options")
    if not x_content or "nosniff" not in x_content.lower():
        findings.append({
            "header": "X-Content-Type-Options",
            "status": "MISSING" if not x_content else "MISCONFIGURED",
            "severity": "MEDIUM",
            "issue": "Missing 'nosniff': browser can execute files based on MIME sniffing.",
        })

    # 3. Content-Security-Policy (CSP)
    csp = normalized.get("content-security-policy")
    if not csp:
        if is_html:
            findings.append({
                "header": "Content-Security-Policy",
                "status": "MISSING",
                "severity": "HIGH",
                "issue": "CSP missing on HTML endpoint: vulnerable to XSS and injection.",
            })
    else:
        csp_issues = []
        if "'unsafe-inline'" in csp and "nonce-" not in csp and "hash-" not in csp:
            csp_issues.append("allows 'unsafe-inline' without nonces/hashes")
        if "default-src *" in csp or "script-src *" in csp:
            csp_issues.append("uses wildcard '*' in script/default sources")

        if csp_issues:
            findings.append({
                "header": "Content-Security-Policy",
                "status": "WEAK",
                "severity": "HIGH",
                "issue": f"CSP has weak directives: {', '.join(csp_issues)}.",
            })

    # 4. X-Frame-Options (Clickjacking)
    xfo = normalized.get("x-frame-options")
    if not xfo:
        if is_html:
            findings.append({
                "header": "X-Frame-Options",
                "status": "MISSING",
                "severity": "MEDIUM",
                "issue": "X-Frame-Options missing on HTML document: vulnerable to Clickjacking.",
            })
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append({
            "header": "X-Frame-Options",
            "status": "MISCONFIGURED",
            "severity": "MEDIUM",
            "issue": f"X-Frame-Options has invalid/deprecated value: '{xfo}'.",
        })

    # 5. Referrer-Policy
    ref = normalized.get("referrer-policy")
    if not ref:
        findings.append({
            "header": "Referrer-Policy",
            "status": "MISSING",
            "severity": "LOW",
            "issue": "Missing Referrer-Policy: sensitive URLs can leak in Referer headers.",
        })

    return {
        "status": "AUDITED",
        "content_type": content_type or "UNSPECIFIED",
        "is_html": is_html,
        "findings": findings,
    }
