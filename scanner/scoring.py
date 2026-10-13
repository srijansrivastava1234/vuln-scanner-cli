from typing import Dict, Any, List


def calculate_score(
    header_audit: Dict[str, Any],
    cookie_audit: List[Dict[str, Any]],
    ssl_audit: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes a security audit score (0-100) and letter grade.
    Aborts scoring on unreachable targets or network errors to avoid generating bogus scores.
    """
    ssl_status = ssl_audit.get("status")

    if ssl_status == "UNREACHABLE":
        return {
            "status": "UNREACHABLE",
            "score": None,
            "grade": "N/A",
            "summary": ssl_audit.get("message", "Target host could not be reached."),
        }

    if ssl_status == "ERROR":
        return {
            "status": "ERROR",
            "score": None,
            "grade": "N/A",
            "summary": ssl_audit.get("message", "An unrecoverable error occurred during probe."),
        }

    if header_audit.get("status") == "FAILED":
        return {
            "status": "HTTP_FAILED",
            "score": None,
            "grade": "N/A",
            "summary": header_audit.get("error", "HTTP probe failed to connect."),
        }

    score = 100

    # 1. SSL Penalties
    if ssl_status == "INSECURE_HTTP":
        score -= 40
    elif ssl_status in ("CERT_UNTRUSTED", "EXPIRED") or ssl_audit.get("expired"):
        score -= 35
    elif ssl_audit.get("days_remaining", 999) < 14:
        score -= 10  # Certificate expiring within 2 weeks

    # 2. Header Finding Penalties
    for finding in header_audit.get("findings", []):
        sev = finding.get("severity", "LOW")
        if sev == "HIGH":
            score -= 15
        elif sev == "MEDIUM":
            score -= 10
        elif sev == "LOW":
            score -= 5

    # 3. Cookie Penalties
    for cookie in cookie_audit:
        if not cookie.get("is_safe", True):
            score -= 10

    # Clamp score to [0, 100]
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"

    return {
        "status": "AUDITED",
        "score": score,
        "grade": grade,
    }
