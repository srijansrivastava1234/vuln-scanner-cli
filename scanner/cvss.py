import math
from typing import Dict, Any, List

# Official FIRST CVSS v3.1 Metric Weight Constants
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def cvss_roundup(val: float) -> float:
    """
    Official CVSS v3.1 Appendix A Roundup function.
    Implements precision-preserving ceiling to 1 decimal place to prevent IEEE 754 float drift.
    """
    int_input = round(val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) * 10 / 100.0


def score_cvss_vector(vector_str: str) -> float:
    """
    Calculates official CVSS v3.1 Base Score from a vector string.
    Follows FIRST.org CVSS v3.1 Specification Section 7.1.
    """
    clean_vec = vector_str.replace("CVSS:3.1/", "").strip()
    parts = {}
    for item in clean_vec.split("/"):
        if ":" in item:
            k, v = item.split(":", 1)
            parts[k.strip()] = v.strip()

    required_keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    for rk in required_keys:
        if rk not in parts:
            raise ValueError(f"Malformed CVSS vector missing required metric '{rk}': {vector_str}")

    scope_changed = parts["S"] == "C"
    pr_weight = PR_C[parts["PR"]] if scope_changed else PR_U[parts["PR"]]

    # Impact Sub-Score (ISS)
    iss = 1.0 - (
        (1.0 - CIA[parts["C"]]) *
        (1.0 - CIA[parts["I"]]) *
        (1.0 - CIA[parts["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * AV[parts["AV"]] * AC[parts["AC"]] * pr_weight * UI[parts["UI"]]

    if impact <= 0:
        return 0.0

    if scope_changed:
        base = cvss_roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = cvss_roundup(min(impact + exploitability, 10.0))

    return round(base, 1)


# Grounded NIST / FIRST CVSS v3.1 Vector Mappings for Audit Findings
CVSS_FINDING_MAPPINGS = {
    "MISSING_HSTS": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Lack of HSTS exposes client traffic to SSL-stripping and active MITM downgrade attacks.",
        "severity": "HIGH",
    },
    "MISSING_CSP": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "Missing CSP permits arbitrary script execution and cross-origin resource theft under XSS.",
        "severity": "MEDIUM",
    },
    "WEAK_CSP": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "CSP contains unsafe-inline or unconstrained wildcards neutralizing script execution boundaries.",
        "severity": "MEDIUM",
    },
    "MISSING_X_FRAME_OPTIONS": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "description": "Missing framing protection permits UI redressing and transparent Clickjacking attacks.",
        "severity": "MEDIUM",
    },
    "MISSING_X_CONTENT_TYPE": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "description": "Missing nosniff enables MIME-type confusion attacks in browser rendering engines.",
        "severity": "LOW",
    },
    "COOKIE_MISSING_HTTPONLY": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "description": "Session cookie without HttpOnly flag is directly readable via DOM-based script injection.",
        "severity": "MEDIUM",
    },
    "COOKIE_MISSING_SECURE": {
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Cookie transmitted over plain HTTP can be intercepted on unencrypted Wi-Fi or transport channels.",
        "severity": "MEDIUM",
    },
    "SSL_EXPIRED": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Expired or untrusted TLS certificate violates transport layer integrity and authenticity guarantees.",
        "severity": "HIGH",
    },
    "SSL_INSECURE_HTTP": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Target operates over cleartext HTTP with zero transport encryption.",
        "severity": "HIGH",
    },
}


def evaluate_cvss_findings(finding_keys: List[str]) -> Dict[str, Any]:
    """
    Evaluates a collection of detected finding keys against official CVSS v3.1 vectors.
    Computes Base Scores, determines overall risk tier, and compiles telemetry breakdown.
    """
    evaluated = []
    max_score = 0.0

    for key in finding_keys:
        if key in CVSS_FINDING_MAPPINGS:
            meta = CVSS_FINDING_MAPPINGS[key]
            score = score_cvss_vector(meta["vector"])
            max_score = max(max_score, score)
            evaluated.append({
                "key": key,
                "score": score,
                "severity": meta["severity"],
                "vector": meta["vector"],
                "description": meta["description"],
            })

    # Overall Risk Tier based on maximum CVSS Base Score
    if max_score >= 9.0:
        overall_tier = "CRITICAL"
    elif max_score >= 7.0:
        overall_tier = "HIGH"
    elif max_score >= 4.0:
        overall_tier = "MEDIUM"
    elif max_score > 0.0:
        overall_tier = "LOW"
    else:
        overall_tier = "NONE"

    return {
        "findings": evaluated,
        "max_cvss_score": max_score,
        "overall_tier": overall_tier,
    }