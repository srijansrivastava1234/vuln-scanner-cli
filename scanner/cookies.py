import re
from typing import List, Dict, Any
from http.cookies import SimpleCookie


def audit_raw_cookies(raw_set_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Parses raw Set-Cookie response headers to ensure no security flags (SameSite, Secure, HttpOnly)
    are dropped or corrupted during HTTP client cookie jar aggregation.
    """
    results = []

    for raw in raw_set_cookie_headers:
        if not raw:
            continue

        # Strip optional header name prefix if present
        cleaned = re.sub(r"^set-cookie:\s*", "", raw, flags=re.IGNORECASE).strip()

        cookie = SimpleCookie()
        try:
            cookie.load(cleaned)
        except Exception:
            continue

        for name, morsel in cookie.items():
            issues = []
            is_secure = bool(morsel["secure"])
            is_httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"]

            if not is_secure:
                issues.append("Missing 'Secure' flag (transmitted over unencrypted HTTP).")
            if not is_httponly:
                issues.append("Missing 'HttpOnly' flag (accessible by client-side JavaScript).")
            if not samesite:
                issues.append("Missing 'SameSite' attribute (vulnerable to CSRF).")
            elif samesite.lower() == "none" and not is_secure:
                issues.append("Invalid SameSite: 'SameSite=None' must have 'Secure' flag.")

            results.append({
                "name": name,
                "secure": is_secure,
                "httponly": is_httponly,
                "samesite": samesite if samesite else "UNSPECIFIED",
                "issues": issues,
                "is_safe": len(issues) == 0,
            })

    return results
