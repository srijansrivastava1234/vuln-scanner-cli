from scanner.headers import audit_headers
from scanner.cookies import audit_raw_cookies
from scanner.scoring import calculate_score
from scanner.ssl_checker import check_ssl


def test_headers_audit_html():
    headers = {
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
    }
    result = audit_headers(headers)
    assert result["is_html"] is True
    assert len(result["findings"]) == 0


def test_headers_audit_json_exemptions():
    headers = {
        "content-type": "application/json",
        "strict-transport-security": "max-age=0",
    }
    result = audit_headers(headers)
    assert result["is_html"] is False
    headers_flagged = [f["header"] for f in result["findings"]]
    # JSON endpoints must NOT flag CSP or X-Frame-Options
    assert "Content-Security-Policy" not in headers_flagged
    assert "X-Frame-Options" not in headers_flagged
    assert "Strict-Transport-Security" in headers_flagged
    assert "X-Content-Type-Options" in headers_flagged


def test_cookies_audit():
    raw_cookies = [
        "session=abc123; Secure; HttpOnly; SameSite=Strict",
        "tracker=xyz; path=/",
    ]
    results = audit_raw_cookies(raw_cookies)
    assert len(results) == 2
    assert results[0]["is_safe"] is True
    assert results[1]["is_safe"] is False
    assert len(results[1]["issues"]) == 3


def test_scoring_unreachable_abort():
    ssl_audit = {"status": "UNREACHABLE", "message": "Host not found"}
    result = calculate_score({}, [], ssl_audit)
    assert result["status"] == "UNREACHABLE"
    assert result["score"] is None
    assert result["grade"] == "N/A"


def test_scoring_clean_run():
    header_audit = {"findings": []}
    cookie_audit = [{"is_safe": True}]
    ssl_audit = {"status": "VALID", "expired": False, "days_remaining": 60}
    result = calculate_score(header_audit, cookie_audit, ssl_audit)
    assert result["status"] == "AUDITED"
    assert result["score"] == 100
    assert result["grade"] == "A+"


def test_scoring_http_failed():
    header_audit = {"status": "FAILED", "error": "Connection refused"}
    ssl_audit = {"status": "VALID", "expired": False, "days_remaining": 60}
    result = calculate_score(header_audit, [], ssl_audit)
    assert result["status"] == "HTTP_FAILED"
    assert result["score"] is None
    assert result["grade"] == "N/A"

