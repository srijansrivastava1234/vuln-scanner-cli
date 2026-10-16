from scanner.headers import audit_headers
from scanner.cookies import audit_raw_cookies
from scanner.scoring import calculate_score
from scanner.ssl_checker import check_ssl
from scanner.cvss import score_cvss_vector, evaluate_cvss_findings, cvss_roundup
from scanner.crawler import AsyncEndpointCrawler


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


# --- CVSS v3.1 Engine Tests ---

def test_cvss_roundup():
    assert cvss_roundup(4.0) == 4.0
    assert cvss_roundup(4.000000000000001) == 4.0
    assert cvss_roundup(4.02) == 4.1
    assert cvss_roundup(7.3999) == 7.4


def test_cvss_vector_calculation():
    # Official CVSS vector for missing CSP Clickjacking
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    score = score_cvss_vector(vector)
    assert score == 6.1


def test_cvss_evaluation_tier():
    eval_res = evaluate_cvss_findings(["MISSING_HSTS", "MISSING_CSP"])
    assert eval_res["max_cvss_score"] == 7.4
    assert eval_res["overall_tier"] == "HIGH"
    assert len(eval_res["findings"]) == 2


def test_cvss_evaluation_empty():
    eval_res = evaluate_cvss_findings([])
    assert eval_res["max_cvss_score"] == 0.0
    assert eval_res["overall_tier"] == "NONE"
    assert len(eval_res["findings"]) == 0


# --- Crawler & BeautifulSoup AST Harvesting Tests ---

def test_crawler_bs4_link_harvesting():
    html_seed = """
    <html>
        <head>
            <script src="/static/bundle.js"></script>
            <link rel="stylesheet" href="/assets/style.css">
        </head>
        <body>
            <a href="/dashboard">Dashboard</a>
            <a href="https://example.com/api/v2/users">Users API</a>
            <a href="https://external-domain.com/phish">External Target</a>
            <a href="mailto:admin@example.com">Contact</a>
            <a href="javascript:void(0)">Click me</a>
            <a href="#section2">Anchor</a>
            <form action="/auth/login" method="POST"></form>
        </body>
    </html>
    """
    crawler = AsyncEndpointCrawler(base_url="https://example.com")
    discovered = crawler.harvest_links_with_bs4(html_seed)

    # Valid internal paths must be extracted
    assert "dashboard" in discovered
    assert "api/v2/users" in discovered
    assert "static/bundle.js" in discovered
    assert "assets/style.css" in discovered
    assert "auth/login" in discovered

    # External domains and invalid schemes must be excluded
    assert "phish" not in discovered
    assert "mailto:admin@example.com" not in discovered
    assert "admin@example.com" not in discovered
    assert "javascript:void(0)" not in discovered
    assert "section2" not in discovered


def test_crawler_soft_404_canary_filtering():
    crawler = AsyncEndpointCrawler(base_url="https://spa-target.com")
    # Simulate an SPA that serves index.html (200 OK, 5000 bytes) for any unknown route
    crawler.canary_status = 200
    crawler.canary_length = 5000
    crawler.canary_redirect = None

    # Unknown route returning same SPA HTML should be flagged as soft-404
    assert crawler.is_soft_404_response(status=200, content_len=5020, location=None) is True

    # Real distinct endpoint (e.g. JSON API or small text file) should NOT be soft-404
    assert crawler.is_soft_404_response(status=200, content_len=300, location=None) is False

    # 403 Forbidden is a real access restriction, not soft-404
    assert crawler.is_soft_404_response(status=403, content_len=200, location=None) is False