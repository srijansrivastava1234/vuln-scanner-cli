import asyncio
import time
import httpx
import pandas as pd
import streamlit as st

from scanner.ssl_checker import check_ssl
from scanner.headers import audit_headers
from scanner.cookies import audit_raw_cookies
from scanner.cvss import evaluate_cvss_findings
from scanner.crawler import AsyncEndpointCrawler

st.set_page_config(
    page_title="Automated Web Security & Endpoint Audit Engine",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Automated Web Security Header & Endpoint Audit Engine")
st.markdown(
    "High-throughput security auditor powered by **Asynchronous I/O (`httpx` + `asyncio`)**, "
    "**BeautifulSoup AST link extraction**, and **CVSS v3.1 Base Severity scoring**."
)

col1, col2 = st.columns([4, 1])
with col1:
    target_url = st.text_input("Enter Target URL or Domain", value="https://example.com")
with col2:
    st.write("")
    st.write("")
    scan_button = st.button("🚀 Run Security Audit", use_container_width=True)

if scan_button and target_url:
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    with st.spinner("Executing TLS handshake, header analysis, and asynchronous endpoint crawl..."):
        start_time = time.time()

        # 1. SSL/TLS Probe
        ssl_res = check_ssl(target_url, timeout=5)

        # 2. HTTP Initial Request & Header Audit
        html_content = ""
        http_status = None
        target_latency = None
        header_audit = {"findings": []}
        cookie_audit = []

        try:
            req_start = time.time()
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                resp = client.get(target_url)
                target_latency = round((time.time() - req_start) * 1000, 2)
                http_status = resp.status_code
                html_content = resp.text
                header_audit = audit_headers(dict(resp.headers))

                # Extract raw Set-Cookie headers
                raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
                cookie_audit = audit_raw_cookies(raw_cookies)
        except Exception as e:
            st.error(f"HTTP Probe Failed: {e}")

        # 3. Asynchronous Crawler Execution
        crawler = AsyncEndpointCrawler(base_url=target_url, concurrency=10, timeout=5.0)
        crawled_routes = asyncio.run(crawler.run_crawl(html_seed=html_content))

        # 4. CVSS v3.1 Vector Mapping
        finding_keys = []
        for f in header_audit.get("findings", []):
            hdr = f["header"]
            if hdr == "Strict-Transport-Security":
                finding_keys.append("MISSING_HSTS")
            elif hdr == "Content-Security-Policy":
                finding_keys.append("WEAK_CSP" if f.get("status") == "WEAK" else "MISSING_CSP")
            elif hdr == "X-Frame-Options":
                finding_keys.append("MISSING_X_FRAME_OPTIONS")
            elif hdr == "X-Content-Type-Options":
                finding_keys.append("MISSING_X_CONTENT_TYPE")

        for c in cookie_audit:
            if not c.get("httponly"):
                finding_keys.append("COOKIE_MISSING_HTTPONLY")
            if not c.get("secure"):
                finding_keys.append("COOKIE_MISSING_SECURE")

        if ssl_res.get("expired"):
            finding_keys.append("SSL_EXPIRED")
        elif ssl_res.get("status") == "INSECURE_HTTP":
            finding_keys.append("SSL_INSECURE_HTTP")

        cvss_res = evaluate_cvss_findings(finding_keys)
        total_time = round(time.time() - start_time, 2)

    # --- Telemetry Metric Bar ---
    st.divider()
    m1, m2, m3, m4, m5 = st.columns(5)
    tier = cvss_res["overall_tier"]
    tier_color = "red" if tier in ("CRITICAL", "HIGH") else ("orange" if tier == "MEDIUM" else "green")

    m1.metric("CVSS Severity", f"{tier}", delta=f"Base Score: {cvss_res['max_cvss_score']}/10")
    m2.metric("TLS Health", ssl_res.get("status", "UNKNOWN"))
    m3.metric("HTTP Status", f"{http_status or 'N/A'}")
    m4.metric("Base Latency", f"{target_latency or 0} ms")
    m5.metric("Exposed Endpoints", f"{len(crawled_routes)} found")

    # --- Tabs ---
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 CVSS v3.1 Severity Matrix",
        "⚡ Latency Telemetry",
        "🗺️ Attack Surface (Crawler)",
        "🔒 Transport & Cookie Posture",
    ])

    with tab1:
        st.subheader("Official CVSS v3.1 Vulnerability Assessment")
        if not cvss_res["findings"]:
            st.success("Zero CVSS vulnerabilities identified across evaluated security headers and transport.")
        else:
            for item in cvss_res["findings"]:
                score = item["score"]
                sev_color = "red" if score >= 7.0 else ("orange" if score >= 4.0 else "blue")
                with st.expander(f":{sev_color}[CVSS {score} ({item['severity']})] — `{item['key']}`"):
                    st.markdown(f"**NIST Vector:** `{item['vector']}`")
                    st.caption(item["description"])

    with tab2:
        st.subheader("Endpoint Latency Telemetry (Async Probe Metrics)")
        if crawled_routes:
            df = pd.DataFrame(crawled_routes)
            valid_latencies = df[df["latency_ms"].notnull()]["latency_ms"]
            if not valid_latencies.empty:
                col_l1, col_l2, col_l3, col_l4 = st.columns(4)
                col_l1.metric("Min Latency", f"{valid_latencies.min():.1f} ms")
                col_l2.metric("Median (p50)", f"{valid_latencies.median():.1f} ms")
                col_l3.metric("p95 Latency", f"{valid_latencies.quantile(0.95):.1f} ms")
                col_l4.metric("Max Latency", f"{valid_latencies.max():.1f} ms")

                st.bar_chart(df.set_index("path")["latency_ms"])
        else:
            st.info("No exposed routes available for telemetry visualization.")

    with tab3:
        st.subheader("Enumerated Attack Surface Endpoints")
        st.caption("Discovered via bounded async crawl with Canary soft-404 filtering and BeautifulSoup AST seed extraction.")
        if not crawled_routes:
            st.info("No accessible endpoints discovered (Canary soft-404 filtering active).")
        else:
            display_df = pd.DataFrame(crawled_routes)[["path", "status_code", "latency_ms", "content_length"]]
            st.dataframe(display_df, use_container_width=True)

    with tab4:
        st.subheader("Transport Layer & Cookie Security Posture")
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            st.write("#### TLS Certificate")
            st.write(f"- **Status:** `{ssl_res.get('status')}`")
            st.write(f"- **Issuer:** {ssl_res.get('issuer', 'N/A')}")
            st.write(f"- **TLS Version:** `{ssl_res.get('tls_version', 'N/A')}`")
            st.write(f"- **Cipher Suite:** `{ssl_res.get('cipher', 'N/A')}`")
            st.write(f"- **Days Remaining:** `{ssl_res.get('days_remaining', 'N/A')} days`")
            if ssl_res.get("error_detail"):
                st.error(f"Certificate Error: {ssl_res['error_detail']}")

        with col_t2:
            st.write("#### Cookie Security Flags")
            if not cookie_audit:
                st.info("No cookies issued by target.")
            else:
                for c in cookie_audit:
                    st.write(f"**Cookie:** `{c['name']}`")
                    st.write(f"- Secure: {'✅' if c['secure'] else '❌'}")
                    st.write(f"- HttpOnly: {'✅' if c['httponly'] else '❌'}")
                    st.write(f"- SameSite: `{c['samesite']}`")