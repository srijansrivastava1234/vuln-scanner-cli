import asyncio
import uuid
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

STATIC_WORDLIST = [
    "admin",
    "admin/login",
    "api",
    "api/v1",
    ".env",
    ".git/HEAD",
    "config.json",
    "robots.txt",
    "swagger",
    "docs",
    "healthz",
    "metrics",
    "backup.zip",
    "wp-admin",
]


class AsyncEndpointCrawler:
    """
    Asynchronous endpoint crawler and attack surface discovery engine.
    Uses httpx.AsyncClient with bounded asyncio.Semaphore concurrency,
    dynamic BeautifulSoup AST parsing of HTML seeds, and canary-based
    soft-404/SPA catch-all baseline filtering.
    """

    def __init__(self, base_url: str, concurrency: int = 10, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.canary_status: int | None = None
        self.canary_length: int = 0
        self.canary_redirect: str | None = None

    async def establish_canary_baseline(self, client: httpx.AsyncClient):
        """
        Probes a non-existent Canary path to establish target-specific baseline
        status, response body length, and redirect behavior for soft-404 / SPA detection.
        """
        canary_path = f"/_canary_probe_{uuid.uuid4().hex[:12]}"
        canary_url = f"{self.base_url}{canary_path}"
        try:
            resp = await client.get(canary_url, follow_redirects=False)
            self.canary_status = resp.status_code
            self.canary_length = len(resp.content)
            self.canary_redirect = resp.headers.get("Location")
        except httpx.RequestError:
            self.canary_status = 404
            self.canary_length = 0
            self.canary_redirect = None

    def harvest_links_with_bs4(self, html_content: str) -> Set[str]:
        """
        Dynamically extracts internal endpoints, scripts, assets, and API routes
        from an HTML response body using BeautifulSoup. Rejects non-HTTP schemes
        (mailto, tel, javascript, data) and external cross-origin links.
        """
        if not html_content:
            return set()

        discovered: Set[str] = set()
        soup = BeautifulSoup(html_content, "html.parser")
        base_parsed = urlparse(self.base_url)
        base_host = base_parsed.netloc.lower()

        tags_and_attrs = [
            ("a", "href"),
            ("script", "src"),
            ("form", "action"),
            ("link", "href"),
        ]

        for tag, attr in tags_and_attrs:
            for el in soup.find_all(tag):
                raw_val = el.get(attr)
                if not raw_val or not isinstance(raw_val, str):
                    continue

                val = raw_val.strip()
                if not val or val.startswith("#") or val.lower().startswith("javascript:"):
                    continue

                parsed = urlparse(val)
                # Ignore non-http schemes (mailto:, tel:, data:)
                if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
                    continue

                # Filter external hosts
                if parsed.netloc and parsed.netloc.lower() != base_host:
                    continue

                # Normalize clean path
                clean_path = parsed.path.strip("/")
                if clean_path:
                    discovered.add(clean_path)

        return discovered

    def is_soft_404_response(self, status: int, content_len: int, location: str | None) -> bool:
        """
        Determines whether a response is a soft-404 catch-all (e.g. SPA index.html fallback)
        by evaluating status code, redirect target, and body length variance.
        """
        if self.canary_status is None or self.canary_status == 404:
            return False

        # If canary returned a redirect (301/302) and this route redirects to the exact same location
        if self.canary_status in (301, 302, 307, 308) and status == self.canary_status:
            if location == self.canary_redirect and location is not None:
                return True

        # If canary returned 200 (SPA catch-all), compare body length within tolerance window
        if self.canary_status in (200, 201) and status == self.canary_status:
            # Tolerates small dynamic shifts (e.g. CSRF tokens, nonces, timestamps)
            tolerance = max(120, int(self.canary_length * 0.05))
            if abs(content_len - self.canary_length) <= tolerance:
                return True

        return False

    async def probe_endpoint(self, client: httpx.AsyncClient, path: str) -> Dict[str, Any]:
        """Probes an individual endpoint under concurrency semaphore limits."""
        norm_path = path.lstrip("/")
        url = f"{self.base_url}/{norm_path}"
        display_path = "/" + norm_path

        async with self.semaphore:
            loop = asyncio.get_running_loop()
            start = loop.time()
            try:
                resp = await client.get(url, follow_redirects=False)
                latency = round((loop.time() - start) * 1000, 2)
                content_len = len(resp.content)
                status = resp.status_code
                loc = resp.headers.get("Location")

                is_soft_404 = self.is_soft_404_response(status, content_len, loc)
                is_accessible = status in (200, 201, 301, 302, 401, 403) and not is_soft_404

                return {
                    "path": display_path,
                    "url": str(resp.url),
                    "status_code": status,
                    "latency_ms": latency,
                    "content_length": content_len,
                    "accessible": is_accessible,
                    "soft_404": is_soft_404,
                }
            except httpx.RequestError:
                return {
                    "path": display_path,
                    "url": url,
                    "status_code": None,
                    "latency_ms": None,
                    "content_length": 0,
                    "accessible": False,
                    "soft_404": False,
                }

    async def run_crawl(
        self,
        wordlist: List[str] | None = None,
        html_seed: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Executes bounded asynchronous directory scan across static wordlist
        and dynamically harvested HTML seed paths.
        """
        limits = httpx.Limits(
            max_connections=self.concurrency,
            max_keepalive_connections=self.concurrency,
        )
        headers = {"User-Agent": "VulnScanner-AsyncAuditEngine/2.0"}

        async with httpx.AsyncClient(timeout=self.timeout, limits=limits, headers=headers) as client:
            await self.establish_canary_baseline(client)

            combined_paths: Set[str] = set(wordlist if wordlist is not None else STATIC_WORDLIST)
            if html_seed:
                dynamic_paths = self.harvest_links_with_bs4(html_seed)
                combined_paths.update(dynamic_paths)

            tasks = [self.probe_endpoint(client, p) for p in combined_paths]
            results = await asyncio.gather(*tasks)

        accessible = [r for r in results if r["accessible"]]
        accessible.sort(key=lambda x: x["path"])
        return accessible


def crawl_endpoints(
    base_url: str,
    wordlist: List[str] | None = None,
    html_seed: str = "",
    concurrency: int = 10,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """Synchronous convenience wrapper to execute async crawl."""
    crawler = AsyncEndpointCrawler(base_url=base_url, concurrency=concurrency, timeout=timeout)
    return asyncio.run(crawler.run_crawl(wordlist=wordlist, html_seed=html_seed))