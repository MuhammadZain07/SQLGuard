import logging
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Crawls a target website and returns a flat list of injectable targets.

    Each target is a dict with:
        url        : str  -- the endpoint to attack
        method     : str  -- "GET" or "POST"
        parameter  : str  -- the individual parameter name being tested
        form_data  : dict -- full form field dict (used by injector for POST)
    """

    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 30):
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages

        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc          # e.g. "example.com"
        self.base_scheme = parsed.scheme          # "http" or "https"

        self.visited: set[str] = set()
        self.targets: list[dict] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (compatible; SQLiScanner/1.0; "
                "+https://github.com/your-repo/sqli-scanner)"
            )
        })

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def crawl(self) -> list[dict]:
        """Start crawling from target_url. Returns list of injection targets."""
        logger.info("Crawling started: %s (depth=%s, pages=%s)",
                    self.target_url, self.max_depth, self.max_pages)
        self._crawl_page(self.target_url, depth=0)
        logger.info("Crawling finished. %s target(s) found across %s page(s).",
                    len(self.targets), len(self.visited))
        return self.targets

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _crawl_page(self, url: str, depth: int) -> None:
        """Recursively crawl a page up to max_depth / max_pages."""
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return

        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return
        if not self._is_internal(normalized):
            return

        self.visited.add(normalized)
        logger.debug("Visiting [depth=%s]: %s", depth, normalized)

        try:
            response = self.session.get(normalized, timeout=10, allow_redirects=True)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Failed to fetch %s: %s", normalized, exc)
            return

        soup = BeautifulSoup(response.text, "html.parser")

        # Extract forms on this page
        self._extract_forms(normalized, soup)

        # Extract GET parameters from the current URL
        self._extract_get_params(normalized)

        # Follow internal links
        for link in soup.find_all("a", href=True):
            href = link["href"].strip()
            if href.startswith(("javascript:", "mailto:", "#", "")):
                continue
            absolute = urljoin(normalized, href)
            self._crawl_page(absolute, depth + 1)

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> None:
        """Parse all <form> elements and build one target per field."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "get") or "get").upper()
            form_url = urljoin(page_url, action) if action else page_url

            # Collect all named input fields
            form_data: dict[str, str] = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                default = tag.get("value", tag.get("placeholder", "test"))
                form_data[name] = default or "test"

            if not form_data:
                continue

            # One target per parameter so the injector tests each individually
            for param_name in form_data:
                self.targets.append({
                    "url": form_url,
                    "method": method,
                    "parameter": param_name,
                    "form_data": dict(form_data),   # full field set for POST
                })

    def _extract_get_params(self, url: str) -> None:
        """Turn existing query-string parameters into GET injection targets."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        # Strip query string for the base URL
        base = urlunparse(parsed._replace(query="", fragment=""))

        for param_name in params:
            self.targets.append({
                "url": base,
                "method": "GET",
                "parameter": param_name,
                "form_data": {k: v[0] for k, v in params.items()},
            })

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _normalize_url(self, url: str) -> str:
        """Remove fragments; keep scheme + netloc + path + query."""
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))

    def _is_internal(self, url: str) -> bool:
        """True if the URL belongs to the same domain as the target."""
        return urlparse(url).netloc == self.base_domain