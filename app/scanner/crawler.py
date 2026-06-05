# app/scanner/crawler.py
import ipaddress
import logging
import socket
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

def is_safe_host(hostname: str) -> bool:
    """
    Resolve hostname and return False if any resolved IP is private,
    loopback, link-local, multicast, reserved, or unspecified.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for result in results:
        ip_str = result[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


def is_safe_url(url: str) -> bool:
    """Return True only for http/https URLs whose host passes is_safe_host()."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        return is_safe_host(hostname)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

_MAX_VISITS_PER_PATH = 3


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
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        self.visited: set[str] = set()         # full normalized URLs
        self._path_visit_count: dict[str, int] = {}  # Fix #D: path → visit count
        self.targets: list[dict] = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (compatible; SQLiScanner/1.0; "
                "+https://github.com/MuhammadZain07/SQLGuard)"
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

        # Deduplicate targets by (url, method, parameter)
        seen: set[tuple] = set()
        unique_targets: list[dict] = []
        for t in self.targets:
            key = (t["url"], t["method"], t["parameter"])
            if key not in seen:
                seen.add(key)
                unique_targets.append(t)
        self.targets = unique_targets

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


        path_key = self._path_key(normalized)
        visit_count = self._path_visit_count.get(path_key, 0)
        if visit_count >= _MAX_VISITS_PER_PATH:
            logger.debug(
                "Redirect loop guard: skipping %s (path visited %s times already)",
                normalized, visit_count,
            )
            return
        self._path_visit_count[path_key] = visit_count + 1

        # SSRF guard
        if not is_safe_url(normalized):
            logger.warning("SSRF guard blocked crawl to: %s", normalized)
            return

        self.visited.add(normalized)
        logger.debug("Visiting [depth=%s]: %s", depth, normalized)

        try:
            response = self.session.get(normalized, timeout=10, allow_redirects=True)
            response.raise_for_status()

            # Fix #D: after redirect, record the final landed URL's path too
            final_url = self._normalize_url(response.url)
            if final_url != normalized:
                final_path_key = self._path_key(final_url)
                self._path_visit_count[final_path_key] = (
                    self._path_visit_count.get(final_path_key, 0) + 1
                )
                logger.debug("Redirect landed on: %s", final_url)

        except requests.RequestException as exc:
            logger.warning("Failed to fetch %s: %s", normalized, exc)
            return

        soup = BeautifulSoup(response.text, "html.parser")

        self._extract_forms(normalized, soup)
        self._extract_get_params(normalized)

        for link in soup.find_all("a", href=True):
            href = link["href"].strip()
            # Fix #C: empty string was in the tuple and matches everything
            if not href or href.startswith(("javascript:", "mailto:", "#")):
                continue
            absolute = urljoin(normalized, href)
            self._crawl_page(absolute, depth + 1)

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> None:
        """Parse all <form> elements and build one target per field."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "get") or "get").upper()
            form_url = urljoin(page_url, action) if action else page_url

            if not is_safe_url(form_url):
                logger.warning("SSRF guard blocked form action: %s", form_url)
                continue

            form_data: dict[str, str] = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                # <select> doesn't have a value attr; extract from child <option>
                if tag.name == "select":
                    selected = tag.find("option", selected=True)
                    if selected:
                        default = selected.get("value", selected.string or "test")
                    else:
                        first_opt = tag.find("option")
                        default = first_opt.get("value", first_opt.string or "test") if first_opt else "test"
                else:
                    default = tag.get("value", tag.get("placeholder", "test"))
                form_data[name] = default or "test"

            if not form_data:
                continue

            for param_name in form_data:
                self.targets.append({
                    "url": form_url,
                    "method": method,
                    "parameter": param_name,
                    "form_data": dict(form_data),
                })

    def _extract_get_params(self, url: str) -> None:
        """Turn existing query-string parameters into GET injection targets."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

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

    def _path_key(self, url: str) -> str:
        """
        Fix #D: return scheme + netloc + path with query stripped.
        Used to detect redirect loops that keep adding new query params.
        """
        parsed = urlparse(url)
        return urlunparse(parsed._replace(query="", fragment=""))

    def _is_internal(self, url: str) -> bool:
        """True if the URL belongs to the same domain as the target."""
        return urlparse(url).netloc == self.base_domain