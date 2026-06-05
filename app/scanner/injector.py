import logging
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# Load payloads from app/scanner/payloads/*.txt
PAYLOADS_DIR = Path(__file__).parent / "payloads"

ATTACK_TYPES = ["error_based", "boolean_based", "time_based", "union_based"]


def _load_payloads() -> dict[str, list[str]]:
    """
    Read each .txt file in the payloads/ folder.
    Each line in the file is one payload. Blank lines are ignored.
    """
    payloads: dict[str, list[str]] = {}
    for attack_type in ATTACK_TYPES:
        filepath = PAYLOADS_DIR / f"{attack_type}.txt"
        if not filepath.exists():
            logger.warning("Payload file not found: %s", filepath)
            payloads[attack_type] = []
            continue
        lines = filepath.read_text(encoding="utf-8").splitlines()
        payloads[attack_type] = [line.strip() for line in lines if line.strip()]
        logger.debug("Loaded %s payloads from %s", len(payloads[attack_type]), filepath.name)
    return payloads


PAYLOADS = _load_payloads()

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

    # Fix 11: increased from 12s → 15s so time-based payloads (5s sleep)
    # have enough headroom for network latency and server overhead.
    REQUEST_TIMEOUT = 15

    # Fix 10: 150ms delay between requests — avoids hammering the target
    # and getting the scanner's IP blocked.
    REQUEST_DELAY_S = 0.15

    def __init__(self, targets: list[dict], mode: str = "normal"):
        self.targets = targets
        self.mode = mode.lower()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (compatible; SQLiScanner/1.0; "
                "+https://github.com/MuhammadZain07/SQLGuard)"
            )
        })
        
        # Adjust delay and timeout configuration based on mode
        if self.mode == "aggressive":
            self.REQUEST_DELAY_S = 0.02
            self.REQUEST_TIMEOUT = 10
        else:
            self.REQUEST_DELAY_S = 0.15
            self.REQUEST_TIMEOUT = 15

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def inject(self, confirmed_vulns: set | None = None) -> list[dict]:
        """
        Run every payload against every target.
        Returns a flat list of result dicts.

        If *confirmed_vulns* is provided it must be a set of
        (url, parameter) tuples.  Targets whose (url, parameter) is
        already in the set are skipped entirely, and newly confirmed
        pairs can be added by the caller between iterations.
        """
        if confirmed_vulns is None:
            confirmed_vulns = set()

        results: list[dict] = []
        total = len(self.targets) * len(ALL_PAYLOADS)
        logger.info(
            "Injector starting: %s target(s) × %s payload(s) = %s request(s).",
            len(self.targets), len(ALL_PAYLOADS), total,
        )

        for target in self.targets:
            target_key = (target["url"], target["parameter"])
            for payload_info in ALL_PAYLOADS:
                # Early exit: skip if this (url, parameter) is already confirmed
                if target_key in confirmed_vulns:
                    break
                result = self.send_request(target, payload_info)
                if result:
                    results.append(result)

        logger.info("Injector finished: %s result(s) collected.", len(results))
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def send_request(self, target: dict, payload_info: dict) -> dict | None:
        """Fire one payload at one target. Returns a result dict or None on error."""
        url         = target["url"]
        method      = target["method"].upper()
        parameter   = target["parameter"]
        form_data   = dict(target.get("form_data", {}))
        payload     = payload_info["payload"]
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

            # throttle after every successful request
            time.sleep(self.REQUEST_DELAY_S)

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

            # throttle on timeout too
            time.sleep(self.REQUEST_DELAY_S)

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

            # throttle even on hard errors so we don't spam the target
            time.sleep(self.REQUEST_DELAY_S)

            return None