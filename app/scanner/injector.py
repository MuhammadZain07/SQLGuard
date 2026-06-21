import logging
import time
from pathlib import Path
from urllib.parse import urljoin

import requests
from app.scanner.crawler import is_safe_url

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

    # Fix 10: 100ms delay between requests — avoids hammering the target
    # and getting the scanner's IP blocked.
    REQUEST_DELAY_S = 0.10

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
            self.REQUEST_TIMEOUT = 12
        else:
            self.REQUEST_DELAY_S = 0.10
            self.REQUEST_TIMEOUT = 15

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

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
            current_url = url
            redirects_followed = 0
            max_redirects = 5
            response = None

            while redirects_followed <= max_redirects:
                if not is_safe_url(current_url):
                    logger.warning("SSRF guard blocked injector redirect to: %s", current_url)
                    return None

                if method == "POST" and redirects_followed == 0:
                    response = self.session.post(
                        current_url,
                        data=injected_data,
                        timeout=self.REQUEST_TIMEOUT,
                        allow_redirects=False,
                    )
                else:
                    response = self.session.get(
                        current_url,
                        params=injected_data if redirects_followed == 0 else None,
                        timeout=self.REQUEST_TIMEOUT,
                        allow_redirects=False,
                    )

                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location")
                    if not location:
                        break
                    current_url = urljoin(current_url, location)
                    redirects_followed += 1
                else:
                    break

            if response is None:
                return None

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
                "timed_out": False,
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