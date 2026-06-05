# app/tasks.py
import logging
import time
import requests as http_requests
from datetime import datetime, timezone

from app import celery
from app.models.database import db, Scan, Vulnerability
from app.scanner.crawler import WebCrawler, is_safe_url
from app.scanner.injector import PayloadInjector, PAYLOADS, ALL_PAYLOADS
from app.scanner.analyzer import ResponseAnalyzer

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Helper: persist one vulnerability to the database
# -----------------------------------------------------------------
def _save_vulnerability(scan_id: int, result: dict) -> bool:
    existing = Vulnerability.query.filter_by(
        scan_id=scan_id,
        url=result.get("url", ""),
        parameter=result.get("parameter", ""),
        vuln_type=result.get("vuln_type", ""),
    ).first()

    if existing:
        logger.debug(
            "Skipping duplicate vuln: %s param=%s type=%s",
            result.get("url"), result.get("parameter"), result.get("vuln_type"),
        )
        return False

    vuln = Vulnerability(
        scan_id=scan_id,
        url=result.get("url", ""),
        parameter=result.get("parameter", ""),
        method=result.get("method", "GET"),
        vuln_type=result.get("vuln_type", "Unknown"),
        severity=result.get("severity", "LOW"),
        payload=result.get("payload", ""),
        response_snippet=result.get("response_snippet", "")[:500],
        recommendation=result.get("recommendation", ""),
        found_at=datetime.now(timezone.utc),
    )
    db.session.add(vuln)
    return True


# -----------------------------------------------------------------
# Helper: fetch neutral baseline response sizes before injecting
# -----------------------------------------------------------------
def _build_baselines(injection_targets: list[dict], analyzer: ResponseAnalyzer) -> None:
    """
    Fetch a neutral (non-malicious) response for each unique (url, parameter)
    pair so the boolean detector has a correct baseline to compare against.

    Fix #B: use target["method"] and send form_data for POST targets.
    A POST-only endpoint (e.g. login page) returns a completely different
    response to a GET request — using the wrong method produced a wrong
    baseline size and caused the boolean detector to flag every POST
    injection as vulnerable.
    """
    seen: set[tuple] = set()

    for target in injection_targets:
        key = (target["url"], target["parameter"])
        if key in seen:
            continue
        seen.add(key)

        # SSRF guard: never fetch a baseline for an internal/private address
        if not is_safe_url(target["url"]):
            logger.warning(
                "SSRF guard: skipped baseline fetch for unsafe URL %s", target["url"]
            )
            continue

        method     = target.get("method", "GET").upper()
        form_data  = dict(target.get("form_data", {}))
        # Use a neutral value for the parameter under test
        neutral_data = {**form_data, target["parameter"]: "test"}

        try:
            start = time.monotonic()
            if method == "POST":
                r = http_requests.post(
                    target["url"],
                    data=neutral_data,
                    timeout=10,
                    allow_redirects=True,
                )
            else:
                r = http_requests.get(
                    target["url"],
                    params=neutral_data,
                    timeout=10,
                    allow_redirects=True,
                )
            elapsed_ms = int((time.monotonic() - start) * 1000)

            analyzer.set_baseline(
                target["url"], target["parameter"],
                len(r.text), neutral_response_time_ms=elapsed_ms,
            )
            logger.debug(
                "Baseline set [%s] for %s param=%s size=%s time=%sms",
                method, target["url"], target["parameter"],
                len(r.text), elapsed_ms,
            )

        except Exception as exc:
            logger.warning(
                "Could not fetch baseline for %s param=%s: %s",
                target["url"], target["parameter"], exc,
            )


# -----------------------------------------------------------------
# Main Celery task
# -----------------------------------------------------------------
@celery.task(bind=True, max_retries=0)
def run_scan(self, scan_id: int, target_url: str, mode: str = "normal") -> dict:
    """
    Background task that runs the full SQL-injection scan pipeline:

        1. Mark scan as "running"
        2. Crawl the target website for forms / GET parameters
        3. Build neutral baselines for boolean-based detection
        4. Inject SQL payloads into every discovered parameter
        5. Analyse each response for vulnerabilities
        6. Persist every unique finding to SQLite
        7. Mark scan as "completed" (or "failed" on error)
    """
    scan = db.session.get(Scan, scan_id)
    if not scan:
        logger.error("run_scan: Scan #%s not found in DB.", scan_id)
        return {"error": f"Scan {scan_id} not found"}

    scan.status = "running"
    db.session.commit()
    logger.info("Scan #%s started for %s in %s mode", scan_id, target_url, mode)

    try:
        # Determine crawl limits based on mode
        if mode == "aggressive":
            max_depth = 3
            max_pages = 30
        else:
            max_depth = 2
            max_pages = 10

        crawler = WebCrawler(
            target_url=target_url,
            max_depth=max_depth,
            max_pages=max_pages,
        )
        injection_targets = crawler.crawl()

        # Check for early cancel
        db.session.expire(scan)
        if scan.status in ("failed", "stopped"):
            logger.info("Scan #%s cancelled during crawling phase.", scan_id)
            return {"scan_id": scan_id, "status": "stopped"}

        scan.pages_crawled = len(crawler.visited)
        db.session.commit()
        logger.info(
            "Scan #%s: crawled %s page(s), found %s target(s).",
            scan_id, scan.pages_crawled, len(injection_targets),
        )

        if not injection_targets:
            logger.warning(
                "Scan #%s: no injectable parameters found — marking completed.", scan_id
            )
            scan.status = "completed"
            scan.vuln_count = 0
            db.session.commit()
            return {"scan_id": scan_id, "vulnerabilities_found": 0}

        analyzer = ResponseAnalyzer()
        _build_baselines(injection_targets, analyzer)

        # Check for early cancel again
        db.session.expire(scan)
        if scan.status in ("failed", "stopped"):
            logger.info("Scan #%s cancelled after baseline collection.", scan_id)
            return {"scan_id": scan_id, "status": "stopped"}

        injector = PayloadInjector(targets=injection_targets, mode=mode)

        # Track confirmed vulnerable (url, parameter) pairs for early exit
        confirmed_vulns: set[tuple] = set()

        # Pre-load boolean payload pairs info
        boolean_payloads = PAYLOADS.get("boolean_based", [])
        boolean_false_map: dict[str, str] = {}
        for i in range(0, len(boolean_payloads) - 1, 2):
            boolean_false_map[boolean_payloads[i]] = boolean_payloads[i + 1]

        # Get non-boolean payloads
        non_boolean_payloads = [p for p in ALL_PAYLOADS if p["attack_type"] != "boolean_based"]

        # Filter payloads for Normal mode
        if mode == "normal":
            filtered = []
            for at in ["error_based", "time_based", "union_based"]:
                subset = [p for p in non_boolean_payloads if p["attack_type"] == at]
                filtered.extend(subset[:2])
            payload_pool = filtered
        else:
            payload_pool = non_boolean_payloads

        vuln_count = 0

        # Inject and analyze target-by-target (and payload-by-payload) on the fly
        for target in injection_targets:
            target_key = (target["url"], target["parameter"])

            # Check if scan has been cancelled
            db.session.expire(scan)
            if scan.status in ("failed", "stopped"):
                logger.info("Scan #%s cancelled/stopped during injection phase.", scan_id)
                return {"scan_id": scan_id, "status": "stopped"}

            if target_key in confirmed_vulns:
                continue

            target_vulnerable = False

            # 1. Test error, union, time based payloads
            for payload_info in payload_pool:
                # Check cancellation in the inner loop too
                db.session.expire(scan)
                if scan.status in ("failed", "stopped"):
                    logger.info("Scan #%s cancelled/stopped during payload run.", scan_id)
                    return {"scan_id": scan_id, "status": "stopped"}

                result = injector.send_request(target, payload_info)
                if result:
                    analysis = analyzer.analyze(result)
                    if analysis.get("is_vulnerable"):
                        combined = {**result, **analysis}
                        if _save_vulnerability(scan_id, combined):
                            vuln_count += 1
                            confirmed_vulns.add(target_key)
                            target_vulnerable = True
                            db.session.commit()
                        break # Early exit: skip other payloads for this target

            if target_vulnerable:
                continue

            # 2. Test boolean based payloads (run in TRUE/FALSE pairs)
            if mode == "normal":
                boolean_pairs = list(boolean_false_map.items())[:1]
            else:
                boolean_pairs = list(boolean_false_map.items())

            for true_pl, false_pl in boolean_pairs:
                db.session.expire(scan)
                if scan.status in ("failed", "stopped"):
                    logger.info("Scan #%s cancelled/stopped during boolean pairing.", scan_id)
                    return {"scan_id": scan_id, "status": "stopped"}

                true_info = {"attack_type": "boolean_based", "payload": true_pl}
                true_result = injector.send_request(target, true_info)
                if not true_result:
                    continue

                false_info = {"attack_type": "boolean_based", "payload": false_pl}
                false_result = injector.send_request(target, false_info)
                if not false_result:
                    continue

                analysis = analyzer.analyze_boolean_pair(true_result, false_result)
                if analysis.get("is_vulnerable"):
                    combined = {**true_result, **analysis}
                    if _save_vulnerability(scan_id, combined):
                        vuln_count += 1
                        confirmed_vulns.add(target_key)
                        db.session.commit()
                    break # Early exit: skip other boolean pairs for this target

        logger.info(
            "Scan #%s: %s vulnerability/vulnerabilities saved.", scan_id, vuln_count
        )

        scan.status = "completed"
        scan.vuln_count = vuln_count
        db.session.commit()

        return {"scan_id": scan_id, "vulnerabilities_found": vuln_count}

    except Exception as exc:
        logger.exception("Scan #%s failed with exception: %s", scan_id, exc)
        try:
            scan.status = "failed"
            db.session.commit()
        except Exception:
            db.session.rollback()
        raise