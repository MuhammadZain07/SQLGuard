# app/tasks.py
import logging
import requests as http_requests
from datetime import datetime

from app import celery
from app.models.database import db, Scan, Vulnerability
from app.scanner.crawler import WebCrawler, is_safe_url
from app.scanner.injector import PayloadInjector
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
        found_at=datetime.utcnow(),
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

            analyzer.set_baseline(target["url"], target["parameter"], len(r.text))
            logger.debug(
                "Baseline set [%s] for %s param=%s size=%s",
                method, target["url"], target["parameter"], len(r.text),
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
def run_scan(self, scan_id: int, target_url: str) -> dict:
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
    logger.info("Scan #%s started for %s", scan_id, target_url)

    try:
        from flask import current_app

        crawler = WebCrawler(
            target_url=target_url,
            max_depth=current_app.config.get("MAX_DEPTH", 3),
            max_pages=current_app.config.get("MAX_PAGES", 30),
        )
        injection_targets = crawler.crawl()

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

        injector = PayloadInjector(targets=injection_targets)
        injection_results = injector.inject()
        logger.info(
            "Scan #%s: %s injection attempt(s) completed.",
            scan_id, len(injection_results),
        )

        vuln_count = 0
        for result in injection_results:
            analysis = analyzer.analyze(result)
            if analysis.get("is_vulnerable"):
                combined = {**result, **analysis}
                if _save_vulnerability(scan_id, combined):
                    vuln_count += 1

        db.session.commit()
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