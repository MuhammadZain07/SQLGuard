import logging
import requests as http_requests 
from datetime import datetime

from app import celery  
from app.models.database import db, Scan, Vulnerability
from app.scanner.crawler import WebCrawler
from app.scanner.injector import PayloadInjector
from app.scanner.analyzer import ResponseAnalyzer

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Helper: persist one vulnerability to the database
# -----------------------------------------------------------------
def _save_vulnerability(scan_id: int, result: dict) -> None:
    """
    Writes a single detected vulnerability to the Vulnerability table.
    Fix 8: Skips duplicates — same (url, parameter, vuln_type) for the same scan.
    """
    # Fix 8 — duplicate check before inserting
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
        return

    vuln = Vulnerability(
        scan_id=scan_id,
        url=result.get("url", ""),
        parameter=result.get("parameter", ""),
        method=result.get("method", "GET"),
        vuln_type=result.get("vuln_type", "Unknown"),
        severity=result.get("severity", "LOW"),
        payload=result.get("payload", ""),
        response_snippet=result.get("response_snippet", "")[:500],  # cap length
        recommendation=result.get("recommendation", ""),
        found_at=datetime.utcnow(),
    )
    db.session.add(vuln)


# -----------------------------------------------------------------
# Helper: fetch neutral baseline response sizes before injecting
# -----------------------------------------------------------------
def _build_baselines(injection_targets: list[dict], analyzer: ResponseAnalyzer) -> None:
    """
    Fix 5: Fetch a neutral response (param=test) for every unique (url, parameter)
    pair BEFORE any payloads are sent. This gives the analyzer a true baseline
    to compare against, eliminating false positives from boolean-based detection.
    """
    seen: set[tuple] = set()

    for target in injection_targets:
        key = (target["url"], target["parameter"])
        if key in seen:
            continue
        seen.add(key)

        try:
            r = http_requests.get(
                target["url"],
                params={target["parameter"]: "test"},
                timeout=10,
            )
            analyzer.set_baseline(target["url"], target["parameter"], len(r.text))
            logger.debug(
                "Baseline set for %s param=%s size=%s",
                target["url"], target["parameter"], len(r.text),
            )
        except Exception as exc:
            # No baseline for this param — boolean check will be skipped for it
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
        3. Build neutral baselines for boolean-based detection  (Fix 5)
        4. Inject SQL payloads into every discovered parameter
        5. Analyse each response for vulnerabilities
        6. Persist every unique finding to SQLite             (Fix 8)
        7. Mark scan as "completed" (or "failed" on error)

    Returns a summary dict that Celery stores as the task result.
    """
    # Fix 1: tasks.py no longer calls create_app() — celery is imported from
    # the app factory in app/__init__.py, so no circular import can occur.

    # ----------------------------------------------------------
    # Step 1 — Mark scan as running
    # ----------------------------------------------------------
    # Fix 7: use db.session.get() instead of deprecated Scan.query.get()
    scan = db.session.get(Scan, scan_id)
    if not scan:
        logger.error("run_scan: Scan #%s not found in DB.", scan_id)
        return {"error": f"Scan {scan_id} not found"}

    scan.status = "running"
    db.session.commit()
    logger.info("Scan #%s started for %s", scan_id, target_url)

    try:
        # ----------------------------------------------------------
        # Step 2 — Crawl the target
        # ----------------------------------------------------------
        from flask import current_app  # safe here — we're inside app context via ContextTask

        crawler = WebCrawler(
            target_url=target_url,
            max_depth=current_app.config.get("MAX_DEPTH", 3),
            max_pages=current_app.config.get("MAX_PAGES", 30),
        )
        injection_targets = crawler.crawl()  # list[dict]

        # Fix 6: use crawler.visited (actual pages) not unique target URLs (which
        # counts parameters, not pages — one page with 3 fields counted as 3).
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

        # ----------------------------------------------------------
        # Step 3 — Build neutral baselines (Fix 5)
        # Must happen BEFORE PayloadInjector fires any requests.
        # ----------------------------------------------------------
        analyzer = ResponseAnalyzer()
        _build_baselines(injection_targets, analyzer)

        # ----------------------------------------------------------
        # Step 4 — Inject payloads
        # ----------------------------------------------------------
        injector = PayloadInjector(targets=injection_targets)
        injection_results = injector.inject()  # list[dict]
        logger.info(
            "Scan #%s: %s injection attempt(s) completed.",
            scan_id, len(injection_results),
        )

        # ----------------------------------------------------------
        # Step 5 & 6 — Analyse responses and save unique findings
        # ----------------------------------------------------------
        vuln_count = 0

        for result in injection_results:
            analysis = analyzer.analyze(result)
            if analysis.get("is_vulnerable"):
                combined = {**result, **analysis}
                _save_vulnerability(scan_id, combined)  # Fix 8: deduplication inside
                vuln_count += 1

        db.session.commit()
        logger.info(
            "Scan #%s: %s vulnerability/vulnerabilities saved.", scan_id, vuln_count
        )

        # ----------------------------------------------------------
        # Step 7 — Mark completed
        # ----------------------------------------------------------
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

        raise  # re-raise so Celery records the task as FAILURE