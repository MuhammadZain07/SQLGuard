import logging
from datetime import datetime

from app import create_app
from app.celery_config import make_celery
from app.models.database import db, Scan, Vulnerability
from app.scanner.crawler import WebCrawler
from app.scanner.injector import PayloadInjector
from app.scanner.analyzer import ResponseAnalyzer

# -----------------------------------------------------------------
# Bootstrap Flask + Celery
# -----------------------------------------------------------------
flask_app = create_app()
celery = make_celery(flask_app)

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Helper: persist one vulnerability to the database
# -----------------------------------------------------------------
def _save_vulnerability(scan_id: int, result: dict) -> None:
    """
    Writes a single detected vulnerability to the Vulnerability table.

    Expected keys in `result` (all provided by ResponseAnalyzer):
        url, parameter, method, vuln_type, severity, cvss_score,
        payload, response_snippet, recommendation
    """
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
# Main Celery task
# -----------------------------------------------------------------
@celery.task(bind=True, max_retries=0)
def run_scan(self, scan_id: int, target_url: str) -> dict:
    """
    Background task that runs the full SQL-injection scan pipeline:

        1. Mark scan as "running"
        2. Crawl the target website for forms / GET parameters
        3. Inject SQL payloads into every discovered parameter
        4. Analyse each response for vulnerabilities
        5. Persist every finding to SQLite
        6. Mark scan as "completed" (or "failed" on error)

    Returns a summary dict that Celery stores as the task result.
    """
    with flask_app.app_context():

        # ----------------------------------------------------------
        # Step 1 -- Mark scan as running
        # ----------------------------------------------------------
        scan = Scan.query.get(scan_id)
        if not scan:
            logger.error("run_scan: Scan #%s not found in DB.", scan_id)
            return {"error": f"Scan {scan_id} not found"}

        scan.status = "running"
        db.session.commit()
        logger.info("Scan #%s started for %s", scan_id, target_url)

        try:
            # ------------------------------------------------------
            # Step 2 -- Crawl the target
            # ------------------------------------------------------
            crawler = WebCrawler(
                target_url=target_url,
                max_depth=flask_app.config.get("MAX_DEPTH", 3),
                max_pages=flask_app.config.get("MAX_PAGES", 30),
            )
            injection_targets = crawler.crawl()  # list[dict]

            pages_crawled = len(set(t["url"] for t in injection_targets))
            scan.pages_crawled = pages_crawled
            db.session.commit()
            logger.info(
                "Scan #%s: crawled %s page(s), found %s target(s).",
                scan_id, pages_crawled, len(injection_targets),
            )

            if not injection_targets:
                logger.warning(
                    "Scan #%s: no injectable parameters found — marking completed.", scan_id
                )
                scan.status = "completed"
                scan.vuln_count = 0
                db.session.commit()
                return {"scan_id": scan_id, "vulnerabilities_found": 0}

            # ------------------------------------------------------
            # Step 3 -- Inject payloads
            # ------------------------------------------------------
            injector = PayloadInjector(targets=injection_targets)
            injection_results = injector.inject()  # list[dict]
            logger.info(
                "Scan #%s: %s injection attempt(s) completed.",
                scan_id, len(injection_results),
            )

            # ------------------------------------------------------
            # Step 4 & 5 -- Analyse responses and save findings
            # ------------------------------------------------------
            analyzer = ResponseAnalyzer()
            vuln_count = 0

            for result in injection_results:
                analysis = analyzer.analyze(result)  # dict with is_vulnerable, …
                if analysis.get("is_vulnerable"):
                    # Merge target metadata into the analysis dict for storage
                    combined = {**result, **analysis}
                    _save_vulnerability(scan_id, combined)
                    vuln_count += 1

            db.session.commit()
            logger.info(
                "Scan #%s: %s vulnerability/vulnerabilities saved.", scan_id, vuln_count
            )

            # ------------------------------------------------------
            # Step 6 -- Mark completed
            # ------------------------------------------------------
            scan.status = "completed"
            scan.vuln_count = vuln_count
            db.session.commit()

            return {"scan_id": scan_id, "vulnerabilities_found": vuln_count}

        except Exception as exc:
            # Log the full traceback and mark the scan as failed
            logger.exception("Scan #%s failed with exception: %s", scan_id, exc)
            try:
                scan.status = "failed"
                db.session.commit()
            except Exception:
                db.session.rollback()

            # Re-raise so Celery records the task as FAILURE
            raise