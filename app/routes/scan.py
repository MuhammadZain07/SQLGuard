# app/routes/scan.py
from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
from ..models.database import db, Scan
from ..tasks import run_scan

scan_bp = Blueprint("scan", __name__)


def _is_valid_url(url: str) -> bool:
    """
    Fix 4: Validate URL before touching the database.
    Accepts only http/https URLs with a non-empty host.
    Rejects None, empty strings, javascript:, file://, etc.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


@scan_bp.route("/start-scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("url", "").strip()

    # Fix 4: reject bad URLs before any DB write happens
    if not _is_valid_url(target_url):
        return jsonify({
            "error": "Invalid or missing URL. Must start with http:// or https://"
        }), 400

    scan = Scan(target_url=target_url, status="pending")
    db.session.add(scan)
    db.session.commit()

    task = run_scan.delay(scan.id, target_url)
    scan.celery_task_id = task.id
    db.session.commit()

    return jsonify({"scan_id": scan.id, "status": "started"})


@scan_bp.route("/scan-status/<int:scan_id>")
def scan_status(scan_id):
    # Fix 7: use db.session.get() instead of deprecated Scan.query.get_or_404()
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "status": scan.status,
        "vuln_count": scan.vuln_count,
        "pages_crawled": scan.pages_crawled,  # bonus: useful for frontend progress display
    })