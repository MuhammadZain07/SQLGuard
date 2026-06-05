# app/routes/scan.py
import ipaddress
import socket

from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
from ..models.database import db, Scan
from ..tasks import run_scan

scan_bp = Blueprint("scan", __name__)


def _is_safe_host(hostname: str) -> bool:
    """
    Resolve hostname to its IP(s) and reject any that fall in
    private / loopback / link-local / reserved ranges.
    This blocks SSRF via http://127.0.0.1, http://192.168.x.x,
    http://169.254.169.254 (AWS metadata), etc.
    """
    try:
        # getaddrinfo returns all A/AAAA records
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Cannot resolve → treat as unsafe
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


def _is_valid_url(url: str) -> bool:
    """
    Validate URL scheme/netloc AND block SSRF-prone hosts.
    Accepts only http/https URLs with a non-empty, publicly-routable host.
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        # Strip port if present to get the bare hostname
        hostname = parsed.hostname
        if not hostname:
            return False
        return _is_safe_host(hostname)
    except Exception:
        return False


from .auth import login_required

@scan_bp.route("/start-scan", methods=["POST"])
@login_required
def start_scan():
    target_url = request.form.get("url", "").strip()
    mode = request.form.get("mode", "normal").strip().lower()
    if mode not in ("normal", "aggressive"):
        mode = "normal"

    if not _is_valid_url(target_url):
        return jsonify({
            "error": (
                "Invalid or unsafe URL. Must be a publicly-routable "
                "http:// or https:// address."
            )
        }), 400

    scan = Scan(target_url=target_url, status="pending", mode=mode)
    db.session.add(scan)
    db.session.commit()

    task = run_scan.delay(scan.id, target_url, mode=mode)
    scan.celery_task_id = task.id
    db.session.commit()

    return jsonify({"scan_id": scan.id, "status": "started"})


@scan_bp.route("/stop-scan/<int:scan_id>", methods=["POST"])
@login_required
def stop_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    if scan.status in ("pending", "running"):
        # Revoke the task in Celery
        if scan.celery_task_id:
            from app import celery
            try:
                celery.control.revoke(scan.celery_task_id, terminate=True, signal='SIGKILL')
            except Exception:
                pass
        
        # Mark as failed/stopped
        scan.status = "failed"
        db.session.commit()
        return jsonify({"status": "stopped", "scan_id": scan_id})
    
    return jsonify({"error": "Scan is not running"}), 400


@scan_bp.route("/scan-status/<int:scan_id>")
@login_required
def scan_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    from ..models.database import Vulnerability

    critical = Vulnerability.query.filter_by(scan_id=scan_id, severity="CRITICAL").count()
    high     = Vulnerability.query.filter_by(scan_id=scan_id, severity="HIGH").count()
    medium   = Vulnerability.query.filter_by(scan_id=scan_id, severity="MEDIUM").count()
    low      = Vulnerability.query.filter_by(scan_id=scan_id, severity="LOW").count()

    return jsonify({
        "status": scan.status,
        "vuln_count": scan.vuln_count,
        "pages_crawled": scan.pages_crawled,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    })