# app/routes/scan.py
from flask import Blueprint, request, jsonify
from ..models.database import db, Scan
from ..tasks import run_scan  # Celery task

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/start-scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("url")
    scan = Scan(target_url=target_url, status="pending")
    db.session.add(scan)
    db.session.commit()

    # Send job to Celery (runs in background via Redis)
    task = run_scan.delay(scan.id, target_url)
    scan.celery_task_id = task.id
    db.session.commit()

    return jsonify({"scan_id": scan.id, "status": "started"})

@scan_bp.route("/scan-status/<int:scan_id>")
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({"status": scan.status, "vuln_count": scan.vuln_count})