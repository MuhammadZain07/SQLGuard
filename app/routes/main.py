# app/routes/main.py
from flask import Blueprint, render_template, abort, send_file
from ..models.database import db, Scan, Vulnerability
import io

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
def home():
    return render_template("index.html")

@main_bp.route("/dashboard")
def dashboard():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template("dashboard.html", scans=scans)

@main_bp.route("/scan/results/<int:scan_id>")
def scan_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    return render_template("results.html", scan=scan, vulnerabilities=vulns)

@main_bp.route("/history")
def history():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("history.html", scans=scans)

@main_bp.route("/report/<int:scan_id>/download")
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    # Basic text report — frontend (Part 4) may replace this with PDF
    report_lines = [f"Scan Report — {scan.target_url}", f"Status: {scan.status}", ""]
    for v in vulns:
        report_lines.append(f"[{v.severity}] {v.vuln_type} at {v.url}")
    report_bytes = "\n".join(report_lines).encode()
    return send_file(
        io.BytesIO(report_bytes),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"report_{scan_id}.txt"
    )