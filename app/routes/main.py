# app/routes/main.py
from flask import Blueprint, render_template, abort, send_file
from ..models.database import db, Scan, Vulnerability
import io
import feedparser

main_bp = Blueprint("main", __name__)


# Fix 3: renamed 'home' → 'index' so url_for('main.index') in base.html works
@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/dashboard")
def dashboard():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template("dashboard.html", scans=scans)


# Fix 2: corrected template name from "results.html" → "scan_result.html"
@main_bp.route("/scan/results/<int:scan_id>")
def scan_results(scan_id):
    scan = db.session.get(Scan, scan_id)  # Fix 7 (already noted)
    if scan is None:
        abort(404)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    return render_template("scan_result.html", scan=scan, vulnerabilities=vulns)


@main_bp.route("/history")
def history():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("history.html", scans=scans)


# Fix 9: added missing 'report' route — url_for('main.report') in base.html was crashing
@main_bp.route("/reports")
def reports():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("report.html", scans=scans)


# Fix 9: added missing 'news' route — url_for('main.news') in base.html was crashing
@main_bp.route("/news")
def news():
    articles = []
    try:
        feed = feedparser.parse("https://feeds.feedburner.com/TheHackersNews")
        for entry in feed.entries[:6]:
            articles.append({
                "title": entry.title,
                "summary": entry.get("summary", "")[:200] + "...",
                "link": entry.link,
                "date": entry.get("published", "")[:16]
            })
    except:
        pass  # if it fails, articles stays empty, fallback shows
    return render_template("news.html", articles=articles)

@main_bp.route('/analytics')
def analytics():
    return render_template('analytics.html')


@main_bp.route("/report/<int:scan_id>/download")
def download_report(scan_id):
    scan = db.session.get(Scan, scan_id)  # Fix 7 (already noted)
    if scan is None:
        abort(404)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
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

