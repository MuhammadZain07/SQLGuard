# app/routes/main.py
from flask import Blueprint, render_template, abort, send_file, redirect, url_for, session, request, flash
from ..models.database import db, Scan, Vulnerability, User
from .auth import login_required
import io
import feedparser

main_bp = Blueprint("main", __name__)


# Root route redirects to dashboard if logged in, otherwise to login page
@main_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    uid = session['user_id']
    scans = Scan.query.filter_by(user_id=uid).order_by(Scan.created_at.desc()).all()
    scan_ids = [s.id for s in scans]
    
    # Calculate cumulative vulnerability statistics scoped to this user
    user_vulns = Vulnerability.query.filter(Vulnerability.scan_id.in_(scan_ids)) if scan_ids else Vulnerability.query.filter(False)
    critical_count = user_vulns.filter(Vulnerability.severity == 'CRITICAL').count()
    high_count = user_vulns.filter(Vulnerability.severity == 'HIGH').count()
    medium_count = user_vulns.filter(Vulnerability.severity == 'MEDIUM').count()
    low_count = user_vulns.filter(Vulnerability.severity == 'LOW').count()
    
    error_count = user_vulns.filter(Vulnerability.vuln_type.like('%Error%')).count()
    boolean_count = user_vulns.filter(Vulnerability.vuln_type.like('%Boolean%')).count()
    time_count = user_vulns.filter(Vulnerability.vuln_type.like('%Time%')).count()
    union_count = user_vulns.filter(Vulnerability.vuln_type.like('%Union%')).count()
    
    # Calculate top vulnerable hosts
    from urllib.parse import urlparse
    from collections import Counter
    vuln_urls = db.session.query(Vulnerability.url, Scan.target_url).join(Scan, Vulnerability.scan_id == Scan.id).filter(Scan.user_id == uid).all()
    host_counter = Counter()
    for v_url, s_url in vuln_urls:
        url_to_parse = v_url or s_url
        if url_to_parse:
            try:
                host = urlparse(url_to_parse).netloc
                if host:
                    host_counter[host] += 1
            except Exception:
                continue
    top_hosts = host_counter.most_common(5)
    top_hosts_data = {
        'labels': [h[0] for h in top_hosts],
        'counts': [h[1] for h in top_hosts]
    }
    
    return render_template(
        "dashboard.html", 
        scans=scans,
        vuln_severity={
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count
        },
        vuln_types={
            'error': error_count,
            'boolean': boolean_count,
            'time': time_count,
            'union': union_count
        },
        top_hosts=top_hosts_data
    )


# Fix 2: corrected template name from "results.html" → "scan_result.html"
@main_bp.route("/scan/results/<int:scan_id>")
@login_required
def scan_results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != session.get('user_id'):
        abort(404)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    return render_template("scan_result.html", scan=scan, vulnerabilities=vulns)


@main_bp.route("/history")
@login_required
def history():
    scans = Scan.query.filter_by(user_id=session['user_id']).order_by(Scan.created_at.desc()).all()
    return render_template("history.html", scans=scans)


# Fix 9: added missing 'report' route — url_for('main.report') in base.html was crashing
@main_bp.route("/reports")
@login_required
def reports():
    scans = Scan.query.filter_by(user_id=session['user_id']).order_by(Scan.created_at.desc()).all()
    return render_template("report.html", scans=scans)


def _fetch_news_articles():
    articles = []
    import requests
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    # Try primary Feedburner first, fallback to the Blogger RSS endpoint
    urls = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://thehackernews.com/feeds/posts/default?alt=rss"
    ]
    
    for url in urls:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                feed = feedparser.parse(response.text)
                if feed.entries:
                    for entry in feed.entries[:10]:
                        summary = entry.get("summary", "")
                        if not summary:
                            summary = entry.get("description", "")
                        
                        date = entry.get("published", "")
                        if not date:
                            date = entry.get("pubDate", "")
                            
                        articles.append({
                            "title": entry.title,
                            "summary": (summary[:200] + "...") if summary else "",
                            "link": entry.link,
                            "date": date[:16] if date else ""
                        })
                    break  # Success!
        except Exception:
            continue
            
    return articles


# Fix 9: added missing 'news' route — url_for('main.news') in base.html was crashing
@main_bp.route("/news")
@login_required
def news():
    articles = _fetch_news_articles()
    return render_template("news.html", articles=articles[:6])


@main_bp.route("/api/news")
@login_required
def api_news():
    articles = _fetch_news_articles()
    return {"articles": [{"title": a["title"], "link": a["link"]} for a in articles]}

@main_bp.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')


@main_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db.session.get(User, session['user_id'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            full_name = request.form.get('full_name')
            birthday = request.form.get('birthday')
            gender = request.form.get('gender')
            
            user.full_name = full_name
            user.birthday = birthday
            user.gender = gender
            db.session.commit()
            flash('Profile details updated successfully!', 'success')
            return redirect(url_for('main.profile'))
            
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_password or not new_password or not confirm_password:
                flash('All password fields are required.', 'error')
                return redirect(url_for('main.profile'))
                
            if new_password != confirm_password:
                flash('New password and confirmation do not match.', 'error')
                return redirect(url_for('main.profile'))
                
            if not user or not user.check_password(current_password):
                flash('Incorrect current password.', 'error')
                return redirect(url_for('main.profile'))
                
            user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('main.profile'))
            
        elif action == 'delete_account':
            confirm_username = request.form.get('confirm_username')
            if confirm_username != user.username:
                flash('Username confirmation does not match. Account was not deleted.', 'error')
                return redirect(url_for('main.profile'))
                
            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash('Your account has been permanently deleted.', 'success')
            return redirect(url_for('auth.login'))
            
    return render_template('profile.html', user=user)


@main_bp.route("/report/<int:scan_id>/download")
@login_required
def download_report(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != session.get('user_id'):
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

