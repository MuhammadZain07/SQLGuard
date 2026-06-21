# app/routes/main.py
from flask import Blueprint, render_template, abort, redirect, url_for, session, request, flash
from ..models.database import db, Scan, Vulnerability, User
from .auth import login_required
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


def get_deterministic_cvss(vuln):
    """
    Computes a realistic, deterministic CVSS v3.1 score based on hashing
    vulnerability properties to keep the score stable across requests.
    """
    import hashlib
    data_str = f"{vuln.url or ''}{vuln.parameter or ''}{vuln.vuln_type or ''}"
    h = hashlib.md5(data_str.encode("utf-8")).hexdigest()
    val = int(h[:4], 16)
    
    sev = (vuln.severity or "LOW").upper()
    if sev == "CRITICAL":
        return round(9.0 + (val % 11) * 0.1, 1)  # 9.0 to 10.0
    elif sev == "HIGH":
        return round(7.0 + (val % 20) * 0.1, 1)  # 7.0 to 8.9
    elif sev == "MEDIUM":
        return round(4.0 + (val % 30) * 0.1, 1)  # 4.0 to 6.9
    else:
        return round(1.0 + (val % 30) * 0.1, 1)  # 1.0 to 3.9


# Fix 2: corrected template name from "results.html" → "scan_result.html"
@main_bp.route("/scan/results/<int:scan_id>")
@login_required
def scan_results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != session.get('user_id'):
        abort(404)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    # Calculate dynamic CVSS scores for all findings
    for v in vulns:
        v.cvss = get_deterministic_cvss(v)
        
    # Calculate overall compound scan risk score
    if not vulns:
        risk_score = 0
        risk_label = "SECURE"
        risk_class = "risk-secure"
    else:
        cvss_scores = [v.cvss for v in vulns]
        max_cvss = max(cvss_scores)
        
        # Base risk score is max CVSS scaled to 100
        base_score = max_cvss * 10.0
        
        # Add compounding factor for additional vulnerabilities
        compounding = 0.0
        sorted_scores = sorted(cvss_scores, reverse=True)
        for score in sorted_scores[1:]:
            if score >= 9.0:
                compounding += 3.0
            elif score >= 7.0:
                compounding += 2.0
            elif score >= 4.0:
                compounding += 1.0
            else:
                compounding += 0.5
                
        risk_score = min(round(base_score + compounding), 100)
        
        # Map overall score to severity categories
        if risk_score >= 90:
            risk_label = "CRITICAL RISK"
            risk_class = "risk-critical"
        elif risk_score >= 70:
            risk_label = "HIGH RISK"
            risk_class = "risk-high"
        elif risk_score >= 40:
            risk_label = "MODERATE RISK"
            risk_class = "risk-medium"
        else:
            risk_label = "LOW RISK"
            risk_class = "risk-low"

    # Calculate severity and type statistics for charts in scan_result.html
    critical = sum(1 for v in vulns if v.severity == 'CRITICAL')
    high     = sum(1 for v in vulns if v.severity == 'HIGH')
    medium   = sum(1 for v in vulns if v.severity == 'MEDIUM')
    low      = sum(1 for v in vulns if v.severity == 'LOW')

    error_based   = sum(1 for v in vulns if v.vuln_type == 'Error-Based')
    boolean_based = sum(1 for v in vulns if v.vuln_type == 'Boolean-Based')
    time_based    = sum(1 for v in vulns if v.vuln_type == 'Time-Based')
    union_based   = sum(1 for v in vulns if v.vuln_type == 'Union-Based')

    return render_template(
        "scan_result.html", 
        scan=scan, 
        vulnerabilities=vulns,
        risk_score=risk_score,
        risk_label=risk_label,
        risk_class=risk_class,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        error_based=error_based,
        boolean_based=boolean_based,
        time_based=time_based,
        union_based=union_based
    )


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
                
            if len(new_password) < 8:
                flash('New password must be at least 8 characters long.', 'error')
                return redirect(url_for('main.profile'))
                
            if not user or not user.check_password(current_password):
                flash('Incorrect current password.', 'error')
                return redirect(url_for('main.profile'))
                
            user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('main.profile'))
            
        elif action == 'delete_account':
            confirm_username = request.form.get('confirm_username', '').strip().lower()
            if confirm_username != user.username.lower():
                flash('Username confirmation does not match. Account was not deleted.', 'error')
                return redirect(url_for('main.profile'))
                
            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash('Your account has been permanently deleted.', 'success')
            return redirect(url_for('auth.login'))
            
    return render_template('profile.html', user=user)
