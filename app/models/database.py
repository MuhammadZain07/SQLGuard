from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending/running/completed/failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    pages_crawled = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)
    celery_task_id = db.Column(db.String(200), nullable=True)

    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)
    reports = db.relationship('Report', backref='scan', lazy=True)

    def __repr__(self):
        return f'<Scan {self.id} - {self.target_url}>'


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    url = db.Column(db.String(500))
    parameter = db.Column(db.String(200))
    method = db.Column(db.String(10))         # GET or POST
    vuln_type = db.Column(db.String(100))     # error-based, boolean, etc.
    severity = db.Column(db.String(20))       # CRITICAL / HIGH / MEDIUM / LOW
    payload = db.Column(db.Text)
    response_snippet = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    found_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Vulnerability {self.id} - {self.vuln_type}>'


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    filename = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Report {self.id} - {self.filename}>'