from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    birthday = db.Column(db.String(50), nullable=True)
    gender = db.Column(db.String(50), nullable=True)

    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending/running/completed/failed
    mode = db.Column(db.String(20), default='normal')      # normal/aggressive
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    pages_crawled = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)
    celery_task_id = db.Column(db.String(200), nullable=True)

    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')

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
    found_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Vulnerability {self.id} - {self.vuln_type}>'