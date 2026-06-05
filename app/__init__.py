from flask import Flask
from .models.database import db
from config import Config
from celery import Celery

# Create a real Celery instance upfront — not None
# It gets fully configured inside create_app()
celery = Celery(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

        # Lightweight migrations for existing databases
        _migrations = [
            ("scans", "mode", "VARCHAR(20) DEFAULT 'normal'"),
            ("scans", "user_id", "INTEGER REFERENCES users(id)"),
            ("users", "full_name", "VARCHAR(150)"),
            ("users", "birthday", "VARCHAR(50)"),
            ("users", "gender", "VARCHAR(50)"),
        ]
        for table, col, col_type in _migrations:
            try:
                db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
                db.session.commit()
            except Exception:
                db.session.rollback()

    # Configure the celery instance that already exists
    from .celery_config import make_celery
    make_celery(app, celery)  # pass existing celery in, configure it

    from .routes.main import main_bp
    from .routes.scan import scan_bp
    from .routes.auth import auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(auth_bp)

    return app