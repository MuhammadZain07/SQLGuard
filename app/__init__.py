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

    # Configure the celery instance that already exists
    from .celery_config import make_celery
    make_celery(app, celery)  # pass existing celery in, configure it

    from .routes.main import main_bp
    from .routes.scan import scan_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)

    return app