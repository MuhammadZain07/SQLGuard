from flask import Flask
from .models.database import db
from config import Config

celery = None  # will be set by create_app()

def create_app():
    global celery
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    from .celery_config import make_celery
    celery = make_celery(app)

    from .routes.main import main_bp
    from .routes.scan import scan_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)

    return app