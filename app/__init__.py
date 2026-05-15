from flask import Flask
from .models.database import db
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        db.create_all()

   from .routes.main import main_bp
   from .routes.scan import scan_bp
   app.register_blueprint(main_bp)
   app.register_blueprint(scan_bp)

    return app
