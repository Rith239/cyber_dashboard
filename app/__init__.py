"""
app/__init__.py

The Application Factory.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_login import current_user
from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from app import models

    from app.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix='/')

    from app.scanner import scanner_bp
    app.register_blueprint(scanner_bp, url_prefix='/')

    from app.phishing import phishing_bp
    app.register_blueprint(phishing_bp, url_prefix='/')

    from app.malware import malware_bp
    app.register_blueprint(malware_bp, url_prefix='/')

    from app.reports import reports_bp
    app.register_blueprint(reports_bp, url_prefix='/')

    from app.alerts import alerts_bp
    app.register_blueprint(alerts_bp, url_prefix='/')

    @app.context_processor
    def inject_unread_alert_count():
        """
        Makes 'unread_alert_count' automatically available in every
        template (used by the navbar badge in base.html), without
        needing to pass it manually from every single route.
        """
        if current_user.is_authenticated:
            from app.models import Alert
            count = Alert.query.filter_by(user_id=current_user.id, is_read=False).count()
            return {'unread_alert_count': count}
        return {'unread_alert_count': 0}

    return app
