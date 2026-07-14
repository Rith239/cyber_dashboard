"""
app/__init__.py

The Application Factory.
This file creates and configures the Flask app, initializes
extensions (database, login manager, password hashing), and
registers all feature blueprints.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # redirects here if @login_required blocks access


def create_app():
    """
    Application factory function.
    Creates a configured Flask app instance.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from app import models

    # Register the auth blueprint (login, register, logout routes)
    from app.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    @app.route("/")
    def index():
        return "<h1>Cyber Security Dashboard</h1><p>Flask app is running successfully.</p>"

    return app
