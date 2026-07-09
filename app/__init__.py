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

# These are created here (unbound to any app yet) so that
# models.py and route files can import them without circular imports.
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()


def create_app():
    """
    Application factory function.
    Creates a configured Flask app instance.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Bind the extensions (created above) to this specific app instance
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Blueprints will be registered here as we build each module.
    # Example (added in later modules):
    # from app.auth.routes import auth_bp
    # app.register_blueprint(auth_bp)

    @app.route('/')
    def index():
        return '<h1>Cyber Security Dashboard</h1><p>Flask app is running successfully.</p>'

    return app