"""
config.py

Central configuration file for the Flask application.
Reads secret values from the .env file (never hardcoded here)
so this file is safe to commit to GitHub.
"""

import os
import ssl
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration -- shared by all environments."""

    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Neon requires SSL. pg8000's URL-based "ssl_context=true" query
    # parameter doesn't reliably convert to a real SSL context object in
    # this driver/SQLAlchemy combination, so we pass one explicitly here
    # instead -- a genuine ssl.SSLContext, not a string.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {'ssl_context': ssl.create_default_context()}
    }

    DEBUG = os.environ.get('FLASK_ENV', 'production') == 'development'