"""
config.py

Central configuration file for the Flask application.
Reads secret values from the .env file (never hardcoded here)
so this file is safe to commit to GitHub.
"""

import os
from dotenv import load_dotenv

# Load variables from .env into the environment
load_dotenv()


class Config:
    """Base configuration class used by the Flask app factory."""

    # Used by Flask to cryptographically sign session cookies
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # MySQL connection string, loaded from .env
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

    # Disables a SQLAlchemy feature we don't need; avoids console warnings
    SQLALCHEMY_TRACK_MODIFICATIONS = False