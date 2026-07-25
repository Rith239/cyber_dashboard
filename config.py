"""
config.py

Central configuration file for the Flask application.
Reads secret values from the .env file (never hardcoded here)
so this file is safe to commit to GitHub.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration -- shared by all environments."""

    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Whether Flask runs in debug mode -- controlled by FLASK_ENV in .env.
    # NEVER let this be True in a real deployment: debug mode can leak
    # stack traces, source code, and expose an interactive code-execution
    # debugger to anyone who can reach the server.
    # Defaults to 'production' (debug OFF) if FLASK_ENV is missing entirely --
    # a secure-by-default fallback.
    DEBUG = os.environ.get('FLASK_ENV', 'production') == 'development'
