"""
app/phishing/__init__.py

Defines the 'phishing' Blueprint -- lets a logged-in user submit a URL
and get an AI-based phishing/legitimate prediction.
"""

from flask import Blueprint

phishing_bp = Blueprint('phishing', __name__, template_folder='templates')

from app.phishing import routes
