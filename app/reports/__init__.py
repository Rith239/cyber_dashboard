"""
app/reports/__init__.py

Defines the 'reports' Blueprint -- shows a user's scan history
across all three tools (vulnerability, phishing, malware).
"""

from flask import Blueprint

reports_bp = Blueprint('reports', __name__, template_folder='templates')

from app.reports import routes
