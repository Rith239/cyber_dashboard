"""
app/domain/__init__.py

Defines the 'domain' Blueprint -- WHOIS-based domain lookup tool.
"""

from flask import Blueprint

domain_bp = Blueprint('domain', __name__, template_folder='templates')

from app.domain import routes
