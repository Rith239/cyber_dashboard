"""
app/iplookup/__init__.py

Defines the 'iplookup' Blueprint -- combines IP geolocation
(ip-api.com) with abuse reputation (AbuseIPDB).
"""

from flask import Blueprint

iplookup_bp = Blueprint('iplookup', __name__, template_folder='templates')

from app.iplookup import routes
