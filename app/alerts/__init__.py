"""
app/alerts/__init__.py

Defines the 'alerts' Blueprint -- shows high-risk findings flagged
automatically after scans complete.
"""

from flask import Blueprint

alerts_bp = Blueprint('alerts', __name__, template_folder='templates')

from app.alerts import routes
