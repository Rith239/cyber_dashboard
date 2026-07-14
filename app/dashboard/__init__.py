"""
app/dashboard/__init__.py

Defines the 'dashboard' Blueprint -- the main landing page
users see after logging in.
"""

from flask import Blueprint

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')

from app.dashboard import routes
