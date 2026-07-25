"""
app/admin/__init__.py

Defines the 'admin' Blueprint -- restricted to users with role='admin'.
"""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__, template_folder='templates')

from app.admin import routes
