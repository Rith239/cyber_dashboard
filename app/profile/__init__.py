"""
app/profile/__init__.py

Defines the 'profile' Blueprint -- lets a user view their account
details and update their email or password.
"""

from flask import Blueprint

profile_bp = Blueprint('profile', __name__, template_folder='templates')

from app.profile import routes
