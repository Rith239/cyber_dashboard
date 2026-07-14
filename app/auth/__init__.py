"""
app/auth/__init__.py

Defines the 'auth' Blueprint, which groups all authentication-related
routes (register, login, logout) together.
"""

from flask import Blueprint

auth_bp = Blueprint('auth', __name__, template_folder='templates')

from app.auth import routes
