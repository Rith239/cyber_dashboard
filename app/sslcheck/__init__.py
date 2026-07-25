"""
app/sslcheck/__init__.py

Defines the 'sslcheck' Blueprint -- inspects a domain's SSL/TLS
certificate directly over a real socket connection, no API needed.
"""

from flask import Blueprint

sslcheck_bp = Blueprint('sslcheck', __name__, template_folder='templates')

from app.sslcheck import routes
