"""
app/breach/__init__.py

Defines the 'breach' Blueprint -- checks passwords against the
Have I Been Pwned database using k-anonymity (privacy-preserving).
"""

from flask import Blueprint

breach_bp = Blueprint('breach', __name__, template_folder='templates')

from app.breach import routes
