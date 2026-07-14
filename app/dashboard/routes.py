"""
app/dashboard/routes.py

Handles the main dashboard homepage, shown to logged-in users only.
"""

from flask import render_template
from flask_login import login_required, current_user

from app.dashboard import dashboard_bp


@dashboard_bp.route('/')
@login_required
def home():
    """
    Main dashboard homepage.
    Only accessible to logged-in users (enforced by @login_required).
    """
    return render_template('dashboard/home.html', user=current_user)
