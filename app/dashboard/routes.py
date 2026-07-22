"""
app/dashboard/routes.py

Handles the main dashboard homepage, shown to logged-in users only.
Shows the user's 5 most recent scans across all tools.
"""

from flask import render_template
from flask_login import login_required, current_user

from app.dashboard import dashboard_bp
from app.models import Scan


@dashboard_bp.route('/')
@login_required
def home():
    """
    Main dashboard homepage.
    Only accessible to logged-in users (enforced by @login_required).
    """
    recent_scans = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )
    return render_template('dashboard/home.html', user=current_user, recent_scans=recent_scans)
