"""
app/alerts/routes.py

Displays the current user's alerts and lets them mark alerts as read.
"""

from flask import render_template, redirect, url_for
from flask_login import login_required, current_user

from app import db
from app.alerts import alerts_bp
from app.models import Alert


@alerts_bp.route('/alerts')
@login_required
def list_alerts():
    """
    Shows all of the current user's alerts, most recent first.

    SECURITY NOTE: filtered by Alert.user_id == current_user.id,
    same IDOR-prevention principle used throughout the app.
    """
    alerts = (
        Alert.query
        .filter_by(user_id=current_user.id)
        .order_by(Alert.created_at.desc())
        .all()
    )
    return render_template('alerts/list.html', alerts=alerts)


@alerts_bp.route('/alerts/<int:alert_id>/read', methods=['POST'])
@login_required
def mark_read(alert_id):
    """Marks a single alert as read. Only works on the current user's own alerts."""
    alert = Alert.query.filter_by(id=alert_id, user_id=current_user.id).first_or_404()
    alert.is_read = True
    db.session.commit()
    return redirect(url_for('alerts.list_alerts'))
