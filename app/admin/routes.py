"""
app/admin/routes.py

Admin-only views: list all users, view any user's scan history,
and promote/demote user roles.
"""

from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from app import db
from app.admin import admin_bp
from app.admin.decorators import admin_required
from app.models import User, Scan


@admin_bp.route('/admin')
@login_required
@admin_required
def dashboard():
    """Lists every user on the system with their role and scan count."""
    users = User.query.order_by(User.created_at.asc()).all()

    user_data = []
    for user in users:
        scan_count = Scan.query.filter_by(user_id=user.id).count()
        user_data.append({'user': user, 'scan_count': scan_count})

    return render_template('admin/users.html', user_data=user_data)


@admin_bp.route('/admin/users/<int:user_id>/scans')
@login_required
@admin_required
def user_scans(user_id):
    """Shows a specific user's full scan history -- admin oversight view."""
    user = User.query.get_or_404(user_id)
    scans = (
        Scan.query
        .filter_by(user_id=user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    return render_template('admin/user_scans.html', target_user=user, scans=scans)


@admin_bp.route('/admin/users/<int:user_id>/toggle-role', methods=['POST'])
@login_required
@admin_required
def toggle_role(user_id):
    """
    Promotes a regular user to admin, or demotes an admin back to user.
    Prevents an admin from demoting themselves (which could lock the
    only admin out of the admin panel entirely).
    """
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You can't change your own role.", 'warning')
        return redirect(url_for('admin.dashboard'))

    user.role = 'admin' if user.role == 'user' else 'user'
    db.session.commit()
    flash(f"{user.username}'s role updated to '{user.role}'.", 'success')
    return redirect(url_for('admin.dashboard'))
