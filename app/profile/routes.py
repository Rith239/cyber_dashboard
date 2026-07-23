"""
app/profile/routes.py

Displays account details and handles email updates and password changes.
"""

from flask import render_template, flash, redirect, url_for
from flask_login import login_required, current_user

from app import db, bcrypt
from app.profile import profile_bp
from app.profile.forms import UpdateEmailForm, ChangePasswordForm
from app.models import User, Scan


@profile_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def view():
    """
    Shows the current user's account details and activity summary.
    Handles both the email-update form and the password-change form
    on the same page (distinguished by which submit button was clicked).
    """
    email_form = UpdateEmailForm()
    password_form = ChangePasswordForm()

    # Pre-fill the email field with the current value on a normal page load
    if not email_form.is_submitted():
        email_form.email.data = current_user.email

    if email_form.submit_email.data and email_form.validate_on_submit():
        existing = User.query.filter(
            User.email == email_form.email.data, User.id != current_user.id
        ).first()

        if existing:
            flash('That email is already in use by another account.', 'warning')
        else:
            current_user.email = email_form.email.data
            db.session.commit()
            flash('Email updated successfully.', 'success')
        return redirect(url_for('profile.view'))

    if password_form.submit_password.data and password_form.validate_on_submit():
        # Re-authentication: verify the CURRENT password before allowing the change.
        if not bcrypt.check_password_hash(current_user.password_hash, password_form.current_password.data):
            flash('Current password is incorrect.', 'danger')
        else:
            new_hash = bcrypt.generate_password_hash(password_form.new_password.data).decode('utf-8')
            current_user.password_hash = new_hash
            db.session.commit()
            flash('Password changed successfully.', 'success')
        return redirect(url_for('profile.view'))

    # Activity summary: count of scans by type, for the logged-in user only
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    vulnerability_count = Scan.query.filter_by(user_id=current_user.id, scan_type='vulnerability').count()
    phishing_count = Scan.query.filter_by(user_id=current_user.id, scan_type='phishing').count()
    malware_count = Scan.query.filter_by(user_id=current_user.id, scan_type='malware').count()

    return render_template(
        'profile/view.html',
        email_form=email_form,
        password_form=password_form,
        total_scans=total_scans,
        vulnerability_count=vulnerability_count,
        phishing_count=phishing_count,
        malware_count=malware_count
    )
