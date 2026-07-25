"""
app/auth/routes.py

Handles user registration (with email OTP verification), login, and logout.
"""

from datetime import datetime, timedelta
from flask import render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required

from app import db, bcrypt
from app.auth import auth_bp
from app.auth.forms import RegisterForm, LoginForm, OTPForm
from app.auth.email_utils import generate_otp, send_otp_email, OTP_VALID_MINUTES
from app.models import User

RESEND_COOLDOWN_SECONDS = 60


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Creates a new (unverified) account and sends an OTP verification email."""
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).first()

        if existing_user:
            flash('Username or email already registered. Please log in instead.', 'warning')
            return redirect(url_for('auth.login'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        otp_code = generate_otp()

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            is_verified=False,
            otp_code=otp_code,
            otp_generated_at=datetime.utcnow()
        )

        db.session.add(new_user)
        db.session.commit()

        email_sent = send_otp_email(new_user.email, new_user.username, otp_code)

        # Store which user is pending verification in the session,
        # so the verify page knows who it's checking without a URL parameter
        # (which could otherwise let someone guess another user's ID).
        session['pending_verification_user_id'] = new_user.id

        if email_sent:
            flash('Account created! Check your email for a 6-digit verification code.', 'success')
        else:
            flash('Account created, but the verification email could not be sent. Contact support or try resending.', 'warning')

        return redirect(url_for('auth.verify_email'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Lets a newly registered user enter their OTP code to verify their email."""
    user_id = session.get('pending_verification_user_id')
    if not user_id:
        flash('No pending verification found. Please register or log in.', 'warning')
        return redirect(url_for('auth.register'))

    user = User.query.get(user_id)
    if not user or user.is_verified:
        session.pop('pending_verification_user_id', None)
        return redirect(url_for('auth.login'))

    form = OTPForm()

    if form.validate_on_submit():
        expiry_time = user.otp_generated_at + timedelta(minutes=OTP_VALID_MINUTES)

        if datetime.utcnow() > expiry_time:
            flash('That code has expired. Please request a new one.', 'danger')
        elif form.otp_code.data != user.otp_code:
            flash('Incorrect code. Please try again.', 'danger')
        else:
            user.is_verified = True
            user.otp_code = None
            user.otp_generated_at = None
            db.session.commit()
            session.pop('pending_verification_user_id', None)
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('auth/verify_email.html', form=form, email=user.email)


@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Generates and sends a fresh OTP code, with a cooldown to prevent spamming."""
    user_id = session.get('pending_verification_user_id')
    if not user_id:
        return redirect(url_for('auth.register'))

    user = User.query.get(user_id)
    if not user or user.is_verified:
        return redirect(url_for('auth.login'))

    if user.otp_generated_at and datetime.utcnow() < user.otp_generated_at + timedelta(seconds=RESEND_COOLDOWN_SECONDS):
        flash(f'Please wait a bit before requesting another code.', 'warning')
        return redirect(url_for('auth.verify_email'))

    new_otp = generate_otp()
    user.otp_code = new_otp
    user.otp_generated_at = datetime.utcnow()
    db.session.commit()

    email_sent = send_otp_email(user.email, user.username, new_otp)
    if email_sent:
        flash('A new code has been sent to your email.', 'success')
    else:
        flash('Could not send the email right now. Please try again shortly.', 'danger')

    return redirect(url_for('auth.verify_email'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login. Blocks unverified accounts from logging in."""
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            if not user.is_verified:
                session['pending_verification_user_id'] = user.id
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('auth.verify_email'))

            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard.home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Logs the current user out."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
