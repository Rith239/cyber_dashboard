"""
app/auth/routes.py

Handles user registration, login, and logout.
"""

from flask import render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required

from app import db, bcrypt
from app.auth import auth_bp
from app.auth.forms import RegisterForm, LoginForm
from app.models import User


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user account creation."""
    form = RegisterForm()

    if form.validate_on_submit():
        # Check if username or email is already taken
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).first()

        if existing_user:
            flash('Username or email already registered. Please log in instead.', 'warning')
            return redirect(url_for('auth.login'))

        # Hash the password before storing -- never save plain text passwords
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        # Check the user exists AND the hashed password matches
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
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
