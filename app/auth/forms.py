"""
app/auth/forms.py

Defines the web forms used for registration and login, using Flask-WTF.
Flask-WTF automatically adds CSRF protection to every form here.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegisterForm(FlaskForm):
    """Form for creating a new user account."""

    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=3, max=80)]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6)]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Form for logging into an existing account."""

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
