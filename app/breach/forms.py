"""
app/breach/forms.py

Form for submitting a password to check against known breaches.
"""

from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired


class BreachCheckForm(FlaskForm):
    password = PasswordField('Password to check', validators=[DataRequired()])
    submit = SubmitField('Check Password')
