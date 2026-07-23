"""
app/profile/forms.py

Forms for updating email and changing password.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class UpdateEmailForm(FlaskForm):
    """Form for updating the account's email address."""

    email = StringField('New Email', validators=[DataRequired(), Email()])
    submit_email = SubmitField('Update Email')


class ChangePasswordForm(FlaskForm):
    """
    Form for changing the account password.
    Requires the CURRENT password first -- re-authentication before
    allowing a sensitive change, so an unattended logged-in session
    can't be used to silently lock the real owner out.
    """

    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField(
        'New Password',
        validators=[DataRequired(), Length(min=6)]
    )
    confirm_new_password = PasswordField(
        'Confirm New Password',
        validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')]
    )
    submit_password = SubmitField('Change Password')
