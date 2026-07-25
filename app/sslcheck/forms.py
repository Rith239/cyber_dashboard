"""
app/sslcheck/forms.py

Form for submitting a domain to check its SSL/TLS certificate.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class SSLCheckForm(FlaskForm):
    domain = StringField(
        'Domain (e.g. example.com)',
        validators=[DataRequired(), Length(min=3, max=255)]
    )
    submit = SubmitField('Check Certificate')
