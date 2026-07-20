"""
app/scanner/forms.py

Form for submitting a scan target.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class ScanForm(FlaskForm):
    """Form for entering a target to scan."""

    target = StringField(
        'Target (IP address or domain)',
        validators=[DataRequired(), Length(min=1, max=255)]
    )
    submit = SubmitField('Run Scan')
