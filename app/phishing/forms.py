"""
app/phishing/forms.py

Form for submitting a URL to check.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class URLCheckForm(FlaskForm):
    """Form for entering a URL to check for phishing."""

    url = StringField(
        'URL to check',
        validators=[DataRequired(), Length(min=1, max=2000)]
    )
    submit = SubmitField('Check URL')
