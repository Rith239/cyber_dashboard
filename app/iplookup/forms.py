"""
app/iplookup/forms.py

Form for submitting an IP address to look up.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class IPLookupForm(FlaskForm):
    ip_address = StringField(
        'IP Address (e.g. 8.8.8.8)',
        validators=[DataRequired(), Length(min=7, max=45)]
    )
    submit = SubmitField('Look Up IP')
