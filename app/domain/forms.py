"""
app/domain/forms.py

Form for submitting a domain to look up.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class DomainLookupForm(FlaskForm):
    domain = StringField(
        'Domain (e.g. example.com)',
        validators=[DataRequired(), Length(min=3, max=255)]
    )
    submit = SubmitField('Look Up Domain')
