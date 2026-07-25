"""
app/domain/routes.py

Looks up WHOIS registration details for a domain.
"""

import re
import whois
from datetime import datetime
from flask import render_template, flash
from flask_login import login_required, current_user

from app import db
from app.domain import domain_bp
from app.domain.forms import DomainLookupForm
from app.models import Scan

DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')


def clean_domain(raw):
    domain = raw.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.replace('www.', '', 1) if domain.startswith('www.') else domain
    return domain


def make_naive(dt):
    """Strips timezone info so it can be safely compared against datetime.now()."""
    if dt and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def first_if_list(value):
    """Some WHOIS fields come back as a list of duplicates -- take the first."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def format_date(value):
    value = first_if_list(value)
    if isinstance(value, datetime):
        return value.strftime('%d %b %Y')
    return str(value) if value else 'Unknown'


@domain_bp.route('/domain', methods=['GET', 'POST'])
@login_required
def lookup():
    """Displays the domain lookup form and, on submission, fetches WHOIS data."""
    form = DomainLookupForm()
    result = None

    if form.validate_on_submit():
        domain = clean_domain(form.domain.data)

        if not DOMAIN_PATTERN.match(domain):
            flash("That doesn't look like a valid domain (e.g. example.com).", 'danger')
        else:
            try:
                w = whois.whois(domain)

                if not w or not w.domain_name:
                    flash(f'No WHOIS record found for "{domain}". It may be unregistered or use privacy protection.', 'warning')
                else:
                    creation_date = format_date(w.creation_date)
                    expiration_date = format_date(w.expiration_date)
                    registrar = w.registrar or 'Unknown'

                    nameservers = w.name_servers if w.name_servers else []
                    if isinstance(nameservers, str):
                        nameservers = [nameservers]

                    # Domain status codes (e.g. clientTransferProhibited) --
                    # indicate security locks registrars apply to a domain.
                    statuses = w.status if w.status else []
                    if isinstance(statuses, str):
                        statuses = [statuses]
                    # Status strings often include a trailing URL reference -- keep just the code.
                    statuses = [s.split(' ')[0] for s in statuses][:6]

                    raw_creation = make_naive(first_if_list(w.creation_date))
                    raw_expiration = make_naive(first_if_list(w.expiration_date))

                    is_newly_registered = False
                    if isinstance(raw_creation, datetime):
                        age_days = (datetime.now() - raw_creation).days
                        is_newly_registered = age_days < 90

                    days_until_expiry = None
                    expiring_soon = False
                    if isinstance(raw_expiration, datetime):
                        days_until_expiry = (raw_expiration - datetime.now()).days
                        expiring_soon = 0 <= days_until_expiry < 30

                    # Raw WHOIS text, for a collapsible "full details" section
                    raw_text = w.text if hasattr(w, 'text') and w.text else 'Raw WHOIS text not available.'

                    result = {
                        'domain': domain,
                        'registrar': registrar,
                        'creation_date': creation_date,
                        'expiration_date': expiration_date,
                        'nameservers': nameservers[:4],
                        'statuses': statuses,
                        'is_newly_registered': is_newly_registered,
                        'days_until_expiry': days_until_expiry,
                        'expiring_soon': expiring_soon,
                        'raw_text': raw_text,
                    }

                    result_summary = (
                        f"Registrar: {registrar} | Created: {creation_date} | "
                        f"Expires: {expiration_date}"
                        + (" | FLAG: newly registered (<90 days)" if is_newly_registered else "")
                        + (" | FLAG: expiring soon (<30 days)" if expiring_soon else "")
                    )

                    new_scan = Scan(
                        user_id=current_user.id,
                        scan_type='domain',
                        target=domain,
                        result=result_summary
                    )
                    db.session.add(new_scan)
                    db.session.commit()

                    flash('Domain lookup completed and saved.', 'success')

            except Exception as e:
                flash(f'Could not retrieve WHOIS data: {str(e)}', 'danger')

    return render_template('domain/lookup.html', form=form, result=result)