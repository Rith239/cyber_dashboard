"""
app/breach/routes.py

Checks a password against the Have I Been Pwned Pwned Passwords API
using k-anonymity -- only the first 5 characters of the SHA-1 hash
are ever sent over the network. The full password and full hash
never leave this server, and are never stored anywhere.
"""

import hashlib
import requests
from flask import render_template, flash
from flask_login import login_required, current_user

from app import db
from app.breach import breach_bp
from app.breach.forms import BreachCheckForm
from app.models import Scan

HIBP_API_URL = 'https://api.pwnedpasswords.com/range/'


def check_password_breach(password):
    """
    Returns the number of times this password has appeared in known
    breaches (0 if not found), or None if the check itself failed
    (e.g. network error) -- callers should distinguish "0 = safe"
    from "None = could not check".
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        # Only the 5-character PREFIX is sent -- the API returns every
        # suffix sharing that prefix, and we check locally which (if any)
        # matches. HIBP never receives the full hash, let alone the password.
        response = requests.get(HIBP_API_URL + prefix, timeout=10)
        response.raise_for_status()

        for line in response.text.splitlines():
            returned_suffix, count = line.split(':')
            if returned_suffix == suffix:
                return int(count)

        return 0  # prefix matched others, but our exact suffix wasn't among them

    except requests.exceptions.RequestException:
        return None


@breach_bp.route('/breach-check', methods=['GET', 'POST'])
@login_required
def check():
    """
    Displays the password-check form and, on submission, checks it
    against HIBP. The password itself is NEVER stored -- only the
    breach count is saved to scan history.
    """
    form = BreachCheckForm()
    result = None

    if form.validate_on_submit():
        password = form.password.data
        breach_count = check_password_breach(password)

        if breach_count is None:
            flash('Could not reach the breach-check service right now. Please try again.', 'danger')
        else:
            is_breached = breach_count > 0
            result = {
                'is_breached': is_breached,
                'breach_count': breach_count,
            }

            result_summary = (
                f"Found in {breach_count:,} known breach(es) -- do not reuse this password."
                if is_breached else
                "Not found in known breaches."
            )

            # SECURITY: target is a fixed label, NEVER the actual password checked.
            new_scan = Scan(
                user_id=current_user.id,
                scan_type='breach_check',
                target='[password not stored]',
                result=result_summary
            )
            db.session.add(new_scan)
            db.session.commit()

            flash('Password check completed.', 'success')

    return render_template('breach/check.html', form=form, result=result)
