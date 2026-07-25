"""
app/iplookup/routes.py

Looks up an IP address's geolocation (ip-api.com, no key needed) and
abuse reputation (AbuseIPDB, requires a free API key).
"""

import os
import re
import requests
from flask import render_template, flash
from flask_login import login_required, current_user

from app import db
from app.iplookup import iplookup_bp
from app.iplookup.forms import IPLookupForm
from app.models import Scan

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

IP_PATTERN = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)


def is_valid_ipv4(ip):
    match = IP_PATTERN.match(ip)
    if not match:
        return False
    return all(0 <= int(part) <= 255 for part in match.groups())


def get_geolocation(ip):
    """Free, no-key geolocation lookup via ip-api.com."""
    response = requests.get(f'http://ip-api.com/json/{ip}', timeout=8)
    data = response.json()

    if data.get('status') != 'success':
        return None

    return {
        'country': data.get('country', 'Unknown'),
        'city': data.get('city', 'Unknown'),
        'region': data.get('regionName', 'Unknown'),
        'isp': data.get('isp', 'Unknown'),
        'org': data.get('org', 'Unknown'),
    }


def get_abuse_reputation(ip):
    """
    Checks AbuseIPDB for abuse reports on this IP.
    Returns None if the API key isn't configured or the request fails,
    rather than crashing -- geolocation can still be shown on its own.
    """
    if not ABUSEIPDB_API_KEY:
        return None

    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}

    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers, params=params, timeout=8
        )
        response.raise_for_status()
        data = response.json().get('data', {})

        return {
            'abuse_score': data.get('abuseConfidenceScore', 0),
            'total_reports': data.get('totalReports', 0),
            'is_whitelisted': data.get('isWhitelisted', False),
        }
    except requests.exceptions.RequestException:
        return None


@iplookup_bp.route('/ip-lookup', methods=['GET', 'POST'])
@login_required
def lookup():
    """Displays the IP lookup form and, on submission, fetches geolocation + reputation."""
    form = IPLookupForm()
    result = None

    if form.validate_on_submit():
        ip = form.ip_address.data.strip()

        if not is_valid_ipv4(ip):
            flash('That doesn\'t look like a valid IPv4 address (e.g. 8.8.8.8).', 'danger')
        else:
            geo = get_geolocation(ip)

            if geo is None:
                flash(f'Could not find geolocation data for "{ip}".', 'warning')
            else:
                reputation = get_abuse_reputation(ip)

                result = {
                    'ip': ip,
                    'geo': geo,
                    'reputation': reputation,
                }

                summary_parts = [f"Location: {geo['city']}, {geo['country']} | ISP: {geo['isp']}"]
                if reputation:
                    summary_parts.append(f"Abuse score: {reputation['abuse_score']}% ({reputation['total_reports']} reports)")

                new_scan = Scan(
                    user_id=current_user.id,
                    scan_type='ip_lookup',
                    target=ip,
                    result=' | '.join(summary_parts)
                )
                db.session.add(new_scan)
                db.session.commit()

                flash('IP lookup completed and saved.', 'success')

    return render_template('iplookup/lookup.html', form=form, result=result)
