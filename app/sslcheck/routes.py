"""
app/sslcheck/routes.py

Connects directly to a domain over port 443 and inspects its SSL/TLS
certificate -- issuer, validity dates, and days remaining until expiry.
No external API needed; Python's built-in ssl/socket modules handle
the real TLS handshake and certificate retrieval.
"""

import re
import ssl
import socket
from datetime import datetime
from flask import render_template, flash
from flask_login import login_required, current_user

from app import db
from app.sslcheck import sslcheck_bp
from app.sslcheck.forms import SSLCheckForm
from app.models import Scan

DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')

CERT_DATE_FORMAT = '%b %d %H:%M:%S %Y %Z'


def clean_domain(raw):
    domain = raw.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]  # strip any port the user included
    return domain


def get_certificate_info(domain, timeout=8):
    """
    Opens a real TLS connection to the domain on port 443 and retrieves
    its certificate. If this succeeds with default verification settings,
    Python has already validated the certificate chain and hostname --
    an invalid/expired/mismatched cert would raise an exception instead.
    """
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    issuer_parts = dict(x[0] for x in cert.get('issuer', []))
    subject_parts = dict(x[0] for x in cert.get('subject', []))

    not_before = datetime.strptime(cert['notBefore'], CERT_DATE_FORMAT)
    not_after = datetime.strptime(cert['notAfter'], CERT_DATE_FORMAT)

    days_remaining = (not_after - datetime.now()).days

    return {
        'issuer': issuer_parts.get('organizationName', issuer_parts.get('commonName', 'Unknown')),
        'subject': subject_parts.get('commonName', domain),
        'valid_from': not_before.strftime('%d %b %Y'),
        'valid_until': not_after.strftime('%d %b %Y'),
        'days_remaining': days_remaining,
        'expiring_soon': 0 <= days_remaining < 30,
        'expired': days_remaining < 0,
    }


@sslcheck_bp.route('/ssl-check', methods=['GET', 'POST'])
@login_required
def check():
    """Displays the SSL check form and, on submission, inspects the domain's certificate."""
    form = SSLCheckForm()
    result = None

    if form.validate_on_submit():
        domain = clean_domain(form.domain.data)

        if not DOMAIN_PATTERN.match(domain):
            flash("That doesn't look like a valid domain (e.g. example.com).", 'danger')
        else:
            try:
                cert_info = get_certificate_info(domain)
                cert_info['domain'] = domain
                result = cert_info

                status = "EXPIRED" if cert_info['expired'] else (
                    "expiring soon" if cert_info['expiring_soon'] else "valid"
                )
                result_summary = (
                    f"Issuer: {cert_info['issuer']} | Valid until: {cert_info['valid_until']} "
                    f"({cert_info['days_remaining']} days) | Status: {status}"
                )

                new_scan = Scan(
                    user_id=current_user.id,
                    scan_type='ssl_check',
                    target=domain,
                    result=result_summary
                )
                db.session.add(new_scan)
                db.session.commit()

                flash('SSL certificate check completed and saved.', 'success')

            except ssl.SSLCertVerificationError:
                flash(f'Certificate verification failed for "{domain}" -- it may be invalid, expired, or mismatched.', 'danger')
            except socket.timeout:
                flash(f'Connection to "{domain}" timed out.', 'danger')
            except socket.gaierror:
                flash(f'Could not resolve "{domain}" -- check the domain is correct.', 'danger')
            except Exception as e:
                flash(f'Could not check certificate: {str(e)}', 'danger')

    return render_template('sslcheck/check.html', form=form, result=result)
