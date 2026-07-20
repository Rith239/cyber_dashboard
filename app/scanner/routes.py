"""
app/scanner/routes.py

Handles running Nmap vulnerability scans and displaying/saving results.
"""

import nmap
from flask import render_template, flash
from flask_login import login_required, current_user

from app import db
from app.scanner import scanner_bp
from app.scanner.forms import ScanForm
from app.models import Scan

# Only these targets are allowed to be scanned, for legal/ethical safety.
# localhost is your own machine; scanme.nmap.org is a target Nmap's creators
# explicitly set up for public testing.
ALLOWED_TARGETS = ['localhost', '127.0.0.1', 'scanme.nmap.org']


@scanner_bp.route('/scanner', methods=['GET', 'POST'])
@login_required
def scan():
    """
    Displays the scan form and, on submission, runs an Nmap scan
    against the given target, then saves the result to the database.
    """
    form = ScanForm()
    scan_results = None

    if form.validate_on_submit():
        target = form.target.data.strip()

        if target not in ALLOWED_TARGETS:
            flash(
                f'For legal and ethical reasons, only these targets are allowed in this demo: '
                f'{", ".join(ALLOWED_TARGETS)}',
                'danger'
            )
        else:
            try:
                scanner = nmap.PortScanner()
                # -sV: detect service/version info on open ports
                scanner.scan(target, arguments='-sV')

                # Build a readable summary of what was found
                summary_lines = []
                for host in scanner.all_hosts():
                    summary_lines.append(f"Host: {host} ({scanner[host].hostname()})")
                    summary_lines.append(f"State: {scanner[host].state()}")

                    for proto in scanner[host].all_protocols():
                        summary_lines.append(f"Protocol: {proto}")
                        ports = scanner[host][proto].keys()
                        for port in sorted(ports):
                            port_info = scanner[host][proto][port]
                            summary_lines.append(
                                f"  Port {port}: {port_info['state']} "
                                f"({port_info.get('name', 'unknown')} "
                                f"{port_info.get('product', '')} {port_info.get('version', '')})"
                            )

                scan_results = '\n'.join(summary_lines) if summary_lines else 'No open ports found.'

                # Save this scan to the database, linked to the logged-in user
                new_scan = Scan(
                    user_id=current_user.id,
                    scan_type='vulnerability',
                    target=target,
                    result=scan_results
                )
                db.session.add(new_scan)
                db.session.commit()

                flash('Scan completed and saved successfully.', 'success')

            except Exception as e:
                flash(f'Scan failed: {str(e)}', 'danger')

    return render_template('scanner/scan.html', form=form, scan_results=scan_results, allowed_targets=ALLOWED_TARGETS)
