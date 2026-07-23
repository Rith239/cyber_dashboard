"""
app/alerts/rules.py

Simple, explainable rule-based logic that decides whether a completed
scan deserves an alert. Deliberately NOT machine learning -- alerting
rules should be predictable and easy to justify, not a black box.
"""

from app import db
from app.models import Alert

# Ports historically associated with high risk if found open
# (old/insecure protocols frequently targeted by attackers).
RISKY_PORTS = {
    21: 'FTP (unencrypted file transfer, often misconfigured)',
    23: 'Telnet (unencrypted remote access, deprecated)',
    3389: 'RDP (frequent target of brute-force/ransomware attacks)',
}

PHISHING_CONFIDENCE_THRESHOLD = 80.0


def check_and_create_alert(scan, user_id):
    """
    Inspects a just-saved Scan record and creates an Alert if it matches
    one of our risk rules. Called right after each scan type saves its
    result in scanner/phishing/malware routes.py.
    """
    alert = None

    if scan.scan_type == 'malware':
        if 'Detected by' in (scan.result or ''):
            try:
                detected_part = scan.result.split('Detected by')[1]
                malicious_count = int(detected_part.strip().split('/')[0])
                if malicious_count > 0:
                    alert = Alert(
                        user_id=user_id,
                        scan_id=scan.id,
                        severity='high',
                        message=f"Malware detected in '{scan.target}' ({malicious_count} engines flagged it)."
                    )
            except (ValueError, IndexError):
                pass  # couldn't parse the count -- skip alerting rather than guess

    elif scan.scan_type == 'phishing':
        if 'Phishing' in (scan.result or ''):
            try:
                confidence_part = scan.result.split('confidence:')[1]
                confidence = float(confidence_part.strip().rstrip('%)'))
                if confidence >= PHISHING_CONFIDENCE_THRESHOLD:
                    alert = Alert(
                        user_id=user_id,
                        scan_id=scan.id,
                        severity='high',
                        message=f"High-confidence phishing URL detected: '{scan.target}' ({confidence}% confidence)."
                    )
            except (ValueError, IndexError):
                pass

    elif scan.scan_type == 'vulnerability':
        found_risky = []
        for port, description in RISKY_PORTS.items():
            if f'Port {port}:' in (scan.result or '') and 'open' in scan.result:
                found_risky.append(f"{port} ({description})")

        if found_risky:
            alert = Alert(
                user_id=user_id,
                scan_id=scan.id,
                severity='medium',
                message=f"Risky open port(s) found on '{scan.target}': {'; '.join(found_risky)}."
            )

    if alert:
        db.session.add(alert)
        db.session.commit()

    return alert
