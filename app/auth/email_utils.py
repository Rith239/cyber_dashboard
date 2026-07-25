"""
app/auth/email_utils.py

Handles OTP generation and sending verification emails via Gmail SMTP.
"""

import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS')
EMAIL_APP_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD')
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

OTP_VALID_MINUTES = 10


def generate_otp():
    """Generates a random 6-digit numeric code as a string, e.g. '042817'."""
    return str(random.randint(100000, 999999))


def send_otp_email(to_email, username, otp_code):
    """
    Sends a verification email containing the OTP code.
    Returns True on success, False on failure (caller decides how to
    handle a failed send -- e.g. flash a warning rather than crash).
    """
    if not EMAIL_ADDRESS or not EMAIL_APP_PASSWORD:
        print("EMAIL_ADDRESS / EMAIL_APP_PASSWORD not configured in .env")
        return False

    subject = "Verify your Cyber Security Dashboard account"
    body = f"""Hi {username},

Your verification code is: {otp_code}

This code expires in {OTP_VALID_MINUTES} minutes. If you didn't request this, you can ignore this email.

- Cyber Security Dashboard
"""

    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = to_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
            server.send_message(message)
        return True
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False
