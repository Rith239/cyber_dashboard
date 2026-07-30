# Cyber Security Dashboard

A full-stack web-based cybersecurity dashboard built with Flask, combining network scanning, machine learning-based phishing detection, and integration with industry-standard security APIs into a single, role-based, multi-user platform.

**Live demo:** [https://cyber-dashboard-hxrn.onrender.com](https://cyber-dashboard-hxrn.onrender.com)
*(Free-tier hosting — the app spins down after inactivity, so the first request after a period of no traffic may take up to a minute to respond.)*

Built as a final-year BCA Cyber Security capstone project.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Security Design Highlights](#security-design-highlights)
- [Screenshots](#screenshots)
- [Setup & Installation (Local Development)](#setup--installation-local-development)
- [Deployment](#deployment)
- [Project Structure](#project-structure)
- [Known Limitations & Future Improvements](#known-limitations--future-improvements)
- [Credits & Acknowledgments](#credits--acknowledgments)

---

## Problem Statement

Individuals and small teams often lack a single, accessible place to run basic security checks — checking a suspicious link, scanning a file before opening it, verifying a domain's legitimacy, or seeing whether a password has been leaked. Enterprise security suites exist for this, but they're expensive, complex, and overkill for personal or small-scale use.

This project consolidates seven practical security tools into one authenticated, multi-user web dashboard — giving users a lightweight, self-hostable alternative that demonstrates how these checks work under the hood, rather than treating them as opaque black boxes.

## Features

| Tool | What it does | Powered by |
|---|---|---|
| **Vulnerability Scanner** | Runs live Nmap scans against a target, detecting open ports and service versions | `python-nmap`, with a target whitelist enforced in code for ethical/legal safety. *(Available at `/scanner`; not currently linked from the dashboard.)* |
| **AI Phishing Detector** | Classifies a submitted URL as phishing or legitimate | A Random Forest model trained on 549,346 real labeled URLs (Kaggle), layered with a trusted-domain whitelist |
| **Malware Scanner** | Scans an uploaded file against 60+ antivirus engines | VirusTotal API, with SHA-256 hash-first lookup before falling back to a full upload |
| **Domain Details Finder** | WHOIS lookup — registrar, creation/expiry dates, nameservers, status codes | `python-whois`, with automatic flags for newly-registered (<90 days) and soon-to-expire (<30 days) domains |
| **Password Breach Checker** | Checks whether a password has appeared in known data breaches | Have I Been Pwned API, using k-anonymity so the full password/hash is never transmitted |
| **SSL/TLS Certificate Checker** | Inspects a domain's live SSL certificate — issuer, validity, expiry | Direct Python `ssl`/`socket` connection — no third-party API required |
| **IP Geolocation & Reputation** | Shows an IP's location, ISP, and abuse reports | `ip-api.com` (geolocation) + AbuseIPDB (reputation scoring) |

**Supporting platform features:**
- User authentication with **email OTP verification** (6-digit code, 10-minute expiry, resend cooldown)
- Bcrypt password hashing, CSRF protection on all forms
- Role-based access control (user/admin) with a custom `@admin_required` decorator
- Unified, filterable, paginated scan history across all 7 tools
- CSV and PDF report export (generated in-memory, no disk writes)
- Automatic rule-based alerting for high-risk findings (malicious files, high-confidence phishing, risky open ports)
- Admin panel: view all users, oversee any user's scan history, promote/demote roles
- Custom hacker-terminal UI theme (dark, neon, monospace) layered over Bootstrap

## Tech Stack

- **Backend:** Flask (application factory + Blueprint pattern)
- **Database:** PostgreSQL, hosted on [Neon](https://neon.tech) (serverless), via SQLAlchemy ORM with the `pg8000` driver
- **Auth:** Flask-Login (sessions), Flask-Bcrypt (password hashing), Flask-WTF (forms + CSRF)
- **Machine Learning:** scikit-learn (Random Forest), pandas, joblib
- **Frontend:** Jinja2 templates, Bootstrap 5, custom CSS theme
- **Production server:** Waitress (WSGI)
- **Deployment:** Docker container on [Render](https://render.com) (Docker used specifically so Nmap, a system binary, is available at runtime)
- **External APIs:** VirusTotal, Have I Been Pwned, AbuseIPDB, ip-api.com

## Architecture

```mermaid
graph TD
    A[Browser] --> B[Flask App Factory]
    B --> C[Auth Blueprint<br/>Register / Login / OTP Verify]
    B --> D[Dashboard Blueprint]
    B --> E[Scanner Blueprint<br/>Nmap]
    B --> F[Phishing Blueprint<br/>Random Forest ML]
    B --> G[Malware Blueprint<br/>VirusTotal]
    B --> H[Domain Blueprint<br/>WHOIS]
    B --> I[Breach Blueprint<br/>HIBP]
    B --> J[SSL Check Blueprint]
    B --> K[IP Lookup Blueprint]
    B --> L[Reports Blueprint<br/>CSV/PDF Export]
    B --> M[Alerts Blueprint<br/>Rule Engine]
    B --> N[Admin Blueprint<br/>Role-Gated]
    B --> O[Profile Blueprint]

    E & F & G & H & I & J & K --> P[(PostgreSQL: scans table)]
    P --> M
    M --> Q[(PostgreSQL: alerts table)]
    C --> R[(PostgreSQL: users table)]
    N --> R
    N --> P
```

Each tool is implemented as an isolated Flask Blueprint with its own routes, forms, and templates, all sharing a common `Scan` model for history/reporting and a common `Alert` model for automated risk flagging.

## Security Design Highlights

This project was built with deliberate attention to common OWASP-recognized vulnerability categories, not just feature completeness:

- **Broken Access Control:** every database query is scoped to `current_user.id`; a custom `@admin_required` decorator returns a genuine 403 for non-admins attempting to reach `/admin` directly.
- **CSRF:** every form uses Flask-WTF's built-in CSRF token.
- **Authentication:** Bcrypt password hashing, re-authentication (current password required) before allowing a password change, email OTP verification at registration.
- **Secure defaults:** production `DEBUG` mode defaults to **off** if the environment variable controlling it is ever missing — the safe behavior happens automatically rather than requiring explicit configuration.
- **Path traversal prevention:** uploaded filenames are sanitized with `secure_filename()` before touching the filesystem.
- **Privacy-preserving API design:** the Password Breach Checker never transmits the full password or full hash — only a 5-character SHA-1 prefix (k-anonymity).
- **No secrets in source control:** all API keys and credentials are loaded from environment variables (a git-ignored `.env` locally, Render's environment settings in production).
- **Ethical scanning boundary:** the Vulnerability Scanner enforces a hard-coded target whitelist in code, not just a UI warning.

## Screenshots

> _Add screenshots of the dashboard, each tool in action, and the admin panel here before submission._

## Setup & Installation (Local Development)

### Prerequisites
- Python 3.10+
- A PostgreSQL database (e.g. a free [Neon](https://neon.tech) project) or local PostgreSQL/MySQL
- Nmap (Windows: [nmap.org/download.html](https://nmap.org/download.html))

### Steps

```bash
# Clone the repository
git clone https://github.com/Rith239/cyber_dashboard.git
cd cyber_dashboard

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
SECRET_KEY=your_generated_secret_key
DATABASE_URL=postgresql+pg8000://user:password@your-neon-host/dbname
FLASK_ENV=development
VIRUSTOTAL_API_KEY=your_virustotal_key
EMAIL_ADDRESS=your_gmail_address
EMAIL_APP_PASSWORD=your_gmail_app_password
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

```bash
# Create the database tables
python create_tables.py

# (Phishing detector) train the ML model
python train_model.py

# Run the app
python run.py
```

Visit `http://127.0.0.1:5000`.

## Deployment

This project is deployed on **Render** using the included `Dockerfile`, which installs Nmap alongside the Python dependencies (Nmap is a system binary and can't be installed via `pip`, so a standard Python buildpack alone isn't sufficient).

**To deploy your own copy:**
1. Push the repository to GitHub.
2. On [Render](https://render.com), create a new **Web Service**, connect the repo, and select **Docker** as the runtime (Render detects the `Dockerfile` automatically).
3. Add the same environment variables listed above under **Settings → Environment** (in place of a local `.env` file).
4. Deploy. Render builds the Docker image and starts the app via Waitress, reading the port Render assigns dynamically (`$PORT`).

**Database:** production uses [Neon](https://neon.tech), a free serverless PostgreSQL host. Locally, the same `DATABASE_URL` format works against any PostgreSQL instance.

## Project Structure

```
cyber_dashboard/
├── app/
│   ├── auth/          # Registration, login, OTP verification
│   ├── dashboard/      # Main landing page
│   ├── scanner/        # Vulnerability scanner (Nmap)
│   ├── phishing/       # AI phishing detector
│   ├── malware/        # Malware scanner (VirusTotal)
│   ├── domain/         # Domain details finder (WHOIS)
│   ├── breach/         # Password breach checker (HIBP)
│   ├── sslcheck/        # SSL/TLS certificate checker
│   ├── iplookup/        # IP geolocation & reputation
│   ├── reports/         # Scan history, CSV/PDF export
│   ├── alerts/          # Rule-based alerting
│   ├── admin/           # Admin panel
│   ├── profile/          # User profile management
│   ├── ml/               # Shared feature extraction + trained model
│   ├── templates/         # Jinja2 templates, organized by blueprint
│   ├── static/css/         # Custom hacker-theme stylesheet
│   └── models.py           # SQLAlchemy models: User, Scan, Alert
├── data/                   # Training dataset (git-ignored)
├── Dockerfile              # Production image, includes Nmap
├── .dockerignore
├── config.py
├── run.py
├── train_model.py
├── create_tables.py
└── requirements.txt
```

## Known Limitations & Future Improvements

- The Vulnerability Scanner route remains fully functional but isn't currently linked from the dashboard UI.
- The phishing detector's `has_https` feature carries no signal on the training dataset used (URLs lacked scheme prefixes) — documented rather than silently left in.
- Phishing model precision/recall reflects a deliberate class-weighted tradeoff favoring catching more real phishing at the cost of some false positives — see training output for the honest metrics.
- OTP emails may land in spam for a brand-new sending address — a dedicated transactional email service (e.g., SendGrid) would improve deliverability in a real deployment.
- No automated test suite yet — testing was conducted via a structured manual checklist (documented separately); `pytest`-based automated tests are a natural next step.
- IP geolocation accuracy is inherently approximate, as is standard for all IP-based location services.
- The free Render tier spins the service down after inactivity, causing a delayed first response (~50s) after idle periods.

## Credits & Acknowledgments

- Phishing dataset: [Phishing Site URLs](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) — Kaggle, taruntiwarihp
- Malware scanning: [VirusTotal API](https://www.virustotal.com)
- Password breach data: [Have I Been Pwned](https://haveibeenpwned.com)
- IP reputation: [AbuseIPDB](https://www.abuseipdb.com)
- IP geolocation: [ip-api.com](https://ip-api.com)
- Network scanning: [Nmap](https://nmap.org)
- Database hosting: [Neon](https://neon.tech)
- Application hosting: [Render](https://render.com)
