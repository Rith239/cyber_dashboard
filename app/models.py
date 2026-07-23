"""
app/models.py

Defines the database models (tables) for the application using
SQLAlchemy's ORM. Each class below becomes a real MySQL table.
"""

from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    """
    Required by Flask-Login.
    Given a user's ID (stored in their session cookie), this function
    tells Flask-Login how to load the full User object from the database.
    """
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """
    Represents a registered user of the dashboard.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship('Scan', backref='user', lazy=True)
    alerts = db.relationship('Alert', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    """
    Represents a single scan performed by a user
    (vulnerability scan, phishing check, or malware scan).
    """
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    alerts = db.relationship('Alert', backref='scan', lazy=True)

    def __repr__(self):
        return f'<Scan {self.scan_type} on {self.target}>'


class Alert(db.Model):
    """
    Represents a high-risk finding automatically flagged after a scan,
    based on rule-based logic in app/alerts/rules.py.
    """
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # 'high' or 'medium'
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Alert {self.severity}: {self.message[:30]}>'
