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
    UserMixin (from Flask-Login) adds default implementations of
    properties Flask-Login needs, like is_authenticated and is_active.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: lets us write user.scans to get all scans by this user.
    # 'backref' lets us also write scan.user to get the owning user from a scan.
    scans = db.relationship('Scan', backref='user', lazy=True)

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
    scan_type = db.Column(db.String(50), nullable=False)   # e.g. 'vulnerability', 'phishing', 'malware'
    target = db.Column(db.String(255), nullable=False)      # e.g. IP, URL, or filename
    result = db.Column(db.Text, nullable=True)               # summary of findings
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Scan {self.scan_type} on {self.target}>'