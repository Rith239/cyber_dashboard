"""
create_tables.py

One-time script to create all database tables defined in app/models.py.
Run once, then this file can be deleted (tables persist in MySQL).
"""

from app import create_app, db

app = create_app()

with app.app_context():
    db.create_all()
    print("Tables created successfully.")