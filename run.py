"""
run.py

Entry point for starting the Flask development server.
Run this file directly: python run.py
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)