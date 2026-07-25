"""
run.py

Entry point for starting the Flask app.

- For LOCAL DEVELOPMENT: run this file directly with `python run.py`.
  Debug mode is controlled by FLASK_ENV in .env (set to 'development'
  to enable auto-reload and detailed error pages).

- For PRODUCTION: do NOT use this file directly. Use Waitress instead:
    waitress-serve --host=0.0.0.0 --port=8000 run:app
  This runs the app through a real WSGI server, with debug mode
  guaranteed off regardless of .env settings.
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])
