"""
app/phishing/routes.py

Loads the trained phishing detection model once, then uses it to
classify user-submitted URLs as phishing or legitimate. A trusted-domain
whitelist is checked first, since the ML model alone can misjudge very
short, minimal-feature URLs (e.g. a bare "google.com").
"""

import os
import joblib
import pandas as pd
from urllib.parse import urlparse
from flask import render_template, flash
from flask_login import login_required, current_user

from app import db
from app.phishing import phishing_bp
from app.phishing.forms import URLCheckForm
from app.models import Scan
from app.ml.feature_extraction import extract_features, FEATURE_NAMES

MODEL_PATH = os.path.join('app', 'ml', 'phishing_model.pkl')

# Load the trained model ONCE when this module is first imported,
# not on every single request -- loading from disk is relatively slow,
# and the model doesn't change between requests.
_model = None

# A small set of widely-known, high-traffic legitimate domains.
# The ML model alone can misjudge very short/minimal-feature URLs
# (e.g. a bare "google.com" has almost no lexical signal to work with),
# so we short-circuit well-known domains to "legitimate" before
# involving the model at all. This is a common real-world pattern:
# combining a trusted-domain heuristic with a machine learning model,
# rather than relying on ML in isolation.
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'wikipedia.org', 'microsoft.com', 'apple.com', 'github.com',
    'paypal.com', 'netflix.com', 'linkedin.com', 'instagram.com',
    'twitter.com', 'x.com', 'reddit.com', 'yahoo.com',
]


def get_model():
    """Lazy-loads the trained model into memory the first time it's needed."""
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def is_trusted_domain(url):
    """
    Returns True if the URL's domain (ignoring 'www.' and any port number)
    exactly matches a known trusted domain -- not just contains it as a
    substring, so 'google.com.suspicious-login.xyz' does NOT match.
    """
    target = url if '://' in url else 'http://' + url
    try:
        netloc = urlparse(target).netloc.lower()
    except Exception:
        return False

    netloc = netloc.split(':')[0]  # strip any port number
    if netloc.startswith('www.'):
        netloc = netloc[4:]

    return netloc in TRUSTED_DOMAINS


@phishing_bp.route('/phishing', methods=['GET', 'POST'])
@login_required
def check():
    """
    Displays the URL-check form and, on submission, runs the trained
    model (or the trusted-domain whitelist) against the submitted URL,
    then saves the result.
    """
    form = URLCheckForm()
    prediction_result = None

    if form.validate_on_submit():
        url = form.url.data.strip()

        if is_trusted_domain(url):
            # Skip the ML model entirely for known, trusted domains.
            is_phishing = False
            confidence = 99.0
        else:
            model = get_model()

            # IMPORTANT: uses the exact same feature extraction function
            # that was used during training (train_model.py), so the model
            # receives input in the format it was trained on.
            features = extract_features(url)
            features_df = pd.DataFrame([features], columns=FEATURE_NAMES)

            prediction = model.predict(features_df)[0]
            probabilities = model.predict_proba(features_df)[0]

            is_phishing = bool(prediction == 1)
            confidence = round((probabilities[1] if is_phishing else probabilities[0]) * 100, 1)

        prediction_result = {
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence,
            'label': 'Phishing' if is_phishing else 'Legitimate'
        }

        result_summary = (
            f"Prediction: {prediction_result['label']} "
            f"(confidence: {prediction_result['confidence']}%)"
        )

        new_scan = Scan(
            user_id=current_user.id,
            scan_type='phishing',
            target=url,
            result=result_summary
        )
        db.session.add(new_scan)
        db.session.commit()

        flash('URL checked and result saved.', 'success')

    return render_template('phishing/check.html', form=form, result=prediction_result)