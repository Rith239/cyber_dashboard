"""
app/ml/feature_extraction.py

Converts a raw URL string into a fixed-length list of numeric features.
This EXACT function is used both when training the model (train_model.py)
and when predicting on a live user-submitted URL (app/phishing/routes.py).
Using the same function in both places avoids "feature skew" -- a subtle
bug where training and real-world predictions are computed differently.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse

# Common words that show up disproportionately often in phishing URLs,
# based on published phishing-detection research (login pages, account
# verification prompts, urgency tactics, etc.)
SUSPICIOUS_WORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'banking',
    'confirm', 'signin', 'webscr', 'ebayisapi', 'paypal', 'password',
    'urgent', 'suspend', 'click', 'free'
]

IP_PATTERN = re.compile(r'(\d{1,3}\.){3}\d{1,3}')


def shannon_entropy(text):
    """
    Measures how 'random' a string looks, on a scale that grows with
    randomness. Phishing URLs are often auto-generated and tend to have
    higher entropy (more randomness) than typical human-chosen domain names.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(url):
    """
    Given a raw URL string, returns a list of numeric features in a
    FIXED, CONSISTENT ORDER. This order must never change once the
    model is trained on it.
    """
    url = str(url).strip()

    # Ensure a scheme exists so urlparse behaves consistently
    parse_target = url if '://' in url else 'http://' + url

    try:
        parsed = urlparse(parse_target)
        netloc = parsed.netloc
        path = parsed.path
    except Exception:
        netloc = ''
        path = ''

    url_length = len(url)
    num_dots = url.count('.')
    has_https = 1 if url.lower().startswith('https') else 0
    has_ip = 1 if IP_PATTERN.search(netloc) else 0
    num_subdirs = path.count('/')
    num_params = url.count('?') + url.count('&')
    suspicious_words = sum(1 for word in SUSPICIOUS_WORDS if word in url.lower())
    special_char_count = sum(url.count(ch) for ch in ['-', '_', '%', '@', '=', '~'])
    digits_count = sum(ch.isdigit() for ch in url)
    entropy = shannon_entropy(url)

    return [
        url_length,
        num_dots,
        has_https,
        has_ip,
        num_subdirs,
        num_params,
        suspicious_words,
        special_char_count,
        digits_count,
        entropy,
    ]


# Human-readable names for each feature, in the same order as extract_features()
# returns them. Used for logging/debugging and for displaying results.
FEATURE_NAMES = [
    'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdirs',
    'num_params', 'suspicious_words', 'special_char_count',
    'digits_count', 'entropy'
]
