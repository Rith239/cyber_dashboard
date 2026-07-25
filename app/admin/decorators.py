"""
app/admin/decorators.py

Custom decorator that restricts a route to admin users only.
Built the same way Flask-Login's @login_required works internally:
wrap the original view function, check a condition first, and either
let the request through or redirect/abort.
"""

from functools import wraps
from flask import abort
from flask_login import current_user


def admin_required(view_function):
    """
    Use as @admin_required (below @login_required) on any route that
    should only be accessible to users with role == 'admin'.
    Returns a 403 Forbidden for logged-in non-admin users.
    """
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return view_function(*args, **kwargs)
    return wrapped_view
