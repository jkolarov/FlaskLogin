"""
Authentication and authorization decorators.

This module provides custom decorators for access control:
- login_required: Requires user authentication, redirects to login if not authenticated
- admin_required: Requires admin role, returns 403 if not admin

Requirements addressed:
- 5.1: WHEN an unauthenticated visitor accesses a protected route, 
       THE System SHALL redirect to the login page
- 5.2: WHEN a User accesses an admin-only route, THE System SHALL return a 403 Forbidden response
- 5.3: WHEN an Admin accesses an admin-only route, THE System SHALL allow access
"""

from functools import wraps
from typing import Callable

from flask import redirect, url_for, flash, abort
from flask_login import current_user, login_required as flask_login_required


def login_required(f: Callable) -> Callable:
    """
    Decorator that requires user authentication.
    
    This decorator wraps Flask-Login's login_required decorator to ensure
    consistent behavior across the application. When an unauthenticated user
    attempts to access a protected route, they are redirected to the login page.
    
    The redirect destination is configured in the application factory via
    login_manager.login_view = 'auth.login'.
    
    Args:
        f: The view function to protect
    
    Returns:
        Decorated function that checks authentication before execution
    
    Requirements:
        - 5.1: Redirect unauthenticated visitors to login page
    
    Example:
        @app.route('/dashboard')
        @login_required
        def dashboard():
            return render_template('dashboard.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f: Callable) -> Callable:
    """
    Decorator that restricts access to admin users only.
    
    This decorator checks if the current user has admin privileges.
    It should be used in conjunction with login_required to ensure
    the user is both authenticated and has admin role.
    
    When a non-admin user attempts to access an admin-only route,
    a 403 Forbidden response is returned.
    
    Args:
        f: The view function to protect
    
    Returns:
        Decorated function that checks admin role before execution
    
    Requirements:
        - 5.2: Return 403 Forbidden for non-admin users accessing admin routes
        - 5.3: Allow admin users to access admin-only routes
        - 5.4: User role is available in session for checking
    
    Example:
        @app.route('/admin/users')
        @login_required
        @admin_required
        def admin_users():
            return render_template('admin/users.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is authenticated
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))
        
        # Check if user has admin role
        if not current_user.is_admin():
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function
