"""
Main routes for the Flask Auth Skeleton application.

This module provides routes for:
- Home page
- Dashboard (protected)

Routes will be fully implemented in Task 15.

Requirements addressed:
- 5.1: Protected routes redirect unauthenticated users to login
"""

from flask import render_template, redirect, url_for
from flask_login import login_required, current_user

from app.main import main_bp


@main_bp.route('/')
def index():
    """
    Home page route.
    
    Redirects authenticated users to dashboard, shows landing page otherwise.
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Dashboard route (protected).
    
    Displays user dashboard with welcome message and navigation.
    
    Will be fully implemented in Task 15.1.
    """
    # Placeholder - will be implemented in Task 15.1
    return render_template('main/dashboard.html')
