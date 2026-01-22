"""
Auth blueprint module.

This module provides authentication-related routes including:
- Email/password login and registration
- OAuth authentication
- Logout functionality

Requirements addressed:
- 1.x: User Registration
- 2.x: Email/Password Login
- 3.x: OAuth Authentication
- 4.x: User Logout
- 5.1: Protected route redirect for unauthenticated users
"""

from flask import Blueprint

# Create the auth blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Import decorators for easy access
from app.auth.decorators import login_required  # noqa: F401, E402

# Import routes after blueprint creation to avoid circular imports
# Routes will be implemented in Task 8
from app.auth import routes  # noqa: F401, E402
