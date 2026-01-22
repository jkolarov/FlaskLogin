"""
Main blueprint module.

This module provides the main application routes including:
- Dashboard (protected)
- Home page

Requirements addressed:
- 5.1: Protected routes redirect unauthenticated users
"""

from flask import Blueprint

# Create the main blueprint
main_bp = Blueprint('main', __name__)

# Import routes after blueprint creation to avoid circular imports
# Routes will be implemented in Task 15
from app.main import routes  # noqa: F401, E402
