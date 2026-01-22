"""
Admin blueprint module.

This module provides administrative routes including:
- User list management
- User role editing
- User deletion

Requirements addressed:
- 6.x: Admin User Management
"""

from flask import Blueprint

# Create the admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Import routes after blueprint creation to avoid circular imports
# Routes will be implemented in Task 12
from app.admin import routes  # noqa: F401, E402
