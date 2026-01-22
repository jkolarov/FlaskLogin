"""
Services package for business logic operations.

This package contains service classes that encapsulate business logic
and provide a clean interface between routes and data models.
"""

from app.services.user_service import UserService

__all__ = ['UserService']
