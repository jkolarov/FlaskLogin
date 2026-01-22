"""
Pytest configuration and fixtures.

This module provides shared fixtures for testing the Flask Auth Skeleton application.
"""

import pytest
from app import create_app
from app.models import db, User


@pytest.fixture
def app():
    """Create and configure a test application instance."""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create a test client for the application."""
    return app.test_client()


@pytest.fixture
def app_context(app):
    """Create an application context for testing."""
    with app.app_context():
        yield


@pytest.fixture
def test_user(app):
    """Create a test user for authentication tests."""
    with app.app_context():
        from app.services.user_service import UserService
        user = UserService.create_user(
            email='test@example.com',
            password='password123',
            role='user'
        )
        yield user
