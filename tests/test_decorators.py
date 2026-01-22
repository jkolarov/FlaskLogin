"""
Tests for authentication and authorization decorators.

This module tests the custom decorators for access control:
- login_required: Redirects unauthenticated users to login

Requirements tested:
- 5.1: WHEN an unauthenticated visitor accesses a protected route,
       THE System SHALL redirect to the login page
"""

import pytest
from flask import url_for
from flask_login import login_user, logout_user

from app import create_app
from app.models import db, User
from app.auth.decorators import login_required, admin_required


class TestLoginRequiredDecorator:
    """Tests for the login_required decorator."""

    def test_unauthenticated_user_redirected_to_login(self, app, client):
        """
        Test that unauthenticated users are redirected to login page.
        
        Validates: Requirement 5.1
        """
        # Create a test route protected by login_required
        @app.route('/test-protected')
        @login_required
        def protected_route():
            return 'Protected content'
        
        # Access the protected route without authentication
        response = client.get('/test-protected')
        
        # Should redirect to login page
        assert response.status_code == 302
        assert '/auth/login' in response.location

    def test_authenticated_user_can_access_protected_route(self, app, client):
        """
        Test that authenticated users can access protected routes.
        
        Validates: Requirement 5.1 (inverse - authenticated users should pass)
        """
        # Create a test route protected by login_required
        @app.route('/test-protected-auth')
        @login_required
        def protected_route_auth():
            return 'Protected content'
        
        with app.app_context():
            # Create a test user
            from app.services.user_service import UserService
            user = UserService.create_user(
                email='decorator_test@example.com',
                password='password123',
                role='user'
            )
            
            # Log in the user
            with client.session_transaction() as sess:
                sess['_user_id'] = str(user.id)
                sess['_fresh'] = True
        
        # Access the protected route while authenticated
        response = client.get('/test-protected-auth')
        
        # Should allow access (200 OK)
        assert response.status_code == 200
        assert b'Protected content' in response.data

    def test_decorator_preserves_function_name(self):
        """Test that the decorator preserves the original function name."""
        @login_required
        def my_view_function():
            return 'test'
        
        assert my_view_function.__name__ == 'my_view_function'

    def test_decorator_preserves_function_docstring(self):
        """Test that the decorator preserves the original function docstring."""
        @login_required
        def my_view_function():
            """This is my docstring."""
            return 'test'
        
        assert my_view_function.__doc__ == 'This is my docstring.'


class TestAdminRequiredDecorator:
    """Tests for the admin_required decorator.
    
    Requirements tested:
    - 5.2: WHEN a User accesses an admin-only route, THE System SHALL return a 403 Forbidden response
    - 5.3: WHEN an Admin accesses an admin-only route, THE System SHALL allow access
    - 5.4: WHILE a user is authenticated, THE System SHALL include their role in the Session
    """

    def test_unauthenticated_user_redirected_to_login(self, app, client):
        """
        Test that unauthenticated users are redirected to login page.
        
        Validates: Requirement 5.1 (admin_required also checks authentication)
        """
        # Create a test route protected by admin_required
        @app.route('/test-admin-unauth')
        @admin_required
        def admin_route_unauth():
            return 'Admin content'
        
        # Access the admin route without authentication
        response = client.get('/test-admin-unauth')
        
        # Should redirect to login page
        assert response.status_code == 302
        assert '/auth/login' in response.location

    def test_non_admin_user_gets_403(self, app, client):
        """
        Test that non-admin users receive 403 Forbidden response.
        
        Validates: Requirement 5.2
        """
        # Create a test route protected by admin_required
        @app.route('/test-admin-forbidden')
        @admin_required
        def admin_route_forbidden():
            return 'Admin content'
        
        with app.app_context():
            # Create a regular user (not admin)
            from app.services.user_service import UserService
            user = UserService.create_user(
                email='regular_user@example.com',
                password='password123',
                role='user'
            )
            
            # Log in the user
            with client.session_transaction() as sess:
                sess['_user_id'] = str(user.id)
                sess['_fresh'] = True
        
        # Access the admin route as a regular user
        response = client.get('/test-admin-forbidden')
        
        # Should return 403 Forbidden
        assert response.status_code == 403

    def test_admin_user_can_access_admin_route(self, app, client):
        """
        Test that admin users can access admin-only routes.
        
        Validates: Requirement 5.3
        """
        # Create a test route protected by admin_required
        @app.route('/test-admin-allowed')
        @admin_required
        def admin_route_allowed():
            return 'Admin content'
        
        with app.app_context():
            # Create an admin user
            from app.services.user_service import UserService
            admin_user = UserService.create_user(
                email='admin_user@example.com',
                password='password123',
                role='admin'
            )
            
            # Log in the admin user
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin_user.id)
                sess['_fresh'] = True
        
        # Access the admin route as an admin user
        response = client.get('/test-admin-allowed')
        
        # Should allow access (200 OK)
        assert response.status_code == 200
        assert b'Admin content' in response.data

    def test_decorator_preserves_function_name(self):
        """Test that the decorator preserves the original function name."""
        @admin_required
        def my_admin_view():
            return 'test'
        
        assert my_admin_view.__name__ == 'my_admin_view'

    def test_decorator_preserves_function_docstring(self):
        """Test that the decorator preserves the original function docstring."""
        @admin_required
        def my_admin_view():
            """This is my admin docstring."""
            return 'test'
        
        assert my_admin_view.__doc__ == 'This is my admin docstring.'
