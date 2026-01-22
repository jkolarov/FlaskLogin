"""
Property-based tests for access control decorators.

This module uses Hypothesis to test universal properties of access control
across randomly generated inputs.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4**

Properties tested:
- Property 12: Protected route redirect
- Property 13: Role-based access control
- Property 14: Session contains user role
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import uuid

from app import create_app
from app.models import db, User
from app.services.user_service import UserService


# Strategy for valid roles
valid_roles = st.sampled_from(['user', 'admin'])

# Strategy for valid passwords
valid_passwords = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N')),
    min_size=8, 
    max_size=20
)


@pytest.fixture(scope='module')
def app():
    """Create a test Flask application."""
    app = create_app('testing')
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.drop_all()


def generate_unique_email():
    """Generate a unique email for testing."""
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


class TestAccessControlProperties:
    """Property-based tests for access control."""
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_12_protected_route_redirect(self, app, password):
        """
        Property 12: Protected route redirect
        
        For any protected route and any unauthenticated request,
        the response should redirect to the login page.
        
        **Validates: Requirements 5.1**
        """
        with app.app_context():
            with app.test_client() as client:
                # Test dashboard (protected route)
                response = client.get('/dashboard', follow_redirects=False)
                assert response.status_code == 302
                assert '/auth/login' in response.location
                
                # Test admin routes (protected routes)
                response = client.get('/admin/users', follow_redirects=False)
                assert response.status_code == 302
                assert '/auth/login' in response.location
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_13_role_based_access_control_user_denied(self, app, password):
        """
        Property 13: Role-based access control (user denied)
        
        For any admin-only route, requests from users with "user" role
        should receive 403 Forbidden.
        
        **Validates: Requirements 5.2**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create a regular user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            with app.test_client() as client:
                # Login as regular user
                client.post('/auth/login', data={
                    'email': email,
                    'password': password
                })
                
                # Try to access admin route
                response = client.get('/admin/users')
                
                # Should get 403 Forbidden
                assert response.status_code == 403
            
            # Cleanup
            UserService.delete_user(user_id)
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_13_role_based_access_control_admin_allowed(self, app, password):
        """
        Property 13: Role-based access control (admin allowed)
        
        For any admin-only route, requests from users with "admin" role
        should be allowed.
        
        **Validates: Requirements 5.3**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create an admin user
            user = UserService.create_user(email, password, role='admin')
            user_id = user.id
            
            with app.test_client() as client:
                # Login as admin
                client.post('/auth/login', data={
                    'email': email,
                    'password': password
                })
                
                # Try to access admin route
                response = client.get('/admin/users')
                
                # Should be allowed (200 OK)
                assert response.status_code == 200
            
            # Cleanup
            UserService.delete_user(user_id)
    
    @given(password=valid_passwords, role=valid_roles)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_14_session_contains_user_role(self, app, password, role):
        """
        Property 14: Session contains user role
        
        For any authenticated user, the session should contain
        the user's current role.
        
        **Validates: Requirements 5.4**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create user with specified role
            user = UserService.create_user(email, password, role=role)
            user_id = user.id
            
            with app.test_client() as client:
                # Login
                client.post('/auth/login', data={
                    'email': email,
                    'password': password
                })
                
                # Access dashboard to verify session
                response = client.get('/dashboard')
                assert response.status_code == 200
                
                # The user's role should be accessible in the session
                # We verify this by checking role-based behavior
                if role == 'admin':
                    # Admin should be able to access admin routes
                    response = client.get('/admin/users')
                    assert response.status_code == 200
                else:
                    # Regular user should get 403 on admin routes
                    response = client.get('/admin/users')
                    assert response.status_code == 403
            
            # Cleanup
            UserService.delete_user(user_id)
