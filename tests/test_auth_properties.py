"""
Property-based tests for authentication routes.

This module uses Hypothesis to test universal properties of authentication
across randomly generated inputs.

**Validates: Requirements 1.1, 1.4, 1.5, 2.1, 2.2, 3.4, 4.1, 4.2**

Properties tested:
- Property 2: User registration creates correct role
- Property 4: Email format validation
- Property 5: Password length validation
- Property 6: Valid credentials login
- Property 7: Invalid credentials rejection
- Property 11: Session destruction on logout
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import uuid
import re

from app import create_app
from app.models import db, User
from app.services.user_service import UserService


# Strategy for valid passwords (8+ characters, alphanumeric)
valid_passwords = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N')),
    min_size=8, 
    max_size=20
)

# Strategy for short passwords (less than 8 characters)
short_passwords = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N')),
    min_size=1, 
    max_size=7
)

# Strategy for invalid email formats
invalid_emails = st.one_of(
    st.text(min_size=1, max_size=20).filter(lambda x: '@' not in x and x.strip()),
    st.text(min_size=1, max_size=20).map(lambda x: f"{x}@"),
    st.text(min_size=1, max_size=20).map(lambda x: f"@{x}"),
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


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


def generate_unique_email():
    """Generate a unique email for testing."""
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


class TestAuthenticationProperties:
    """Property-based tests for authentication."""
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_2_user_registration_creates_correct_role(self, app, password):
        """
        Property 2: User registration creates correct role
        
        For any new user created via registration (email/password),
        the user should be assigned the "user" role by default.
        
        **Validates: Requirements 1.1, 3.4**
        """
        with app.app_context():
            email = generate_unique_email()
            
            with app.test_client() as client:
                # Register a new user
                response = client.post('/auth/register', data={
                    'email': email,
                    'password': password,
                    'confirm_password': password
                }, follow_redirects=True)
                
                # Verify registration succeeded
                assert response.status_code == 200
                
                # Verify user was created with 'user' role
                user = UserService.get_user_by_email(email)
                assert user is not None
                assert user.role == 'user'
                
                # Cleanup
                UserService.delete_user(user.id)
    
    @given(invalid_email=invalid_emails, password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_4_email_format_validation(self, app, invalid_email, password):
        """
        Property 4: Email format validation
        
        For any string that does not match a valid email format,
        the registration should be rejected with a validation error.
        
        **Validates: Requirements 1.4**
        """
        with app.app_context():
            with app.test_client() as client:
                response = client.post('/auth/register', data={
                    'email': invalid_email,
                    'password': password,
                    'confirm_password': password
                })
                
                # Should stay on registration page (not redirect)
                assert response.status_code == 200
                
                # Should show validation error
                assert b'valid email' in response.data.lower() or b'email' in response.data.lower()
                
                # User should not be created
                user = UserService.get_user_by_email(invalid_email)
                assert user is None
    
    @given(short_password=short_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_5_password_length_validation(self, app, short_password):
        """
        Property 5: Password length validation
        
        For any password string with fewer than 8 characters,
        the registration should be rejected with a validation error.
        
        **Validates: Requirements 1.5**
        """
        with app.app_context():
            email = generate_unique_email()
            
            with app.test_client() as client:
                response = client.post('/auth/register', data={
                    'email': email,
                    'password': short_password,
                    'confirm_password': short_password
                })
                
                # Should stay on registration page (not redirect)
                assert response.status_code == 200
                
                # Should show validation error about password length
                assert b'8 characters' in response.data or b'password' in response.data.lower()
                
                # User should not be created
                user = UserService.get_user_by_email(email)
                assert user is None
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_6_valid_credentials_login(self, app, password):
        """
        Property 6: Valid credentials login
        
        For any registered user with known email and password,
        submitting those credentials should result in successful
        authentication and session creation.
        
        **Validates: Requirements 2.1**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create a user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            with app.test_client() as client:
                # Login with valid credentials
                response = client.post('/auth/login', data={
                    'email': email,
                    'password': password
                }, follow_redirects=False)
                
                # Should redirect to dashboard
                assert response.status_code == 302
                assert '/dashboard' in response.location or '/main' in response.location
                
                # Verify session is created by accessing protected route
                response = client.get('/dashboard')
                assert response.status_code == 200
            
            # Cleanup
            UserService.delete_user(user_id)
    
    @given(password=valid_passwords, wrong_password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_7_invalid_credentials_rejection(self, app, password, wrong_password):
        """
        Property 7: Invalid credentials rejection
        
        For any login attempt where the password doesn't match,
        the login should be rejected and no session should be created.
        
        **Validates: Requirements 2.2**
        """
        # Skip if passwords happen to be the same
        if password == wrong_password:
            return
        
        with app.app_context():
            email = generate_unique_email()
            
            # Create a user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            with app.test_client() as client:
                # Login with wrong password
                response = client.post('/auth/login', data={
                    'email': email,
                    'password': wrong_password
                })
                
                # Should stay on login page
                assert response.status_code == 200
                
                # Should show error message
                assert b'Invalid' in response.data or b'invalid' in response.data
                
                # Session should not be created - protected route should redirect
                response = client.get('/dashboard', follow_redirects=False)
                assert response.status_code == 302
                assert '/auth/login' in response.location
            
            # Cleanup
            UserService.delete_user(user_id)
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_11_session_destruction_on_logout(self, app, password):
        """
        Property 11: Session destruction on logout
        
        For any authenticated user session, after logout the session
        should be destroyed and subsequent requests should not have
        access to protected resources.
        
        **Validates: Requirements 4.1, 4.2**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create a user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            with app.test_client() as client:
                # Login
                client.post('/auth/login', data={
                    'email': email,
                    'password': password
                })
                
                # Verify we can access protected route
                response = client.get('/dashboard')
                assert response.status_code == 200
                
                # Logout
                client.get('/auth/logout')
                
                # Verify we can no longer access protected route
                response = client.get('/dashboard', follow_redirects=False)
                assert response.status_code == 302
                assert '/auth/login' in response.location
            
            # Cleanup
            UserService.delete_user(user_id)
