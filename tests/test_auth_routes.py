"""
Tests for authentication routes.

This module tests the registration, login, and logout routes.

Requirements tested:
- 1.1: Create new User account with "User" role on valid submission
- 1.4: Reject invalid email format with validation error
- 1.5: Reject password shorter than 8 characters with validation error
- 1.6: Redirect to login page with success message on successful registration
"""

import pytest
from app.models import db, User
from app.services.user_service import UserService


class TestRegistrationRoute:
    """Tests for the registration route."""
    
    def test_register_page_loads(self, client):
        """Test that the registration page loads successfully."""
        response = client.get('/auth/register')
        assert response.status_code == 200
        assert b'Create your account' in response.data
    
    def test_register_success_creates_user(self, client, app):
        """
        Test successful registration creates a user with 'user' role.
        
        Requirement 1.1: WHEN a visitor submits a valid email and password,
        THE System SHALL create a new User account with the "User" role.
        """
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Verify user was created with correct role
        with app.app_context():
            user = UserService.get_user_by_email('newuser@example.com')
            assert user is not None
            assert user.email == 'newuser@example.com'
            assert user.role == 'user'
    
    def test_register_success_redirects_to_login(self, client):
        """
        Test successful registration redirects to login page.
        
        Requirement 1.6: WHEN registration succeeds, THE System SHALL redirect
        the user to the login page with a success message.
        """
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=False)
        
        # Should redirect to login
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_register_success_shows_flash_message(self, client):
        """
        Test successful registration shows success flash message.
        
        Requirement 1.6: WHEN registration succeeds, THE System SHALL redirect
        the user to the login page with a success message.
        """
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        
        assert b'Registration successful' in response.data
    
    def test_register_invalid_email_format(self, client):
        """
        Test registration with invalid email format is rejected.
        
        Requirement 1.4: WHEN a visitor submits an invalid email format,
        THE System SHALL reject the registration and display a validation error.
        """
        response = client.post('/auth/register', data={
            'email': 'invalid-email',
            'password': 'password123',
            'confirm_password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'Please enter a valid email address' in response.data
    
    def test_register_password_too_short(self, client):
        """
        Test registration with short password is rejected.
        
        Requirement 1.5: WHEN a visitor submits a password shorter than 8 characters,
        THE System SHALL reject the registration and display a validation error.
        """
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': 'short',
            'confirm_password': 'short'
        })
        
        assert response.status_code == 200
        assert b'Password must be at least 8 characters' in response.data
    
    def test_register_password_mismatch(self, client):
        """Test registration with mismatched passwords is rejected."""
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': 'password123',
            'confirm_password': 'different123'
        })
        
        assert response.status_code == 200
        assert b'Passwords must match' in response.data
    
    def test_register_duplicate_email(self, client, app):
        """
        Test registration with existing email is rejected.
        
        Requirement 1.2: WHEN a visitor submits an email that already exists,
        THE System SHALL reject the registration and display an error message.
        """
        # First, create a user
        with app.app_context():
            UserService.create_user(
                email='existing@example.com',
                password='password123',
                role='user'
            )
        
        # Try to register with the same email
        response = client.post('/auth/register', data={
            'email': 'existing@example.com',
            'password': 'password123',
            'confirm_password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'An account with this email already exists' in response.data
    
    def test_register_missing_email(self, client):
        """Test registration with missing email is rejected."""
        response = client.post('/auth/register', data={
            'email': '',
            'password': 'password123',
            'confirm_password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'Email is required' in response.data
    
    def test_register_missing_password(self, client):
        """Test registration with missing password is rejected."""
        response = client.post('/auth/register', data={
            'email': 'newuser@example.com',
            'password': '',
            'confirm_password': ''
        })
        
        assert response.status_code == 200
        assert b'Password is required' in response.data


class TestLoginRoute:
    """
    Tests for the login route.
    
    Requirements tested:
    - 2.1: WHEN a user submits valid credentials, THE Auth_Controller SHALL 
           create a Session and redirect to the dashboard
    - 2.2: WHEN a user submits invalid credentials, THE Auth_Controller SHALL 
           reject the login and display an error message
    - 2.3: WHEN a user submits credentials, THE Password_Hasher SHALL verify 
           the password against the stored hash
    - 2.4: WHEN a user is already logged in, THE System SHALL redirect them 
           to the dashboard instead of showing the login page
    """
    
    def test_login_page_loads(self, client):
        """Test that the login page loads successfully."""
        response = client.get('/auth/login')
        assert response.status_code == 200
        assert b'Sign in to your account' in response.data
    
    def test_login_success_with_valid_credentials(self, client, app):
        """
        Test successful login with valid credentials creates a session.
        
        Requirement 2.1: WHEN a user submits valid credentials, THE Auth_Controller 
        SHALL create a Session and redirect to the dashboard.
        """
        # Create a test user
        with app.app_context():
            UserService.create_user(
                email='logintest@example.com',
                password='password123',
                role='user'
            )
        
        # Attempt login
        response = client.post('/auth/login', data={
            'email': 'logintest@example.com',
            'password': 'password123'
        }, follow_redirects=False)
        
        # Should redirect to dashboard
        assert response.status_code == 302
        assert '/dashboard' in response.location or '/main/dashboard' in response.location
    
    def test_login_success_shows_flash_message(self, client, app):
        """Test successful login shows success flash message."""
        # Create a test user
        with app.app_context():
            UserService.create_user(
                email='logintest@example.com',
                password='password123',
                role='user'
            )
        
        # Attempt login with follow redirects
        response = client.post('/auth/login', data={
            'email': 'logintest@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Login successful' in response.data
    
    def test_login_invalid_email(self, client, app):
        """
        Test login with non-existent email is rejected.
        
        Requirement 2.2: WHEN a user submits invalid credentials, THE Auth_Controller 
        SHALL reject the login and display an error message.
        """
        response = client.post('/auth/login', data={
            'email': 'nonexistent@example.com',
            'password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'Invalid email or password' in response.data
    
    def test_login_invalid_password(self, client, app):
        """
        Test login with wrong password is rejected.
        
        Requirement 2.2: WHEN a user submits invalid credentials, THE Auth_Controller 
        SHALL reject the login and display an error message.
        Requirement 2.3: WHEN a user submits credentials, THE Password_Hasher SHALL 
        verify the password against the stored hash.
        """
        # Create a test user
        with app.app_context():
            UserService.create_user(
                email='logintest@example.com',
                password='password123',
                role='user'
            )
        
        # Attempt login with wrong password
        response = client.post('/auth/login', data={
            'email': 'logintest@example.com',
            'password': 'wrongpassword'
        })
        
        assert response.status_code == 200
        assert b'Invalid email or password' in response.data
    
    def test_login_missing_email(self, client):
        """Test login with missing email is rejected."""
        response = client.post('/auth/login', data={
            'email': '',
            'password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'Email is required' in response.data
    
    def test_login_missing_password(self, client):
        """Test login with missing password is rejected."""
        response = client.post('/auth/login', data={
            'email': 'test@example.com',
            'password': ''
        })
        
        assert response.status_code == 200
        assert b'Password is required' in response.data
    
    def test_login_invalid_email_format(self, client):
        """Test login with invalid email format shows validation error."""
        response = client.post('/auth/login', data={
            'email': 'invalid-email',
            'password': 'password123'
        })
        
        assert response.status_code == 200
        assert b'Please enter a valid email address' in response.data
    
    def test_authenticated_user_redirected_from_login(self, client, app):
        """
        Test that authenticated users are redirected from login page.
        
        Requirement 2.4: WHEN a user is already logged in, THE System SHALL 
        redirect them to the dashboard instead of showing the login page.
        """
        # Create and login a test user
        with app.app_context():
            UserService.create_user(
                email='logintest@example.com',
                password='password123',
                role='user'
            )
        
        # Login first
        client.post('/auth/login', data={
            'email': 'logintest@example.com',
            'password': 'password123'
        })
        
        # Try to access login page again
        response = client.get('/auth/login', follow_redirects=False)
        
        # Should redirect to dashboard
        assert response.status_code == 302
        assert '/dashboard' in response.location or '/main/dashboard' in response.location
    
    def test_login_creates_session(self, client, app):
        """
        Test that successful login creates a session.
        
        Requirement 2.1: WHEN a user submits valid credentials, THE Auth_Controller 
        SHALL create a Session and redirect to the dashboard.
        """
        # Create a test user
        with app.app_context():
            UserService.create_user(
                email='logintest@example.com',
                password='password123',
                role='user'
            )
        
        # Login
        client.post('/auth/login', data={
            'email': 'logintest@example.com',
            'password': 'password123'
        })
        
        # Access a protected page to verify session exists
        response = client.get('/dashboard')
        
        # Should be able to access dashboard (not redirected to login)
        assert response.status_code == 200
    
    def test_login_oauth_only_user_rejected(self, client, app):
        """
        Test that OAuth-only users (no password) cannot login with password.
        
        OAuth-only users have password_hash set to None.
        """
        # Create an OAuth-only user (no password hash)
        with app.app_context():
            user = User(
                email='oauth@example.com',
                password_hash=None,  # OAuth-only user
                role='user'
            )
            db.session.add(user)
            db.session.commit()
        
        # Attempt login with any password
        response = client.post('/auth/login', data={
            'email': 'oauth@example.com',
            'password': 'anypassword'
        })
        
        assert response.status_code == 200
        assert b'Invalid email or password' in response.data
    
    def test_login_remember_me_checkbox(self, client, app):
        """Test that remember me checkbox is present and functional."""
        # Create a test user
        with app.app_context():
            UserService.create_user(
                email='logintest@example.com',
                password='password123',
                role='user'
            )
        
        # Login with remember me checked
        response = client.post('/auth/login', data={
            'email': 'logintest@example.com',
            'password': 'password123',
            'remember_me': 'y'
        }, follow_redirects=False)
        
        # Should still redirect to dashboard
        assert response.status_code == 302
        assert '/dashboard' in response.location or '/main/dashboard' in response.location


class TestLogoutRoute:
    """
    Tests for the logout route.
    
    Requirements tested:
    - 4.1: WHEN a user requests logout, THE System SHALL destroy the Session 
           and redirect to the login page
    - 4.2: WHEN a user logs out, THE System SHALL clear all session data
    """
    
    def test_logout_redirects_to_login(self, client, app):
        """
        Test that logout redirects to login page.
        
        Requirement 4.1: WHEN a user requests logout, THE System SHALL destroy 
        the Session and redirect to the login page.
        """
        # Create and login a test user
        with app.app_context():
            UserService.create_user(
                email='logouttest@example.com',
                password='password123',
                role='user'
            )
        
        # Login first
        client.post('/auth/login', data={
            'email': 'logouttest@example.com',
            'password': 'password123'
        })
        
        # Logout
        response = client.get('/auth/logout', follow_redirects=False)
        
        # Should redirect to login page
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_logout_shows_flash_message(self, client, app):
        """Test that logout shows confirmation flash message."""
        # Create and login a test user
        with app.app_context():
            UserService.create_user(
                email='logouttest@example.com',
                password='password123',
                role='user'
            )
        
        # Login first
        client.post('/auth/login', data={
            'email': 'logouttest@example.com',
            'password': 'password123'
        })
        
        # Logout with follow redirects
        response = client.get('/auth/logout', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'You have been logged out' in response.data
    
    def test_logout_destroys_session(self, client, app):
        """
        Test that logout destroys the session.
        
        Requirement 4.1: WHEN a user requests logout, THE System SHALL destroy 
        the Session and redirect to the login page.
        Requirement 4.2: WHEN a user logs out, THE System SHALL clear all session data.
        """
        # Create and login a test user
        with app.app_context():
            UserService.create_user(
                email='logouttest@example.com',
                password='password123',
                role='user'
            )
        
        # Login first
        client.post('/auth/login', data={
            'email': 'logouttest@example.com',
            'password': 'password123'
        })
        
        # Verify we can access protected page
        response = client.get('/dashboard')
        assert response.status_code == 200
        
        # Logout
        client.get('/auth/logout')
        
        # Try to access protected page - should redirect to login
        response = client.get('/dashboard', follow_redirects=False)
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_logout_requires_authentication(self, client):
        """
        Test that logout route requires authentication.
        
        Unauthenticated users should be redirected to login.
        """
        # Try to logout without being logged in
        response = client.get('/auth/logout', follow_redirects=False)
        
        # Should redirect to login page
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_logout_clears_all_session_data(self, client, app):
        """
        Test that logout clears all session data.
        
        Requirement 4.2: WHEN a user logs out, THE System SHALL clear all session data.
        """
        # Create and login a test user
        with app.app_context():
            UserService.create_user(
                email='logouttest@example.com',
                password='password123',
                role='user'
            )
        
        # Login first
        client.post('/auth/login', data={
            'email': 'logouttest@example.com',
            'password': 'password123'
        })
        
        # Logout
        client.get('/auth/logout')
        
        # After logout, accessing login page should not redirect
        # (which would happen if user was still authenticated)
        response = client.get('/auth/login', follow_redirects=False)
        assert response.status_code == 200
