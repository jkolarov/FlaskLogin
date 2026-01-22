"""
Integration tests for Flask Auth Skeleton.

This module tests complete user flows end-to-end, verifying that
all components work together correctly.

**Validates: Requirements 1.1, 2.1, 6.1**

Integration tests:
- Complete registration flow
- Complete login flow
- Admin user management flow
"""

import pytest
import uuid

from app import create_app
from app.models import db, User
from app.services.user_service import UserService


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


class TestRegistrationFlow:
    """Integration tests for complete registration flow."""
    
    def test_complete_registration_flow(self, app, client):
        """
        Test complete registration flow from start to finish.
        
        1. User visits registration page
        2. User fills out form with valid data
        3. User submits form
        4. System creates user account
        5. System redirects to login page with success message
        6. User can now login with new credentials
        
        **Validates: Requirements 1.1**
        """
        with app.app_context():
            email = generate_unique_email()
            password = 'securepassword123'
            
            # Step 1: Visit registration page
            response = client.get('/auth/register')
            assert response.status_code == 200
            assert b'Create your account' in response.data
            
            # Step 2-3: Fill out and submit form
            response = client.post('/auth/register', data={
                'email': email,
                'password': password,
                'confirm_password': password
            }, follow_redirects=False)
            
            # Step 5: Should redirect to login
            assert response.status_code == 302
            assert '/auth/login' in response.location
            
            # Step 4: Verify user was created
            user = UserService.get_user_by_email(email)
            assert user is not None
            assert user.email == email
            assert user.role == 'user'
            
            # Follow redirect to see success message
            response = client.get(response.location)
            assert b'Registration successful' in response.data
            
            # Step 6: Verify user can login
            response = client.post('/auth/login', data={
                'email': email,
                'password': password
            }, follow_redirects=False)
            
            assert response.status_code == 302
            assert '/dashboard' in response.location or '/main' in response.location
            
            # Cleanup
            UserService.delete_user(user.id)
    
    def test_registration_with_invalid_data_shows_errors(self, app, client):
        """
        Test that registration with invalid data shows appropriate errors.
        
        **Validates: Requirements 1.4, 1.5**
        """
        with app.app_context():
            # Test with invalid email
            response = client.post('/auth/register', data={
                'email': 'invalid-email',
                'password': 'password123',
                'confirm_password': 'password123'
            })
            
            assert response.status_code == 200
            assert b'valid email' in response.data.lower()
            
            # Test with short password
            response = client.post('/auth/register', data={
                'email': generate_unique_email(),
                'password': 'short',
                'confirm_password': 'short'
            })
            
            assert response.status_code == 200
            assert b'8 characters' in response.data


class TestLoginFlow:
    """Integration tests for complete login flow."""
    
    def test_complete_login_flow(self, app, client):
        """
        Test complete login flow from start to finish.
        
        1. User visits login page
        2. User enters valid credentials
        3. User submits form
        4. System verifies credentials
        5. System creates session
        6. System redirects to dashboard
        7. User can access protected resources
        
        **Validates: Requirements 2.1**
        """
        with app.app_context():
            email = generate_unique_email()
            password = 'securepassword123'
            
            # Create test user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            # Step 1: Visit login page
            response = client.get('/auth/login')
            assert response.status_code == 200
            assert b'Sign in' in response.data
            
            # Step 2-3: Enter credentials and submit
            response = client.post('/auth/login', data={
                'email': email,
                'password': password
            }, follow_redirects=False)
            
            # Step 6: Should redirect to dashboard
            assert response.status_code == 302
            assert '/dashboard' in response.location or '/main' in response.location
            
            # Step 7: Can access protected resources
            response = client.get('/dashboard')
            assert response.status_code == 200
            
            # Cleanup
            client.get('/auth/logout')
            UserService.delete_user(user_id)
    
    def test_login_logout_flow(self, app, client):
        """
        Test complete login and logout flow.
        
        1. User logs in
        2. User accesses protected resource
        3. User logs out
        4. User can no longer access protected resource
        
        **Validates: Requirements 2.1, 4.1, 4.2**
        """
        with app.app_context():
            email = generate_unique_email()
            password = 'securepassword123'
            
            # Create test user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            # Login
            client.post('/auth/login', data={
                'email': email,
                'password': password
            })
            
            # Access protected resource
            response = client.get('/dashboard')
            assert response.status_code == 200
            
            # Logout
            response = client.get('/auth/logout', follow_redirects=False)
            assert response.status_code == 302
            assert '/auth/login' in response.location
            
            # Can no longer access protected resource
            response = client.get('/dashboard', follow_redirects=False)
            assert response.status_code == 302
            assert '/auth/login' in response.location
            
            # Cleanup
            UserService.delete_user(user_id)


class TestAdminUserManagementFlow:
    """Integration tests for admin user management flow."""
    
    def test_complete_admin_user_management_flow(self, app, client):
        """
        Test complete admin user management flow.
        
        1. Admin logs in
        2. Admin views user list
        3. Admin edits user role
        4. Admin verifies role change
        5. Admin deletes user
        6. Admin verifies user is deleted
        
        **Validates: Requirements 6.1, 6.2, 6.3**
        """
        with app.app_context():
            admin_email = generate_unique_email()
            admin_password = 'adminpassword123'
            user_email = generate_unique_email()
            user_password = 'userpassword123'
            
            # Create admin and regular user
            admin = UserService.create_user(admin_email, admin_password, role='admin')
            admin_id = admin.id
            user = UserService.create_user(user_email, user_password, role='user')
            user_id = user.id
            
            # Step 1: Admin logs in
            client.post('/auth/login', data={
                'email': admin_email,
                'password': admin_password
            })
            
            # Step 2: Admin views user list
            response = client.get('/admin/users')
            assert response.status_code == 200
            assert user_email.encode() in response.data
            
            # Step 3: Admin edits user role
            response = client.post(f'/admin/users/{user_id}/edit', data={
                'role': 'admin'
            }, follow_redirects=True)
            
            assert response.status_code == 200
            
            # Step 4: Verify role change
            updated_user = UserService.get_user_by_id(user_id)
            assert updated_user.role == 'admin'
            
            # Step 5: Admin deletes user
            response = client.post(f'/admin/users/{user_id}/delete', follow_redirects=True)
            assert response.status_code == 200
            
            # Step 6: Verify user is deleted
            deleted_user = UserService.get_user_by_id(user_id)
            assert deleted_user is None
            
            # Cleanup
            client.get('/auth/logout')
            UserService.delete_user(admin_id)
    
    def test_admin_cannot_delete_self(self, app, client):
        """
        Test that admin cannot delete their own account.
        
        **Validates: Requirements 6.4**
        """
        with app.app_context():
            admin_email = generate_unique_email()
            admin_password = 'adminpassword123'
            
            # Create admin
            admin = UserService.create_user(admin_email, admin_password, role='admin')
            admin_id = admin.id
            
            # Admin logs in
            client.post('/auth/login', data={
                'email': admin_email,
                'password': admin_password
            })
            
            # Try to delete self
            response = client.post(f'/admin/users/{admin_id}/delete', follow_redirects=True)
            
            # Should show error or prevent deletion
            assert response.status_code == 200
            
            # Admin should still exist
            admin_still_exists = UserService.get_user_by_id(admin_id)
            assert admin_still_exists is not None
            
            # Cleanup
            client.get('/auth/logout')
            UserService.delete_user(admin_id)
    
    def test_regular_user_cannot_access_admin_panel(self, app, client):
        """
        Test that regular users cannot access admin panel.
        
        **Validates: Requirements 5.2**
        """
        with app.app_context():
            user_email = generate_unique_email()
            user_password = 'userpassword123'
            
            # Create regular user
            user = UserService.create_user(user_email, user_password, role='user')
            user_id = user.id
            
            # User logs in
            client.post('/auth/login', data={
                'email': user_email,
                'password': user_password
            })
            
            # Try to access admin panel
            response = client.get('/admin/users')
            
            # Should get 403 Forbidden
            assert response.status_code == 403
            
            # Cleanup
            client.get('/auth/logout')
            UserService.delete_user(user_id)
