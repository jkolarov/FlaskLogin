"""
Tests for admin routes.

This module tests the admin panel functionality including:
- User list display
- User role editing
- User deletion

Requirements tested:
- 6.1: Admin_Panel SHALL display a list of all users with their roles
- 6.5: Display email, role, and registration date for each user
"""

import pytest
from flask_login import login_user

from app.models import db, User
from app.services.user_service import UserService


@pytest.fixture
def admin_user(app):
    """Create an admin user for testing."""
    with app.app_context():
        user = UserService.create_user(
            email='admin@example.com',
            password='adminpass123',
            role='admin'
        )
        yield user


@pytest.fixture
def regular_user(app):
    """Create a regular user for testing."""
    with app.app_context():
        user = UserService.create_user(
            email='user@example.com',
            password='userpass123',
            role='user'
        )
        yield user


@pytest.fixture
def multiple_users(app):
    """Create multiple users for testing the user list."""
    with app.app_context():
        users = []
        # Create admin user
        admin = UserService.create_user(
            email='admin@example.com',
            password='adminpass123',
            role='admin'
        )
        users.append(admin)
        
        # Create regular users
        for i in range(3):
            user = UserService.create_user(
                email=f'user{i}@example.com',
                password='userpass123',
                role='user'
            )
            users.append(user)
        
        yield users


class TestAdminUserList:
    """Tests for the admin user list route (Task 12.1)."""
    
    def test_admin_can_access_user_list(self, client, app, admin_user):
        """
        Test that an admin user can access the user list page.
        
        Validates: Requirement 6.1 - Admin can access Admin_Panel
        """
        with app.app_context():
            # Re-fetch the user within this context
            admin = db.session.get(User, admin_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            assert b'User Management' in response.data
    
    def test_user_list_displays_all_users(self, client, app, multiple_users):
        """
        Test that the user list displays all users in the database.
        
        Validates: Requirement 6.1 - Display a list of all users with their roles
        """
        with app.app_context():
            # Get the admin user (first in the list)
            admin = db.session.get(User, multiple_users[0].id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            # Check that all user emails are displayed
            assert b'admin@example.com' in response.data
            assert b'user0@example.com' in response.data
            assert b'user1@example.com' in response.data
            assert b'user2@example.com' in response.data
    
    def test_user_list_displays_email_role_date(self, client, app, admin_user, regular_user):
        """
        Test that the user list displays email, role, and registration date.
        
        Validates: Requirement 6.5 - Display email, role, and registration date
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            # Check email is displayed
            assert b'admin@example.com' in response.data
            assert b'user@example.com' in response.data
            # Check role badges are displayed
            assert b'Admin' in response.data
            assert b'User' in response.data
            # Check that the table headers for date are present
            assert b'Registered' in response.data
    
    def test_user_list_has_edit_buttons(self, client, app, admin_user, regular_user):
        """
        Test that the user list has edit action buttons for each user.
        
        Validates: Task 12.1 - Add edit action buttons
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            # Check that edit links are present
            assert b'Edit' in response.data
            assert f'/admin/users/{regular.id}/edit'.encode() in response.data
    
    def test_user_list_has_delete_buttons(self, client, app, admin_user, regular_user):
        """
        Test that the user list has delete action buttons for other users.
        
        Validates: Task 12.1 - Add delete action buttons
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            # Check that delete form is present for other users
            assert f'/admin/users/{regular.id}/delete'.encode() in response.data
    
    def test_regular_user_cannot_access_user_list(self, client, app, regular_user):
        """
        Test that a regular user cannot access the admin user list.
        
        Validates: Requirement 5.2 - Non-admin users get 403 Forbidden
        """
        with app.app_context():
            user = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(user.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 403
    
    def test_unauthenticated_user_redirected_to_login(self, client, app):
        """
        Test that an unauthenticated user is redirected to login.
        
        Validates: Requirement 5.1 - Redirect unauthenticated visitors to login
        """
        response = client.get('/admin/users')
        
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_user_count_displayed(self, client, app, multiple_users):
        """
        Test that the total user count is displayed on the page.
        """
        with app.app_context():
            admin = db.session.get(User, multiple_users[0].id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            # Check that user count is displayed (4 users total)
            assert b'4 users' in response.data
    
    def test_current_user_marked_as_you(self, client, app, admin_user):
        """
        Test that the current user is marked with '(You)' indicator.
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users')
            
            assert response.status_code == 200
            assert b'(You)' in response.data


class TestAdminEditUser:
    """Tests for the admin edit user route (Task 12.2)."""
    
    def test_admin_can_access_edit_user_page(self, client, app, admin_user, regular_user):
        """
        Test that an admin user can access the edit user page.
        
        Validates: Requirement 6.2 - Admin can change a user's role
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get(f'/admin/users/{regular.id}/edit')
            
            assert response.status_code == 200
            assert b'Edit User Role' in response.data
            assert regular.email.encode() in response.data
    
    def test_edit_user_page_shows_role_dropdown(self, client, app, admin_user, regular_user):
        """
        Test that the edit user page shows a role selection dropdown.
        
        Validates: Task 12.2 - Allow role selection (admin/user)
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get(f'/admin/users/{regular.id}/edit')
            
            assert response.status_code == 200
            # Check that role dropdown options are present
            assert b'<select' in response.data
            assert b'name="role"' in response.data
            assert b'value="user"' in response.data
            assert b'value="admin"' in response.data
    
    def test_admin_can_change_user_role_to_admin(self, client, app, admin_user, regular_user):
        """
        Test that an admin can change a user's role from user to admin.
        
        Validates: Requirement 6.2 - User_Repository SHALL update the role and persist the change
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the form to change role to admin
            response = client.post(
                f'/admin/users/{regular.id}/edit',
                data={'role': 'admin'},
                follow_redirects=True
            )
            
            assert response.status_code == 200
            # Check for success message
            assert b'Successfully updated role' in response.data
            
            # Verify the role was persisted
            updated_user = db.session.get(User, regular.id)
            assert updated_user.role == 'admin'
    
    def test_admin_can_change_user_role_to_user(self, client, app, admin_user):
        """
        Test that an admin can change a user's role from admin to user.
        
        Validates: Requirement 6.2 - User_Repository SHALL update the role and persist the change
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            
            # Create another admin user to demote
            another_admin = UserService.create_user(
                email='another_admin@example.com',
                password='adminpass123',
                role='admin'
            )
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the form to change role to user
            response = client.post(
                f'/admin/users/{another_admin.id}/edit',
                data={'role': 'user'},
                follow_redirects=True
            )
            
            assert response.status_code == 200
            # Check for success message
            assert b'Successfully updated role' in response.data
            
            # Verify the role was persisted
            updated_user = db.session.get(User, another_admin.id)
            assert updated_user.role == 'user'
    
    def test_edit_user_redirects_to_user_list(self, client, app, admin_user, regular_user):
        """
        Test that after editing a user, the admin is redirected to the user list.
        
        Validates: Task 12.2 - Redirect back to user list after update
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the form
            response = client.post(
                f'/admin/users/{regular.id}/edit',
                data={'role': 'admin'},
                follow_redirects=False
            )
            
            assert response.status_code == 302
            assert '/admin/users' in response.location
    
    def test_edit_nonexistent_user_returns_404(self, client, app, admin_user):
        """
        Test that editing a non-existent user returns 404.
        
        Validates: Task 12.2 - Handle case where user is not found (404)
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get('/admin/users/99999/edit')
            
            assert response.status_code == 404
    
    def test_edit_user_with_invalid_role_shows_error(self, client, app, admin_user, regular_user):
        """
        Test that submitting an invalid role shows an error message.
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the form with invalid role
            response = client.post(
                f'/admin/users/{regular.id}/edit',
                data={'role': 'invalid_role'},
                follow_redirects=True
            )
            
            assert response.status_code == 200
            assert b'Invalid role selected' in response.data
            
            # Verify the role was NOT changed
            unchanged_user = db.session.get(User, regular.id)
            assert unchanged_user.role == 'user'
    
    def test_regular_user_cannot_edit_users(self, client, app, admin_user, regular_user):
        """
        Test that a regular user cannot access the edit user page.
        
        Validates: Requirement 5.2 - Non-admin users get 403 Forbidden
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(regular.id)
                sess['_fresh'] = True
            
            response = client.get(f'/admin/users/{admin.id}/edit')
            
            assert response.status_code == 403
    
    def test_unauthenticated_user_cannot_edit_users(self, client, app, regular_user):
        """
        Test that an unauthenticated user is redirected to login.
        
        Validates: Requirement 5.1 - Redirect unauthenticated visitors to login
        """
        with app.app_context():
            regular = db.session.get(User, regular_user.id)
            
            response = client.get(f'/admin/users/{regular.id}/edit')
            
            assert response.status_code == 302
            assert '/auth/login' in response.location
    
    def test_edit_user_page_shows_warning_for_self_edit(self, client, app, admin_user):
        """
        Test that the edit user page shows a warning when editing own account.
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.get(f'/admin/users/{admin.id}/edit')
            
            assert response.status_code == 200
            assert b'Warning: You are editing your own account' in response.data


class TestAdminDeleteUser:
    """Tests for the admin delete user route (Task 12.3)."""
    
    def test_admin_can_delete_user(self, client, app, admin_user, regular_user):
        """
        Test that an admin can delete a regular user.
        
        Validates: Requirement 6.3 - User_Repository SHALL remove the user from the database
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            regular_id = regular.id
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the delete request
            response = client.post(
                f'/admin/users/{regular_id}/delete',
                follow_redirects=True
            )
            
            assert response.status_code == 200
            # Check for success message
            assert b'Successfully deleted user' in response.data
            
            # Verify the user was removed from the database
            deleted_user = db.session.get(User, regular_id)
            assert deleted_user is None
    
    def test_admin_cannot_delete_self(self, client, app, admin_user):
        """
        Test that an admin cannot delete their own account.
        
        Validates: Requirement 6.4 - System SHALL prevent self-deletion and display an error
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            admin_id = admin.id
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Attempt to delete own account
            response = client.post(
                f'/admin/users/{admin_id}/delete',
                follow_redirects=True
            )
            
            assert response.status_code == 200
            # Check for error message
            assert b'You cannot delete your own account' in response.data
            
            # Verify the admin user still exists
            admin_still_exists = db.session.get(User, admin_id)
            assert admin_still_exists is not None
    
    def test_delete_nonexistent_user_returns_404(self, client, app, admin_user):
        """
        Test that deleting a non-existent user returns 404.
        
        Validates: Task 12.3 - Handle case where user is not found (404)
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            response = client.post('/admin/users/99999/delete')
            
            assert response.status_code == 404
    
    def test_delete_user_redirects_to_user_list(self, client, app, admin_user, regular_user):
        """
        Test that after deleting a user, the admin is redirected to the user list.
        
        Validates: Task 12.3 - Redirect back to user list
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the delete request
            response = client.post(
                f'/admin/users/{regular.id}/delete',
                follow_redirects=False
            )
            
            assert response.status_code == 302
            assert '/admin/users' in response.location
    
    def test_regular_user_cannot_delete_users(self, client, app, admin_user, regular_user):
        """
        Test that a regular user cannot delete other users.
        
        Validates: Requirement 5.2 - Non-admin users get 403 Forbidden
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(regular.id)
                sess['_fresh'] = True
            
            response = client.post(f'/admin/users/{admin.id}/delete')
            
            assert response.status_code == 403
    
    def test_unauthenticated_user_cannot_delete_users(self, client, app, regular_user):
        """
        Test that an unauthenticated user is redirected to login.
        
        Validates: Requirement 5.1 - Redirect unauthenticated visitors to login
        """
        with app.app_context():
            regular = db.session.get(User, regular_user.id)
            
            response = client.post(f'/admin/users/{regular.id}/delete')
            
            assert response.status_code == 302
            assert '/auth/login' in response.location
    
    def test_delete_only_accepts_post_method(self, client, app, admin_user, regular_user):
        """
        Test that the delete route only accepts POST requests.
        
        Validates: Task 12.3 - The route should only accept POST requests
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Try GET request
            response = client.get(f'/admin/users/{regular.id}/delete')
            
            # Should return 405 Method Not Allowed
            assert response.status_code == 405
    
    def test_delete_user_shows_success_message_with_email(self, client, app, admin_user, regular_user):
        """
        Test that the success message includes the deleted user's email.
        """
        with app.app_context():
            admin = db.session.get(User, admin_user.id)
            regular = db.session.get(User, regular_user.id)
            regular_email = regular.email
            
            with client.session_transaction() as sess:
                sess['_user_id'] = str(admin.id)
                sess['_fresh'] = True
            
            # Submit the delete request
            response = client.post(
                f'/admin/users/{regular.id}/delete',
                follow_redirects=True
            )
            
            assert response.status_code == 200
            assert regular_email.encode() in response.data
