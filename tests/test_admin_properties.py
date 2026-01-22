"""
Property-based tests for admin panel.

This module uses Hypothesis to test universal properties of the admin panel
across randomly generated inputs.

**Validates: Requirements 6.1, 6.5**

Properties tested:
- Property 15: Admin user list completeness
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

# Strategy for number of users to create
num_users = st.integers(min_value=1, max_value=5)


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


class TestAdminPanelProperties:
    """Property-based tests for admin panel."""
    
    @given(num_users=num_users, password=valid_passwords)
    @settings(max_examples=10, deadline=5000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_15_admin_user_list_completeness(self, app, num_users, password):
        """
        Property 15: Admin user list completeness
        
        For any set of users in the database, the admin panel user list
        should display all users with their email, role, and registration date.
        
        **Validates: Requirements 6.1, 6.5**
        """
        with app.app_context():
            # Create admin user for accessing admin panel
            admin_email = generate_unique_email()
            admin_user = UserService.create_user(admin_email, password, role='admin')
            admin_id = admin_user.id
            
            # Create test users
            created_users = []
            for i in range(num_users):
                email = generate_unique_email()
                role = 'user' if i % 2 == 0 else 'admin'
                user = UserService.create_user(email, password, role=role)
                created_users.append(user)
            
            with app.test_client() as client:
                # Login as admin
                client.post('/auth/login', data={
                    'email': admin_email,
                    'password': password
                })
                
                # Access admin user list
                response = client.get('/admin/users')
                assert response.status_code == 200
                
                # Verify all created users are displayed
                response_data = response.data.decode('utf-8')
                
                # Admin user should be in the list
                assert admin_email in response_data
                
                # All created users should be in the list
                for user in created_users:
                    assert user.email in response_data
                    # Role should be displayed
                    assert user.role in response_data
            
            # Cleanup
            for user in created_users:
                UserService.delete_user(user.id)
            UserService.delete_user(admin_id)
    
    @given(password=valid_passwords, role=valid_roles)
    @settings(max_examples=10, deadline=3000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_15_user_details_displayed(self, app, password, role):
        """
        Property 15: User details displayed correctly
        
        For any user, the admin panel should display their email and role.
        
        **Validates: Requirements 6.1, 6.5**
        """
        with app.app_context():
            # Create admin user
            admin_email = generate_unique_email()
            admin_user = UserService.create_user(admin_email, password, role='admin')
            admin_id = admin_user.id
            
            # Create test user
            test_email = generate_unique_email()
            test_user = UserService.create_user(test_email, password, role=role)
            test_id = test_user.id
            
            with app.test_client() as client:
                # Login as admin
                client.post('/auth/login', data={
                    'email': admin_email,
                    'password': password
                })
                
                # Access admin user list
                response = client.get('/admin/users')
                assert response.status_code == 200
                
                response_data = response.data.decode('utf-8')
                
                # Test user email should be displayed
                assert test_email in response_data
                
                # Test user role should be displayed
                assert role in response_data
            
            # Cleanup
            UserService.delete_user(test_id)
            UserService.delete_user(admin_id)
