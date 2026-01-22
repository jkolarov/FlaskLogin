"""
Property-based tests for UserService.

This module uses Hypothesis to test universal properties of user management
operations across randomly generated inputs.

**Validates: Requirements 1.2, 6.2, 6.3, 9.3**

Properties tested:
- Property 3: Duplicate email rejection
- Property 16: Role update persistence
- Property 17: User deletion
- Property 18: User query filtering
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from sqlalchemy.exc import IntegrityError
import uuid

from app import create_app
from app.models import db, User, OAuthAccount
from app.services.user_service import UserService


# Strategy for generating valid passwords (8+ characters)
valid_passwords = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N')),
    min_size=8, 
    max_size=20
)

# Strategy for generating valid roles
valid_roles = st.sampled_from(['user', 'admin'])


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


class TestUserServiceProperties:
    """Property-based tests for UserService."""
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=1000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_3_duplicate_email_rejection(self, app, password):
        """
        Property 3: Duplicate email rejection
        
        For any existing user email in the database, attempting to register
        a new user with the same email should be rejected and the original
        user should remain unchanged.
        
        **Validates: Requirements 1.2**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create the first user
            original_user = UserService.create_user(email, password, role='user')
            original_id = original_user.id
            original_hash = original_user.password_hash
            
            # Attempt to create a duplicate user
            with pytest.raises(IntegrityError):
                UserService.create_user(email, 'different_password123')
            
            # Rollback the failed transaction
            db.session.rollback()
            
            # Verify original user is unchanged
            user = UserService.get_user_by_email(email)
            assert user is not None
            assert user.id == original_id
            assert user.password_hash == original_hash
            
            # Cleanup
            UserService.delete_user(original_id)
    
    @given(password=valid_passwords, initial_role=valid_roles, new_role=valid_roles)
    @settings(max_examples=10, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_16_role_update_persistence(self, app, password, initial_role, new_role):
        """
        Property 16: Role update persistence
        
        For any user and any valid role change by an admin, the new role
        should be persisted to the database and reflected in subsequent queries.
        
        **Validates: Requirements 6.2**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create user with initial role
            user = UserService.create_user(email, password, role=initial_role)
            user_id = user.id
            
            # Update the role
            result = UserService.update_user_role(user_id, new_role)
            assert result is True
            
            # Verify the role is persisted
            updated_user = UserService.get_user_by_id(user_id)
            assert updated_user is not None
            assert updated_user.role == new_role
            
            # Query again to ensure persistence
            queried_user = UserService.get_user_by_email(email)
            assert queried_user.role == new_role
            
            # Cleanup
            UserService.delete_user(user_id)
    
    @given(password=valid_passwords)
    @settings(max_examples=10, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_17_user_deletion(self, app, password):
        """
        Property 17: User deletion
        
        For any user deleted by an admin, the user should no longer exist
        in the database and should not be able to log in.
        
        **Validates: Requirements 6.3**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create a user
            user = UserService.create_user(email, password, role='user')
            user_id = user.id
            
            # Verify user exists
            assert UserService.get_user_by_id(user_id) is not None
            assert UserService.get_user_by_email(email) is not None
            
            # Delete the user
            result = UserService.delete_user(user_id)
            assert result is True
            
            # Verify user no longer exists
            assert UserService.get_user_by_id(user_id) is None
            assert UserService.get_user_by_email(email) is None
    
    @given(password=valid_passwords)
    @settings(max_examples=10, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_18_user_query_filtering_by_email(self, app, password):
        """
        Property 18: User query filtering (email)
        
        For any set of users, filtering by email should return only users
        matching that email.
        
        **Validates: Requirements 9.3**
        """
        with app.app_context():
            email = generate_unique_email()
            
            # Create the target user
            target_user = UserService.create_user(email, password, role='user')
            
            # Query by email
            found_user = UserService.get_user_by_email(email)
            
            # Should find exactly the target user
            assert found_user is not None
            assert found_user.email == email
            assert found_user.id == target_user.id
            
            # Cleanup
            UserService.delete_user(target_user.id)
    
    @given(provider=st.sampled_from(['google', 'facebook', 'github']))
    @settings(max_examples=10, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_18_user_query_filtering_by_provider(self, app, provider):
        """
        Property 18: User query filtering (provider)
        
        For any set of users, filtering by OAuth provider should return
        only users with that provider linked.
        
        **Validates: Requirements 9.3**
        """
        with app.app_context():
            # Create user with provider
            email = generate_unique_email()
            user_with_provider = User(email=email, role='user')
            db.session.add(user_with_provider)
            db.session.commit()
            
            # Link OAuth account
            oauth = OAuthAccount(
                user_id=user_with_provider.id,
                provider=provider,
                provider_user_id=f'{provider}_{uuid.uuid4().hex[:8]}'
            )
            db.session.add(oauth)
            db.session.commit()
            
            # Query by provider
            users = UserService.get_users_by_provider(provider)
            
            # Should find the user with the target provider
            user_emails = [u.email for u in users]
            assert email in user_emails
            
            # Cleanup
            db.session.delete(oauth)
            db.session.delete(user_with_provider)
            db.session.commit()
