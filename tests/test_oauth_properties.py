"""
Property-based tests for OAuth authentication.

This module uses Hypothesis to test universal properties of OAuth
authentication across randomly generated inputs.

**Validates: Requirements 3.2, 3.3, 3.6, 10.5**

Properties tested:
- Property 9: OAuth user creation and linking
- Property 10: Multiple authentication methods
- Property 21: No OAuth token storage
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import uuid

from app import create_app
from app.models import db, User, OAuthAccount
from app.auth.oauth import OAuthService
from app.services.user_service import UserService


# Strategy for OAuth providers
oauth_providers = st.sampled_from(['google', 'facebook', 'github'])

# Strategy for provider user IDs
provider_user_ids = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N')),
    min_size=5, 
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


class TestOAuthProperties:
    """Property-based tests for OAuth authentication."""
    
    @given(provider=oauth_providers, provider_user_id=provider_user_ids)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_9_oauth_user_creation_and_linking(self, app, provider, provider_user_id):
        """
        Property 9: OAuth user creation and linking
        
        For any OAuth authentication response with valid user info,
        the system should either create a new user or update an existing one,
        and the OAuth account should be properly linked to the user.
        
        **Validates: Requirements 3.2, 3.3**
        """
        with app.app_context():
            email = generate_unique_email()
            unique_provider_id = f"{provider_user_id}_{uuid.uuid4().hex[:8]}"
            
            user_info = {
                'provider_user_id': unique_provider_id,
                'email': email,
                'name': 'Test User'
            }
            
            # Create user via OAuth
            user = OAuthService.create_or_update_user(provider, user_info)
            
            # Verify user was created
            assert user is not None
            assert user.email == email
            assert user.role == 'user'  # Default role
            
            # Verify OAuth account is linked
            oauth_account = OAuthAccount.query.filter_by(
                provider=provider,
                provider_user_id=unique_provider_id
            ).first()
            
            assert oauth_account is not None
            assert oauth_account.user_id == user.id
            
            # Calling again with same OAuth info should return same user
            same_user = OAuthService.create_or_update_user(provider, user_info)
            assert same_user.id == user.id
            
            # Cleanup
            db.session.delete(oauth_account)
            db.session.delete(user)
            db.session.commit()
    
    @given(provider=oauth_providers, provider_user_id=provider_user_ids)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_9_oauth_links_to_existing_user(self, app, provider, provider_user_id):
        """
        Property 9: OAuth links to existing user with same email
        
        If a user with the same email already exists, OAuth should link
        to that existing user rather than creating a new one.
        
        **Validates: Requirements 3.2, 3.3**
        """
        with app.app_context():
            email = generate_unique_email()
            unique_provider_id = f"{provider_user_id}_{uuid.uuid4().hex[:8]}"
            
            # Create existing user with password
            existing_user = UserService.create_user(email, 'password123', role='user')
            existing_user_id = existing_user.id
            
            user_info = {
                'provider_user_id': unique_provider_id,
                'email': email,
                'name': 'Test User'
            }
            
            # OAuth should link to existing user
            user = OAuthService.create_or_update_user(provider, user_info)
            
            # Should be the same user
            assert user.id == existing_user_id
            
            # OAuth account should be linked
            oauth_account = OAuthAccount.query.filter_by(
                provider=provider,
                provider_user_id=unique_provider_id
            ).first()
            
            assert oauth_account is not None
            assert oauth_account.user_id == existing_user_id
            
            # Cleanup
            db.session.delete(oauth_account)
            UserService.delete_user(existing_user_id)
    
    @given(provider=oauth_providers, provider_user_id=provider_user_ids)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_10_multiple_authentication_methods(self, app, provider, provider_user_id):
        """
        Property 10: Multiple authentication methods
        
        For any user with both email/password and OAuth credentials,
        login should succeed via either method and result in the same user.
        
        **Validates: Requirements 3.6**
        """
        with app.app_context():
            email = generate_unique_email()
            password = 'password123'
            unique_provider_id = f"{provider_user_id}_{uuid.uuid4().hex[:8]}"
            
            # Create user with password
            password_user = UserService.create_user(email, password, role='user')
            password_user_id = password_user.id
            
            # Link OAuth account
            user_info = {
                'provider_user_id': unique_provider_id,
                'email': email,
                'name': 'Test User'
            }
            oauth_user = OAuthService.create_or_update_user(provider, user_info)
            
            # Both should be the same user
            assert oauth_user.id == password_user_id
            
            # User should have password hash (can login with password)
            assert password_user.password_hash is not None
            
            # User should have OAuth account linked
            oauth_account = OAuthAccount.query.filter_by(
                user_id=password_user_id,
                provider=provider
            ).first()
            assert oauth_account is not None
            
            # Cleanup
            db.session.delete(oauth_account)
            UserService.delete_user(password_user_id)
    
    @given(provider=oauth_providers, provider_user_id=provider_user_ids)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_21_no_oauth_token_storage(self, app, provider, provider_user_id):
        """
        Property 21: No OAuth token storage
        
        For any OAuth authentication flow, access tokens should not be
        persisted to the database.
        
        **Validates: Requirements 10.5**
        """
        with app.app_context():
            email = generate_unique_email()
            unique_provider_id = f"{provider_user_id}_{uuid.uuid4().hex[:8]}"
            
            user_info = {
                'provider_user_id': unique_provider_id,
                'email': email,
                'name': 'Test User'
            }
            
            # Create user via OAuth
            user = OAuthService.create_or_update_user(provider, user_info)
            
            # Verify OAuth account exists
            oauth_account = OAuthAccount.query.filter_by(
                provider=provider,
                provider_user_id=unique_provider_id
            ).first()
            
            assert oauth_account is not None
            
            # Verify no token fields exist on OAuthAccount model
            # The model should only store provider and provider_user_id
            assert not hasattr(oauth_account, 'access_token')
            assert not hasattr(oauth_account, 'refresh_token')
            assert not hasattr(oauth_account, 'token')
            
            # Cleanup
            db.session.delete(oauth_account)
            db.session.delete(user)
            db.session.commit()
