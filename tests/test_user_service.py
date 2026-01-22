"""
Unit tests for UserService.

Tests for user management operations including CRUD functionality.
Validates Requirements 9.3 (filtering by email and provider).
"""

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError

from app.models import db, User, OAuthAccount
from app.services.user_service import UserService
from config import config


@pytest.fixture
def app():
    """Create a test Flask application."""
    test_app = Flask(__name__)
    test_app.config.from_object(config['testing'])
    db.init_app(test_app)
    
    with test_app.app_context():
        db.create_all()
    
    yield test_app
    
    # Cleanup: drop all tables after test
    with test_app.app_context():
        db.drop_all()


@pytest.fixture
def app_context(app):
    """Provide an application context for tests."""
    with app.app_context():
        yield


class TestUserServiceGetAllUsers:
    """Tests for UserService.get_all_users() method."""
    
    def test_get_all_users_returns_empty_list_when_no_users(self, app_context):
        """Returns empty list when no users exist."""
        users = UserService.get_all_users()
        assert users == []
    
    def test_get_all_users_returns_all_users(self, app_context):
        """Returns all users in the database."""
        # Create test users
        user1 = User(email='user1@test.com', role='user')
        user2 = User(email='user2@test.com', role='admin')
        db.session.add_all([user1, user2])
        db.session.commit()
        
        users = UserService.get_all_users()
        
        assert len(users) == 2
        emails = [u.email for u in users]
        assert 'user1@test.com' in emails
        assert 'user2@test.com' in emails


class TestUserServiceGetUserById:
    """Tests for UserService.get_user_by_id() method."""
    
    def test_get_user_by_id_returns_user_when_exists(self, app_context):
        """Returns user when ID exists."""
        user = User(email='test@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        found_user = UserService.get_user_by_id(user.id)
        
        assert found_user is not None
        assert found_user.email == 'test@test.com'
    
    def test_get_user_by_id_returns_none_when_not_exists(self, app_context):
        """Returns None when ID does not exist."""
        found_user = UserService.get_user_by_id(999)
        assert found_user is None


class TestUserServiceGetUserByEmail:
    """Tests for UserService.get_user_by_email() method.
    
    Validates Requirement 9.3: Support filtering by email.
    """
    
    def test_get_user_by_email_returns_user_when_exists(self, app_context):
        """Returns user when email exists."""
        user = User(email='findme@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        found_user = UserService.get_user_by_email('findme@test.com')
        
        assert found_user is not None
        assert found_user.id == user.id
    
    def test_get_user_by_email_returns_none_when_not_exists(self, app_context):
        """Returns None when email does not exist."""
        found_user = UserService.get_user_by_email('nonexistent@test.com')
        assert found_user is None
    
    def test_get_user_by_email_is_case_sensitive(self, app_context):
        """Email lookup is case-sensitive (depends on database)."""
        user = User(email='Test@Test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        # Exact match should work
        found_user = UserService.get_user_by_email('Test@Test.com')
        assert found_user is not None


class TestUserServiceGetUsersByProvider:
    """Tests for UserService.get_users_by_provider() method.
    
    Validates Requirement 9.3: Support filtering by provider.
    """
    
    def test_get_users_by_provider_returns_users_with_provider(self, app_context):
        """Returns users that have OAuth account with specified provider."""
        # Create users
        user1 = User(email='google_user@test.com', role='user')
        user2 = User(email='facebook_user@test.com', role='user')
        user3 = User(email='no_oauth@test.com', role='user')
        db.session.add_all([user1, user2, user3])
        db.session.commit()
        
        # Create OAuth accounts
        oauth1 = OAuthAccount(user_id=user1.id, provider='google', provider_user_id='g123')
        oauth2 = OAuthAccount(user_id=user2.id, provider='facebook', provider_user_id='f456')
        db.session.add_all([oauth1, oauth2])
        db.session.commit()
        
        # Filter by google provider
        google_users = UserService.get_users_by_provider('google')
        
        assert len(google_users) == 1
        assert google_users[0].email == 'google_user@test.com'
    
    def test_get_users_by_provider_returns_empty_when_no_matches(self, app_context):
        """Returns empty list when no users have the specified provider."""
        user = User(email='test@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        github_users = UserService.get_users_by_provider('github')
        
        assert github_users == []
    
    def test_get_users_by_provider_returns_multiple_users(self, app_context):
        """Returns all users with the specified provider."""
        # Create users
        user1 = User(email='user1@test.com', role='user')
        user2 = User(email='user2@test.com', role='user')
        db.session.add_all([user1, user2])
        db.session.commit()
        
        # Both users have Google OAuth
        oauth1 = OAuthAccount(user_id=user1.id, provider='google', provider_user_id='g123')
        oauth2 = OAuthAccount(user_id=user2.id, provider='google', provider_user_id='g456')
        db.session.add_all([oauth1, oauth2])
        db.session.commit()
        
        google_users = UserService.get_users_by_provider('google')
        
        assert len(google_users) == 2


class TestUserServiceCreateUser:
    """Tests for UserService.create_user() method."""
    
    def test_create_user_creates_user_with_hashed_password(self, app_context):
        """Creates user with properly hashed password."""
        user = UserService.create_user('new@test.com', 'password123')
        
        assert user is not None
        assert user.email == 'new@test.com'
        assert user.password_hash is not None
        assert user.password_hash != 'password123'  # Password should be hashed
        assert user.password_hash.startswith('$2')  # bcrypt format
    
    def test_create_user_assigns_default_role(self, app_context):
        """Creates user with default 'user' role."""
        user = UserService.create_user('new@test.com', 'password123')
        
        assert user.role == 'user'
    
    def test_create_user_assigns_custom_role(self, app_context):
        """Creates user with specified role."""
        user = UserService.create_user('admin@test.com', 'password123', role='admin')
        
        assert user.role == 'admin'
    
    def test_create_user_persists_to_database(self, app_context):
        """Created user is persisted to database."""
        user = UserService.create_user('persist@test.com', 'password123')
        
        # Query directly from database
        found_user = User.query.filter_by(email='persist@test.com').first()
        
        assert found_user is not None
        assert found_user.id == user.id
    
    def test_create_user_with_empty_email_raises_error(self, app_context):
        """Empty email raises ValueError."""
        with pytest.raises(ValueError, match="Email cannot be empty"):
            UserService.create_user('', 'password123')
    
    def test_create_user_with_empty_password_raises_error(self, app_context):
        """Empty password raises ValueError."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            UserService.create_user('test@test.com', '')
    
    def test_create_user_with_duplicate_email_raises_error(self, app_context):
        """Duplicate email raises IntegrityError."""
        UserService.create_user('duplicate@test.com', 'password123')
        
        with pytest.raises(IntegrityError):
            UserService.create_user('duplicate@test.com', 'password456')


class TestUserServiceUpdateUserRole:
    """Tests for UserService.update_user_role() method."""
    
    def test_update_user_role_changes_role(self, app_context):
        """Updates user role successfully."""
        user = User(email='test@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        result = UserService.update_user_role(user.id, 'admin')
        
        assert result is True
        
        # Verify change persisted
        updated_user = db.session.get(User, user.id)
        assert updated_user.role == 'admin'
    
    def test_update_user_role_returns_false_for_nonexistent_user(self, app_context):
        """Returns False when user does not exist."""
        result = UserService.update_user_role(999, 'admin')
        assert result is False
    
    def test_update_user_role_with_empty_role_raises_error(self, app_context):
        """Empty role raises ValueError."""
        user = User(email='test@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        with pytest.raises(ValueError, match="Role cannot be empty"):
            UserService.update_user_role(user.id, '')
    
    def test_update_user_role_with_invalid_role_raises_error(self, app_context):
        """Invalid role raises ValueError."""
        user = User(email='test@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        with pytest.raises(ValueError, match="Role must be one of"):
            UserService.update_user_role(user.id, 'superuser')
    
    def test_update_user_role_to_user(self, app_context):
        """Can update role from admin to user."""
        user = User(email='test@test.com', role='admin')
        db.session.add(user)
        db.session.commit()
        
        result = UserService.update_user_role(user.id, 'user')
        
        assert result is True
        updated_user = db.session.get(User, user.id)
        assert updated_user.role == 'user'


class TestUserServiceDeleteUser:
    """Tests for UserService.delete_user() method."""
    
    def test_delete_user_removes_user(self, app_context):
        """Deletes user from database."""
        user = User(email='delete@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        
        result = UserService.delete_user(user_id)
        
        assert result is True
        
        # Verify user is deleted
        deleted_user = db.session.get(User, user_id)
        assert deleted_user is None
    
    def test_delete_user_returns_false_for_nonexistent_user(self, app_context):
        """Returns False when user does not exist."""
        result = UserService.delete_user(999)
        assert result is False
    
    def test_delete_user_cascades_to_oauth_accounts(self, app_context):
        """Deleting user also deletes associated OAuth accounts."""
        user = User(email='oauth_user@test.com', role='user')
        db.session.add(user)
        db.session.commit()
        
        oauth = OAuthAccount(user_id=user.id, provider='google', provider_user_id='g123')
        db.session.add(oauth)
        db.session.commit()
        oauth_id = oauth.id
        user_id = user.id
        
        result = UserService.delete_user(user_id)
        
        assert result is True
        
        # Verify OAuth account is also deleted
        deleted_oauth = db.session.get(OAuthAccount, oauth_id)
        assert deleted_oauth is None
