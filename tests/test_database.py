"""
Tests for database initialization module.

This module tests the database initialization and seeding functionality.

Requirements tested:
- 9.4: THE System SHALL initialize the database schema on first run
"""

import os
import pytest
from flask import Flask

from app.models import db, User
from app.database import init_db, seed_admin_user, init_and_seed_db, reset_db
from config import config


@pytest.fixture
def app():
    """Create a test Flask application."""
    test_app = Flask(__name__)
    test_app.config.from_object(config['testing'])
    db.init_app(test_app)
    
    yield test_app
    
    # Cleanup: drop all tables after test
    with test_app.app_context():
        db.drop_all()


@pytest.fixture
def app_with_db(app):
    """Create a test Flask application with initialized database."""
    init_db(app)
    yield app


class TestInitDb:
    """Tests for init_db function."""
    
    def test_init_db_creates_tables(self, app):
        """Test that init_db creates all database tables."""
        init_db(app)
        
        with app.app_context():
            # Verify tables exist by querying them
            users = User.query.all()
            assert users == []  # Empty but table exists
    
    def test_init_db_is_idempotent(self, app):
        """Test that init_db can be called multiple times safely."""
        init_db(app)
        init_db(app)  # Should not raise an error
        
        with app.app_context():
            users = User.query.all()
            assert users == []


class TestSeedAdminUser:
    """Tests for seed_admin_user function."""
    
    def test_seed_admin_user_creates_admin(self, app_with_db, monkeypatch):
        """Test that seed_admin_user creates an admin user."""
        monkeypatch.setenv('ADMIN_EMAIL', 'admin@test.com')
        monkeypatch.setenv('ADMIN_PASSWORD', 'securepassword123')
        
        result = seed_admin_user(app_with_db)
        
        assert result is not None
        assert result['email'] == 'admin@test.com'
        assert result['role'] == 'admin'
        assert result['created'] is True
        
        # Verify user exists in database
        with app_with_db.app_context():
            user = User.query.filter_by(email='admin@test.com').first()
            assert user is not None
            assert user.is_admin() is True
            assert user.password_hash is not None
    
    def test_seed_admin_user_returns_none_without_env_vars(self, app_with_db, monkeypatch):
        """Test that seed_admin_user returns None when env vars are not set."""
        monkeypatch.delenv('ADMIN_EMAIL', raising=False)
        monkeypatch.delenv('ADMIN_PASSWORD', raising=False)
        
        result = seed_admin_user(app_with_db)
        
        assert result is None
    
    def test_seed_admin_user_returns_none_with_partial_env_vars(self, app_with_db, monkeypatch):
        """Test that seed_admin_user returns None when only email is set."""
        monkeypatch.setenv('ADMIN_EMAIL', 'admin@test.com')
        monkeypatch.delenv('ADMIN_PASSWORD', raising=False)
        
        result = seed_admin_user(app_with_db)
        
        assert result is None
    
    def test_seed_admin_user_does_not_duplicate(self, app_with_db, monkeypatch):
        """Test that seed_admin_user doesn't create duplicate users."""
        monkeypatch.setenv('ADMIN_EMAIL', 'admin@test.com')
        monkeypatch.setenv('ADMIN_PASSWORD', 'securepassword123')
        
        # First call creates the user
        result1 = seed_admin_user(app_with_db)
        assert result1['created'] is True
        
        # Second call returns existing user
        result2 = seed_admin_user(app_with_db)
        assert result2['created'] is False
        assert result2['id'] == result1['id']
        
        # Verify only one user exists
        with app_with_db.app_context():
            users = User.query.filter_by(email='admin@test.com').all()
            assert len(users) == 1
    
    def test_seed_admin_user_hashes_password(self, app_with_db, monkeypatch):
        """Test that seed_admin_user properly hashes the password."""
        monkeypatch.setenv('ADMIN_EMAIL', 'admin@test.com')
        monkeypatch.setenv('ADMIN_PASSWORD', 'securepassword123')
        
        seed_admin_user(app_with_db)
        
        with app_with_db.app_context():
            user = User.query.filter_by(email='admin@test.com').first()
            # Password should be hashed, not plain text
            assert user.password_hash != 'securepassword123'
            # Bcrypt hashes start with $2b$
            assert user.password_hash.startswith('$2')


class TestInitAndSeedDb:
    """Tests for init_and_seed_db function."""
    
    def test_init_and_seed_db_creates_tables_and_admin(self, app, monkeypatch):
        """Test that init_and_seed_db initializes database and seeds admin."""
        monkeypatch.setenv('ADMIN_EMAIL', 'admin@test.com')
        monkeypatch.setenv('ADMIN_PASSWORD', 'securepassword123')
        
        init_and_seed_db(app)
        
        with app.app_context():
            user = User.query.filter_by(email='admin@test.com').first()
            assert user is not None
            assert user.is_admin() is True


class TestResetDb:
    """Tests for reset_db function."""
    
    def test_reset_db_clears_and_recreates(self, app_with_db, monkeypatch):
        """Test that reset_db drops and recreates tables."""
        monkeypatch.setenv('ADMIN_EMAIL', 'admin@test.com')
        monkeypatch.setenv('ADMIN_PASSWORD', 'securepassword123')
        
        # Create initial admin
        seed_admin_user(app_with_db)
        
        # Add another user
        with app_with_db.app_context():
            user = User(email='user@test.com', role='user')
            db.session.add(user)
            db.session.commit()
            
            # Verify two users exist
            assert User.query.count() == 2
        
        # Reset database
        reset_db(app_with_db)
        
        # Verify only admin exists (seeded during reset)
        with app_with_db.app_context():
            users = User.query.all()
            assert len(users) == 1
            assert users[0].email == 'admin@test.com'
