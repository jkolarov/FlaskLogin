"""
Flask application configuration.

This module provides configuration classes for different environments:
- Development: Debug mode enabled, local SQLite database
- Production: Debug disabled, secure settings
- Testing: In-memory database, testing optimizations

Requirements addressed:
- 8.4: Environment variables for configuration (database path, secret keys, OAuth credentials)
- 10.2: Secure session data with secret key
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class with common settings."""
    
    # Secret key for session management (Requirement 10.2)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # SQLAlchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-WTF CSRF protection
    WTF_CSRF_ENABLED = True
    
    # OAuth provider credentials (Requirement 8.4)
    # Google OAuth
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # Facebook OAuth
    FACEBOOK_CLIENT_ID = os.environ.get('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.environ.get('FACEBOOK_CLIENT_SECRET')
    
    # GitHub OAuth
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
    
    # Session configuration
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class DevelopmentConfig(Config):
    """Development environment configuration."""
    
    DEBUG = True
    
    # SQLite database path (Requirement 8.4)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///dev.db'
    
    # Development-specific settings
    TEMPLATES_AUTO_RELOAD = True


class ProductionConfig(Config):
    """Production environment configuration."""
    
    DEBUG = False
    
    # SQLite database path (Requirement 8.4)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///prod.db'
    
    # Production security settings
    SESSION_COOKIE_SECURE = True  # Requires HTTPS
    
    # Ensure secret key is set in production
    @classmethod
    def init_app(cls, app):
        """Initialize production-specific settings."""
        if app.config['SECRET_KEY'] == 'dev-secret-key-change-in-production':
            raise ValueError('SECRET_KEY must be set in production environment')


class TestingConfig(Config):
    """Testing environment configuration."""
    
    TESTING = True
    DEBUG = True
    
    # Use in-memory SQLite for faster tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for easier testing
    WTF_CSRF_ENABLED = False
    
    # Use a fixed secret key for testing
    SECRET_KEY = 'testing-secret-key'


# Configuration dictionary for easy access
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
