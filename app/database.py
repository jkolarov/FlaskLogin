"""
Database initialization and seeding module.

This module provides functions for initializing the database schema and
seeding initial data such as the admin user.

Requirements addressed:
- 9.4: THE System SHALL initialize the database schema on first run
"""

import os
from typing import Optional

from app.models import db, User


def init_db(app) -> None:
    """
    Initialize the database schema.
    
    Creates all database tables defined in the models if they don't exist.
    This function should be called during application startup.
    
    Args:
        app: Flask application instance
    
    Requirements:
        - 9.4: Initialize the database schema on first run
    """
    with app.app_context():
        db.create_all()


def seed_admin_user(app) -> Optional[dict]:
    """
    Seed the initial admin user from environment variables.
    
    Creates an admin user using ADMIN_EMAIL and ADMIN_PASSWORD environment
    variables if they are set and the user doesn't already exist.
    
    Args:
        app: Flask application instance
    
    Returns:
        A dictionary with user info {'id': int, 'email': str, 'role': str, 'created': bool}
        or None if environment variables are not set.
        The 'created' field indicates if a new user was created (True) or
        an existing user was found (False).
    
    Note:
        This function uses bcrypt for password hashing. It imports the
        PasswordService lazily to avoid circular imports and to allow
        the function to work before PasswordService is implemented.
    """
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    
    if not admin_email or not admin_password:
        return None
    
    with app.app_context():
        # Check if admin user already exists
        existing_user = User.query.filter_by(email=admin_email).first()
        if existing_user:
            return {
                'id': existing_user.id,
                'email': existing_user.email,
                'role': existing_user.role,
                'created': False
            }
        
        # Hash the password using bcrypt
        # Import here to avoid circular imports and allow flexibility
        try:
            from app.auth.password import PasswordService
            password_hash = PasswordService.hash_password(admin_password)
        except ImportError:
            # Fallback to direct bcrypt usage if PasswordService not yet implemented
            import bcrypt
            password_hash = bcrypt.hashpw(
                admin_password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
        
        # Create the admin user
        admin_user = User(
            email=admin_email,
            password_hash=password_hash,
            role='admin'
        )
        
        db.session.add(admin_user)
        db.session.commit()
        
        return {
            'id': admin_user.id,
            'email': admin_user.email,
            'role': admin_user.role,
            'created': True
        }


def init_and_seed_db(app) -> None:
    """
    Initialize database and seed initial data.
    
    Convenience function that combines database initialization and seeding.
    This is the main entry point for database setup during application startup.
    
    Args:
        app: Flask application instance
    
    Requirements:
        - 9.4: Initialize the database schema on first run
    """
    init_db(app)
    seed_admin_user(app)


def drop_all_tables(app) -> None:
    """
    Drop all database tables.
    
    WARNING: This will delete all data! Use only for testing or development.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        db.drop_all()


def reset_db(app) -> None:
    """
    Reset the database by dropping and recreating all tables.
    
    WARNING: This will delete all data! Use only for testing or development.
    
    Args:
        app: Flask application instance
    """
    drop_all_tables(app)
    init_and_seed_db(app)
