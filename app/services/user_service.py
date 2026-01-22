"""
User service for user management operations.

This module provides the UserService class that handles all user-related
business logic including CRUD operations and password management.

Requirements addressed:
- 9.3: WHEN querying users, THE User_Repository SHALL support filtering by email and provider
"""

from typing import List, Optional

from app.models import db, User, OAuthAccount
from app.auth.password import PasswordService


class UserService:
    """Service for user management operations.
    
    Provides methods for creating, reading, updating, and deleting users.
    All password handling is delegated to the PasswordService for secure hashing.
    
    Requirements:
        - 9.3: Support filtering by email and provider
    """
    
    @staticmethod
    def get_all_users() -> List[User]:
        """Retrieve all users from the database.
        
        Returns:
            List of all User objects in the database.
        """
        return User.query.all()
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[User]:
        """Retrieve a user by their ID.
        
        Args:
            user_id: The unique identifier of the user.
            
        Returns:
            The User object if found, None otherwise.
        """
        return db.session.get(User, user_id)
    
    @staticmethod
    def get_user_by_email(email: str) -> Optional[User]:
        """Retrieve a user by their email address.
        
        Supports requirement 9.3 for filtering by email.
        
        Args:
            email: The email address to search for.
            
        Returns:
            The User object if found, None otherwise.
        """
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def get_users_by_provider(provider: str) -> List[User]:
        """Retrieve all users that have an OAuth account with the specified provider.
        
        Supports requirement 9.3 for filtering by provider.
        
        Args:
            provider: The OAuth provider name (e.g., 'google', 'facebook', 'github').
            
        Returns:
            List of User objects that have an OAuth account with the specified provider.
        """
        return User.query.join(OAuthAccount).filter(
            OAuthAccount.provider == provider
        ).all()
    
    @staticmethod
    def create_user(email: str, password: str, role: str = 'user') -> User:
        """Create a new user with a hashed password.
        
        The password is hashed using bcrypt via the PasswordService before storage.
        
        Args:
            email: The email address for the new user.
            password: The plain text password to be hashed.
            role: The user's role, defaults to 'user'.
            
        Returns:
            The newly created User object.
            
        Raises:
            ValueError: If email or password is empty.
            sqlalchemy.exc.IntegrityError: If email already exists.
        """
        if not email:
            raise ValueError("Email cannot be empty")
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Hash the password using PasswordService
        password_hash = PasswordService.hash_password(password)
        
        # Create the new user
        user = User(
            email=email,
            password_hash=password_hash,
            role=role
        )
        
        db.session.add(user)
        db.session.commit()
        
        return user
    
    @staticmethod
    def update_user_role(user_id: int, role: str) -> bool:
        """Update a user's role.
        
        Args:
            user_id: The unique identifier of the user to update.
            role: The new role to assign ('user' or 'admin').
            
        Returns:
            True if the update was successful, False if user not found.
            
        Raises:
            ValueError: If role is empty or invalid.
        """
        if not role:
            raise ValueError("Role cannot be empty")
        
        valid_roles = ['user', 'admin']
        if role not in valid_roles:
            raise ValueError(f"Role must be one of: {', '.join(valid_roles)}")
        
        user = db.session.get(User, user_id)
        if user is None:
            return False
        
        user.role = role
        db.session.commit()
        
        return True
    
    @staticmethod
    def delete_user(user_id: int) -> bool:
        """Delete a user by their ID.
        
        This will also delete all associated OAuth accounts due to cascade delete.
        
        Args:
            user_id: The unique identifier of the user to delete.
            
        Returns:
            True if the deletion was successful, False if user not found.
        """
        user = db.session.get(User, user_id)
        if user is None:
            return False
        
        db.session.delete(user)
        db.session.commit()
        
        return True
