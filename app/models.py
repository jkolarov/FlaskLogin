"""
Database models for the Flask Auth Skeleton application.

This module defines SQLAlchemy models for user authentication and OAuth integration.

Requirements addressed:
- 9.1: User_Repository SHALL store user records with: id, email, password_hash, role, created_at
- 9.2: User_Repository SHALL store OAuth links with: id, user_id, provider, provider_user_id
"""

from datetime import datetime
from typing import Optional

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint

# Initialize SQLAlchemy instance
# This will be bound to the Flask app in the application factory
db = SQLAlchemy()


class User(db.Model, UserMixin):
    """
    User account model.
    
    Implements Flask-Login's UserMixin for session management compatibility.
    Supports both email/password and OAuth authentication methods.
    
    Attributes:
        id: Primary key identifier
        email: Unique email address for the user
        password_hash: Bcrypt hashed password (nullable for OAuth-only users)
        role: User role ('user' or 'admin')
        created_at: Timestamp of account creation
        oauth_accounts: Related OAuth provider accounts
    
    Requirements:
        - 9.1: Store user records with id, email, password_hash, role, created_at
    """
    
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Nullable for OAuth-only users
    role: Mapped[str] = mapped_column(String(50), nullable=False, default='user')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationship to OAuth accounts
    oauth_accounts: Mapped[list['OAuthAccount']] = relationship(
        'OAuthAccount',
        back_populates='user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    def is_admin(self) -> bool:
        """
        Check if user has admin role.
        
        Returns:
            True if user has 'admin' role, False otherwise.
        """
        return self.role == 'admin'
    
    def __repr__(self) -> str:
        """Return string representation of User."""
        return f'<User {self.email}>'


class OAuthAccount(db.Model):
    """
    OAuth provider account link.
    
    Links external OAuth provider accounts to local user accounts.
    A user can have multiple OAuth accounts from different providers.
    
    Attributes:
        id: Primary key identifier
        user_id: Foreign key to the associated User
        provider: OAuth provider name ('google', 'facebook', 'github')
        provider_user_id: Unique user ID from the OAuth provider
        user: Reference to the associated User object
    
    Requirements:
        - 9.2: Store OAuth links with id, user_id, provider, provider_user_id
    
    Constraints:
        - Unique constraint on (provider, provider_user_id) ensures each OAuth
          account can only be linked to one local user account.
    """
    
    __tablename__ = 'oauth_accounts'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # 'google', 'facebook', 'github'
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Relationship back to User
    user: Mapped['User'] = relationship('User', back_populates='oauth_accounts')
    
    __table_args__ = (
        UniqueConstraint('provider', 'provider_user_id', name='unique_provider_account'),
    )
    
    def __repr__(self) -> str:
        """Return string representation of OAuthAccount."""
        return f'<OAuthAccount {self.provider}:{self.provider_user_id}>'
