"""Password hashing and verification service.

This module provides secure password hashing using bcrypt as specified
in Requirements 1.3 and 10.3.
"""

import bcrypt


class PasswordService:
    """Service for password hashing and verification.
    
    Uses bcrypt for secure password hashing as required by:
    - Requirement 1.3: Hash passwords using a secure algorithm before storage
    - Requirement 10.3: Use bcrypt or argon2 for password hashing
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt.
        
        Args:
            password: The plain text password to hash.
            
        Returns:
            The bcrypt hash of the password as a string.
            
        Raises:
            ValueError: If password is empty or None.
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Generate salt and hash the password
        # bcrypt.gensalt() generates a random salt with default work factor (12)
        salt = bcrypt.gensalt()
        password_bytes = password.encode('utf-8')
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Return hash as string for storage
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against stored hash.
        
        Args:
            password: The plain text password to verify.
            password_hash: The stored bcrypt hash to verify against.
            
        Returns:
            True if the password matches the hash, False otherwise.
            
        Raises:
            ValueError: If password or password_hash is empty or None.
        """
        if not password:
            raise ValueError("Password cannot be empty")
        if not password_hash:
            raise ValueError("Password hash cannot be empty")
        
        try:
            password_bytes = password.encode('utf-8')
            hash_bytes = password_hash.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hash_bytes)
        except (ValueError, TypeError):
            # Invalid hash format
            return False
