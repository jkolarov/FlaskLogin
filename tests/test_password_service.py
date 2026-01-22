"""Unit tests for PasswordService.

Tests for password hashing and verification functionality.
Validates Requirements 1.3, 2.3, and 10.3.
"""

import pytest
from app.auth.password import PasswordService


class TestPasswordServiceHashPassword:
    """Tests for PasswordService.hash_password() method."""
    
    def test_hash_password_returns_non_empty_string(self):
        """Hash generation produces non-empty string."""
        password = "testpassword123"
        hashed = PasswordService.hash_password(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_is_different_from_original_password(self):
        """Hash is different from original password."""
        password = "mysecretpassword"
        hashed = PasswordService.hash_password(password)
        
        assert hashed != password
    
    def test_hash_starts_with_bcrypt_prefix(self):
        """Hash has valid bcrypt format (starts with $2b$)."""
        password = "testpassword"
        hashed = PasswordService.hash_password(password)
        
        # bcrypt hashes start with $2a$, $2b$, or $2y$
        assert hashed.startswith('$2')
    
    def test_same_password_produces_different_hashes(self):
        """Same password produces different hashes due to random salt."""
        password = "samepassword"
        hash1 = PasswordService.hash_password(password)
        hash2 = PasswordService.hash_password(password)
        
        assert hash1 != hash2
    
    def test_hash_password_with_empty_string_raises_error(self):
        """Empty password raises ValueError."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            PasswordService.hash_password("")
    
    def test_hash_password_with_none_raises_error(self):
        """None password raises ValueError."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            PasswordService.hash_password(None)
    
    def test_hash_password_with_unicode_characters(self):
        """Password with unicode characters is hashed correctly."""
        password = "пароль123日本語"
        hashed = PasswordService.hash_password(password)
        
        assert hashed is not None
        assert len(hashed) > 0
        assert hashed.startswith('$2')


class TestPasswordServiceVerifyPassword:
    """Tests for PasswordService.verify_password() method."""
    
    def test_verify_correct_password_returns_true(self):
        """Verification with correct password returns True."""
        password = "correctpassword"
        hashed = PasswordService.hash_password(password)
        
        assert PasswordService.verify_password(password, hashed) is True
    
    def test_verify_incorrect_password_returns_false(self):
        """Verification with incorrect password returns False."""
        password = "correctpassword"
        wrong_password = "wrongpassword"
        hashed = PasswordService.hash_password(password)
        
        assert PasswordService.verify_password(wrong_password, hashed) is False
    
    def test_verify_similar_password_returns_false(self):
        """Verification with similar but different password returns False."""
        password = "password123"
        similar_password = "password124"
        hashed = PasswordService.hash_password(password)
        
        assert PasswordService.verify_password(similar_password, hashed) is False
    
    def test_verify_case_sensitive(self):
        """Password verification is case-sensitive."""
        password = "CaseSensitive"
        hashed = PasswordService.hash_password(password)
        
        assert PasswordService.verify_password("casesensitive", hashed) is False
        assert PasswordService.verify_password("CASESENSITIVE", hashed) is False
        assert PasswordService.verify_password("CaseSensitive", hashed) is True
    
    def test_verify_with_empty_password_raises_error(self):
        """Empty password raises ValueError."""
        hashed = PasswordService.hash_password("somepassword")
        
        with pytest.raises(ValueError, match="Password cannot be empty"):
            PasswordService.verify_password("", hashed)
    
    def test_verify_with_none_password_raises_error(self):
        """None password raises ValueError."""
        hashed = PasswordService.hash_password("somepassword")
        
        with pytest.raises(ValueError, match="Password cannot be empty"):
            PasswordService.verify_password(None, hashed)
    
    def test_verify_with_empty_hash_raises_error(self):
        """Empty hash raises ValueError."""
        with pytest.raises(ValueError, match="Password hash cannot be empty"):
            PasswordService.verify_password("password", "")
    
    def test_verify_with_none_hash_raises_error(self):
        """None hash raises ValueError."""
        with pytest.raises(ValueError, match="Password hash cannot be empty"):
            PasswordService.verify_password("password", None)
    
    def test_verify_with_invalid_hash_returns_false(self):
        """Invalid hash format returns False instead of raising."""
        password = "testpassword"
        invalid_hash = "not_a_valid_bcrypt_hash"
        
        assert PasswordService.verify_password(password, invalid_hash) is False
    
    def test_verify_with_unicode_password(self):
        """Unicode password verification works correctly."""
        password = "пароль123日本語"
        hashed = PasswordService.hash_password(password)
        
        assert PasswordService.verify_password(password, hashed) is True
        assert PasswordService.verify_password("wrongpassword", hashed) is False
