"""
Property-based tests for PasswordService.

This module uses Hypothesis to test universal properties of password hashing
and verification across randomly generated inputs.

**Validates: Requirements 1.3, 2.3, 10.3**

Properties tested:
- Property 1: Password hashing round-trip
- Property 8: Password verification correctness
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

from app.auth.password import PasswordService


# Strategy for generating valid passwords (non-empty strings, max 72 bytes for bcrypt)
# bcrypt has a 72-byte limit, so we use ASCII characters only
valid_passwords = st.text(
    alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    min_size=1, 
    max_size=50
)


class TestPasswordServiceProperties:
    """Property-based tests for PasswordService."""
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000)
    def test_property_1_password_hashing_round_trip(self, password):
        """
        Property 1: Password hashing round-trip
        
        For any valid password string, hashing it and then verifying the original
        password against the hash should return true.
        
        **Validates: Requirements 1.3, 10.3**
        """
        # Hash the password
        password_hash = PasswordService.hash_password(password)
        
        # Verify the original password against the hash
        result = PasswordService.verify_password(password, password_hash)
        
        assert result is True, f"Password '{password}' should verify against its own hash"
    
    @given(password=valid_passwords, wrong_password=valid_passwords)
    @settings(max_examples=10, deadline=2000)
    def test_property_8_password_verification_correctness(self, password, wrong_password):
        """
        Property 8: Password verification correctness
        
        For any stored password hash and the original password, verification should
        return true. For any stored hash and a different password, verification
        should return false.
        
        **Validates: Requirements 2.3**
        """
        # Skip if passwords are the same (we want to test different passwords)
        assume(password != wrong_password)
        
        # Hash the original password
        password_hash = PasswordService.hash_password(password)
        
        # Verify correct password returns True
        assert PasswordService.verify_password(password, password_hash) is True
        
        # Verify wrong password returns False
        assert PasswordService.verify_password(wrong_password, password_hash) is False
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000)
    def test_property_hash_is_different_from_password(self, password):
        """
        Property: Hash is always different from the original password.
        
        This ensures the password is actually being transformed.
        
        **Validates: Requirements 1.3, 10.3**
        """
        password_hash = PasswordService.hash_password(password)
        
        assert password_hash != password, "Hash should be different from original password"
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000)
    def test_property_hash_has_bcrypt_format(self, password):
        """
        Property: Hash always has valid bcrypt format.
        
        bcrypt hashes start with $2a$, $2b$, or $2y$ followed by cost factor.
        
        **Validates: Requirements 10.3**
        """
        password_hash = PasswordService.hash_password(password)
        
        # bcrypt hashes start with $2
        assert password_hash.startswith('$2'), "Hash should have bcrypt format"
        
        # bcrypt hashes have a specific length (60 characters)
        assert len(password_hash) == 60, "bcrypt hash should be 60 characters"
    
    @given(password=valid_passwords)
    @settings(max_examples=10, deadline=2000)
    def test_property_same_password_different_hashes(self, password):
        """
        Property: Same password produces different hashes due to random salt.
        
        This ensures proper salting is being used.
        
        **Validates: Requirements 10.3**
        """
        hash1 = PasswordService.hash_password(password)
        hash2 = PasswordService.hash_password(password)
        
        # Hashes should be different due to random salt
        assert hash1 != hash2, "Same password should produce different hashes"
        
        # But both should verify correctly
        assert PasswordService.verify_password(password, hash1) is True
        assert PasswordService.verify_password(password, hash2) is True
