"""
Unit tests for input sanitization utilities.

This module tests the sanitization functions to ensure they properly
sanitize user inputs and prevent injection attacks.

Requirements addressed:
- 10.4: THE System SHALL sanitize all user inputs to prevent injection attacks
"""

import pytest
from app.utils.sanitization import (
    sanitize_string,
    sanitize_email,
    escape_html,
    is_safe_role,
    sanitize_role
)


class TestSanitizeString:
    """Tests for sanitize_string function."""
    
    def test_strips_whitespace(self):
        """Test that leading and trailing whitespace is stripped."""
        assert sanitize_string("  hello world  ") == "hello world"
        assert sanitize_string("\t\nhello\n\t") == "hello"
    
    def test_returns_empty_for_none(self):
        """Test that None input returns empty string."""
        assert sanitize_string(None) == ""
    
    def test_limits_length(self):
        """Test that string is truncated to max_length."""
        long_string = "a" * 300
        result = sanitize_string(long_string, max_length=10)
        assert len(result) == 10
        assert result == "a" * 10
    
    def test_default_max_length(self):
        """Test default max_length of 255."""
        long_string = "a" * 300
        result = sanitize_string(long_string)
        assert len(result) == 255
    
    def test_preserves_valid_string(self):
        """Test that valid strings are preserved."""
        assert sanitize_string("hello") == "hello"
        assert sanitize_string("hello world") == "hello world"
    
    def test_no_strip_option(self):
        """Test that strip=False preserves whitespace."""
        result = sanitize_string("  hello  ", strip=False)
        assert result == "  hello  "
    
    def test_converts_non_string_to_string(self):
        """Test that non-string values are converted to strings."""
        assert sanitize_string(123) == "123"
        assert sanitize_string(12.34) == "12.34"


class TestSanitizeEmail:
    """Tests for sanitize_email function."""
    
    def test_converts_to_lowercase(self):
        """Test that email is converted to lowercase."""
        assert sanitize_email("User@Example.COM") == "user@example.com"
    
    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert sanitize_email("  user@example.com  ") == "user@example.com"
    
    def test_returns_empty_for_none(self):
        """Test that None input returns empty string."""
        assert sanitize_email(None) == ""
    
    def test_limits_length(self):
        """Test that email is limited to 255 characters."""
        long_email = "a" * 300 + "@example.com"
        result = sanitize_email(long_email)
        assert len(result) == 255
    
    def test_preserves_valid_email(self):
        """Test that valid emails are preserved (except case)."""
        assert sanitize_email("user@example.com") == "user@example.com"


class TestEscapeHtml:
    """Tests for escape_html function."""
    
    def test_escapes_script_tags(self):
        """Test that script tags are escaped."""
        result = escape_html("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
    
    def test_escapes_html_entities(self):
        """Test that HTML entities are escaped."""
        assert "&amp;" in escape_html("&")
        assert "&lt;" in escape_html("<")
        assert "&gt;" in escape_html(">")
        assert "&quot;" in escape_html('"')
    
    def test_returns_empty_for_none(self):
        """Test that None input returns empty string."""
        assert escape_html(None) == ""
    
    def test_preserves_safe_text(self):
        """Test that safe text is preserved."""
        assert escape_html("hello world") == "hello world"
    
    def test_escapes_sql_injection_attempt(self):
        """Test that SQL injection attempts are escaped."""
        result = escape_html("'; DROP TABLE users; --")
        # The apostrophe should be escaped
        assert "&#x27;" in result


class TestIsSafeRole:
    """Tests for is_safe_role function."""
    
    def test_valid_user_role(self):
        """Test that 'user' is a valid role."""
        assert is_safe_role("user") is True
    
    def test_valid_admin_role(self):
        """Test that 'admin' is a valid role."""
        assert is_safe_role("admin") is True
    
    def test_invalid_role(self):
        """Test that invalid roles return False."""
        assert is_safe_role("superuser") is False
        assert is_safe_role("root") is False
        assert is_safe_role("moderator") is False
    
    def test_none_role(self):
        """Test that None returns False."""
        assert is_safe_role(None) is False
    
    def test_empty_role(self):
        """Test that empty string returns False."""
        assert is_safe_role("") is False
    
    def test_case_insensitive(self):
        """Test that role validation is case-insensitive."""
        assert is_safe_role("USER") is True
        assert is_safe_role("Admin") is True
        assert is_safe_role("ADMIN") is True
    
    def test_whitespace_handling(self):
        """Test that whitespace is handled."""
        assert is_safe_role("  user  ") is True
        assert is_safe_role("  admin  ") is True


class TestSanitizeRole:
    """Tests for sanitize_role function."""
    
    def test_sanitizes_valid_user_role(self):
        """Test that valid 'user' role is sanitized."""
        assert sanitize_role("user") == "user"
        assert sanitize_role("USER") == "user"
        assert sanitize_role("  user  ") == "user"
    
    def test_sanitizes_valid_admin_role(self):
        """Test that valid 'admin' role is sanitized."""
        assert sanitize_role("admin") == "admin"
        assert sanitize_role("ADMIN") == "admin"
        assert sanitize_role("  Admin  ") == "admin"
    
    def test_returns_none_for_invalid_role(self):
        """Test that invalid roles return None."""
        assert sanitize_role("superuser") is None
        assert sanitize_role("root") is None
        assert sanitize_role("moderator") is None
    
    def test_returns_none_for_none_input(self):
        """Test that None input returns None."""
        assert sanitize_role(None) is None
    
    def test_returns_none_for_empty_string(self):
        """Test that empty string returns None."""
        assert sanitize_role("") is None
    
    def test_prevents_injection_in_role(self):
        """Test that injection attempts in role are rejected."""
        assert sanitize_role("admin'; DROP TABLE users; --") is None
        assert sanitize_role("<script>alert('xss')</script>") is None


class TestXSSPrevention:
    """Tests for XSS prevention in sanitization functions."""
    
    def test_script_tag_in_string(self):
        """Test that script tags in strings are handled."""
        malicious = "<script>alert('xss')</script>"
        # sanitize_string doesn't escape HTML (that's Jinja2's job)
        # but it should handle the string without error
        result = sanitize_string(malicious)
        assert result == malicious  # String is preserved, escaping is done in templates
    
    def test_script_tag_escaped_by_escape_html(self):
        """Test that escape_html properly escapes script tags."""
        malicious = "<script>alert('xss')</script>"
        result = escape_html(malicious)
        assert "<script>" not in result
        assert "alert" in result  # Content is preserved but escaped


class TestSQLInjectionPrevention:
    """Tests for SQL injection prevention in sanitization functions."""
    
    def test_sql_injection_in_email(self):
        """Test that SQL injection in email is handled."""
        malicious = "user@example.com'; DROP TABLE users; --"
        result = sanitize_email(malicious)
        # Email is sanitized (lowercase, stripped) but SQL injection
        # prevention is handled by SQLAlchemy's parameterized queries
        assert result == malicious.lower()
    
    def test_sql_injection_in_role(self):
        """Test that SQL injection in role is rejected."""
        malicious = "admin'; DROP TABLE users; --"
        result = sanitize_role(malicious)
        assert result is None  # Invalid role is rejected
