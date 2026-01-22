"""
Input sanitization utilities for the Flask Auth Skeleton application.

This module provides functions for sanitizing user inputs to prevent injection attacks.
While Flask/Jinja2 provides auto-escaping for template output and SQLAlchemy uses
parameterized queries for database operations, this module provides additional
sanitization utilities for defense-in-depth.

Requirements addressed:
- 10.4: THE System SHALL sanitize all user inputs to prevent injection attacks

Security Layers:
1. WTForms validation - validates input format and constraints
2. SQLAlchemy parameterized queries - prevents SQL injection
3. Jinja2 auto-escaping - prevents XSS in template output
4. This module - provides additional sanitization utilities for defense-in-depth
"""

import re
from html import escape
from typing import Optional


def sanitize_string(value: Optional[str], max_length: int = 255, strip: bool = True) -> str:
    """
    Sanitize a string input by stripping whitespace and limiting length.
    
    This function provides basic string sanitization:
    - Strips leading/trailing whitespace (optional)
    - Limits string length to prevent buffer overflow attacks
    - Returns empty string for None values
    
    Note: HTML escaping is handled by Jinja2 auto-escaping in templates.
    SQL injection is prevented by SQLAlchemy's parameterized queries.
    
    Args:
        value: The input string to sanitize. Can be None.
        max_length: Maximum allowed length for the string. Defaults to 255.
        strip: Whether to strip leading/trailing whitespace. Defaults to True.
    
    Returns:
        Sanitized string, or empty string if input is None.
    
    Example:
        >>> sanitize_string("  hello world  ")
        'hello world'
        >>> sanitize_string(None)
        ''
        >>> sanitize_string("a" * 300, max_length=10)
        'aaaaaaaaaa'
    """
    if value is None:
        return ''
    
    # Convert to string if not already
    result = str(value)
    
    # Strip whitespace if requested
    if strip:
        result = result.strip()
    
    # Limit length
    if len(result) > max_length:
        result = result[:max_length]
    
    return result


def sanitize_email(email: Optional[str]) -> str:
    """
    Sanitize an email address input.
    
    This function normalizes email addresses by:
    - Converting to lowercase
    - Stripping whitespace
    - Limiting length to 255 characters
    
    Note: Email format validation should be done separately using WTForms
    Email validator or similar.
    
    Args:
        email: The email address to sanitize. Can be None.
    
    Returns:
        Sanitized email string, or empty string if input is None.
    
    Example:
        >>> sanitize_email("  User@Example.COM  ")
        'user@example.com'
        >>> sanitize_email(None)
        ''
    """
    if email is None:
        return ''
    
    # Sanitize as string first
    result = sanitize_string(email, max_length=255)
    
    # Normalize to lowercase
    result = result.lower()
    
    return result


def escape_html(value: Optional[str]) -> str:
    """
    Escape HTML special characters in a string.
    
    This function is provided for cases where manual HTML escaping is needed
    outside of Jinja2 templates. In most cases, Jinja2's auto-escaping should
    be used instead.
    
    Characters escaped:
    - & -> &amp;
    - < -> &lt;
    - > -> &gt;
    - " -> &quot;
    - ' -> &#x27;
    
    Args:
        value: The string to escape. Can be None.
    
    Returns:
        HTML-escaped string, or empty string if input is None.
    
    Example:
        >>> escape_html("<script>alert('xss')</script>")
        "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
    """
    if value is None:
        return ''
    
    return escape(str(value))


def is_safe_role(role: Optional[str]) -> bool:
    """
    Validate that a role value is one of the allowed roles.
    
    This function provides whitelist validation for role values to ensure
    only valid roles can be assigned to users.
    
    Args:
        role: The role value to validate. Can be None.
    
    Returns:
        True if the role is valid ('user' or 'admin'), False otherwise.
    
    Example:
        >>> is_safe_role('admin')
        True
        >>> is_safe_role('superuser')
        False
        >>> is_safe_role(None)
        False
    """
    if role is None:
        return False
    
    valid_roles = {'user', 'admin'}
    return sanitize_string(role).lower() in valid_roles


def sanitize_role(role: Optional[str]) -> Optional[str]:
    """
    Sanitize and validate a role value.
    
    This function sanitizes the role input and validates it against
    the whitelist of allowed roles.
    
    Args:
        role: The role value to sanitize. Can be None.
    
    Returns:
        Sanitized role string if valid, None if invalid or None input.
    
    Example:
        >>> sanitize_role("  ADMIN  ")
        'admin'
        >>> sanitize_role("superuser")
        None
        >>> sanitize_role(None)
        None
    """
    if role is None:
        return None
    
    sanitized = sanitize_string(role).lower()
    
    if is_safe_role(sanitized):
        return sanitized
    
    return None
