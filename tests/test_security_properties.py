"""
Property-based tests for security measures.

This module uses Hypothesis to test universal properties of security
measures across randomly generated inputs.

**Validates: Requirements 10.1, 10.4**

Properties tested:
- Property 19: CSRF token presence
- Property 20: Input sanitization
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import uuid
import re

from app import create_app
from app.models import db
from app.utils.sanitization import sanitize_string, sanitize_email, escape_html
from config import config as app_config


# Strategy for potentially malicious strings
malicious_strings = st.one_of(
    st.just("<script>alert('xss')</script>"),
    st.just("'; DROP TABLE users; --"),
    st.just("<img src=x onerror=alert('xss')>"),
    st.just("javascript:alert('xss')"),
    st.text(min_size=1, max_size=50).map(lambda x: f"<script>{x}</script>"),
    st.text(min_size=1, max_size=50).map(lambda x: f"'; {x}; --"),
)

# Strategy for normal strings
normal_strings = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N', 'P', 'Z')),
    min_size=1, 
    max_size=100
)


@pytest.fixture(scope='module')
def app():
    """Create a test Flask application."""
    app = create_app('testing')
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.drop_all()


class TestSecurityProperties:
    """Property-based tests for security measures."""
    
    def test_property_19_csrf_enabled_in_production_config(self):
        """
        Property 19: CSRF protection enabled in production
        
        CSRF protection should be enabled in production and development
        configurations to protect against cross-site request forgery attacks.
        
        **Validates: Requirements 10.1**
        """
        # Verify CSRF is enabled in production config
        assert app_config['production'].WTF_CSRF_ENABLED is True
        
        # Verify CSRF is enabled in development config
        assert app_config['development'].WTF_CSRF_ENABLED is True
        
        # Testing config may have CSRF disabled for easier testing
        # This is acceptable as long as production has it enabled
    
    def test_property_19_csrf_token_in_forms_with_csrf_enabled(self):
        """
        Property 19: CSRF token presence when CSRF is enabled
        
        When CSRF protection is enabled, forms should include CSRF tokens.
        
        **Validates: Requirements 10.1**
        """
        # Create app with development config (CSRF enabled)
        dev_app = create_app('development')
        
        with dev_app.app_context():
            db.create_all()
            
            with dev_app.test_client() as client:
                # Get login page
                response = client.get('/auth/login')
                assert response.status_code == 200
                
                response_data = response.data.decode('utf-8')
                
                # With CSRF enabled, the form should have a hidden CSRF token
                # Flask-WTF renders it as <input id="csrf_token" name="csrf_token" type="hidden" value="...">
                assert 'csrf_token' in response_data or 'type="hidden"' in response_data
            
            db.drop_all()
    
    @given(malicious_input=malicious_strings)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_20_input_sanitization_escape_html(self, malicious_input):
        """
        Property 20: Input sanitization (HTML escaping)
        
        For any user input containing potentially malicious content,
        the escape_html function should escape dangerous characters.
        
        **Validates: Requirements 10.4**
        """
        result = escape_html(malicious_input)
        
        # Script tags should be escaped
        assert '<script>' not in result
        assert '</script>' not in result
        
        # HTML special characters should be escaped
        if '<' in malicious_input:
            assert '&lt;' in result
        if '>' in malicious_input:
            assert '&gt;' in result
    
    @given(input_string=normal_strings)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_20_input_sanitization_string_length(self, input_string):
        """
        Property 20: Input sanitization (string length)
        
        For any user input, the sanitize_string function should
        limit the length to prevent buffer overflow attacks.
        
        **Validates: Requirements 10.4**
        """
        max_length = 50
        result = sanitize_string(input_string, max_length=max_length)
        
        # Result should never exceed max_length
        assert len(result) <= max_length
    
    @given(input_string=normal_strings)
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_20_input_sanitization_whitespace(self, input_string):
        """
        Property 20: Input sanitization (whitespace stripping)
        
        For any user input, the sanitize_string function should
        strip leading and trailing whitespace by default.
        
        **Validates: Requirements 10.4**
        """
        padded_input = f"  {input_string}  "
        result = sanitize_string(padded_input)
        
        # Result should not have leading/trailing whitespace
        assert result == result.strip()
    
    @given(email=st.emails())
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_20_email_sanitization_lowercase(self, email):
        """
        Property 20: Input sanitization (email normalization)
        
        For any email input, the sanitize_email function should
        normalize to lowercase.
        
        **Validates: Requirements 10.4**
        """
        result = sanitize_email(email)
        
        # Result should be lowercase
        assert result == result.lower()
    
    @given(xss_payload=st.sampled_from([
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
    ]))
    @settings(max_examples=10, deadline=2000, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_property_20_xss_prevention_escape_html_function(self, xss_payload):
        """
        Property 20: XSS prevention via escape_html function
        
        For any XSS payload, the escape_html function should
        properly escape the angle brackets that form HTML tags.
        
        **Validates: Requirements 10.4**
        """
        result = escape_html(xss_payload)
        
        # The escaped result should not contain raw HTML tags
        # (angle brackets should be escaped)
        assert '<script>' not in result
        assert '<img' not in result
        assert '<svg' not in result
        
        # Should contain escaped angle brackets
        assert '&lt;' in result
        assert '&gt;' in result
    
    def test_property_20_sql_injection_role_validation(self, app):
        """
        Property 20: SQL injection prevention via role validation
        
        SQL injection attempts in role field should be rejected
        by the sanitize_role function.
        
        **Validates: Requirements 10.4**
        """
        from app.utils.sanitization import sanitize_role
        
        sql_injections = [
            "admin'; DROP TABLE users; --",
            "user' OR '1'='1",
            "admin; DELETE FROM users;",
        ]
        
        for injection in sql_injections:
            result = sanitize_role(injection)
            # Invalid roles should return None
            assert result is None
