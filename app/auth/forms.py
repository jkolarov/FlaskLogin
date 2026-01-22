"""
WTForms form classes for authentication.

This module provides form classes for user registration and login
with validation for email format and password requirements.

Requirements addressed:
- 1.4: WHEN a visitor submits an invalid email format, THE System SHALL reject the registration
- 1.5: WHEN a visitor submits a password shorter than 8 characters, THE System SHALL reject the registration
- 2.1: WHEN a user submits valid credentials, THE Auth_Controller SHALL create a Session
- 2.2: WHEN a user submits invalid credentials, THE Auth_Controller SHALL reject the login
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError


class LoginForm(FlaskForm):
    """
    Login form with email and password fields.
    
    Validates:
    - Email format (must be valid email)
    - Password is provided
    
    Note: Credential verification is done in the route handler using
    UserService and PasswordService.
    
    Requirements:
        - 2.1: Create session on valid credentials
        - 2.2: Reject login on invalid credentials
        - 2.3: Verify password against stored hash
    """
    
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required.'),
            Email(message='Please enter a valid email address.')
        ]
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.')
        ]
    )
    
    remember_me = BooleanField('Remember me')
    
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    """
    Registration form with email and password validation.
    
    Validates:
    - Email format (must be valid email)
    - Password length (minimum 8 characters)
    - Password confirmation (must match password)
    
    Note: Email uniqueness is validated in the route handler to avoid circular imports.
    
    Requirements:
        - 1.4: Reject invalid email format with validation error
        - 1.5: Reject password shorter than 8 characters with validation error
    """
    
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required.'),
            Email(message='Please enter a valid email address.')
        ]
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=8, message='Password must be at least 8 characters.')
        ]
    )
    
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password.'),
            EqualTo('password', message='Passwords must match.')
        ]
    )
    
    submit = SubmitField('Register')
