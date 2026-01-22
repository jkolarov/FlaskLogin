"""
WTForms form classes for admin panel.

This module provides form classes for admin user management
with validation for role selection.

Requirements addressed:
- 6.2: WHEN an Admin changes a user's role, THE User_Repository SHALL update the role
- 10.4: THE System SHALL sanitize all user inputs to prevent injection attacks
"""

from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired, AnyOf


class EditUserRoleForm(FlaskForm):
    """
    Form for editing a user's role.
    
    Validates:
    - Role is provided
    - Role is one of the allowed values ('user' or 'admin')
    
    Using WTForms ensures:
    - CSRF protection via Flask-WTF
    - Input validation and sanitization
    - Consistent form handling
    
    Requirements:
        - 6.2: Update user role
        - 10.4: Sanitize user inputs
    """
    
    role = SelectField(
        'User Role',
        choices=[
            ('user', 'User - Standard access'),
            ('admin', 'Admin - Full access including user management')
        ],
        validators=[
            DataRequired(message='Please select a role.'),
            AnyOf(['user', 'admin'], message='Invalid role selected.')
        ]
    )
    
    submit = SubmitField('Save Changes')
