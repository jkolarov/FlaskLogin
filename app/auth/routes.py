"""
Authentication routes for the Flask Auth Skeleton application.

This module provides routes for:
- User login (email/password)
- User registration
- User logout
- OAuth authentication

Requirements addressed:
- 1.x: User Registration
- 2.x: Email/Password Login
- 3.x: OAuth Authentication
- 4.x: User Logout
"""

from flask import render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from app.auth import auth_bp
from app.auth.forms import RegistrationForm, LoginForm
from app.auth.password import PasswordService
from app.models import db
from app.metrics import login_counter, registration_counter


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle email/password login.
    
    GET: Display login form
    POST: Process login credentials
    
    Requirements:
        - 2.1: WHEN a user submits valid credentials, THE Auth_Controller SHALL 
               create a Session and redirect to the dashboard
        - 2.2: WHEN a user submits invalid credentials, THE Auth_Controller SHALL 
               reject the login and display an error message
        - 2.3: WHEN a user submits credentials, THE Password_Hasher SHALL verify 
               the password against the stored hash
        - 2.4: WHEN a user is already logged in, THE System SHALL redirect them 
               to the dashboard instead of showing the login page
    
    Returns:
        GET: Rendered login form template
        POST (success): Redirect to dashboard
        POST (failure): Rendered login form with error message
    """
    # Import here to avoid circular imports
    from app.services.user_service import UserService
    
    # Redirect if already logged in (Requirement 2.4)
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # Get user by email
        user = UserService.get_user_by_email(form.email.data)
        
        # Check if user exists and has a password hash (not OAuth-only user)
        if user is None or user.password_hash is None:
            # Invalid credentials - user doesn't exist or is OAuth-only (Requirement 2.2)
            login_counter.labels(method='password', status='failure').inc()
            flash('Invalid email or password.', 'error')
            return render_template('auth/login.html', form=form)
        
        # Verify password against stored hash (Requirement 2.3)
        if not PasswordService.verify_password(form.password.data, user.password_hash):
            # Invalid credentials - password doesn't match (Requirement 2.2)
            login_counter.labels(method='password', status='failure').inc()
            flash('Invalid email or password.', 'error')
            return render_template('auth/login.html', form=form)
        
        # Create session with Flask-Login (Requirement 2.1)
        login_user(user, remember=form.remember_me.data)
        login_counter.labels(method='password', status='success').inc()
        
        # Redirect to dashboard (Requirement 2.1)
        flash('Login successful!', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('auth/login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user registration.
    
    GET: Display registration form
    POST: Process registration data
    
    Requirements:
        - 1.1: Create new User account with "User" role on valid submission
        - 1.2: Reject registration if email already exists
        - 1.4: Reject invalid email format with validation error
        - 1.5: Reject password shorter than 8 characters with validation error
        - 1.6: Redirect to login page with success message on successful registration
    
    Returns:
        GET: Rendered registration form template
        POST (success): Redirect to login page
        POST (failure): Rendered registration form with validation errors
    """
    # Import here to avoid circular imports
    from app.services.user_service import UserService
    
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check for duplicate email (Requirement 1.2)
        existing_user = UserService.get_user_by_email(form.email.data)
        if existing_user:
            form.email.errors.append('An account with this email already exists.')
            return render_template('auth/register.html', form=form)
        
        try:
            # Create user with UserService (Requirement 1.1)
            # UserService.create_user() assigns 'user' role by default
            UserService.create_user(
                email=form.email.data,
                password=form.password.data,
                role='user'
            )
            
            registration_counter.labels(status='success').inc()
            # Flash success message and redirect to login (Requirement 1.6)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except IntegrityError:
            # Handle duplicate email error gracefully (race condition)
            db.session.rollback()
            registration_counter.labels(status='failure').inc()
            form.email.errors.append('An account with this email already exists.')
        except ValueError as e:
            # Handle validation errors from UserService
            db.session.rollback()
            registration_counter.labels(status='failure').inc()
            flash(str(e), 'error')
    
    return render_template('auth/register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """
    Handle user logout.
    
    Destroys the user session and redirects to login page.
    
    Requirements:
        - 4.1: WHEN a user requests logout, THE System SHALL destroy the Session 
               and redirect to the login page
        - 4.2: WHEN a user logs out, THE System SHALL clear all session data
    
    Returns:
        Redirect to login page with logout confirmation message
    """
    # Destroy session with Flask-Login (Requirement 4.1)
    logout_user()
    
    # Clear all session data (Requirement 4.2)
    session.clear()
    
    # Flash confirmation message and redirect to login page (Requirement 4.1)
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/oauth/<provider>')
def oauth_login(provider: str):
    """
    Initiate OAuth flow for specified provider.
    
    Redirects the user to the OAuth provider's authorization page.
    
    Args:
        provider: OAuth provider name ('google', 'facebook', 'github')
    
    Requirements:
        - 3.1: WHEN a visitor initiates OAuth login, THE Auth_Controller SHALL 
               redirect to the selected OAuth_Provider
        - 3.5: WHEN an OAuth_Provider returns an error, THE System SHALL display 
               an appropriate error message
    
    Returns:
        Redirect to OAuth provider authorization page
        OR redirect to login with error message if provider is invalid/not configured
    """
    from app.auth.oauth import OAuthService
    
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    # Validate provider name (Requirement 3.5 - handle errors gracefully)
    if provider not in OAuthService.SUPPORTED_PROVIDERS:
        flash(f'Unsupported OAuth provider: {provider}', 'error')
        return redirect(url_for('auth.login'))
    
    # Check if provider is configured
    if not OAuthService.is_provider_configured(provider):
        flash(f'{provider.capitalize()} login is not configured.', 'error')
        return redirect(url_for('auth.login'))
    
    try:
        # Get the OAuth provider client
        oauth_client = OAuthService.get_provider(provider)
        
        # Build the callback URL
        redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
        
        # Redirect to OAuth provider (Requirement 3.1)
        return oauth_client.authorize_redirect(redirect_uri)
        
    except Exception as e:
        # Handle any errors during OAuth initiation (Requirement 3.5)
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))


@auth_bp.route('/oauth/<provider>/callback')
def oauth_callback(provider: str):
    """
    Handle OAuth callback from provider.
    
    Processes the OAuth callback, extracts user information, creates or updates
    the user account, links the OAuth account, and logs the user in.
    
    Args:
        provider: OAuth provider name ('google', 'facebook', 'github')
    
    Requirements:
        - 3.2: WHEN an OAuth_Provider returns a successful authentication, 
               THE System SHALL create or update the User account
        - 3.3: WHEN an OAuth_Provider returns user information, THE User_Repository 
               SHALL store the provider ID and link it to the user
        - 3.4: WHEN a user logs in via OAuth for the first time, THE System SHALL 
               assign the "User" role by default
        - 3.5: WHEN an OAuth_Provider returns an error, THE System SHALL display 
               an appropriate error message
        - 3.6: WHEN a user has both OAuth and email/password credentials, 
               THE System SHALL allow login via either method
    
    Returns:
        Redirect to dashboard on success
        OR redirect to login with error message on failure
    """
    from app.auth.oauth import OAuthService
    
    # Validate provider name (Requirement 3.5)
    if provider not in OAuthService.SUPPORTED_PROVIDERS:
        flash(f'Unsupported OAuth provider: {provider}', 'error')
        return redirect(url_for('auth.login'))
    
    # Check if provider is configured
    if not OAuthService.is_provider_configured(provider):
        flash(f'{provider.capitalize()} login is not configured.', 'error')
        return redirect(url_for('auth.login'))
    
    try:
        # Get the OAuth provider client
        oauth_client = OAuthService.get_provider(provider)
        
        # Exchange authorization code for access token
        token = oauth_client.authorize_access_token()
        
        if token is None:
            # OAuth provider returned an error (Requirement 3.5)
            flash('Authentication failed. Please try again.', 'error')
            return redirect(url_for('auth.login'))
        
        # Extract user information from provider response (Requirement 3.3)
        user_info = OAuthService.get_user_info_from_provider(provider, token)
        
        if not user_info.get('email'):
            # No email provided by OAuth provider (Requirement 3.5)
            flash('Could not retrieve email from OAuth provider. Please try again or use email/password login.', 'error')
            return redirect(url_for('auth.login'))
        
        # Create or update user from OAuth data (Requirements 3.2, 3.3, 3.4, 3.6)
        # This method handles:
        # - Creating new users with 'user' role (3.4)
        # - Linking OAuth accounts to existing users (3.3, 3.6)
        # - Returning existing users if OAuth account already linked (3.2)
        user = OAuthService.create_or_update_user(provider, user_info)
        
        # Log the user in with Flask-Login
        login_user(user)
        login_counter.labels(method=f'oauth_{provider}', status='success').inc()
        
        # Redirect to dashboard with success message
        flash(f'Successfully logged in with {provider.capitalize()}!', 'success')
        return redirect(url_for('main.dashboard'))
        
    except ValueError as e:
        # Handle validation errors (missing provider_user_id or email)
        login_counter.labels(method=f'oauth_{provider}', status='failure').inc()
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))
        
    except Exception as e:
        # Handle any other errors during OAuth callback (Requirement 3.5)
        login_counter.labels(method=f'oauth_{provider}', status='failure').inc()
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))
