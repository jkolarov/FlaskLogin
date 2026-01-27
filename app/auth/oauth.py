"""
OAuth service for managing OAuth authentication with Authlib.

This module provides the OAuthService class for configuring and managing
OAuth providers (Google, Facebook, GitHub) using Authlib.

Requirements addressed:
- 3.1: WHEN a visitor initiates OAuth login, THE Auth_Controller SHALL 
       redirect to the selected OAuth_Provider
- 3.2: WHEN an OAuth_Provider returns a successful authentication, 
       THE System SHALL create or update the User account
- 3.3: WHEN an OAuth_Provider returns user information, THE User_Repository 
       SHALL store the provider ID and link it to the user
- 3.4: WHEN a user logs in via OAuth for the first time, THE System SHALL 
       assign the "User" role by default
"""

from typing import Optional
from flask import Flask
from authlib.integrations.flask_client import OAuth, FlaskOAuth2App


# Global OAuth instance
oauth = OAuth()


def init_oauth(app: Flask) -> None:
    """
    Initialize OAuth with the Flask application and register providers.
    
    This function initializes the Authlib OAuth instance with the Flask app
    and registers all configured OAuth providers (Google, Facebook, GitHub).
    
    Args:
        app: Flask application instance
    
    Requirements:
        - 3.1: Configure OAuth providers for redirect capability
    """
    oauth.init_app(app)
    
    # Register Google OAuth client
    # Google uses OpenID Connect (OIDC) which provides userinfo endpoint
    oauth.register(
        name='google',
        client_id=app.config.get('GOOGLE_CLIENT_ID'),
        client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )
    
    # Register Facebook OAuth client
    oauth.register(
        name='facebook',
        client_id=app.config.get('FACEBOOK_CLIENT_ID'),
        client_secret=app.config.get('FACEBOOK_CLIENT_SECRET'),
        access_token_url='https://graph.facebook.com/oauth/access_token',
        authorize_url='https://www.facebook.com/dialog/oauth',
        api_base_url='https://graph.facebook.com/',
        client_kwargs={
            'scope': 'email public_profile'
        }
    )
    
    # Register GitHub OAuth client
    oauth.register(
        name='github',
        client_id=app.config.get('GITHUB_CLIENT_ID'),
        client_secret=app.config.get('GITHUB_CLIENT_SECRET'),
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={
            'scope': 'user:email'
        }
    )


class OAuthService:
    """
    Service for managing OAuth authentication.
    
    This class provides methods for:
    - Getting configured OAuth providers by name
    - Creating or updating users from OAuth data
    - Linking OAuth accounts to users
    
    The service uses Authlib's OAuth class for provider management.
    
    Attributes:
        SUPPORTED_PROVIDERS: List of supported OAuth provider names
    """
    
    SUPPORTED_PROVIDERS = ['google', 'github']
    
    @staticmethod
    def get_provider(name: str) -> Optional[FlaskOAuth2App]:
        """
        Get configured OAuth provider by name.
        
        Args:
            name: Provider name ('google', 'facebook', 'github')
        
        Returns:
            FlaskOAuth2App instance for the provider, or None if not found
        
        Raises:
            ValueError: If provider name is not supported
        
        Requirements:
            - 3.1: Provide access to OAuth providers for redirect
        
        Example:
            >>> provider = OAuthService.get_provider('google')
            >>> redirect_uri = url_for('auth.oauth_callback', provider='google', _external=True)
            >>> return provider.authorize_redirect(redirect_uri)
        """
        if name not in OAuthService.SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported OAuth provider: {name}. "
                           f"Supported providers: {', '.join(OAuthService.SUPPORTED_PROVIDERS)}")
        
        return getattr(oauth, name, None)
    
    @staticmethod
    def is_provider_configured(name: str) -> bool:
        """
        Check if an OAuth provider is properly configured with credentials.
        
        Args:
            name: Provider name ('google', 'facebook', 'github')
        
        Returns:
            True if the provider has client_id and client_secret configured,
            False otherwise
        
        Example:
            >>> if OAuthService.is_provider_configured('google'):
            ...     # Show Google login button
            ...     pass
        """
        from flask import current_app
        
        if name not in OAuthService.SUPPORTED_PROVIDERS:
            return False
        
        # Check the Flask app config directly for OAuth credentials
        config_key = f'{name.upper()}_CLIENT_ID'
        client_id = current_app.config.get(config_key)
        
        return (client_id is not None and 
                client_id != '' and 
                not client_id.startswith('your-'))
    
    @staticmethod
    def get_configured_providers() -> list[str]:
        """
        Get list of OAuth providers that are properly configured.
        
        Returns:
            List of provider names that have valid credentials configured
        
        Example:
            >>> providers = OAuthService.get_configured_providers()
            >>> # ['google', 'github']  # if only these are configured
        """
        return [
            provider for provider in OAuthService.SUPPORTED_PROVIDERS
            if OAuthService.is_provider_configured(provider)
        ]
    
    @staticmethod
    def get_user_info_from_provider(provider_name: str, token: dict) -> dict:
        """
        Extract user information from OAuth provider response.
        
        This method handles the different response formats from each provider
        and normalizes them into a consistent format.
        
        Args:
            provider_name: Name of the OAuth provider
            token: OAuth token response containing user info or access token
        
        Returns:
            Dictionary with normalized user info:
            - provider_user_id: Unique ID from the provider
            - email: User's email address
            - name: User's display name (optional)
        
        Requirements:
            - 3.3: Extract provider ID for linking to user
        
        Example:
            >>> token = provider.authorize_access_token()
            >>> user_info = OAuthService.get_user_info_from_provider('google', token)
            >>> # {'provider_user_id': '123', 'email': 'user@gmail.com', 'name': 'John'}
        """
        provider = OAuthService.get_provider(provider_name)
        
        if provider_name == 'google':
            # Google provides userinfo in the token response via OIDC
            userinfo = token.get('userinfo', {})
            if not userinfo:
                # Fallback: fetch from userinfo endpoint
                userinfo = provider.userinfo()
            
            return {
                'provider_user_id': userinfo.get('sub'),
                'email': userinfo.get('email'),
                'name': userinfo.get('name')
            }
        
        elif provider_name == 'facebook':
            # Facebook requires fetching user info from Graph API
            resp = provider.get('me?fields=id,email,name')
            user_data = resp.json()
            
            return {
                'provider_user_id': user_data.get('id'),
                'email': user_data.get('email'),
                'name': user_data.get('name')
            }
        
        elif provider_name == 'github':
            # GitHub requires fetching user info from API
            resp = provider.get('user')
            user_data = resp.json()
            
            # GitHub email might be private, need to fetch from emails endpoint
            email = user_data.get('email')
            if not email:
                emails_resp = provider.get('user/emails')
                emails = emails_resp.json()
                # Get primary email
                for email_obj in emails:
                    if email_obj.get('primary'):
                        email = email_obj.get('email')
                        break
            
            return {
                'provider_user_id': str(user_data.get('id')),
                'email': email,
                'name': user_data.get('name') or user_data.get('login')
            }
        
        raise ValueError(f"Unknown provider: {provider_name}")
    
    @staticmethod
    def create_or_update_user(provider: str, user_info: dict):
        """
        Create new user or update existing from OAuth data.
        
        This method handles the OAuth user creation/update flow:
        1. Check if OAuth account already exists (by provider + provider_user_id)
        2. If exists, return the linked user
        3. If not, check if user with same email exists
        4. If email exists, link OAuth account to existing user
        5. If no user exists, create new user with OAuth account
        
        Args:
            provider: OAuth provider name ('google', 'facebook', 'github')
            user_info: Dictionary with user info from get_user_info_from_provider()
                - provider_user_id: Unique ID from the provider
                - email: User's email address
                - name: User's display name (optional)
        
        Returns:
            User model instance (created or existing)
        
        Requirements:
            - 3.2: Create or update User account from OAuth data
            - 3.3: Store provider ID and link to user
            - 3.4: Assign "User" role by default for new users
        
        Example:
            >>> user_info = OAuthService.get_user_info_from_provider('google', token)
            >>> user = OAuthService.create_or_update_user('google', user_info)
            >>> login_user(user)
        """
        from app.models import db, User, OAuthAccount
        
        provider_user_id = user_info.get('provider_user_id')
        email = user_info.get('email')
        
        if not provider_user_id:
            raise ValueError("OAuth response missing provider_user_id")
        
        if not email:
            raise ValueError("OAuth response missing email")
        
        # Check if OAuth account already exists
        oauth_account = OAuthAccount.query.filter_by(
            provider=provider,
            provider_user_id=provider_user_id
        ).first()
        
        if oauth_account:
            # OAuth account exists, return linked user
            return oauth_account.user
        
        # Check if user with same email exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # User exists, link OAuth account to existing user
            oauth_account = OAuthAccount(
                user_id=user.id,
                provider=provider,
                provider_user_id=provider_user_id
            )
            db.session.add(oauth_account)
            db.session.commit()
            return user
        
        # Create new user with OAuth account (Requirement 3.4: default 'user' role)
        user = User(
            email=email,
            password_hash=None,  # OAuth-only user, no password
            role='user'
        )
        db.session.add(user)
        db.session.flush()  # Get user.id before creating OAuth account
        
        oauth_account = OAuthAccount(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id
        )
        db.session.add(oauth_account)
        db.session.commit()
        
        return user
