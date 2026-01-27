"""
Flask application factory.

This module provides the application factory pattern for creating and configuring
the Flask application instance. It initializes all extensions, registers blueprints,
and configures session management.

Requirements addressed:
- 10.1: THE System SHALL use CSRF protection on all forms
- 10.2: THE System SHALL store session data securely with a secret key
- 3.1: OAuth provider configuration for redirect capability
"""

from flask import Flask, request
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from prometheus_flask_exporter import PrometheusMetrics

from config import config
from app.models import db, User
from app.auth.oauth import init_oauth


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize Flask-WTF CSRF protection (Requirement 10.1)
csrf = CSRFProtect()

# Initialize Prometheus metrics with path labels
metrics = PrometheusMetrics.for_app_factory(default_labels={'app': 'flask-auth'})
metrics.info('flask_app_info', 'Flask Auth application info', version='1.0.0')


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """
    Load user by ID for Flask-Login session management.
    
    This callback is used by Flask-Login to reload the user object
    from the user ID stored in the session.
    
    Args:
        user_id: The user ID stored in the session (as string)
    
    Returns:
        User object if found, None otherwise
    """
    return User.query.get(int(user_id))


def create_app(config_name: str = 'development') -> Flask:
    """
    Create and configure the Flask application.
    
    This factory function creates a new Flask application instance with:
    - Configuration based on environment (development, production, testing)
    - SQLAlchemy database initialization
    - Flask-Login for session management
    - Flask-WTF for CSRF protection
    - Registered blueprints (auth, admin, main)
    
    Args:
        config_name: Configuration environment ('development', 'production', 'testing')
                    Defaults to 'development'.
    
    Returns:
        Configured Flask application instance
    
    Requirements:
        - 10.1: CSRF protection on all forms
        - 10.2: Secure session data with secret key
    
    Example:
        >>> app = create_app('development')
        >>> app.run()
    """
    # Create Flask application instance
    app = Flask(__name__)
    
    # Load configuration based on environment
    app.config.from_object(config.get(config_name, config['default']))
    
    # Apply ProxyFix middleware for reverse proxy support (Cloudflare Tunnel, nginx, etc.)
    # This ensures url_for(_external=True) generates correct URLs with proper scheme and host
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Call init_app if the config class has it (e.g., ProductionConfig)
    config_class = config.get(config_name, config['default'])
    if hasattr(config_class, 'init_app'):
        config_class.init_app(app)
    
    # Initialize SQLAlchemy with the app
    db.init_app(app)
    
    # Initialize Flask-Login for session management (Requirement 10.2)
    login_manager.init_app(app)
    
    # Initialize Flask-WTF CSRF protection (Requirement 10.1)
    csrf.init_app(app)
    
    # Initialize Prometheus metrics (exposes /metrics endpoint)
    metrics.init_app(app)
    
    # Track requests by IP address
    @app.before_request
    def track_ip():
        from app.metrics import requests_by_ip, unique_ips, seen_ips
        ip = request.remote_addr or 'unknown'
        requests_by_ip.labels(ip=ip).inc()
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.set(len(seen_ips))
    
    # Initialize OAuth providers (Requirement 3.1)
    init_oauth(app)
    
    # Register blueprints
    _register_blueprints(app)
    
    # Create database tables within app context
    with app.app_context():
        db.create_all()
    
    return app


def _register_blueprints(app: Flask) -> None:
    """
    Register all application blueprints.
    
    Blueprints provide modular organization of routes:
    - auth: Authentication routes (login, register, logout, OAuth)
    - admin: Administrative routes (user management)
    - main: Main application routes (dashboard, home)
    
    Args:
        app: Flask application instance
    """
    # Import blueprints
    from app.auth import auth_bp
    from app.admin import admin_bp
    from app.main import main_bp
    
    # Register blueprints with the application
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(main_bp)
