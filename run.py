#!/usr/bin/env python
"""
Application entry point for Flask Auth Skeleton.

This module provides:
- The `app` variable for Gunicorn/WSGI servers
- Flask CLI commands for database initialization
- Development server runner

Requirements addressed:
- 8.3: WHEN docker-compose up is executed, THE System SHALL start the application with all dependencies

Usage:
    Development server:
        $ python run.py
    
    With Gunicorn (production):
        $ gunicorn run:app
    
    Flask CLI commands:
        $ flask db-init      # Initialize database tables
        $ flask seed-admin   # Create initial admin user
"""

import os
import click
from app import create_app
from app.models import db, User
from app.auth.password import PasswordService


# Determine configuration from environment variable
config_name = os.environ.get('FLASK_ENV', 'development')

# Create the Flask application instance
# This is the entry point for Gunicorn: `gunicorn run:app`
app = create_app(config_name)


@app.cli.command('db-init')
def db_init():
    """Initialize the database tables.
    
    Creates all database tables defined in the SQLAlchemy models.
    Safe to run multiple times - will not overwrite existing data.
    
    Usage:
        $ flask db-init
    """
    with app.app_context():
        db.create_all()
        click.echo('Database tables created successfully.')


@app.cli.command('seed-admin')
@click.option('--email', default=None, help='Admin email address')
@click.option('--password', default=None, help='Admin password')
def seed_admin(email, password):
    """Create an initial admin user.
    
    Creates an admin user with the specified email and password.
    If no arguments provided, uses environment variables:
    - ADMIN_EMAIL (default: admin@example.com)
    - ADMIN_PASSWORD (default: changeme123)
    
    Usage:
        $ flask seed-admin
        $ flask seed-admin --email admin@mysite.com --password secretpass
    """
    # Get credentials from arguments or environment variables
    admin_email = email or os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    admin_password = password or os.environ.get('ADMIN_PASSWORD', 'changeme123')
    
    with app.app_context():
        # Check if admin user already exists
        existing_user = User.query.filter_by(email=admin_email).first()
        if existing_user:
            click.echo(f'User with email {admin_email} already exists.')
            if existing_user.role != 'admin':
                existing_user.role = 'admin'
                db.session.commit()
                click.echo(f'Updated user role to admin.')
            return
        
        # Create new admin user
        password_hash = PasswordService.hash_password(admin_password)
        admin_user = User(
            email=admin_email,
            password_hash=password_hash,
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        click.echo(f'Admin user created: {admin_email}')


@app.cli.command('list-users')
def list_users():
    """List all users in the database.
    
    Displays a table of all registered users with their ID, email, and role.
    
    Usage:
        $ flask list-users
    """
    with app.app_context():
        users = User.query.all()
        if not users:
            click.echo('No users found in the database.')
            return
        
        click.echo('\nRegistered Users:')
        click.echo('-' * 60)
        click.echo(f'{"ID":<6} {"Email":<35} {"Role":<10}')
        click.echo('-' * 60)
        for user in users:
            click.echo(f'{user.id:<6} {user.email:<35} {user.role:<10}')
        click.echo('-' * 60)
        click.echo(f'Total: {len(users)} user(s)')


if __name__ == '__main__':
    # Run the development server
    # Get host and port from environment variables with defaults
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    
    print(f'Starting Flask development server on {host}:{port}')
    print(f'Debug mode: {"enabled" if debug else "disabled"}')
    print('Press Ctrl+C to stop the server.')
    
    app.run(host=host, port=port, debug=debug)
