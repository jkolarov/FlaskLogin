#!/usr/bin/env python
"""
Database initialization script.

This script initializes the database schema and optionally seeds the initial
admin user. It can be run from the command line or imported as a module.

Usage:
    python scripts/init_db.py [--seed] [--reset]

Options:
    --seed   Seed the initial admin user from environment variables
    --reset  Drop all tables and recreate (WARNING: deletes all data)

Requirements addressed:
- 9.4: THE System SHALL initialize the database schema on first run
"""

import argparse
import os
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def create_minimal_app():
    """
    Create a minimal Flask app for database operations.
    
    This creates a Flask app with just enough configuration to perform
    database operations, without loading all blueprints and extensions.
    
    Returns:
        Flask application instance configured for database operations
    """
    from flask import Flask
    from app.models import db
    from config import config
    
    app = Flask(__name__)
    
    # Get configuration from environment or use development
    config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config.get(config_name, config['default']))
    
    # Initialize SQLAlchemy with the app
    db.init_app(app)
    
    return app


def main():
    """Main entry point for the database initialization script."""
    parser = argparse.ArgumentParser(
        description='Initialize the Flask Auth Skeleton database'
    )
    parser.add_argument(
        '--seed',
        action='store_true',
        help='Seed the initial admin user from environment variables'
    )
    parser.add_argument(
        '--reset',
        action='store_true',
        help='Drop all tables and recreate (WARNING: deletes all data)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Create the Flask app
    app = create_minimal_app()
    
    # Import database functions
    from app.database import init_db, seed_admin_user, reset_db
    
    if args.reset:
        if args.verbose:
            print('Resetting database (dropping all tables)...')
        reset_db(app)
        print('Database reset complete.')
    else:
        if args.verbose:
            print('Initializing database schema...')
        init_db(app)
        print('Database schema initialized.')
    
    if args.seed or args.reset:
        if args.verbose:
            admin_email = os.environ.get('ADMIN_EMAIL', 'not set')
            print(f'Seeding admin user: {admin_email}')
        
        admin_info = seed_admin_user(app)
        
        if admin_info:
            status = 'created' if admin_info['created'] else 'already exists'
            print(f"Admin user {status}: {admin_info['email']} (role: {admin_info['role']})")
        else:
            print('No admin user seeded (ADMIN_EMAIL or ADMIN_PASSWORD not set)')
    
    print('Done!')


if __name__ == '__main__':
    main()
