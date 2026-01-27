#!/usr/bin/env python
"""Seed test users for demo purposes."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from flask import Flask
from app.models import db, User
from app.auth.password import PasswordService
from config import config

def create_app():
    app = Flask(__name__)
    config_name = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config.get(config_name, config['default']))
    db.init_app(app)
    return app

def seed_test_users():
    app = create_app()
    
    test_users = [
        {'email': 'admin@test.com', 'password': 'admin123', 'role': 'admin'},
        {'email': 'user@test.com', 'password': 'user123', 'role': 'user'},
    ]
    
    with app.app_context():
        for user_data in test_users:
            existing = User.query.filter_by(email=user_data['email']).first()
            if existing:
                print(f"User {user_data['email']} already exists, skipping")
                continue
            
            user = User(
                email=user_data['email'],
                password_hash=PasswordService.hash_password(user_data['password']),
                role=user_data['role']
            )
            db.session.add(user)
            print(f"Created {user_data['role']}: {user_data['email']}")
        
        db.session.commit()
        print("Done!")

if __name__ == '__main__':
    seed_test_users()
