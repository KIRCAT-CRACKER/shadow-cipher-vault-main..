#!/usr/bin/env python3
"""
List All Users Script
"""

from app import app, db, User

with app.app_context():
    users = User.query.all()
    print(f"📋 Found {len(users)} users:")
    print("=" * 50)
    
    for user in users:
        print(f"ID: {user.id}")
        print(f"Username: {user.username}")
        print(f"Email: {user.email}")
        print(f"Is Admin: {user.is_admin}")
        print(f"Created: {user.created_at}")
        print("-" * 30) 