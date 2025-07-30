#!/usr/bin/env python3
"""
Check Admin User Status
"""

from app import app, db, User

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print("✅ Admin user found:")
        print(f"   Username: {admin.username}")
        print(f"   Email: {admin.email}")
        print(f"   Is Admin: {admin.is_admin}")
        print(f"   Created: {admin.created_at}")
    else:
        print("❌ Admin user not found!") 