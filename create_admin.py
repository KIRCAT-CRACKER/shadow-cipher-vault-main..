#!/usr/bin/env python3
"""
Admin User Creation Script for Shadow Cipher Vault
Creates an admin user with the specified credentials
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, validate_password_strength
from werkzeug.security import generate_password_hash
import datetime

def create_admin_user():
    """Create admin user with specified credentials"""
    
    admin_username = "admin"
    admin_email = "kk9593742@gmail.com"
    admin_password = "KIRCATCRACKER!@#$900k"
    
    with app.app_context():
        # Check if admin user already exists
        existing_admin = User.query.filter_by(username=admin_username).first()
        if existing_admin:
            print(f"❌ Admin user '{admin_username}' already exists!")
            return False
        
        # Check if email already exists
        existing_email = User.query.filter_by(email=admin_email).first()
        if existing_email:
            print(f"❌ Email '{admin_email}' is already registered!")
            return False
        
        # Validate password strength
        is_valid_password, password_error = validate_password_strength(admin_password)
        if not is_valid_password:
            print(f"❌ Password validation failed: {password_error}")
            return False
        
        # Create admin user
        admin_user = User(
            username=admin_username,
            email=admin_email,
            password_hash=generate_password_hash(admin_password),
            is_admin=True,
            created_at=datetime.datetime.utcnow()
        )
        
        try:
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created successfully!")
            print(f"   Username: {admin_username}")
            print(f"   Email: {admin_email}")
            print(f"   Password: {admin_password}")
            print(f"   Admin Status: True")
            print(f"   Created: {admin_user.created_at}")
            return True
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            db.session.rollback()
            return False

def verify_admin_user():
    """Verify admin user exists and show details"""
    
    with app.app_context():
        admin_user = User.query.filter_by(username="admin").first()
        if admin_user:
            print("✅ Admin user found:")
            print(f"   Username: {admin_user.username}")
            print(f"   Email: {admin_user.email}")
            print(f"   Admin Status: {admin_user.is_admin}")
            print(f"   Created: {admin_user.created_at}")
            return True
        else:
            print("❌ Admin user not found!")
            return False

if __name__ == "__main__":
    print("🔐 Shadow Cipher Vault - Admin User Creation")
    print("=" * 50)
    
    # Create admin user
    success = create_admin_user()
    
    if success:
        print("\n" + "=" * 50)
        print("🔍 Verifying admin user...")
        verify_admin_user()
        
        print("\n" + "=" * 50)
        print("🎉 Setup complete! You can now:")
        print("   1. Run the app: python app.py")
        print("   2. Login as admin at: /admin-login")
        print("   3. Use the credentials above")
    else:
        print("\n❌ Admin user creation failed!")
        print("   Please check the error messages above.") 