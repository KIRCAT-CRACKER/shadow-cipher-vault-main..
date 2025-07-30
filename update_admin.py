#!/usr/bin/env python3
"""
Admin User Update Script for Shadow Cipher Vault
Updates existing admin user with new credentials
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, validate_password_strength
from werkzeug.security import generate_password_hash
import datetime

def update_admin_user():
    """Update admin user with new credentials"""
    
    admin_username = "admin"
    admin_email = "kk9593742@gmail.com"
    admin_password = "KIRCATCRACKER!@#$900k"
    
    with app.app_context():
        # Find existing admin user
        admin_user = User.query.filter_by(username=admin_username).first()
        if not admin_user:
            print(f"❌ Admin user '{admin_username}' not found!")
            print("   Run create_admin.py first to create the admin user.")
            return False
        
        # Check if new email is already used by another user
        existing_email_user = User.query.filter_by(email=admin_email).first()
        if existing_email_user and existing_email_user.id != admin_user.id:
            print(f"❌ Email '{admin_email}' is already used by another user!")
            return False
        
        # Validate password strength
        is_valid_password, password_error = validate_password_strength(admin_password)
        if not is_valid_password:
            print(f"❌ Password validation failed: {password_error}")
            return False
        
        # Update admin user
        try:
            admin_user.email = admin_email
            admin_user.password_hash = generate_password_hash(admin_password)
            admin_user.is_admin = True
            
            db.session.commit()
            
            print("✅ Admin user updated successfully!")
            print(f"   Username: {admin_user.username}")
            print(f"   Email: {admin_user.email}")
            print(f"   Password: {admin_password}")
            print(f"   Admin Status: {admin_user.is_admin}")
            print(f"   Updated: {datetime.datetime.utcnow()}")
            return True
            
        except Exception as e:
            print(f"❌ Error updating admin user: {e}")
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
    print("🔐 Shadow Cipher Vault - Admin User Update")
    print("=" * 50)
    
    # Update admin user
    success = update_admin_user()
    
    if success:
        print("\n" + "=" * 50)
        print("🔍 Verifying admin user...")
        verify_admin_user()
        
        print("\n" + "=" * 50)
        print("🎉 Update complete! You can now:")
        print("   1. Run the app: python app.py")
        print("   2. Login as admin at: /admin-login")
        print("   3. Use the new credentials:")
        print(f"      Username: admin")
        print(f"      Email: kk9593742@gmail.com")
        print(f"      Password: KIRCATCRACKER!@#$900k")
    else:
        print("\n❌ Admin user update failed!")
        print("   Please check the error messages above.") 