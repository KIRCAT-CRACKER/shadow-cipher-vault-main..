#!/usr/bin/env python3
"""
Update Admin Credentials Script
Updates admin user with new email and password
"""

from app import app, db, User, validate_password_strength
from werkzeug.security import generate_password_hash

def update_admin_credentials():
    with app.app_context():
        admin_username = "admin"
        new_email = "kk9593742@gmail.com"
        new_password = "KIRCATCRACKER!@#$900k"
        
        # Find admin user
        admin_user = User.query.filter_by(username=admin_username).first()
        if not admin_user:
            print("❌ Admin user not found!")
            return False
        
        # Validate password strength
        is_valid_password, password_error = validate_password_strength(new_password)
        if not is_valid_password:
            print(f"❌ Password validation failed: {password_error}")
            return False
        
        # Check if email is used by another user
        email_user = User.query.filter_by(email=new_email).first()
        
        if email_user and email_user.username != admin_username:
            print(f"⚠️  Email {new_email} is currently used by user '{email_user.username}'")
            
            # Automatically change the conflicting user's email
            new_email_for_user = f"{email_user.username}@shadowcipher.com"
            email_user.email = new_email_for_user
            db.session.commit()
            print(f"✅ Updated user '{email_user.username}' email to {new_email_for_user}")
        
        # Update admin user
        admin_user.email = new_email
        admin_user.password_hash = generate_password_hash(new_password)
        admin_user.is_admin = True
        
        db.session.commit()
        
        print("✅ Admin credentials updated successfully!")
        print(f"   Username: {admin_user.username}")
        print(f"   Email: {admin_user.email}")
        print(f"   Password: {new_password}")
        print(f"   Is Admin: {admin_user.is_admin}")
        return True

if __name__ == "__main__":
    print("🔐 Update Admin Credentials")
    print("=" * 50)
    update_admin_credentials() 