#!/usr/bin/env python3
"""
Final Admin Setup Script
Handles admin user setup with proper conflict resolution
"""

from app import app, db, User, validate_password_strength
from werkzeug.security import generate_password_hash

def setup_admin():
    with app.app_context():
        admin_username = "admin"
        admin_email = "kk9593742@gmail.com"
        admin_password = "KIRCATCRACKER!@#$900k"
        
        # Check if admin user exists
        admin_user = User.query.filter_by(username=admin_username).first()
        
        # Check if email is used by another user
        email_user = User.query.filter_by(email=admin_email).first()
        
        if email_user and email_user.username != admin_username:
            print(f"⚠️  Email {admin_email} is used by user '{email_user.username}'")
            print("   Updating admin user with current email...")
            # Keep admin's current email but update password and admin status
            if admin_user:
                admin_user.password_hash = generate_password_hash(admin_password)
                admin_user.is_admin = True
                db.session.commit()
                print("✅ Admin user updated successfully!")
                print(f"   Username: {admin_user.username}")
                print(f"   Email: {admin_user.email} (kept existing)")
                print(f"   Password: {admin_password}")
                print(f"   Is Admin: {admin_user.is_admin}")
                return True
        else:
            # Email is available, update admin user
            if admin_user:
                admin_user.email = admin_email
                admin_user.password_hash = generate_password_hash(admin_password)
                admin_user.is_admin = True
                db.session.commit()
                print("✅ Admin user updated successfully!")
                print(f"   Username: {admin_user.username}")
                print(f"   Email: {admin_user.email}")
                print(f"   Password: {admin_password}")
                print(f"   Is Admin: {admin_user.is_admin}")
                return True
        
        return False

if __name__ == "__main__":
    print("🔐 Final Admin Setup")
    print("=" * 50)
    setup_admin() 