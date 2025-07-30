#!/usr/bin/env python3
"""
Fix Admin User Script
Updates admin user with proper credentials and admin status
"""

from app import app, db, User, validate_password_strength
from werkzeug.security import generate_password_hash

def fix_admin_user():
    with app.app_context():
        # Find admin user
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("❌ Admin user not found!")
            return False
        
        # Update admin user
        admin.email = "kk9593742@gmail.com"
        admin.password_hash = generate_password_hash("KIRCATCRACKER!@#$900k")
        admin.is_admin = True
        
        try:
            db.session.commit()
            print("✅ Admin user updated successfully!")
            print(f"   Username: {admin.username}")
            print(f"   Email: {admin.email}")
            print(f"   Password: KIRCATCRACKER!@#$900k")
            print(f"   Is Admin: {admin.is_admin}")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()
            return False

if __name__ == "__main__":
    print("🔧 Fixing Admin User...")
    fix_admin_user() 