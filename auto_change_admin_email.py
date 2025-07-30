#!/usr/bin/env python3
"""
Auto Change Admin Email Script
Automatically changes admin email to kk9593742@gmail.com
"""

from app import app, db, User

def auto_change_admin_email():
    with app.app_context():
        admin_username = "admin"
        new_email = "kk9593742@gmail.com"
        
        # Find admin user
        admin_user = User.query.filter_by(username=admin_username).first()
        if not admin_user:
            print("❌ Admin user not found!")
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
            
            # Now update admin email
            admin_user.email = new_email
            db.session.commit()
            print("✅ Admin email updated successfully!")
            
        else:
            # Email is available, update admin user
            admin_user.email = new_email
            db.session.commit()
            print("✅ Admin email updated successfully!")
        
        print(f"   Username: {admin_user.username}")
        print(f"   New Email: {admin_user.email}")
        print(f"   Is Admin: {admin_user.is_admin}")
        return True

if __name__ == "__main__":
    print("📧 Auto Change Admin Email")
    print("=" * 50)
    auto_change_admin_email() 