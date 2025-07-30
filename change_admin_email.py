#!/usr/bin/env python3
"""
Change Admin Email Script
Changes admin email to kk9593742@gmail.com
"""

from app import app, db, User

def change_admin_email():
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
            print("   Options:")
            print("   1. Delete the conflicting user")
            print("   2. Change the conflicting user's email")
            print("   3. Keep admin email as is")
            
            choice = input("   Enter your choice (1/2/3): ").strip()
            
            if choice == "1":
                # Delete the conflicting user
                db.session.delete(email_user)
                db.session.commit()
                print(f"✅ Deleted user '{email_user.username}'")
                
                # Now update admin email
                admin_user.email = new_email
                db.session.commit()
                print("✅ Admin email updated successfully!")
                
            elif choice == "2":
                # Change the conflicting user's email
                new_email_for_user = input(f"   Enter new email for user '{email_user.username}': ").strip()
                if new_email_for_user:
                    email_user.email = new_email_for_user
                    db.session.commit()
                    print(f"✅ Updated user '{email_user.username}' email to {new_email_for_user}")
                    
                    # Now update admin email
                    admin_user.email = new_email
                    db.session.commit()
                    print("✅ Admin email updated successfully!")
                else:
                    print("❌ No email provided, keeping admin email as is")
                    return False
                    
            else:
                print("❌ Keeping admin email as is")
                return False
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
    print("📧 Change Admin Email")
    print("=" * 50)
    change_admin_email() 