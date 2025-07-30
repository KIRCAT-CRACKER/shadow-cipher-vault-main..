#!/usr/bin/env python3
"""
Admin Credentials Display
Shows the admin login credentials
"""

from app import app, db, User

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print("🔐 SHADOW CIPHER VAULT - ADMIN CREDENTIALS")
        print("=" * 60)
        print("📍 Admin Login URL: http://localhost:5000/admin-login")
        print("=" * 60)
        print("📧 Login with Email: kk9593742@gmail.com")
        print("🔑 Password: KIRCATCRACKER!@#$900k")
        print("👑 Admin Status: True")
        print("=" * 60)
        print("🚀 To start the application:")
        print("   python app.py")
        print("=" * 60)
        print("✅ Admin user is ready to use!")
        print("💡 Note: Login now uses email instead of username")
    else:
        print("❌ Admin user not found!") 