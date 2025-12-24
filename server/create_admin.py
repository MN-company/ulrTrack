"""
Admin User Setup Script
Creates initial admin user for dashboard access.
Run this script once after deploying the application.
"""
import sys
import os

# Add parent directory to path
# Add parent directory to path to allow importing server package
# Correctly handles running from root or server/ dir
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Try relative import first (if package), then fallback to absolute
try:
    from server import create_app, db
    from server.models import User
except ImportError:
    # If we are running inside server/, we might need to adjust
    sys.path.insert(0, current_dir)
    from server import create_app, db
    from server.models import User
from werkzeug.security import generate_password_hash
import getpass

def create_admin():
    app = create_app()
    
    with app.app_context():
        # Check if admin already exists
        existing = User.query.filter_by(username='admin').first()
        if existing:
            print("⚠️  Admin user already exists!")
            overwrite = input("Do you want to reset the password? (yes/no): ")
            if overwrite.lower() != 'yes':
                print("❌ Setup cancelled.")
                return
            
            # Reset password
            print("\n🔐 Reset Admin Password")
            password = getpass.getpass("New password: ")
            password_confirm = getpass.getpass("Confirm password: ")
            
            if password != password_confirm:
                print("❌ Passwords do not match!")
                return
            
            existing.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            existing.totp_enabled = False  # Reset 2FA
            existing.totp_secret = None
            existing.passkey_credentials = None
            db.session.commit()
            print("✅ Admin password reset successfully!")
            print("   2FA has been disabled. You can re-enable it in Settings.")
        else:
            # Create new admin
            print("👤 Create Admin User")
            while True:
                password = getpass.getpass("Enter admin password (min 12 chars): ")
                if len(password) < 12:
                    print("❌ Password must be at least 12 characters long.")
                    continue
                break
                
            password_confirm = getpass.getpass("Confirm password: ")
            
            if password != password_confirm:
                print("❌ Passwords do not match!")
                return
            
            admin = User(
                username='admin',
                password_hash=generate_password_hash(password, method='pbkdf2:sha256')
            )
            
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created successfully!")
            print("   Username: admin")
            print("   You can enable 2FA in Settings after logging in.")

if __name__ == '__main__':
    create_admin()
