from flask import Flask
from .config import Config
from .extensions import db, login_manager, limiter, csrf
from .worker import start_worker
import os
from datetime import timedelta # Added for SESSION_COOKIE_LIFETIME

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Security Headers & Session Hardening
    app.config.update(
        SESSION_COOKIE_SECURE=True,  # Requires HTTPS
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax', # Strict can break OAuth/external redirects, Lax is safer for general use
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
    )

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    limiter.init_app(app)
    csrf.init_app(app) # Enable CSRF Protection

    # V29: Markdown Support for AI
    @app.template_filter('markdown')
    def render_markdown(text):
        if not text: return ""
        try:
            import markdown
            return markdown.markdown(text)
        except ImportError:
            # Fallback: Simple line breaks if lib missing
            return text.replace('\n', '<br>')

    # Auto-Migrate (Production Fix)
    with app.app_context():
        import sqlite3
        try:
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            try: c.execute("ALTER TABLE lead ADD COLUMN scan_status VARCHAR(20) DEFAULT 'idle'")
            except: pass
            try: c.execute("ALTER TABLE lead ADD COLUMN last_scan DATETIME")
            except: pass
            
            # V22 Overhaul Migrations
            try: c.execute("ALTER TABLE lead ADD COLUMN tags VARCHAR(256) DEFAULT ''")
            except: pass
            try: c.execute("ALTER TABLE lead ADD COLUMN custom_fields TEXT DEFAULT '{}'")
            except: pass
            
            # V23 Email Policy
            try: c.execute("ALTER TABLE link ADD COLUMN email_policy VARCHAR(20) DEFAULT 'all'")
            except: pass
            
            # V24 Pro Fingerprinting
            try: c.execute("ALTER TABLE visit ADD COLUMN battery_level VARCHAR(20)")
            except: pass
            try: c.execute("ALTER TABLE visit ADD COLUMN cpu_cores INTEGER")
            except: pass
            try: c.execute("ALTER TABLE visit ADD COLUMN ram_gb REAL")
            except: pass
            
            # V27 ETag
            try: c.execute("ALTER TABLE visit ADD COLUMN etag VARCHAR(64)")
            except: pass
            
            # V45 Senior Fingerprinting
            try: c.execute("ALTER TABLE visit ADD COLUMN screen_res VARCHAR(32)")
            except: pass
            try: c.execute("ALTER TABLE visit ADD COLUMN timezone VARCHAR(64)")
            except: pass
            
            # V28 IP Identity
            try: c.execute("ALTER TABLE visit ADD COLUMN org VARCHAR(128)")
            except: pass
            
            # V29 Reverse DNS
            try: c.execute("ALTER TABLE visit ADD COLUMN hostname VARCHAR(256)")
            except: pass
            
            # V38 AI Architect (Custom Landing)
            try: c.execute("ALTER TABLE link ADD COLUMN custom_html TEXT")
            except: pass
            
            # V39 Session Detector
            try: c.execute("ALTER TABLE visit ADD COLUMN detected_sessions TEXT")
            except: pass
            
            conn.commit()
            conn.close()
        except Exception: pass # This catches errors in the sqlite3 operations
        
        # V39 Session Detector (Fingerprint.js Pro)
        try:
            from sqlalchemy import text
            db.session.execute(text("ALTER TABLE visit ADD COLUMN fpjs_confidence FLOAT"))
            db.session.commit()
            print("✅ Added Fingerprint.js Pro columns to Visit table")
        except Exception as e:
            pass  # Column already exists
    
    # V51: User table migration
    # V51: User table migration (Robust)
    with app.app_context():
        try:
            from .models import User
            db.create_all()  # Creates User table if it doesn't exist
            
            # Add missing columns for existing tables
            from sqlalchemy import text, inspect
            inspector = inspect(db.engine)
            if 'user' in inspector.get_table_names():
                columns = [c['name'] for c in inspector.get_columns('user')]
                with db.engine.connect() as conn:
                    if 'totp_secret' not in columns:
                        conn.execute(text("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)"))
                    if 'totp_enabled' not in columns:
                        conn.execute(text("ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0"))
                    if 'backup_codes' not in columns:
                        conn.execute(text("ALTER TABLE user ADD COLUMN backup_codes TEXT"))
                    if 'passkey_credentials' not in columns:
                        conn.execute(text("ALTER TABLE user ADD COLUMN passkey_credentials TEXT"))
                    conn.commit()
            print("✅ User table verified")
        except Exception as e:
            print(f"⚠️  User table migration error: {e}")
    
    # Register Blueprints
    from .routes import auth, api, public
    from .routes.dashboard import bp as dashboard_bp
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api.bp)
    # Catch-all MUST be last
    app.register_blueprint(public.bp)
    
    # Global Filters/Headers
    @app.after_request
    def add_security_headers(response):
        # Remove server fingerprint
        response.headers.pop('Server', None)
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self' https://challenges.cloudflare.com; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data: *; connect-src 'self'; frame-src https://challenges.cloudflare.com;"
        return response

    # Start Worker
    start_worker(app)

    return app

# For legacy compatibility if someone runs 'python -m server'
app = create_app()
