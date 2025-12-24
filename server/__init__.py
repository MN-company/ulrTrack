from flask import Flask
from .config import Config
from .extensions import db, login_manager, limiter, csrf
from .worker import start_worker
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Init Extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    limiter.init_app(app)
    csrf.init_app(app)

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
        except Exception: pass
        
        db.create_all()

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
        response.headers['Content-Security-Policy'] = "default-src 'self' https://challenges.cloudflare.com; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: *; connect-src 'self'; frame-src https://challenges.cloudflare.com;"
        return response

    # Start Worker
    start_worker(app)

    return app

# For legacy compatibility if someone runs 'python -m server'
app = create_app()
