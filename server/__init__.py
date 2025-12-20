from flask import Flask
from .config import Config
from .extensions import db, login_manager, limiter
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
            conn.commit()
            conn.close()
        except Exception: pass
        
        db.create_all()

    # Register Blueprints
    from .routes import auth, dashboard, api, public
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(api.bp)
    # Catch-all MUST be last
    app.register_blueprint(public.bp)
    
    # Global Filters/Headers
    @app.after_request
    def remove_header(response):
        del response.headers['Server']
        return response

    # Start Worker
    start_worker(app)

    return app

# For legacy compatibility if someone runs 'python -m server'
app = create_app()
