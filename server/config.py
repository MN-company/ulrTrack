import os
from dotenv import load_dotenv
from typing import Optional

# Load environment variables
basedir = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(basedir, '.env')

if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    # Fallback to parent directory
    parent_env = os.path.join(os.path.dirname(basedir), '.env')
    if os.path.exists(parent_env):
        load_dotenv(parent_env)
    else:
        load_dotenv()

class Config:
    """Application Configuration."""
    SECRET_KEY: str = os.getenv('SECRET_KEY', 'default_dev_secret')
    
    # Database
    db_path = os.path.join(basedir, 'instance', 'shortener.db')
    if not os.path.exists(os.path.dirname(db_path)):
        db_path = os.path.join(basedir, 'shortener.db')
        
    SQLALCHEMY_DATABASE_URI: str = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    
    # Security / Session
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    PERMANENT_SESSION_LIFETIME: int = 86400 # 24 hours in seconds
    WTF_CSRF_TIME_LIMIT: int = 86400 # Match session lifetime
    WTF_CSRF_SSL_STRICT: bool = False # Allow HTTP for dev/internal proxies
    
    # API Keys & Integrations
    API_KEY: str = os.getenv('API_KEY', 'changeme')
    SERVER_URL: str = os.getenv('SERVER_URL', 'http://127.0.0.1:8080')
    GEMINI_API_KEY: Optional[str] = os.getenv('GEMINI_API_KEY')
    
    TURNSTILE_SITE_KEY: str = os.getenv('TURNSTILE_SITE_KEY', '')
    TURNSTILE_SECRET_KEY: str = os.getenv('TURNSTILE_SECRET_KEY', '')
    
    # AI Configuration
    GEMINI_MODEL: str = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash')
    AI_PROMPT: str = os.getenv('AI_PROMPT', 'You are a cybersecurity expert analyzing user agents and device fingerprints.')
    
    # OSINT Tools
    HOLEHE_CMD: str = os.getenv('HOLEHE_CMD', 'holehe')
    WEBHOOK_URL: Optional[str] = os.getenv('WEBHOOK_URL')
