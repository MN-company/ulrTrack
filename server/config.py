import os
from dotenv import load_dotenv

# Load .env from the server directory (where config.py lives)
basedir = os.path.abspath(os.path.dirname(__file__))
env_path = os.path.join(basedir, '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    # Try parent directory (ulrTrack/.env)
    parent_env = os.path.join(os.path.dirname(basedir), '.env')
    if os.path.exists(parent_env):
        load_dotenv(parent_env)
    else:
        load_dotenv()  # Fallback to default behavior

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_dev_secret')
    
    # Database path
    db_path = os.path.join(basedir, 'instance', 'shortener.db')
    if not os.path.exists(os.path.dirname(db_path)):
        db_path = os.path.join(basedir, 'shortener.db')
        
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Keys
    API_KEY = os.getenv('API_KEY', 'changeme')
    SERVER_URL = os.getenv('SERVER_URL', 'http://127.0.0.1:8080')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    TURNSTILE_SITE_KEY = os.getenv('TURNSTILE_SITE_KEY', '')
    TURNSTILE_SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY', '')
    
    # Default to a KNOWN WORKING model
    GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.0-flash')
    AI_PROMPT = os.getenv('AI_PROMPT', 'You are a cybersecurity expert analyzing user agents and device fingerprints.')
    HOLEHE_CMD = os.getenv('HOLEHE_CMD', 'holehe')
    WEBHOOK_URL = os.getenv('WEBHOOK_URL')
