import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_dev_secret')
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(basedir, 'instance', 'shortener.db')
    if not os.path.exists(os.path.dirname(db_path)):
        # Fallback for non-instance based deployments
        db_path = os.path.join(basedir, 'shortener.db')
        
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Keys
    API_KEY = os.getenv('API_KEY', 'changeme')
    SERVER_URL = os.getenv('SERVER_URL', 'http://127.0.0.1:8080')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    TURNSTILE_SITE_KEY = os.getenv('TURNSTILE_SITE_KEY', 'default_site_key')
    TURNSTILE_SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY') # Mandatory
    GEMINI_MODEL = os.getenv('gemini-3.0-flash-preview') # User requested SOTA
    AI_PROMPT = os.getenv('AI_PROMPT', 'You are a cybersecurity expert...')
    PROXYCHECK_API_KEY = os.getenv('PROXYCHECK_API_KEY', '')
    HOLEHE_CMD = os.getenv('HOLEHE_CMD', 'holehe')
