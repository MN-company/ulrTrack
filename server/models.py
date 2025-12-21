from . import db
from datetime import datetime
from flask_login import UserMixin

# V17/V18: Leads & Contacts
class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    notes = db.Column(db.Text)
    holehe_data = db.Column(db.Text) # JSON list of sites
    scan_status = db.Column(db.String(20), default='idle') # idle, pending, completed, failed
    last_scan = db.Column(db.DateTime, nullable=True)
    
    # V22: Contacts Overhaul
    tags = db.Column(db.String(256), default='') # Comma separate tags: "vip, suspect"
    custom_fields = db.Column(db.Text, default='{}') # JSON for extra data
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(20), unique=True, nullable=False)
    destination = db.Column(db.String(2048), nullable=False)
    
    # Security & Access
    password_hash = db.Column(db.String(128), nullable=True)
    enable_captcha = db.Column(db.Boolean, default=False)
    max_clicks = db.Column(db.Integer, nullable=True)
    expire_date = db.Column(db.DateTime, nullable=True)
    
    # Advanced Routing & Cloaking (V8)
    ios_url = db.Column(db.String(2048), nullable=True)
    android_url = db.Column(db.String(2048), nullable=True)
    safe_url = db.Column(db.String(2048), nullable=True) # Cloaking URL
    block_vpn = db.Column(db.Boolean, default=False)
    block_bots = db.Column(db.Boolean, default=True)
    allow_no_js = db.Column(db.Boolean, default=False)
    
    # V10: Smart Scheduling
    schedule_start_hour = db.Column(db.Integer, nullable=True) # 0-23
    schedule_end_hour = db.Column(db.Integer, nullable=True)   # 0-23
    schedule_timezone = db.Column(db.String(32), default='UTC')

    # V13: Advanced Filters
    block_adblock = db.Column(db.Boolean, default=False)
    allowed_countries = db.Column(db.String(50), nullable=True) # e.g. "IT,US"
    
    # V14: Parity Features
    public_masked_url = db.Column(db.String(512), nullable=True) # is.gd result
    max_clicks = db.Column(db.Integer, default=0)
    expiration_minutes = db.Column(db.Integer, default=0)
    
    # V16: Email Gate
    require_email = db.Column(db.Boolean, default=False)
    email_policy = db.Column(db.String(20), default='all') # all, certified, trackable
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visits = db.relationship('Visit', backref='link', lazy=True)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link_id = db.Column(db.Integer, db.ForeignKey('link.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    referrer = db.Column(db.String(500))
    is_suspicious = db.Column(db.Boolean, default=False)
    
    # Granular Tracking
    os_family = db.Column(db.String(64))
    device_type = db.Column(db.String(64))
    
    # Deep Tracking (Geo & ISP)
    isp = db.Column(db.String(128))
    org = db.Column(db.String(128)) # V28 Identity
    hostname = db.Column(db.String(256), nullable=True) # V29 Reverse DNS
    city = db.Column(db.String(64))
    country = db.Column(db.String(64))
    lat = db.Column(db.Float)
    lon = db.Column(db.Float)
    
    # Client-Side Beacon Data (V8/V9)
    screen_res = db.Column(db.String(32))
    timezone = db.Column(db.String(64))
    browser_bot = db.Column(db.Boolean, default=False)
    browser_language = db.Column(db.String(10)) # V9
    adblock = db.Column(db.Boolean, default=False) # V9
    # V15 AI Analysis
    ai_summary = db.Column(db.String(512), nullable=True) # "iPad Pro 12.9 (2022) - WiFi"
    
    # V16 Deep Fingerprinting & Data
    canvas_hash = db.Column(db.String(64), nullable=True)
    webgl_renderer = db.Column(db.String(256), nullable=True)
    email = db.Column(db.String(256), nullable=True)

    # V24 Pro Fingerprinting
    battery_level = db.Column(db.String(20), nullable=True)
    cpu_cores = db.Column(db.Integer, nullable=True)
    ram_gb = db.Column(db.Float, nullable=True)

    # V27 Zombie Cookie
    etag = db.Column(db.String(64), nullable=True)

# Auth User Model
class User(UserMixin):
    def __init__(self, id):
        self.id = id

    def get_id(self):
        return str(self.id)
