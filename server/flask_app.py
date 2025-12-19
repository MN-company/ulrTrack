from flask import Flask, request, redirect, render_template, abort, jsonify, make_response, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, event # WAL Support
from flask_limiter import Limiter
import csv
import io
import segno
import threading
import queue
import atexit
import atexit
import orjson # Fast JSON
# from google import genai -- Lazy loaded in worker to prevent Init errors
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pytz
from werkzeug.security import check_password_hash
from datetime import datetime
import os
import requests
import hashlib
from urllib.parse import urlparse
from dotenv import load_dotenv
from user_agents import parse

load_dotenv()

# --- Configuration ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'shortener.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# V15: Gemini AI Key
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
# New SDK uses Client instance, configured locally where needed.

# V11: Internal Firewall (Rate Limiting)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
    storage_uri="memory://"
)

# V12 Authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_dev_secret')
API_KEY = os.getenv('API_KEY', 'changeme')
SERVER_URL = os.getenv('SERVER_URL', 'http://127.0.0.1:8080')

TURNSTILE_SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY', '1x0000000000000000000000000000000AA')
TURNSTILE_SITE_KEY = os.getenv('TURNSTILE_SITE_KEY', '1x00000000000000000000AA')
PROXYCHECK_API_KEY = os.getenv('PROXYCHECK_API_KEY', '')

db = SQLAlchemy(app)

# V15: High Performance SQLite (WAL Mode) - DISABLED for PythonAnywhere (NFS I/O Error)
# from sqlalchemy.engine import Engine
# @event.listens_for(Engine, "connect")
# def set_sqlite_pragma(dbapi_connection, connection_record):
#     cursor = dbapi_connection.cursor()
#     cursor.execute("PRAGMA journal_mode=WAL")
#     cursor.execute("PRAGMA synchronous=NORMAL") # Faster writes
#     cursor.close()

# --- Models ---
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
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visits = db.relationship('Visit', backref='link', lazy=True)

# V17/V18: Leads & Contacts
class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    notes = db.Column(db.Text)
    holehe_data = db.Column(db.Text) # JSON list of sites
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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

# --- V15: Async Performance & AI ---

# 1. Async Task Queue (Fire & Forget)
log_queue = queue.Queue()

def worker():
    """Background worker to save visits and run AI analysis."""
    while True:
        task = log_queue.get()
        try:
            with app.app_context():
                if task['type'] == 'log_visit':
                    # Save Visit to DB
                    visit = Visit(**task['data'])
                    db.session.add(visit)
                    db.session.commit()
                    # If AI needed (Screen Res is missing initially, so maybe we wait for beacon?)
                    # Actually, we log the initial visit, then update it with Beacon.
                    print(f"ASYNC LOG: Visit Saved ID={visit.id}")
                
                elif task['type'] == 'ai_analyze':
                    # Run Gemini (New SDK)
                    v_id = task['visit_id']
                    ua = task['ua']
                    screen = task['screen']
                    visit = Visit.query.get(v_id)
                    if visit and GEMINI_API_KEY:
                        try:
                            # Lazy Import to handle environment issues gracefully
                            from google import genai
                            
                            client = genai.Client(api_key=GEMINI_API_KEY)
                            prompt = f"Identify the specific device model from UserAgent: '{ua}' and Screen Resolution: '{screen}'. Return ONLY the device name (e.g. 'Samsung Galaxy S23 Ultra'). If unsure, guess based on screen ratio. Keep it under 50 chars."
                            
                            response = client.models.generate_content(
                                model='gemini-1.5-flash',
                                contents=prompt
                            )
                            visit.ai_summary = response.text.strip()
                            db.session.commit()
                            print(f"AI ANALYSIS: {visit.ai_summary}")
                        except ImportError:
                            print("AI Error: google-genai library not found.")
                        except Exception as e:
                            print(f"AI Error: {e}")

        except Exception as e:
            print(f"Worker Error: {e}")
        finally:
            log_queue.task_done()

# Start Worker Thread
threading.Thread(target=worker, daemon=True).start()

# --- Helpers ---
def is_bot_ua(ua_string):
    """Simple heuristic to detect bots."""
    bots = [
        'bot', 'crawl', 'slurp', 'spider', 'curl', 'wget', 'facebook', 'whatsapp', 'telegram', 
        'expand', 'preview', 'peeker', 'twitter', 'discord', 'slack', 'go-http-client', 'python-requests'
    ]
    ua_lower = ua_string.lower()
    return any(bot in ua_lower for bot in bots)

def generate_slug(length=6):
    """Generates a random alphanumeric slug."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def shorten_with_isgd(url):
    """Shortens a URL using is.gd API for masking."""
    try:
        resp = requests.get(f"https://is.gd/create.php?format=simple&url={url}", timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception as e:
        print(f"is.gd Error: {e}")
    return None

def get_geo_data(ip):
    """Fetch ISP, Geo, AND Proxy/Hosting data from ip-api.com."""
    try:
        # Request specific fields: status, country, city, lat, lon, isp, proxy, hosting, mobile
        # fields=61439 (numeric bitmask) or comma-separated
        fields = "status,country,city,lat,lon,isp,proxy,hosting,mobile,query"
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields={fields}", timeout=1.5)
        data = resp.json()
        if data.get('status') == 'success':
            return data
    except:
        pass
    return {}

def verify_turnstile(token, ip):
    secret = os.getenv('TURNSTILE_SECRET_KEY')
    # Strict check: If secret missing, FAIL securely (or pass for dev? Let's say FAIL for safety)
    if not secret: 
        print("ERROR: TURNSTILE_SECRET_KEY missing in Verify.")
        return False
    
    try:
        resp = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={'secret': secret, 'response': token, 'remoteip': ip}
        )
        data = resp.json()
        if not data.get('success'):
            print(f"Turnstile Failed: {data.get('error-codes')}")
        return data.get('success', False)
    except Exception as e:
        print(f"Turnstile Connection Error: {e}")
        return False

# ... (Routes) ...

# V16 Performance: In-Memory Cache (Compensates for no WAL)
# Structure: {slug: {'link': LinkObject, 'timestamp': time}}
LINK_CACHE = {}
CACHE_TTL = 60 # seconds

@app.route('/<slug>', methods=['GET'])
def redirect_to_url(slug):
    # 1. Cache Lookup
    cached = LINK_CACHE.get(slug)
    link = None
    if cached and (datetime.utcnow().timestamp() - cached['timestamp'] < CACHE_TTL):
        link = cached['link']
        # Even with cache, we need the object attached to session? 
        # SQLAlchemy objects detached from session can be tricky.
        # Ideally we merge it back or just use the cached attributes.
        # But for 'visit.link_id', we just need ID.
    
    if not link:
        link = Link.query.filter_by(slug=slug).first_or_404()
        # Update Cache
        LINK_CACHE[slug] = {'link': link, 'timestamp': datetime.utcnow().timestamp()}

    # ... Proceed ...
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    ua_string = request.user_agent.string
    user_agent = parse(ua_string)
    
    geo = get_geo_data(client_ip)
    
    # Create Visit Record IMMEDIATELY (Log-First)
    visit = Visit(
        link_id=link.id,
        ip_address=client_ip,
        user_agent=ua_string,
        referrer=request.referrer,
        os_family=user_agent.os.family,
        device_type="Mobile" if user_agent.is_mobile else "Tablet" if user_agent.is_tablet else "Desktop",
        isp=geo.get('isp'),
        city=geo.get('city'),
        country=geo.get('country'),
        lat=geo.get('lat'),
        lon=geo.get('lon'),
        is_suspicious=False # Will update if blocked
    )
    db.session.add(visit)
    db.session.commit() # Commit to get ID for Beacon
    
    # --- 2. CHECKS & BLOCKING ---
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest

    # Expiration
    if link.expire_date and datetime.utcnow() > link.expire_date:
        visit.is_suspicious = True # Mark as "failed" in a sense? Or just blocked.
        # Maybe add a 'status' column later? For now, is_suspicious=True usually means blocked/bad.
        db.session.commit()
        return render_template('error.html', message="Link Expired"), 410

    # Max Clicks (re-query to include current one? No, current is just created)
    # Actually, we just added one. So count >= max + 1?
    # Let's keep heuristic: if PREVIOUS count was max.
    clicks = Visit.query.filter_by(link_id=link.id).count()
    if link.max_clicks and clicks > link.max_clicks:
        return render_template('error.html', message="Link Limit Reached"), 410

    # Regional Block
    if link.allowed_countries:
        allowed_list = [c.strip().upper() for c in link.allowed_countries.split(',')]
        current_country = geo.get('countryCode', 'XX').upper()
        if current_country not in allowed_list:
            visit.is_suspicious = True
            db.session.commit()
            if link.safe_url:
                final_dest = link.safe_url
            else:
                 return render_template('error.html', message="Access Denied (Region)"), 403

    # VPN/Bot Block
    is_vpn = False
    if link.block_vpn:
        if geo.get('proxy') or geo.get('hosting'):
             is_vpn = True
        elif geo.get('isp'):
            # Heuristic
            keywords = ['vpn', 'proxy', 'hosting', 'cloud', 'datacenter', 'tor']
            if any(k in geo['isp'].lower() for k in keywords):
                is_vpn = True
    
    if link.block_bots and is_bot_ua(ua_string):
        is_vpn = True # Treat as suspicious
        
    if is_vpn:
        visit.is_suspicious = True
        db.session.commit()
        if link.safe_url:
             final_dest = link.safe_url
        else:
             return render_template('error.html', message="Suspicious Traffic Detected"), 403

    # --- 3. GATES (Modular & Independent) ---
    
    # 3.1 Password Gate
    if link.password_hash:
        auth_cookie = request.cookies.get(f"auth_pass_{slug}")
        # Validate hash (Salted with Secret)
        expected_pass_hash = hashlib.sha256(f"{link.password_hash}{app.config['SECRET_KEY']}".encode()).hexdigest()
        if auth_cookie != expected_pass_hash:
            return render_template('password.html', slug=slug, visit_id=visit.id, site_key=TURNSTILE_SITE_KEY, hide_nav=True)

    # 3.2 Email Gate
    if link.require_email:
        email_cookie = request.cookies.get(f"auth_email_{slug}")
        if not email_cookie:
            # Email Gate uses Turnstile, so it implicitly covers "Human Verification" too.
            return render_template('email_gate.html', slug=slug, visit_id=visit.id, site_key=TURNSTILE_SITE_KEY, hide_nav=True)

    # 3.3 Captcha Gate
    # Only runs if Captcha is enabled AND NOT already satisfied by Email/Password flow (if desired).
    # Logic: If Email Gate was ON, and we passed 3.2, user is verified.
    # However, to be extra modular, we check a specific 'auth_captcha' cookie.
    # To fix "Double Captcha": verify_email route MUST set this cookie too.
    if link.enable_captcha:
        captcha_cookie = request.cookies.get(f"auth_captcha_{slug}")
        expected_captcha_hash = hashlib.sha256(f"captcha_ok_{slug}{app.config['SECRET_KEY']}".encode()).hexdigest()
        
        # Optimization: If email verified (which requires Turnstile), we consider Captcha satisfied.
        # This is fail-safe: if verify_email set the cookie, this check attempts to read it.
        if captcha_cookie != expected_captcha_hash:
             return render_template('captcha.html', slug=slug, visit_id=visit.id, site_key=TURNSTILE_SITE_KEY, hide_nav=True)

    # --- 4. SUCCESS ---
    return render_template('loading.html', destination=final_dest, visit_id=visit.id, allow_no_js=link.allow_no_js, hide_nav=True)

@app.route('/verify_password', methods=['POST'])
def verify_password():
    slug = request.form.get('slug')
    pwd = request.form.get('password')
    visit_id = request.form.get('visit_id')
    
    link = Link.query.filter_by(slug=slug).first()
    if not link or not link.password_hash:
        return redirect(f"/{slug}")
        
    if hashlib.sha256(pwd.encode()).hexdigest() == link.password_hash:
        resp = make_response(redirect(f"/{slug}"))
        # Set Pass Cookie
        h = hashlib.sha256(f"{link.password_hash}{app.config['SECRET_KEY']}".encode()).hexdigest()
        resp.set_cookie(f"auth_pass_{slug}", h, max_age=86400)
        return resp
    else:
        return render_template('password.html', slug=slug, error="Incorrect Password", visit_id=visit_id, hide_nav=True)

@app.route('/verify_captcha', methods=['POST'])
def verify_captcha():
    slug = request.form.get('slug')
    visit_id = request.form.get('visit_id')
    turnstile_token = request.form.get('cf-turnstile-response')
    
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    if verify_turnstile(turnstile_token, ip):
        resp = make_response(redirect(f"/{slug}"))
        h = hashlib.sha256(f"captcha_ok_{slug}{app.config['SECRET_KEY']}".encode()).hexdigest()
        resp.set_cookie(f"auth_captcha_{slug}", h, max_age=86400*30)
        return resp
    else:
        return render_template('captcha.html', slug=slug, error="Verification Failed", site_key=TURNSTILE_SITE_KEY, visit_id=visit_id, hide_nav=True)

@app.route('/verify_email', methods=['POST'])
def verify_email_route():
    slug = request.form.get('slug')
    email = request.form.get('email')
    turnstile_token = request.form.get('cf-turnstile-response')
    visit_id = request.form.get('visit_id')
    
    # 1. Turnstile Check
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    if not verify_turnstile(turnstile_token, ip):
         return render_template('email_gate.html', slug=slug, error="Captcha Failed", site_key=TURNSTILE_SITE_KEY, visit_id=visit_id, hide_nav=True), 400

    # 2. Email Validation
    import re
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
         return render_template('email_gate.html', slug=slug, error="Invalid Email", site_key=TURNSTILE_SITE_KEY, visit_id=visit_id, hide_nav=True), 400
         
    # 3. Save Email to Visit AND Lead
    if visit_id:
        visit = Visit.query.get(visit_id)
        if visit:
            visit.email = email
            db.session.commit()
    
    # Check/Create Lead
    lead = Lead.query.filter_by(email=email).first()
    if not lead:
        lead = Lead(email=email)
        db.session.add(lead)
        db.session.commit()
            
    # 4. Set Cookies & Redirect
    resp = make_response(redirect(f"/{slug}"))
    
    # A. Set Email Cookie
    resp.set_cookie(f"auth_email_{slug}", "verified", max_age=86400*30) 
    
    # B. Set Captcha Cookie (Prevent Double Captcha)
    captcha_hash = hashlib.sha256(f"captcha_ok_{slug}{app.config['SECRET_KEY']}".encode()).hexdigest()
    resp.set_cookie(f"auth_captcha_{slug}", captcha_hash, max_age=86400*30)
    
    return resp

# --- V17 NEW: CONTACTS MANAGER ---
@app.route('/dashboard/contacts', methods=['GET', 'POST'])
@login_required
def dashboard_contacts():
    # Handle Manual Lead Addition
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        notes = request.form.get('notes')
        
        if email:
            existing = Lead.query.filter_by(email=email).first()
            if not existing:
                new_lead = Lead(email=email, name=name, notes=notes)
                db.session.add(new_lead)
                db.session.commit()
                flash(f'Lead {email} added.', 'success')
            else:
                 flash('Lead already exists.', 'warning')
        return redirect('/dashboard/contacts')

    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    return render_template('contacts.html', leads=leads)

@app.route('/dashboard/lead/<int:lead_id>', methods=['GET', 'POST'])
@login_required
def lead_profile(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    
    if request.method == 'POST':
        lead.name = request.form.get('name')
        lead.notes = request.form.get('notes')
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(f'/dashboard/lead/{lead_id}')
        
    # Prepare Data for Graph
    import json
    holehe_list = []
    if lead.holehe_data:
        try:
            holehe_list = json.loads(lead.holehe_data)
        except: pass
        
    # Get Devices from Visits
    visits = Visit.query.filter_by(email=lead.email).all()
    devices = set()
    for v in visits:
        if v.ai_summary: devices.add(v.ai_summary)
        # Maybe add generic UA if AI missing, or WebGL renderer
        if v.webgl_renderer and v.webgl_renderer != "Unknown": devices.add(v.webgl_renderer)
        
    return render_template('profile.html', lead=lead, holehe_list=holehe_list, devices=list(devices))

@app.route('/dashboard/analyze_email', methods=['POST'])
@login_required
def analyze_email():
    email = request.form.get('email')
    if not email: return jsonify({'error': 'No email provided'}), 400
    
    # REAL HOLEHE EXECUTION
    # This is slow (5-10s), so ideally strictly async, but for V18 request we run it.
    import subprocess
    import json
    
    cmd = os.getenv('HOLEHE_CMD', 'holehe')
    
    try:
        # Run holehe --only-used --no-color <email>
        # Ensure it's in path or venv
        if cmd == 'holehe':
            # Try to find in venv if default
            venv_holehe = os.path.join(os.path.dirname(__file__), '..', 'venv', 'bin', 'holehe')
            if os.path.exists(venv_holehe):
                cmd = venv_holehe
                
        print(f"Running OSINT: {cmd} {email}")
        result = subprocess.run([cmd, email, '--only-used', '--no-color'], capture_output=True, text=True, timeout=30)
        
        # Parse Output
        output = result.stdout
        found_sites = []
        for line in output.split('\n'):
            if '[+]' in line:
                # Example: [x] Instagram
                site = line.split(']')[1].strip()
                found_sites.append(site)
        
        # Update Lead
        lead = Lead.query.filter_by(email=email).first()
        if not lead:
            lead = Lead(email=email)
            db.session.add(lead)
            
        lead.holehe_data = json.dumps(found_sites)
        db.session.commit()
        
        return jsonify({
            'email': email,
            'found': found_sites,
            'raw': output[:500]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    try:
        # Programmatic Holehe (Simulated for safety/speed in this context, or wrapper)
        # Real holehe library usage often prints to stdout or returns complex objects.
        # For this implementation, we'll try to use the library if importable, else mock.
        import holehe.core as holehe_core
        
        # Holehe is slow. Ideally async. For now, strict check on limited sites.
        out = []
        # Create a customized list of modules to check (fastest ones)
        # This is a placeholder for the actual library integration logic which varies by version.
        # We will assume a 'check_email' function wrapper exists or we construct one.
        
        # Simulating output for stability if library fails or is too slow for sync request
        # In production, this MUST be a Celery task.
        return jsonify({# Mock for immediate feedback
            'email': email,
            'summary': f"Analysis started for {email}. (Async implementation pending for speed)",
            'found': ['Instagram', 'Twitter', 'Spotify'] # Example
        })
    except ImportError:
        return jsonify({'error': 'Holehe library not installed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/beacon', methods=['POST'])
def receive_beacon():
    """Receives client-side metrics via navigator.sendBeacon and updates the Visit record."""
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            v_id = data.get('visit_id')
            if v_id:
                visit = Visit.query.get(v_id)
                if visit:
                    visit.screen_res = data.get('screen', 'Unknown')
                    visit.timezone = data.get('timezone', 'Unknown')
                    visit.browser_bot = bool(data.get('webdriver', False))
                    visit.browser_language = data.get('language', 'Unknown') # V9
                    visit.adblock = bool(data.get('adblock', False)) # V9
                    
                    # V16 Deep Fingerprinting
                    visit.canvas_hash = data.get('canvas_hash')
                    visit.webgl_renderer = data.get('webgl_renderer')

                    db.session.commit()
                    
                    # V15: Fire AI Detective (Async)
                    log_queue.put({
                        'type': 'ai_analyze',
                        'visit_id': visit.id,
                        'ua': visit.user_agent,
                        'screen': visit.screen_res
                    })
                    # print(f"BEACON SAVED & AI TRIGGERED") # Debug
    except Exception as e:
        print(f"Beacon Error: {e}")
    return "OK", 200

@app.route('/verify_password', methods=['POST'])
def verify_password_route():
    slug = request.form.get('slug')
    password = request.form.get('password')
    turnstile_token = request.form.get('cf-turnstile-response')
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)

    link = Link.query.filter_by(slug=slug).first_or_404()

    # Verify Turnstile
    if not verify_turnstile(turnstile_token, client_ip):
         return render_template('password.html', slug=slug, site_key=TURNSTILE_SITE_KEY, error="Captcha Failed"), 400

    # Verify Password
    users_hash = hashlib.sha256(password.encode()).hexdigest()
    if users_hash == link.password_hash:
        # Set Cookie
        auth_val = hashlib.sha256(f"{link.password_hash}{app.config['SECRET_KEY']}".encode()).hexdigest()
        resp = make_response(redirect(f"/{slug}"))
        resp.set_cookie(f"auth_{slug}", auth_val, max_age=3600) # 1 hour session
        return resp
    else:
        return render_template('password.html', slug=slug, site_key=TURNSTILE_SITE_KEY, error="Invalid Password"), 401

@app.route('/verify_captcha', methods=['POST'])
def verify_captcha_route():
    slug = request.form.get('slug')
    turnstile_token = request.form.get('cf-turnstile-response')
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    
    link = Link.query.filter_by(slug=slug).first_or_404()

    if verify_turnstile(turnstile_token, client_ip):
        auth_val = hashlib.sha256(f"captcha_ok_{slug}{app.config['SECRET_KEY']}".encode()).hexdigest()
        resp = make_response(redirect(f"/{slug}"))
        resp.set_cookie(f"auth_{slug}", auth_val, max_age=3600)
        return resp
    else:
        return render_template('captcha.html', slug=slug, site_key=TURNSTILE_SITE_KEY, error="Verification Failed"), 400

# --- API ---

@app.route('/api/create', methods=['POST'])
@limiter.limit("10 per minute") # Strict Limit for creations
def create_link():
    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    slug = data.get('slug')
    # Generate random slug if missing (basic)
    if not slug:
        slug = generate_slug()
        
    if Link.query.filter_by(slug=slug).first():
        return jsonify({"error": "Slug taken"}), 400

    # 1. Protocol Prepend
    dest = data.get('destination')
    if dest and not (dest.startswith('http://') or dest.startswith('https://')):
        dest = 'https://' + dest

    # 2. Expiration Logic
    from datetime import timedelta
    expire_date = None
    if data.get('expiration_minutes'):
        try:
            minutes = int(data.get('expiration_minutes'))
            expire_date = datetime.utcnow() + timedelta(minutes=minutes)
        except ValueError:
            pass # Ignore invalid int

    pwd_hash = None
    if data.get('password'):
        pwd_hash = hashlib.sha256(data.get('password').encode()).hexdigest()

    new_link = Link(
        slug=slug,
        destination=dest,
        password_hash=pwd_hash,
        enable_captcha=data.get('enable_captcha', False),
        max_clicks=data.get('max_clicks'),
        expire_date=expire_date,
        
        # V8 New Fields
        ios_url=data.get('ios_url'),
        android_url=data.get('android_url'),
        safe_url=data.get('safe_url'),
        block_vpn=data.get('block_vpn', False), # Explicit opt-in
        block_bots=data.get('block_bots', True), # Default BLOCK
        allow_no_js=data.get('allow_no_js', False), # V9
        schedule_start_hour=data.get('schedule_start_hour'), # V10
        schedule_end_hour=data.get('schedule_end_hour'),     # V10
        schedule_timezone=data.get('schedule_timezone', 'UTC')
    )
    db.session.add(new_link)
    db.session.commit()
    
    return jsonify({"slug": slug, "url": request.host_url + slug})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    import csv
    import io
    
    target_slug = request.args.get('slug')
    query = Visit.query
    
    if target_slug:
        link = Link.query.filter_by(slug=target_slug).first()
        if not link: return "Link not found", 404
        query = query.filter_by(link_id=link.id)
        
    visits = query.all()
    
    # CSV Generation
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp', 'Slug', 'IP', 'User-Agent', 'Referrer', 'Suspicious', 'OS', 'Device', 'ISP', 'City', 'Country'])
    
    for v in visits:
        cw.writerow([
            v.timestamp, 
            v.link.slug, 
            v.ip_address, 
            v.user_agent, 
            v.referrer, 
            v.is_suspicious,
            v.os_family,
            v.device_type,
            v.isp,
            v.city,
            v.country
        ])
        
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=stats.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/api/links', methods=['GET'])
def list_links():
    """Returns a list of all links (slug, destination) for CLI selection."""
    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    links = Link.query.with_entities(Link.slug, Link.destination).all()
    # Return list of strings "slug (destination)" or dicts? Dicts are cleaner.
    return jsonify([{"slug": l.slug, "destination": l.destination} for l in links])

@app.route('/api/links/<slug>', methods=['DELETE', 'PATCH'])
def manage_link(slug):
    # V14: Expiration & Max Clicks Logic
    # This logic should ideally be in the main redirect route, but if we want to prevent API modification
    # of expired links, it can be here. For now, assuming API can modify expired links.
    # The provided snippet seems to be misplaced for this API route.
    # I will insert the V14/V11 logic as requested, but note its context might be more suitable elsewhere.
    # The snippet also includes an API key check which is already present. I will avoid duplication.

    # V14: Expiration & Max Clicks Logic (from snippet, adjusted for context)
    # This part of the snippet seems to be intended for the main redirect logic, not API management.
    # However, following the instruction to insert it here.
    # Note: 'link' is not yet defined at this point, it's defined after the API key check.
    # To make it syntactically correct, I'll move the 'link' query up.
    
    link = Link.query.filter_by(slug=slug).first_or_404() # Moved this line up

    if link.max_clicks is not None and link.max_clicks > 0 and len(link.visits) >= link.max_clicks:
         # In an API context, returning an error template is unusual.
         # Assuming the instruction implies this logic should be present, even if the return type is odd for API.
         return jsonify({"error": "Link Expired (Max Clicks)"}), 410
         
    if link.expire_date is not None and datetime.utcnow() > link.expire_date:
         # Similar to above, unusual return for API.
         return jsonify({"error": "Link Expired (Time)"}), 410

    # V11: Bot Blocking (User-Agent) - This is also typically for the redirect route.
    # ua = request.headers.get('User-Agent', '') # Not directly used in this API route for blocking.

    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == 'DELETE':
        # Delete visits first? (Cascade usually handles this or explicit delete)
        Visit.query.filter_by(link_id=link.id).delete()
        db.session.delete(link)
        db.session.commit()
        return jsonify({"message": "Deleted"})

    if request.method == 'PATCH':
        data = request.json
        if 'destination' in data:
            link.destination = data['destination']
        if 'max_clicks' in data:
            link.max_clicks = data['max_clicks']
        if 'password' in data:
             if data['password']:
                link.password_hash = hashlib.sha256(data['password'].encode()).hexdigest()
             else:
                link.password_hash = None # Remove password
        
        db.session.commit()
        return jsonify({"message": "Updated"})

# Initialize DB immediately (for WSGI/PythonAnywhere)
with app.app_context():
    db.create_all()

# --- V12 Dashboard & Auth Routes ---

class User(UserMixin):
    def __init__(self, id):
        self.id = id

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return User("admin")
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    if request.method == 'POST':
        key = request.form.get('api_key')
        if key == API_KEY:
            # Optional: Add Turnstile verification here if strict
            user = User("admin")
            login_user(user)
            return redirect('/dashboard')
        else:
            flash('Access Denied: Invalid Key', 'error')
    return render_template('login.html', site_key=TURNSTILE_SITE_KEY)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/dashboard')
@login_required
def dashboard():
    links = Link.query.order_by(Link.created_at.desc()).all()
    total_clicks = Visit.query.count()
    total_blocked = Visit.query.filter_by(is_suspicious=True).count()
    
    return render_template('dashboard.html', 
                          links=links, 
                          total_links=len(links), 
                          total_clicks=total_clicks,
                          total_blocked=total_blocked,
                          server_url=SERVER_URL)

@app.route('/dashboard/create', methods=['POST'])
@login_required
def dashboard_create():
    dest = request.form.get('destination')
    slug = request.form.get('slug')
    block_bots = request.form.get('block_bots') == 'true'
    block_vpn = request.form.get('block_vpn') == 'true'
    
    if not dest:
        flash('Destination required', 'error')
        return redirect('/dashboard')

    if not slug:
        slug = generate_slug()
    
    # Check collission
    if Link.query.filter_by(slug=slug).first():
        flash('Slug exists', 'error')
        return redirect('/dashboard')

    new_link = Link(
        destination=dest, 
        slug=slug, 
        block_bots=block_bots, 
        block_vpn=block_vpn,
        enable_captcha=request.form.get('enable_captcha') == 'true',
        require_email=request.form.get('require_email') == 'true'
    )
    
    # Auto-mask with is.gd if requested? Or simply always do it if it's "Mask URL" button.
    # The form usually has 'create' button.
    # We'll stick to basic creation, then user can edit to mask or we can do it if enabled.
    # User asked for "is.gd in quick link creator".
    
    if request.form.get('mask_url'):
         full_url = f"{SERVER_URL}/{slug}"
         masked = shorten_with_isgd(full_url)
         if masked: new_link.public_masked_url = masked

    db.session.add(new_link)
    db.session.commit()
    flash(f'Link created: /{slug}', 'success')
    return redirect('/dashboard')

@app.route('/dashboard/delete/<int:id>', methods=['POST'])
@login_required
def dashboard_delete(id):
    link = Link.query.get(id)
    if link:
        # Delete associated visits first
        Visit.query.filter_by(link_id=link.id).delete()
        db.session.delete(link)
        db.session.commit()
        flash('Link deleted', 'success')
    return redirect('/dashboard')

    return output

@app.route('/dashboard/qr/<slug>')
@login_required
def dashboard_qr(slug):
    url = f"{SERVER_URL}/{slug}"
    # Customization params
    color = request.args.get('color', 'black')
    bg = request.args.get('bg', 'white')
    scale = request.args.get('scale', 10)
    logo_url = request.args.get('logo')

    qr = segno.make_qr(url, error='h') # High error correction for logo
    buff = io.BytesIO()
    
    try:
        if logo_url:
            # Fetch logo
            from PIL import Image
            import urllib.request
            
            # Create QR image first
            out = io.BytesIO()
            qr.save(out, kind='png', scale=int(scale), dark=color, light=bg)
            out.seek(0)
            img_qr = Image.open(out).convert("RGBA")
            
            # Fetch and resize logo
            logo_resp = requests.get(logo_url, timeout=3, stream=True).raw
            img_logo = Image.open(logo_resp).convert("RGBA")
            
            # Calculate size (20% of QR)
            qr_width, qr_height = img_qr.size
            logo_size = int(qr_width * 0.25)
            img_logo = img_logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
            
            # Paste logo in center
            pos = ((qr_width - logo_size) // 2, (qr_height - logo_size) // 2)
            img_qr.paste(img_logo, pos, img_logo) # Use logo as mask for transparency
            
            img_qr.save(buff, format="PNG")
        else:
            qr.save(buff, kind='png', scale=int(scale), dark=color, light=bg)
    except Exception as e:
        print(f"QR Error: {e}")
        # Fallback
        buff = io.BytesIO() # Reset buffer
        qr.save(buff, kind='png', scale=10, dark="black", light="white")
        
    buff.seek(0)
    return send_file(buff, mimetype='image/png')

@app.route('/dashboard/qr_view/<slug>') # New View for customization
@login_required
def dashboard_qr_view(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    return render_template('qr_view.html', link=link, server_url=SERVER_URL)

@app.route('/dashboard/create_full', methods=['GET', 'POST'])
@login_required
def dashboard_create_full():
    if request.method == 'POST':
        # Reuse logic or create new Link
        dest = request.form.get('destination')
        slug = request.form.get('slug')
        if not dest:
            flash('Destination required', 'error')
            return redirect('/dashboard/create_full')
        
        if not slug:
            slug = generate_slug()
        if Link.query.filter_by(slug=slug).first():
            flash('Slug exists', 'error')
            return redirect('/dashboard/create_full')

        new_link = Link(
            destination=dest,
            slug=slug,
            ios_url=request.form.get('ios_url'),
            android_url=request.form.get('android_url'),
            safe_url=request.form.get('safe_url'),
            block_bots='block_bots' in request.form,
            block_vpn='block_vpn' in request.form,
            allow_no_js='allow_no_js' in request.form,
            block_adblock='block_adblock' in request.form, 
            allowed_countries=request.form.get('allowed_countries'),
            schedule_timezone=request.form.get('schedule_timezone', 'UTC'),
            enable_captcha='enable_captcha' in request.form,
            require_email='require_email' in request.form
        )
        
        # Hours
        try:
            sh = request.form.get('schedule_start_hour')
            eh = request.form.get('schedule_end_hour')
            if sh: new_link.schedule_start_hour = int(sh)
            if eh: new_link.schedule_end_hour = int(eh)
            
            # V14: Max Clicks / Expire
            mc = request.form.get('max_clicks')
            ex = request.form.get('expiration_minutes')
            if mc: new_link.max_clicks = int(mc)
            if ex: new_link.expiration_minutes = int(ex)
            
        except: pass

        # Password
        pw = request.form.get('password')
        if pw:
            from werkzeug.security import generate_password_hash
            new_link.password_hash = generate_password_hash(pw)

        # V14: Masking
        if 'mask_link' in request.form:
            # Must save first to ensure we have the slug (we do)
            full_url = f"{SERVER_URL}/{slug}"
            masked = shorten_with_isgd(full_url)
            if masked:
                new_link.public_masked_url = masked

        db.session.add(new_link)
        db.session.commit()
        flash(f'Link created: /{slug}', 'success')
        return redirect('/dashboard')

    return render_template('create_full.html')

@app.route('/dashboard/settings', methods=['GET', 'POST'])
@login_required
def dashboard_settings():
    if request.method == 'POST':
        # Update .env file
        new_key = request.form.get('api_key')
        new_url = request.form.get('server_url')
        
        # Read current lines
        env_path = os.path.join(basedir, '../.env')
        try:
            with open(env_path, 'r') as f:
                lines = f.readlines()
            
            with open(env_path, 'w') as f:
                for line in lines:
                    if line.startswith('API_KEY='):
                        f.write(f'API_KEY={new_key}\n')
                    elif line.startswith('SERVER_URL='):
                        f.write(f'SERVER_URL={new_url}\n')
                    else:
                        f.write(line)
            
            # Update globals in memory (requires restart usually, but for display good)
            global API_KEY, SERVER_URL
            API_KEY = new_key
            SERVER_URL = new_url
            
            flash('Settings saved. Restart server to apply fully.', 'success')
        except Exception as e:
            flash(f'Error saving settings: {e}', 'error')
            
    return render_template('settings.html', api_key=API_KEY, server_url=SERVER_URL)

@app.route('/dashboard/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def dashboard_edit(id):
    link = Link.query.get_or_404(id)
    if request.method == 'POST':
        link.destination = request.form.get('destination')
        # Slug is usually immutable in edit to prevent breaking existing links, 
        # but if user insists on changing it, we can allow it if unique.
        # For now, let's keep slug immutable in Edit or handled with care. 
        # create_full allows setting it once. 
        
        link.ios_url = request.form.get('ios_url')
        link.android_url = request.form.get('android_url')
        link.safe_url = request.form.get('safe_url')
        
        link.block_bots = 'block_bots' in request.form
        link.block_vpn = 'block_vpn' in request.form
        link.allow_no_js = 'allow_no_js' in request.form
        link.block_adblock = 'block_adblock' in request.form
        link.allowed_countries = request.form.get('allowed_countries')
        
        # Scheduling
        try:
            sh = request.form.get('schedule_start_hour')
            eh = request.form.get('schedule_end_hour')
            link.schedule_start_hour = int(sh) if sh else None
            link.schedule_end_hour = int(eh) if eh else None
            link.schedule_timezone = request.form.get('schedule_timezone')
        except:
            flash("Invalid Scheduling Hours", "error")

        # Limits (V14)
        try:
            mc = request.form.get('max_clicks')
            ex = request.form.get('expiration_minutes')
            link.max_clicks = int(mc) if mc else 0
            link.expiration_minutes = int(ex) if ex else 0
        except: pass

        # Password
        pw = request.form.get('password')
        if pw and pw != "***":
            from werkzeug.security import generate_password_hash
            link.password_hash = generate_password_hash(pw)
        elif pw == "": 
             link.password_hash = None

        # Masking Regeneration (V14)
        if 'regenerate_mask' in request.form:
             full_url = f"{SERVER_URL}/{link.slug}"
             masked = shorten_with_isgd(full_url)
             if masked:
                 link.public_masked_url = masked
                 flash("Mask regenerated", "success")

        db.session.commit()
        flash('Link updated successfully', 'success')
        return redirect('/dashboard')
    
    return render_template('edit.html', link=link)

@app.route('/dashboard/stats/<slug>')
@login_required
def dashboard_stats(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    # Chart Data (Clicks per Day)
    # SQLite date string formatting: substr(timestamp, 1, 10)
    daily_clicks = db.session.query(
        func.substr(Visit.timestamp, 1, 10).label('date'), 
        func.count(Visit.id)
    ).filter_by(link_id=link.id).group_by('date').all()
    
    labels = [r[0] for r in daily_clicks]
    values = [r[1] for r in daily_clicks]
    
    # Top Countries
    countries = db.session.query(
        Visit.country, func.count(Visit.id)
    ).filter_by(link_id=link.id).group_by(Visit.country).order_by(func.count(Visit.id).desc()).limit(5).all()
    
    # Top Referrers
    referrers = db.session.query(
        Visit.referrer, func.count(Visit.id)
    ).filter_by(link_id=link.id).group_by(Visit.referrer).order_by(func.count(Visit.id).desc()).limit(5).all()

    # V14: Recent Activity Table
    # Order by timestamp desc limit 100
    visits = Visit.query.filter_by(link_id=link.id).order_by(Visit.timestamp.desc()).limit(100).all()

    return render_template('stats.html', link=link, 
                          chart_labels=labels, chart_values=values,
                          top_countries=countries, top_referrers=referrers,
                          visits=visits)

@app.route('/dashboard/lead/merge', methods=['POST'])
@login_required
def dashboard_merge_leads():
    source_id = request.form.get('source_id')
    target_email = request.form.get('target_email')
    
    source = Lead.query.get(source_id)
    target = Lead.query.filter_by(email=target_email).first()
    
    if not source or not target:
        flash('Lead not found.', 'error')
        return redirect(f'/dashboard/lead/{source_id}')
        
    if source.id == target.id:
        flash('Cannot merge into self.', 'error')
        return redirect(f'/dashboard/lead/{source_id}')

    # MERGE LOGIC
    # 1. Reassign Visits
    visits = Visit.query.filter_by(email=source.email).all()
    for v in visits:
        v.email = target.email
    
    # 2. Merge Notes
    if source.notes:
        target.notes = (target.notes or "") + f"\n[Merged {source.email}]: {source.notes}"
        
    # 3. Merge Holehe Data (Simple Append)
    if source.holehe_data:
        target.holehe_data = (target.holehe_data or "[]")[:-1] + "," + (source.holehe_data or "[]")[1:]
        # A bit messy, ideally parse list and set unique.
        
    db.session.commit()
    
    # 4. Delete Source
    db.session.delete(source)
    db.session.commit()
    
    flash(f'Merged {source.email} into {target.email}', 'success')
    return redirect(f'/dashboard/lead/{target.id}')


@app.route('/dashboard/ai_test')
@login_required
def dashboard_ai_test():
    """Diagnose AI Connectivity."""
    log = []
    log.append(f"API KEY Present: {'Yes' if GEMINI_API_KEY else 'NO'}")
    
    try:
        from google import genai
        log.append("Library `google-genai` imported successfully.")
        
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model='gemini-1.5-flash',
            contents="Say 'OK'"
        )
        log.append(f"Test Request Response: {response.text}")
        status = "SUCCESS"
    except ImportError:
        log.append("ERROR: `google-genai` library NOT found.")
        status = "FAILED"
    except Exception as e:
        log.append(f"ERROR: Exception during request: {e}")
        status = "FAILED"
        
    return "<br>".join(log)

@app.route('/dashboard/analyze_email', methods=['POST'])
@login_required
def analyze_email():
    email = request.form.get('email')
    if not email: return jsonify({'error': 'No email provided'}), 400
    
    # REAL HOLEHE EXECUTION
    import subprocess
    import json
    
    cmd = os.getenv('HOLEHE_CMD', 'holehe')
    
    try:
        # Run holehe --only-used --no-color <email>
        if cmd == 'holehe':
            venv_holehe = os.path.join(os.path.dirname(__file__), '..', 'venv', 'bin', 'holehe')
            if os.path.exists(venv_holehe):
                cmd = venv_holehe
                
        # print(f"Running OSINT: {cmd} {email}")
        result = subprocess.run([cmd, email, '--only-used', '--no-color'], capture_output=True, text=True, timeout=45)
        
        output = result.stdout
        found_sites = []
        for line in output.split('\n'):
            if '[+]' in line:
                site = line.split(']')[1].strip()
                found_sites.append(site)
        
        # Update Lead
        lead = Lead.query.filter_by(email=email).first()
        if not lead:
            lead = Lead(email=email)
            db.session.add(lead)
            
        lead.holehe_data = json.dumps(found_sites)
        db.session.commit()
        
        # V19: Render HTML Result
        return render_template('analysis_result.html', email=email, sites=found_sites, raw_log=output)
        
    except Exception as e:
        return f"<h1>Scan Error</h1><pre>{e}</pre>"
        
@app.route('/dashboard/export/<slug>')
@login_required
def dashboard_export(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    visits = Visit.query.filter_by(link_id=link.id).all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp', 'IP', 'Country', 'City', 'OS', 'User-Agent', 'Device', 'Referrer', 'ISP', 'Suspicious', 'Screen', 'Timezone', 'Lang', 'AdBlock', 'Email', 'AI Summary'])
    
    for v in visits:
        cw.writerow([
            v.timestamp, v.ip_address, v.country, v.city, 
            v.os_family, v.user_agent, v.device_type, 
            v.referrer, v.isp, v.is_suspicious,
            v.screen_res, v.timezone, v.browser_language, v.adblock,
            v.email, v.ai_summary
        ])
        
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=stats_{slug}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080)
