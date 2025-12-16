from flask import Flask, request, redirect, render_template, abort, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import requests
import hashlib
from urllib.parse import urlparse
from dotenv import load_dotenv
from user_agents import parse
import io
import csv

load_dotenv()  # Load variables from .env file

# --- Configuration ---
app = Flask(__name__)
# Fix for PythonAnywhere: Use absolute path for DB
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'shortener.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_dev_secret')
API_KEY = os.getenv('API_KEY', 'changeme')

# Cloudflare Turnstile Keys (Env vars or defaults for dev)
TURNSTILE_SECRET_KEY = os.getenv('TURNSTILE_SECRET_KEY', '1x0000000000000000000000000000000AA')
TURNSTILE_SITE_KEY = os.getenv('TURNSTILE_SITE_KEY', '1x00000000000000000000AA')
PROXYCHECK_API_KEY = os.getenv('PROXYCHECK_API_KEY', '')

db = SQLAlchemy(app)

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
    allow_no_js = db.Column(db.Boolean, default=False) # V9: If True, show link in noscript. If False, strict blocking. # Default BLOCK bots
    
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

# --- Helpers ---
def is_bot_ua(ua_string):
    """Simple heuristic to detect bots."""
    bots = [
        'bot', 'crawl', 'slurp', 'spider', 'curl', 'wget', 'facebook', 'whatsapp', 'telegram', 
        'expand', 'preview', 'peeker', 'twitter', 'discord', 'slack', 'go-http-client', 'python-requests'
    ]
    ua_lower = ua_string.lower()
    return any(bot in ua_lower for bot in bots)



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

@app.route('/<slug>', methods=['GET'])
def redirect_to_url(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    # 1. Check Expiration
    if link.expire_date and datetime.utcnow() > link.expire_date:
        return render_template('error.html', message="Link Expired"), 410

    # 2. Check Max Clicks
    clicks = Visit.query.filter_by(link_id=link.id).count()
    if link.max_clicks and clicks >= link.max_clicks:
        return render_template('error.html', message="Link Limit Reached"), 410

    # 3. Detection & Tracking
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    
    # FORCE Absolute URL (Initialize final_dest early for potential cloaking overrides)
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest

    # Parse User Agent
    ua_string = request.user_agent.string
    user_agent = parse(ua_string)
    os_family = user_agent.os.family
    device_type = "Mobile" if user_agent.is_mobile else "Tablet" if user_agent.is_tablet else "Desktop"
    
    # Geo & ISP & Proxy (Unified)
    geo = get_geo_data(client_ip)
    
    is_vpn = False
    tracking_note = None # Initialize tracking_note
    
    # DEBUG: Print exact state
    print(f"DEBUG CHECKS: Slug={slug} BlockVPN={link.block_vpn} BlockBots={link.block_bots}")
    print(f"DEBUG GEO: Proxy={geo.get('proxy')} ({type(geo.get('proxy'))}) Hosting={geo.get('hosting')}")

    if link.block_vpn:
        # 1. Native API Check (ip-api.com returns 'proxy' and 'hosting' bools)
        # Relaxed check (truthy) just in case
        if geo.get('proxy') or geo.get('hosting'):
            is_vpn = True
            print(f"DEBUG: VPN blocked via ip-api")
        
        # 2. ISP Heuristic (Backup/Double Check)
        if not is_vpn and geo.get('isp'):
            isp_lower = geo['isp'].lower()
            hosting_keywords = [
                'amazon', 'google cloud', 'digitalocean', 'microsoft', 'azure', 'hetzner', 'ovh', 
                'linode', 'vultr', 'm247', 'datacenter', 'hosting', 'vpn', 'proxy', 'tor', 'exit node',
                'privatesystems', 'choopa', 'datacamp', 'cdn', 'cloud'
            ]
            if any(k in isp_lower for k in hosting_keywords):
                print(f"DEBUG: ISP blocked via heuristic: {geo['isp']}")
                is_vpn = True

        if is_vpn:
            if link.safe_url:
                 tracking_note = "VPN -> Safe"
                 final_dest = link.safe_url # CLOAKING
            else:
                return render_template('error.html', message="VPN/Proxy Detected. Access Denied."), 403

    # 4. Interstitials
    cookie_val = request.cookies.get(f"auth_{slug}")
    
    if not TURNSTILE_SITE_KEY:
        print("WARNING: TURNSTILE_SITE_KEY is missing!")

    if link.password_hash:
        expected_hash = hashlib.sha256(f"{link.password_hash}{app.config['SECRET_KEY']}".encode()).hexdigest()
        if cookie_val != expected_hash:
            return render_template('password.html', slug=slug, site_key=TURNSTILE_SITE_KEY)

    elif link.enable_captcha:
        expected_hash = hashlib.sha256(f"captcha_ok_{slug}{app.config['SECRET_KEY']}".encode()).hexdigest()
        if cookie_val != expected_hash:
             # Ensure template gets site_key
             return render_template('captcha.html', slug=slug, site_key=TURNSTILE_SITE_KEY)

    # 5. Analytics & Redirect
    visit = Visit(
        link_id=link.id,
        ip_address=client_ip,
        user_agent=ua_string,
        referrer=request.referrer,
        is_suspicious=is_vpn,
        os_family=os_family,
        device_type=device_type,
        isp=geo.get('isp'),
        city=geo.get('city'),
        country=geo.get('country'),
        lat=geo.get('lat'),
        lon=geo.get('lon')
    )
    db.session.add(visit)
    db.session.commit()

    # FORCE Absolute URL (Safety check for ANY final_dest)
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest

    # V8 Stealth Mode: Return 200 OK with JS Redirect
    # This fools URL expanders that look for 30x headers.
    # We pass visit.id to allow the client to send back a Beacon (Screen Res, etc.)
    # V8 Stealth/V9 Features: Pass allow_no_js to template
    return render_template('loading.html', destination=final_dest, visit_id=visit.id, allow_no_js=link.allow_no_js)

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
                    
                    db.session.commit()
                    print(f"BEACON SAVED: ID={v_id} Screen={visit.screen_res} Lang={visit.browser_language} AdBlock={visit.adblock}")
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
def create_link():
    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    slug = data.get('slug')
    # Generate random slug if missing (basic)
    if not slug:
        import random, string
        slug = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        
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
        allow_no_js=data.get('allow_no_js', False) # V9
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
    key = request.headers.get('X-API-KEY')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    link = Link.query.filter_by(slug=slug).first_or_404()

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
