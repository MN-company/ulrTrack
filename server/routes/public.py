from flask import Blueprint, request, render_template, abort, make_response, redirect, render_template_string
from user_agents import parse
from datetime import datetime
from jinja2.sandbox import SandboxedEnvironment
import hashlib

from ..models import Link, Visit
from ..extensions import db, limiter
from ..utils import get_geo_data, is_bot_ua, verify_turnstile, parse_referrer
from ..config import Config

bp = Blueprint('public', __name__)

LINK_CACHE = {}
CACHE_TTL = 60

@bp.route('/<slug>', methods=['GET'])
def redirect_to_url(slug):
    # 1. Cache
    cached = LINK_CACHE.get(slug)
    link = None
    if cached and (datetime.utcnow().timestamp() - cached['timestamp'] < CACHE_TTL):
        link = cached['link']
    
    if not link:
        # PROTECT RESERVED ROUTES from being caught as slugs
        if slug in ['dashboard', 'login', 'logout', 'api', 'static']:
            abort(404)
            
        link = Link.query.filter_by(slug=slug).first_or_404()
        LINK_CACHE[slug] = {'link': link, 'timestamp': datetime.utcnow().timestamp()}

    # Log Visit
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    ua_string = request.user_agent.string
    user_agent = parse(ua_string)
    
    # Critical: Geo Data needed for blocking (Cached)
    geo = get_geo_data(client_ip)
    
    # V27: ETag Zombie Cookie Logic
    client_etag = request.headers.get('If-None-Match')
    if not client_etag:
        import uuid
        client_etag = str(uuid.uuid4())
    
    # 2. Save minimal Visit (Fast)
    visit = Visit(
        link_id=link.id,
        ip_address=client_ip,
        user_agent=ua_string,
        referrer=request.referrer,
        os_family=user_agent.os.family,
        device_type="Mobile" if user_agent.is_mobile else "Tablet" if user_agent.is_tablet else "Desktop",
        isp=geo.get('isp'),
        org=geo.get('org'),
        country=geo.get('country'),
        city=geo.get('city'),
        lat=geo.get('lat'),
        lon=geo.get('lon'),
        etag=client_etag
    )
    db.session.add(visit)
    db.session.commit()
    
    # Async Enrichment (DNS, etc)
    from ..extensions import log_queue
    try:
        log_queue.put({'type': 'enrich_visit', 'visit_id': visit.id, 'ip': client_ip})
    except:
        pass
    
    # === LOGIC IMPLEMENTATION (V41) ===
    
    # 1. Scheduling (Time-based Access) - IMPROVED V42
    if link.schedule_start_hour is not None or link.schedule_end_hour is not None:
        try:
            import pytz
            
            # Determine Timezone
            tz_name = link.schedule_timezone or 'UTC'
            try:
                target_tz = pytz.timezone(tz_name)
            except pytz.UnknownTimeZoneError:
                # Fallback to UTC if invalid TZ provided
                target_tz = pytz.UTC
            
            # Get current time in target timezone
            current_time = datetime.now(target_tz)
            current_hour = current_time.hour
            
            # Start Check
            if link.schedule_start_hour is not None:
                if current_hour < link.schedule_start_hour:
                     return render_template('error.html', message="Link not yet active", hide_nav=True), 404
            
            # End Check
            if link.schedule_end_hour is not None:
                if current_hour >= link.schedule_end_hour:
                     return render_template('error.html', message="Link expired (Schedule)", hide_nav=True), 404
        except Exception as e:
            print(f"Scheduling Error: {e}")

    # 2. Allowed Countries (Geo-Fencing)
    if link.allowed_countries:
        allowed_list = [c.strip().upper() for c in link.allowed_countries.split(',') if c.strip()]
        visitor_cc = geo.get('countryCode', '').upper()
        if visitor_cc and allowed_list and visitor_cc not in allowed_list:
            # Blocked Location
            visit.is_suspicious = True
            visit.notes = f"Blocked: Country {visitor_cc} not allowed"
            db.session.commit()
            return render_template('error.html', message="Access Denied from your location", visit_id=visit.id, hide_nav=True), 403

    # Checks
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest
        
    # 3. Mobile Targeting
    if user_agent.is_mobile or user_agent.is_tablet:
        if user_agent.os.family == 'iOS' and link.ios_url:
            final_dest = link.ios_url
            if not (final_dest.startswith("http://") or final_dest.startswith("https://")): final_dest = "https://" + final_dest
            
        elif user_agent.os.family == 'Android' and link.android_url:
            final_dest = link.android_url
            if not (final_dest.startswith("http://") or final_dest.startswith("https://")): final_dest = "https://" + final_dest
    
    # === LIMITS CHECK (V40) ===
    # 1. Expiration
    if link.expiration_minutes and link.expiration_minutes > 0:
        elapsed = (datetime.utcnow() - link.created_at).total_seconds() / 60
        if elapsed > link.expiration_minutes:
             return render_template('error.html', message="Link Expired", hide_nav=True), 404

    # 2. Max Clicks
    if link.max_clicks and link.max_clicks > 0:
        # Count visits (excluding this current one ideally, but since we already committed it, we check count including it or use <=)
        # We already committed the visit above at line 64. So count will be at least 1.
        # If max_clicks is 1, and we just added 1, count is 1. If we visit again, count is 2.
        # So logic: check count. If count > max_clicks, Block.
        visit_count = Visit.query.filter_by(link_id=link.id).count()
        if visit_count > link.max_clicks:
             return render_template('error.html', message="Link Limit Reached", hide_nav=True), 404
             
    # === SECURITY CHECKS (Correct Order) ===
    # Define cloud providers for VPN/Bot detection - EXPANDED LIST
    cloud_providers = [
        'google', 'amazon', 'microsoft', 'digitalocean', 'oracle', 'aliyun', 'hetzner',
        'ovh', 'linode', 'vultr', 'lease', 'dedibox', 'choopa', 'm247', 'fly.io',
        'datacenter', 'hosting', 'server', 'vpn', 'proxy', 'tor', 'exit', 'node',
        'expressvpn', 'nordvpn', 'cyberghost', 'surfshark', 'cloudflare', 'fastly', 'akamai'
    ]
    
    # 1. VPN/Bot Detection
    is_bot = is_bot_ua(ua_string) or geo.get('hosting') == True
    if geo.get('org'):
        org_lower = geo.get('org').lower()
        if any(p in org_lower for p in cloud_providers):
            is_bot = True # Treat cloud/vpn as potential bot
            
    is_vpn_or_cloud = geo.get('hosting') == True
    if geo.get('org'):
        org_lower = geo.get('org').lower()
        # Check against provider list explicitly for VPN flag
        if any(p in org_lower for p in cloud_providers):
            is_vpn_or_cloud = True
    
    # Check VPN block
    if link.block_vpn and is_vpn_or_cloud:
        visit.is_suspicious = True
        visit.notes = "Blocked: VPN/Cloud Detected"
        db.session.commit()
        if link.safe_url:
            final_dest = link.safe_url
        else:
            return render_template('error.html', message="Anonymizer/VPN/Cloud IP Detected", visit_id=visit.id, hide_nav=True), 403
    
    # Check Bot block
    if link.block_bots and is_bot:
        visit.is_suspicious = True
        visit.notes = "Blocked: Bot Detected"
        db.session.commit()
        if link.safe_url:
            final_dest = link.safe_url
        else:
            return render_template('error.html', message="Suspicious Traffic", visit_id=visit.id, hide_nav=True), 403
    
    # 2. Captcha Check
    if link.enable_captcha:
        captcha_cookie = request.cookies.get(f'auth_captcha_{link.slug}')
        expected_hash = hashlib.sha256(f"captcha_ok_{link.slug}{Config.SECRET_KEY}".encode()).hexdigest()
        if captcha_cookie != expected_hash:
            return render_template('captcha.html', slug=link.slug, visit_id=visit.id, site_key=Config.TURNSTILE_SITE_KEY, hide_nav=True)
    
    # 3. Password Check
    if link.password_hash:
        auth_cookie = request.cookies.get(f'auth_pwd_{link.slug}')
        expected_hash = hashlib.sha256(f"{link.password_hash}{Config.SECRET_KEY}".encode()).hexdigest()
        if auth_cookie != expected_hash:
            return render_template('password.html', slug=link.slug, visit_id=visit.id, site_key=Config.TURNSTILE_SITE_KEY, hide_nav=True)
    
    # 4. Email Gate Check
    if link.require_email:
        verified_cookie = request.cookies.get(f'verified_{link.slug}')
        if not verified_cookie:
            return render_template('email_gate.html', slug=link.slug, visit_id=visit.id, site_key=Config.TURNSTILE_SITE_KEY, hide_nav=True)

    # V38 AI Architect Custom Rendering
    if link.custom_html:
        # Inject Tracking Beacon
        tracking_js = f"""
        <script>
            try {{
                navigator.sendBeacon("/api/beacon", JSON.stringify({{
                    visit_id: "{visit.id}",
                    canvas_hash: "ArchitectFit",
                    webgl_renderer: "CustomLanding"
                }}));
                // Simple version of Session Detector for custom pages
                (function(){{
                    const probes = [{{name:'Github',url:'https://github.com/fluidicon.png'}}];
                    probes.forEach(p => {{
                        new Image().src = p.url;
                    }});
                }})();
            }} catch(e) {{}}
        </script>
        """
        html_content = link.custom_html.replace('</body>', tracking_js + '</body>')
        
        # Security: Use Jinja2 Sandbox to prevent SSTI
        sandbox = SandboxedEnvironment()
        template = sandbox.from_string(html_content)
        return template.render(destination=final_dest, visit_id=visit.id)

    # Success
    resp = make_response(render_template('loading.html', destination=final_dest, visit_id=visit.id, allow_no_js=link.allow_no_js, hide_nav=True))
    
    # 3. SET THE TRAP (Send ETag back to browser)
    resp.headers['ETag'] = client_etag
    resp.headers['Cache-Control'] = 'private, max-age=31536000' # Force caching
    
    return resp

@bp.route('/verify_captcha', methods=['POST'])
@limiter.limit("5 per minute")
def verify_captcha():
    slug = request.form.get('slug')
    turnstile_token = request.form.get('cf-turnstile-response')
    visit_id = request.form.get('visit_id')
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    if verify_turnstile(turnstile_token, client_ip):
        auth_hash = hashlib.sha256(f"captcha_ok_{slug}{Config.SECRET_KEY}".encode()).hexdigest()
        resp = make_response(redirect(f"/{slug}"))
        resp.set_cookie(f"auth_captcha_{slug}", auth_hash, max_age=3600, httponly=True, secure=True, samesite='Lax')
        return resp
    else:
        return render_template('captcha.html', slug=slug, visit_id=visit_id, 
                               site_key=Config.TURNSTILE_SITE_KEY, error="Verification Failed", hide_nav=True), 400

@bp.route('/verify_password', methods=['POST'])
@limiter.limit("5 per minute")
def verify_password():
    slug = request.form.get('slug')
    password = request.form.get('password')
    turnstile_token = request.form.get('cf-turnstile-response')
    visit_id = request.form.get('visit_id')
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    # Verify Turnstile
    if not verify_turnstile(turnstile_token, client_ip):
        return render_template('password.html', slug=slug, visit_id=visit_id,
                               site_key=Config.TURNSTILE_SITE_KEY, error="Captcha Failed", hide_nav=True), 400
    
    # Verify Password
    user_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_hash == link.password_hash:
        auth_hash = hashlib.sha256(f"{link.password_hash}{Config.SECRET_KEY}".encode()).hexdigest()
        resp = make_response(redirect(f"/{slug}"))
        resp.set_cookie(f"auth_pwd_{slug}", auth_hash, max_age=3600, httponly=True, secure=True, samesite='Lax')
        return resp
    else:
        return render_template('password.html', slug=slug, visit_id=visit_id,
                               site_key=Config.TURNSTILE_SITE_KEY, error="Invalid Password", hide_nav=True), 401

@bp.route('/verify_email', methods=['POST'])
def verify_email():
    slug = request.form.get('slug')
    visit_id = request.form.get('visit_id')
    email = request.form.get('email')
    
    # 1. Basic Validation
    if not slug or not email:
        return "Missing data", 400
        
    link = Link.query.filter_by(slug=slug).first_or_404()
    visit = Visit.query.get(visit_id)
    
    # 2. Email Policy Enforcement (V23)
    from ..utils import is_disposable_email, is_privacy_email, validate_email_strict
    
    # SENIOR VALIDATION: Gibberish & Strict Syntax
    is_valid_strict, strict_reason = validate_email_strict(email)
    if not is_valid_strict:
         return render_template('email_gate.html', 
                                 slug=slug, visit_id=visit_id, site_key=Config.TURNSTILE_SITE_KEY,
                                 error=strict_reason)
    
    # Policy: Certified Only (Block Temp)
    if link.email_policy in ['certified', 'trackable']:
        if is_disposable_email(email):
            return render_template('email_gate.html', 
                                 slug=slug, visit_id=visit_id, site_key=Config.TURNSTILE_SITE_KEY,
                                 error="Ephemeral/Temporary emails are not accepted. Please use a standard provider.")

    # Policy: Trackable Only (Block Temp + Privacy)
    if link.email_policy == 'trackable':
        if is_privacy_email(email):
            temp_provider = is_disposable_email(email) # Recheck to be sure
            error_msg = "Private/Anonymous email providers are restricted. Please use a standard ISP or Corporate email."
            return render_template('email_gate.html', 
                                 slug=slug, visit_id=visit_id, site_key=Config.TURNSTILE_SITE_KEY,
                                 error=error_msg)

    # 3. Save Email and Create Lead
    if visit:
        visit.email = email
        db.session.commit()
        
        # Create Lead if not exists
        from ..models import Lead
        lead = Lead.query.filter_by(email=email).first()
        if not lead:
            lead = Lead(email=email, scan_status='pending')
            db.session.add(lead)
            db.session.commit()
        

    
    # 4. Success -> Redirect to Loading
    # Checks
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest
    if link.safe_url: final_dest = link.safe_url
        
    return render_template('loading.html', 
                           destination=final_dest, 
                           visit_id=visit_id, 
                           allow_no_js=link.allow_no_js, 
                           block_adblock=link.block_adblock,
                           hide_nav=True)
