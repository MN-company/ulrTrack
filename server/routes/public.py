from flask import Blueprint, request, render_template, abort, make_response, redirect
from user_agents import parse
from datetime import datetime
import hashlib

from ..models import Link, Visit
from ..extensions import db
from ..utils import get_geo_data, is_bot_ua, verify_turnstile
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
        lon=geo.get('lon')
    )
    db.session.add(visit)
    db.session.commit()
    
    # Checks
    final_dest = link.destination
    if not (final_dest.startswith("http://") or final_dest.startswith("https://")):
        final_dest = "https://" + final_dest

    if link.block_bots and is_bot_ua(ua_string):
         visit.is_suspicious = True
         db.session.commit()
         if link.safe_url: final_dest = link.safe_url
         else: return render_template('error.html', message="Suspicious Traffic", visit_id=visit.id, hide_nav=True), 403

    # Success
    return render_template('loading.html', destination=final_dest, visit_id=visit.id, allow_no_js=link.allow_no_js, hide_nav=True)
