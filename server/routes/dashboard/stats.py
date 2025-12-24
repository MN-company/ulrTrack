from flask import Blueprint, render_template
from flask_login import login_required
import json
from collections import Counter
from datetime import datetime, timedelta

from ...models import Link, Visit
from ...config import Config

bp = Blueprint('dashboard_stats', __name__)

@bp.route('/timeline')
@login_required
def global_timeline():
    """V32: Global Timeline - All visits across all links."""
    from datetime import datetime, timedelta
    
    # Get filter params
    q = request.args.get('q', '').strip()
    country = request.args.get('country', '')
    device = request.args.get('device', '')
    days = int(request.args.get('days', 7))
    
    # Base query
    query = Visit.query
    
    # Date filter
    if days > 0:
        cutoff = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Visit.timestamp >= cutoff)
    
    # Search filter
    if q:
        search = f"%{q}%"
        query = query.filter(
            db.or_(
                Visit.ip_address.ilike(search),
                Visit.email.ilike(search),
                Visit.hostname.ilike(search),
                Visit.org.ilike(search),
                Visit.city.ilike(search),
                Visit.canvas_hash.ilike(search),
                Visit.etag.ilike(search)
            )
        )
    
    # Country filter
    if country:
        query = query.filter(Visit.country == country)
    
    # Device filter
    if device:
        query = query.filter(Visit.device_type == device)
    
    visits = query.order_by(Visit.timestamp.desc()).limit(200).all()
    
    # Get unique countries and devices for filters
    all_countries = db.session.query(Visit.country).distinct().all()
    all_devices = db.session.query(Visit.device_type).distinct().all()
    
    return render_template('timeline.html',
                          visits=visits,
                          q=q,
                          country=country,
                          device=device,
                          days=days,
                          countries=[c[0] for c in all_countries if c[0]],
                          devices=[d[0] for d in all_devices if d[0]])

# ============================================
# V47: UNIFIED AI CONSOLE WITH @MENTIONS
# ============================================


@bp.route('/stats/<slug>')
@login_required
def stats(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    # Calculate Stats
    visits = Visit.query.filter_by(link_id=link.id).order_by(Visit.timestamp.desc()).all()
    
    # Chart Data (Last 7 days)
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    now = datetime.utcnow()
    dates = [(now - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    clicks_map = defaultdict(int)
    
    for v in visits:
        d = v.timestamp.strftime('%Y-%m-%d')
        clicks_map[d] += 1
        
    chart_values = [clicks_map[d] for d in dates]
    
    # Top Countries
    countries = defaultdict(int)
    for v in visits: countries[v.country or 'Unknown'] += 1
    top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Referrers
    referrers = defaultdict(int)
    for v in visits: referrers[v.referrer or 'Direct'] += 1
    top_referrers = sorted(referrers.items(), key=lambda x: x[1], reverse=True)[:5]

    # V29: IP Cross-Link View (Find IPs that visited OTHER links too)
    ip_addresses = list(set([v.ip_address for v in visits if v.ip_address]))
    cross_link_data = {}
    if ip_addresses:
        cross_visits = Visit.query.filter(
            Visit.ip_address.in_(ip_addresses),
            Visit.link_id != link.id
        ).all()
        
        for cv in cross_visits:
            ip = cv.ip_address
            if ip not in cross_link_data:
                cross_link_data[ip] = []
            # Avoid duplicates
            if cv.link.slug not in [x['slug'] for x in cross_link_data[ip]]:
                cross_link_data[ip].append({
                    'slug': cv.link.slug,
                    'timestamp': cv.timestamp,
                    'email': cv.email
                })

    return render_template('stats.html', 
                          link=link, 
                          visits=visits[:100], # Limit log to 100
                          chart_labels=dates,
                          chart_values=chart_values,
                          top_countries=top_countries,
                          top_referrers=top_referrers,
                          cross_link_data=cross_link_data)

@bp.route('/device/<fingerprint>')
@login_required
def device_profile(fingerprint):
    """V29: Device Cluster Page - View all activity from a specific fingerprint."""
    
    # Find all visits matching this fingerprint (canvas_hash OR etag)
    visits = Visit.query.filter(
        db.or_(
            Visit.canvas_hash == fingerprint,
            Visit.etag == fingerprint
        )
    ).order_by(Visit.timestamp.desc()).all()
    
    if not visits:
        flash('No device found with that fingerprint.', 'error')
        return redirect(url_for('dashboard.dashboard_home'))
    
    # Aggregate data
    emails = list(set([v.email for v in visits if v.email]))
    ips = list(set([v.ip_address for v in visits if v.ip_address]))
    links_visited = list(set([v.link.slug for v in visits]))
    countries = list(set([v.country for v in visits if v.country]))
    devices = list(set([f"{v.os_family} / {v.device_type}" for v in visits]))
    
    # Best identity guess
    primary_email = emails[0] if emails else None
    ai_summary = next((v.ai_summary for v in visits if v.ai_summary), None)
    webgl = next((v.webgl_renderer for v in visits if v.webgl_renderer), None)
    
    return render_template('device_profile.html',
                          fingerprint=fingerprint,
                          visits=visits[:50],
                          emails=emails,
                          ips=ips,
                          links_visited=links_visited,
                          countries=countries,
                          devices=devices,
                          primary_email=primary_email,
                          ai_summary=ai_summary,
                          webgl=webgl,
                          total_visits=len(visits))

# ============================================
# V30: EXPORT FUNCTIONALITY
# ============================================

