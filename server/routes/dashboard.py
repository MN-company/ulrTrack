from flask import Blueprint, render_template, request, redirect, flash, send_file, url_for
from flask_login import login_required, current_user
import io
import requests
import segno
import os
from PIL import Image

from ..models import Link, Visit, Lead
from ..extensions import db, log_queue
from ..config import Config
from ..utils import generate_slug, shorten_with_isgd

bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@bp.route('')
@login_required
def dashboard_home():
    print(f"DEBUG: Accessing Dashboard Home BP. User: {current_user.id}")
    try:
        links = Link.query.order_by(Link.created_at.desc()).all()
        total_clicks = Visit.query.count()
        total_blocked = Visit.query.filter_by(is_suspicious=True).count()
        
        return render_template('dashboard.html', 
                              links=links, 
                              total_links=len(links), 
                              total_clicks=total_clicks,
                              total_blocked=total_blocked,
                              server_url=Config.SERVER_URL)
    except Exception as e:
        print(f"DASHBOARD ERROR: {e}")
        return f"Dashboard Error: {e}", 500

@bp.route('/create', methods=['POST'])
@login_required
def create_link():
    dest = request.form.get('destination')
    slug = request.form.get('slug')
    
    if not dest:
        flash('Destination required', 'error')
        return redirect(url_for('dashboard.dashboard_home'))
    if not slug:
        slug = generate_slug()
    if Link.query.filter_by(slug=slug).first():
        flash('Slug exists', 'error')
        return redirect(url_for('dashboard.dashboard_home'))

    new_link = Link(
        destination=dest, 
        slug=slug, 
        block_bots=request.form.get('block_bots') == 'true', 
        block_vpn=request.form.get('block_vpn') == 'true',
        enable_captcha=request.form.get('enable_captcha') == 'true',
        require_email=request.form.get('require_email') == 'true'
    )
    
    if request.form.get('mask_url'):
         full_url = f"{Config.SERVER_URL}/{slug}"
         masked = shorten_with_isgd(full_url)
         if masked: new_link.public_masked_url = masked

    db.session.add(new_link)
    db.session.commit()
    flash(f'Link created: /{slug}', 'success')
    return redirect(url_for('dashboard.dashboard_home'))

@bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_link(id):
    link = Link.query.get(id)
    if link:
        Visit.query.filter_by(link_id=link.id).delete()
        db.session.delete(link)
        db.session.commit()
        flash('Link deleted', 'success')
    return redirect(url_for('dashboard.dashboard_home'))

@bp.route('/contacts', methods=['GET', 'POST'])
@login_required
def contacts():
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
        return redirect(url_for('dashboard.contacts'))

    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    return render_template('contacts.html', leads=leads)

@bp.route('/lead/<int:lead_id>', methods=['GET', 'POST'])
@login_required
def lead_profile(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if request.method == 'POST':
        lead.name = request.form.get('name')
        lead.notes = request.form.get('notes')
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('dashboard.lead_profile', lead_id=lead_id))
        
    import json
    holehe_list = []
    if lead.holehe_data:
        try: holehe_list = json.loads(lead.holehe_data)
        except: pass
        
    # --- Identity Graph Logic (Spiderweb) ---
    visits = Visit.query.filter_by(email=lead.email).all()
    devices = set()
    ips = set()
    canvas_hashes = set()
    
    for v in visits:
        if v.ai_summary: devices.add(v.ai_summary)
        if v.webgl_renderer and v.webgl_renderer != "Unknown": devices.add(v.webgl_renderer)
        if v.ip_address: ips.add(v.ip_address)
        if v.canvas_hash: canvas_hashes.add(v.canvas_hash)
        
    # Find Related Leads (Shared IP or Canvas)
    related_leads = []
    if ips or canvas_hashes:
        # Complex query: Find visits that match IP or Canvas, but have different Email
        # This is heavy, so we limit to last 100 or specific matches.
        # Optimized: query distinct emails from visits where IP in ips OR canvas in hashes
        query = db.session.query(Visit.email).filter(
            (Visit.ip_address.in_(ips)) | (Visit.canvas_hash.in_(canvas_hashes)),
            Visit.email.isnot(None),
            Visit.email != lead.email
        ).distinct()
        
        related_emails = [r[0] for r in query.all()]
        if related_emails:
            related_leads = Lead.query.filter(Lead.email.in_(related_emails)).all()

    return render_template('profile.html', 
                          lead=lead, 
                          holehe_list=holehe_list, 
                          devices=list(devices),
                          related_leads=related_leads,
                          ips=list(ips),
                          canvas_hashes=list(canvas_hashes))

@bp.route('/analyze_email', methods=['POST'])
@login_required
def analyze_email():
    email = request.form.get('email')
    if not email: return "No email", 400
    
    lead = Lead.query.filter_by(email=email).first()
    if not lead:
        lead = Lead(email=email)
        db.session.add(lead)
    
    lead.scan_status = 'pending'
    db.session.commit()
    
    log_queue.put({'type': 'osint', 'email': email, 'lead_id': lead.id})
    flash('Scan started.', 'success')
    return redirect(url_for('dashboard.lead_profile', lead_id=lead.id))

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        flash('Settings updated (Env file write simulated).', 'success')
    return render_template('settings.html', 
                          api_key=Config.API_KEY, 
                          server_url=Config.SERVER_URL,
                          gemini_model=Config.GEMINI_MODEL,
                          gemini_key=Config.GEMINI_API_KEY,
                          ai_prompt=Config.AI_PROMPT,
                          holehe_cmd=Config.HOLEHE_CMD)

@bp.route('/qr_view/<slug>')
@login_required
def qr_view(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    return render_template('qr_view.html', link=link, server_url=Config.SERVER_URL)

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

    return render_template('stats.html', 
                          link=link, 
                          visits=visits[:100], # Limit log to 100
                          chart_labels=dates,
                          chart_values=chart_values,
                          top_countries=top_countries,
                          top_referrers=top_referrers)
