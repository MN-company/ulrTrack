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
        
    visits = Visit.query.filter_by(email=lead.email).all()
    devices = set()
    for v in visits:
        if v.ai_summary: devices.add(v.ai_summary)
        if v.webgl_renderer and v.webgl_renderer != "Unknown": devices.add(v.webgl_renderer)
        
    return render_template('profile.html', lead=lead, holehe_list=holehe_list, devices=list(devices))

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
