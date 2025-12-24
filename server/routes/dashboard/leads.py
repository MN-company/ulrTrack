from flask import Blueprint, render_template, request, redirect, flash, url_for, make_response
from flask_login import login_required, current_user
import json
import csv
from io import StringIO
from collections import defaultdict

from ...models import Lead, Visit
from ...extensions import db, log_queue
from ...config import Config
from ...ai_engine import ai
from ...utils import email_permutations, get_gravatar_profile

bp = Blueprint('dashboard_leads', __name__)

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
        
    return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=lead_id))
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
        return redirect(url_for('dashboard.dashboard_leads.contacts'))

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
        return redirect(url_for('dashboard.dashboard_leads.merge_candidates'))
    
    primary = Lead.query.get(int(primary_id))
    if not primary:
        flash('Primary lead not found.', 'error')
        return redirect(url_for('dashboard.dashboard_leads.merge_candidates'))
    
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
    return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=primary.id))

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
        return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=lead_id))
        
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
    return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=lead.id))

@bp.route('/analyze_identity/<int:lead_id>', methods=['POST'])
@login_required
def analyze_identity(lead_id):
    """V31: Trigger AI Identity Inference for a lead."""
    lead = Lead.query.get_or_404(lead_id)
    log_queue.put({'type': 'identity_inference', 'lead_id': lead_id})
    flash('AI Identity Analysis queued. Refresh in a few seconds.', 'success')
    return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=lead_id))