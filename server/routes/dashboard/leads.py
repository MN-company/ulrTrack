from flask import Blueprint, render_template, request, redirect, flash, url_for, make_response
from flask_login import login_required, current_user
import json
import csv
from io import StringIO
from collections import defaultdict

from ...models import Lead, Visit
from ...extensions import db, log_queue
from ...config import Config


bp = Blueprint('dashboard_leads', __name__)

@bp.route('/contacts', methods=['GET', 'POST'])
@login_required
def contacts():
    if request.method == 'POST':
        try:
            from ...services.lead_service import LeadService
            LeadService.create_lead(
                email=request.form.get('email'),
                name=request.form.get('name'),
                notes=request.form.get('notes')
            )
            flash(f"Lead {request.form.get('email')} added.", 'success')
        except ValueError as e:
            flash(str(e), 'warning')
            
        return redirect(url_for('dashboard.dashboard_leads.contacts'))

    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    return render_template('contacts.html', leads=leads)



@bp.route('/merge_candidates')
@login_required
def merge_candidates():
    """Find potential duplicate leads using Service."""
    from ...services.lead_service import LeadService
    candidates = LeadService.get_merge_candidates()
    return render_template('merge_candidates.html', candidates=candidates)

@bp.route('/merge_leads', methods=['POST'])
@login_required
def merge_leads():
    """Merge leads using Service."""
    primary_id = request.form.get('primary_id', type=int)
    secondary_ids = request.form.getlist('secondary_ids')
    
    if not primary_id or not secondary_ids:
        flash('Invalid selection.', 'error')
        return redirect(url_for('dashboard.dashboard_leads.merge_candidates'))
        
    try:
        from ...services.lead_service import LeadService
        count = LeadService.merge_leads(primary_id, secondary_ids)
        flash(f'Merged {count} leads successfully.', 'success')
        return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=primary_id))
    except Exception as e:
        flash(f'Merge failed: {str(e)}', 'error')
        return redirect(url_for('dashboard.dashboard_leads.merge_candidates'))

@bp.route('/contacts/export_csv')
@login_required
def export_contacts_csv():
    from ...services.lead_service import LeadService
    csv_data = LeadService.export_csv()
    
    output = make_response(csv_data)
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
        lead.tags = request.form.get('tags')
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('dashboard.dashboard_leads.lead_profile', lead_id=lead_id))
        
    # Uses Service for graph data
    from ...services.lead_service import LeadService
    graph_data = LeadService.build_identity_graph(lead)


    # OSINT Enrichment (REMOVED) - Deep Data Only
    
    # Custom Fields (JSON)
    cf = lead.custom_fields_data

    return render_template('profile.html', 
                          lead=lead, 
                          devices=graph_data['devices'],
                          related_leads=graph_data['related_leads'],
                          ips=graph_data['ips'],
                          canvas_hashes=graph_data['canvas_hashes'],
                          timeline_visits=graph_data['visits']
                          )

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





