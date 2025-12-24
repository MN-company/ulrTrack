from flask import Blueprint, render_template, request, redirect, flash, url_for
from flask_login import login_required
import json
import re

from ...models import Lead, Visit
from ...extensions import db, log_queue
from ...ai_engine import ai

bp = Blueprint('dashboard_ai', __name__)

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
        
        # @db:xxx - DISABLED FOR SECURITY
        db_match = re.search(r'@db:(.+)', message)
        if db_match:
            context_data += """
⚠️ SECURITY NOTICE: The @db command has been disabled for production security.
This feature allowed direct SQL queries which posed SQL injection and data exfiltration risks.

If you need database insights, please use:
- @email:user@example.com to query lead data
- @hash:xxx to query fingerprint data
- @visit:123 to query specific visit details

For advanced analytics, please use the Export features (CSV/JSON/PDF).
"""
        
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
