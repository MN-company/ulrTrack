from flask import Blueprint, render_template, request, redirect, flash, url_for, jsonify
from flask_login import login_required
import json
import re

from ...models import Lead, Visit
from ...extensions import db, log_queue

from ...config import Config

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
    """Process AI message using AIService."""
    message = request.form.get('message', '')
    
    if not message:
        return jsonify({'error': 'No message'}), 400
    
    try:
        from ...services.ai_service import AIService
        result = AIService.generate_response(message)
        return jsonify(result)
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400 # Config error
    except Exception as e:
        return jsonify({'error': f"AI Service Error: {str(e)}"}), 500

# Legacy routes redirect to console
@bp.route('/ai')
@login_required
def ai_dashboard():
    """Redirect to unified console."""
    return redirect(url_for('dashboard.dashboard_ai.ai_console'))

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
    return redirect(url_for('dashboard.dashboard_ai.ai_console'))

@bp.route('/ai/auto_tag', methods=['POST'])
@login_required
def ai_auto_tag():
    """V33: Trigger AI Auto-Tagging for a lead."""
    lead_id = request.form.get('lead_id')
    if lead_id:
        log_queue.put({'type': 'ai_auto_tag', 'lead_id': int(lead_id)})
        flash('AI Auto-Tagging queued.', 'success')
    return redirect(request.referrer or url_for('dashboard.dashboard_ai.ai_console'))

@bp.route('/ai/auto_tag_all', methods=['POST'])
@login_required
def ai_auto_tag_all():
    """Queue AI auto-tagging for all leads."""
    leads = Lead.query.all()
    for lead in leads:
        log_queue.put({'type': 'ai_auto_tag', 'lead_id': lead.id})
    flash(f'Queued {len(leads)} leads for AI auto-tagging.', 'success')
    return redirect(url_for('dashboard.dashboard_ai.ai_console'))
