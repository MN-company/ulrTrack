from flask import Blueprint, request, jsonify
from flask_login import login_required
from ..extensions import log_queue, db
from ..models import Lead, Visit
from ..config import Config

bp = Blueprint('api', __name__, url_prefix='/api')

@bp.route('/beacon', methods=['POST'])
def receive_beacon():
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            v_id = data.get('visit_id')
            if v_id:
                visit = Visit.query.get(v_id)
                if visit:
                    visit.screen_res = data.get('screen_res', 'Unknown')
                    visit.timezone = data.get('timezone', 'Unknown')
                    visit.browser_bot = bool(data.get('webdriver', False))
                    visit.browser_language = data.get('language', 'Unknown')
                    visit.adblock = bool(data.get('adblock', False))
                    visit.canvas_hash = data.get('canvas_hash')
                    visit.webgl_renderer = data.get('webgl_renderer')
                    
                    # V24 Pro Data
                    visit.cpu_cores = data.get('cpu_cores')
                    visit.ram_gb = data.get('ram_gb')
                    visit.battery_level = data.get('battery_level')
                    
                    db.session.commit()
                    
                    log_queue.put({
                        'type': 'ai_analyze',
                        'visit_id': visit.id,
                        'ua': visit.user_agent,
                        'screen': visit.screen_res
                    })
    except Exception as e:
        print(f"Beacon Error: {e}")
    return "OK", 200

@bp.route('/lead/<int:lead_id>/status')
@login_required
def lead_status(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    return jsonify({
        'status': lead.scan_status,
        'sites': lead.holehe_data, 
        'last_scan': lead.last_scan.isoformat() if lead.last_scan else None
    })
@bp.route('/log_session', methods=['POST'])
def log_session():
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            v_id = data.get('visit_id')
            sessions = data.get('sessions', [])
            if v_id and sessions:
                visit = Visit.query.get(v_id)
                if visit:
                    import json
                    # Merge with existing
                    existing = []
                    if visit.detected_sessions:
                        try: existing = json.loads(visit.detected_sessions)
                        except: pass
                    
                    # Add new uniq
                    existing.extend([s for s in sessions if s not in existing])
                    visit.detected_sessions = json.dumps(existing)
                    db.session.commit()
    except Exception as e:
        print(f"Session Log Error: {e}")
    return "OK", 200
