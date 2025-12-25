"""
Security & 2FA Management Routes
Handles TOTP setup, backup codes, and passkey registration.
"""
from flask import Blueprint, render_template, request, redirect, flash, url_for, session
from flask_login import login_required, current_user
import pyotp
import qrcode
import io
import base64
import json
import secrets
import bcrypt

from ...models import User, db
from ...config import Config
from ...extensions import limiter

bp = Blueprint('dashboard_security', __name__)

@bp.route('/security')
@login_required
def security_settings():
    """Security management page."""
    user = User.query.get(current_user.id)
    
    # Count backup codes
    backup_count = 0
    if user.backup_codes:
        try:
            backup_count = len(json.loads(user.backup_codes))
        except:
            pass
    
    # Count passkeys
    passkey_count = 0
    if user.passkey_credentials:
        try:
            passkey_count = len(json.loads(user.passkey_credentials))
        except:
            pass
    
    return render_template('security_settings.html',
                         user=user,
                         backup_count=backup_count,
                         passkey_count=passkey_count)

@bp.route('/security/2fa/setup')
@login_required
def setup_2fa():
    """Generate TOTP secret and show QR code."""
    user = User.query.get(current_user.id)
    
    if user.totp_enabled:
        flash('2FA is already enabled. Disable it first to set up again.', 'warning')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    # Generate new secret
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret
    
    # Generate QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.username,
        issuer_name='ULRTrack Dashboard'
    )
    
    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    qr_code_base64 = base64.b64encode(buf.getvalue()).decode()
    
    return render_template('2fa_setup.html',
                         secret=secret,
                         qr_code=qr_code_base64,
                         username=user.username)

@bp.route('/security/2fa/verify_setup', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def verify_2fa_setup():
    """Verify TOTP code and enable 2FA."""
    user = User.query.get(current_user.id)
    secret = session.get('temp_totp_secret')
    
    if not secret:
        flash('Session expired. Please start 2FA setup again.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    code = request.form.get('totp_code')
    totp = pyotp.TOTP(secret)
    
    if totp.verify(code, valid_window=1):
        # Code valid! Enable 2FA
        user.totp_secret = secret
        user.totp_enabled = True
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(6).upper() for _ in range(10)]
        
        # Hash backup codes before storing
        hashed_codes = [bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode() for code in backup_codes]
        user.backup_codes = json.dumps(hashed_codes)
        
        db.session.commit()
        session.pop('temp_totp_secret', None)
        
        # Show backup codes to user (only time they'll see them)
        session['new_backup_codes'] = backup_codes
        flash('2FA enabled successfully!', 'success')
        return redirect(url_for('dashboard.dashboard_security.show_backup_codes'))
    else:
        flash('Invalid code. Please try again.', 'error')
        return redirect(url_for('dashboard.dashboard_security.setup_2fa'))

@bp.route('/security/2fa/backup_codes')
@login_required
def show_backup_codes():
    """Show newly generated backup codes (one-time view)."""
    backup_codes = session.pop('new_backup_codes', None)
    
    if not backup_codes:
        flash('Backup codes have already been displayed.', 'warning')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    return render_template('backup_codes.html', backup_codes=backup_codes)

@bp.route('/security/2fa/regenerate_backup', methods=['POST'])
@login_required
def regenerate_backup_codes():
    """Regenerate backup codes."""
    user = User.query.get(current_user.id)
    
    if not user.totp_enabled:
        flash('2FA is not enabled.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    # Generate new backup codes
    backup_codes = [secrets.token_hex(6).upper() for _ in range(10)]
    hashed_codes = [bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode() for code in backup_codes]
    
    user.backup_codes = json.dumps(hashed_codes)
    db.session.commit()
    
    session['new_backup_codes'] = backup_codes
    flash('Backup codes regenerated!', 'success')
    return redirect(url_for('dashboard.dashboard_security.show_backup_codes'))

@bp.route('/security/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA for user."""
    user = User.query.get(current_user.id)
    
    # Require password confirmation
    password = request.form.get('password')
    if not password:
        flash('Password required to disable 2FA.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    from werkzeug.security import check_password_hash
    if not check_password_hash(user.password_hash, password):
        flash('Incorrect password.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    # Disable 2FA
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.session.commit()
    
    flash('2FA disabled.', 'success')
    return redirect(url_for('dashboard.dashboard_security.security_settings'))

@bp.route('/security/password', methods=['POST'])
@login_required
def change_password():
    """Change user password."""
    user = User.query.get(current_user.id)
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    # Verify current
    from werkzeug.security import check_password_hash, generate_password_hash
    if not check_password_hash(user.password_hash, current_password):
        flash('Current password incorrect.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    # Verify match
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
    
    # Verify strength (basic)
    if len(new_password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('dashboard.dashboard_security.security_settings'))
        
    # Update
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    flash('Password updated successfully.', 'success')
    return redirect(url_for('dashboard.dashboard_security.security_settings'))
