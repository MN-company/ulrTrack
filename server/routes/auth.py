from flask import Blueprint, render_template, request, redirect, flash, url_for, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
import pyotp
import json

from ..extensions import login_manager, limiter
from ..config import Config
from ..models import User, db

bp = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    """Load user from database by ID."""
    try:
        if not user_id: return None
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Two-step login: username/password → optional 2FA."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
    
    if request.method == 'POST':
        # Step 1: Username & Password
        if 'username' in request.form and 'password' in request.form:
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                # Check if 2FA is enabled
                if user.totp_enabled:
                    # Store user_id in session for 2FA step
                    session['pending_2fa_user_id'] = user.id
                    session['2fa_verified'] = False
                    return render_template('2fa_verify.html', 
                                         username=username,
                                         has_passkey=bool(user.passkey_credentials),
                                         hide_nav=True)
                else:
                    # No 2FA, login directly
                    login_user(user, remember=True)
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
            else:
                flash('Invalid username or password', 'error')
        
        # Step 2: 2FA Verification
        elif 'totp_code' in request.form or 'backup_code' in request.form:
            user_id = session.get('pending_2fa_user_id')
            if not user_id:
                flash('Session expired. Please login again.', 'error')
                return redirect(url_for('auth.login'))
            
            user = User.query.get(user_id)
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('auth.login'))
            
            # Try TOTP code
            if 'totp_code' in request.form:
                totp_code = request.form.get('totp_code')
                totp = pyotp.TOTP(user.totp_secret)
                
                if totp.verify(totp_code, valid_window=1):  # Allow ±30 seconds
                    # Success!
                    session.pop('pending_2fa_user_id', None)
                    session.pop('2fa_verified', None)
                    login_user(user, remember=True)
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
                else:
                    flash('Invalid verification code', 'error')
                    return render_template('2fa_verify.html', 
                                         username=user.username,
                                         has_passkey=bool(user.passkey_credentials),
                                         hide_nav=True)
            
            # Try backup code
            elif 'backup_code' in request.form:
                backup_code = request.form.get('backup_code').strip()
                
                try:
                    backup_codes = json.loads(user.backup_codes or '[]')
                    
                    # Check if code matches any stored code
                    import bcrypt
                    for stored_code in backup_codes:
                        if bcrypt.checkpw(backup_code.encode(), stored_code.encode()):
                            # Valid backup code - remove it and login
                            backup_codes.remove(stored_code)
                            user.backup_codes = json.dumps(backup_codes)
                            db.session.commit()
                            
                            session.pop('pending_2fa_user_id', None)
                            session.pop('2fa_verified', None)
                            login_user(user, remember=True)
                            flash(f'Login successful! {len(backup_codes)} backup codes remaining.', 'success')
                            return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
                    
                    flash('Invalid backup code', 'error')
                    return render_template('2fa_verify.html', 
                                         username=user.username,
                                         has_passkey=bool(user.passkey_credentials),
                                         hide_nav=True)
                except Exception as e:
                    flash('Error verifying backup code', 'error')
                    return render_template('2fa_verify.html', 
                                         username=user.username,
                                         has_passkey=bool(user.passkey_credentials),
                                         hide_nav=True)
    
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    """Logout user."""
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))
