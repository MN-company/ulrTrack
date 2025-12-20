from flask import Blueprint, render_template, request, redirect, flash, url_for
from flask_login import login_user, logout_user, login_required, current_user
from ..extensions import login_manager
from ..config import Config
from ..models import User

bp = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    if user_id == "admin":
        return User("admin")
    return None

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard_home'))
    if request.method == 'POST':
        key = request.form.get('api_key')
        if key == Config.API_KEY:
            user = User("admin")
            login_user(user)
            return redirect(url_for('dashboard.dashboard_home'))
        else:
            flash('Access Denied: Invalid Key', 'error')
    return render_template('login.html', site_key=Config.TURNSTILE_SITE_KEY)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
