from flask import Blueprint, render_template, request, redirect, flash, url_for, make_response
from flask_login import login_required, current_user
import hashlib
import io
import segno

from ...models import Link, Visit
from ...extensions import db
from ...config import Config
from ...utils import generate_slug, shorten_with_isgd

bp = Blueprint('dashboard_links', __name__)

@bp.route('/')
@bp.route('')
@login_required
def dashboard_home():
    """Command Center / Main Dashboard"""
    try:
        from ...models import Lead
        
        # Get data for Command Center
        links = Link.query.order_by(Link.created_at.desc()).all()
        visits = Visit.query.order_by(Visit.timestamp.desc()).limit(50).all()
        leads = Lead.query.all()
        
        return render_template('dashboard.html', 
                              links=links,
                              visits=visits,
                              leads=leads, 
                              server_url=Config.SERVER_URL)
    except Exception as e:
        print(f"DASHBOARD ERROR: {e}")
        return f"Dashboard Error: {e}", 500

@bp.route('/links')
@login_required
def links():
    """Campaigns List"""
    links = Link.query.order_by(Link.created_at.desc()).all()
    return render_template('links.html', links=links)

@bp.route('/create', methods=['POST'])
@login_required
def create_link():
    dest = request.form.get('destination')
    slug = request.form.get('slug')
    
    if not dest:
        flash('Destination required', 'error')
        return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
    if not slug:
        slug = generate_slug()
    if Link.query.filter_by(slug=slug).first():
        flash('Slug exists', 'error')
        return redirect(url_for('dashboard.dashboard_links.dashboard_home'))

    new_link = Link(
        destination=dest, 
        slug=slug, 
        block_bots=request.form.get('block_bots') in ['true', 'on', '1'], 
        block_vpn=request.form.get('block_vpn') in ['true', 'on', '1'],
        enable_captcha=request.form.get('enable_captcha') in ['true', 'on', '1'],
        require_email=request.form.get('require_email') in ['true', 'on', '1'],
        email_policy=request.form.get('email_policy', 'all')
    )
    
    if request.form.get('mask_url'):
         full_url = f"{Config.SERVER_URL}/{slug}"
         masked = shorten_with_isgd(full_url)
         if masked: new_link.public_masked_url = masked

    db.session.add(new_link)
    db.session.commit()
    flash(f'Link created: /{slug}', 'success')
    return redirect(url_for('dashboard.dashboard_links.dashboard_home'))

@bp.route('/create_full', methods=['GET', 'POST'])
@login_required
def create_full():
    """Full link creation form with all options."""
    if request.method == 'POST':
        dest = request.form.get('destination')
        slug = request.form.get('slug')
        
        if not dest:
            flash('Destination required', 'error')
            return redirect(url_for('dashboard.dashboard_links.create_full'))
        if not slug:
            slug = generate_slug()
        if Link.query.filter_by(slug=slug).first():
            flash('Slug exists', 'error')
            return redirect(url_for('dashboard.dashboard_links.create_full'))
        
        new_link = Link(
            destination=dest,
            slug=slug,
            block_bots=request.form.get('block_bots') == 'true',
            block_vpn=request.form.get('block_vpn') == 'true',
            block_adblock=request.form.get('block_adblock') == 'true',
            enable_captcha=request.form.get('enable_captcha') == 'true',
            require_email=request.form.get('require_email') == 'true',
            email_policy=request.form.get('email_policy', 'all'),
            ios_url=request.form.get('ios_url') or None,
            android_url=request.form.get('android_url') or None,
            safe_url=request.form.get('safe_url') or None,
            allowed_countries=request.form.get('allowed_countries') or None,
            schedule_start_hour=int(request.form.get('schedule_start_hour')) if request.form.get('schedule_start_hour') else None,
            schedule_end_hour=int(request.form.get('schedule_end_hour')) if request.form.get('schedule_end_hour') else None,
            schedule_timezone=request.form.get('schedule_timezone') or 'UTC',
            max_clicks=int(request.form.get('max_clicks') or 0),
            expiration_minutes=int(request.form.get('expiration_minutes') or 0)
        )
        
        # Password
        if request.form.get('password'):
            new_link.password_hash = hashlib.sha256(request.form.get('password').encode()).hexdigest()
        
        # Mask URL
        if request.form.get('mask_link'):
            full_url = f"{Config.SERVER_URL}/{slug}"
            masked = shorten_with_isgd(full_url)
            if masked: new_link.public_masked_url = masked
        
        db.session.add(new_link)
        db.session.commit()
        flash(f'Link created: /{slug}', 'success')
        return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
    
    return render_template('create_full.html', server_url=Config.SERVER_URL)

@bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_link(id):
    link = Link.query.get(id)
    if link:
        Visit.query.filter_by(link_id=link.id).delete()
        db.session.delete(link)
        db.session.commit()
        flash('Link deleted', 'success')
    return redirect(url_for('dashboard.dashboard_links.dashboard_home'))

@bp.route('/edit/<slug>', methods=['GET', 'POST'])
@login_required
def edit_link(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    
    if request.method == 'POST':
        link.destination = request.form.get('destination')
        link.block_bots = request.form.get('block_bots') == 'true'
        link.block_vpn = request.form.get('block_vpn') == 'true'
        link.enable_captcha = request.form.get('enable_captcha') == 'true'
        link.require_email = request.form.get('require_email') == 'true'
        link.email_policy = request.form.get('email_policy', 'all')
        link.safe_url = request.form.get('safe_url') or None
        link.allowed_countries = request.form.get('allowed_countries') or None
        
        # Password
        password = request.form.get('password')
        if password:
            link.password_hash = hashlib.sha256(password.encode()).hexdigest()
        elif request.form.get('remove_password'):
            link.password_hash = None
        
        db.session.commit()
        flash('Link updated', 'success')
        return redirect(url_for('dashboard.dashboard_links.dashboard_home'))
    
    return render_template('edit.html', link=link, server_url=Config.SERVER_URL)

@bp.route('/qr/<slug>')
@login_required
def qr_code(slug):
    """Generate QR code for link."""
    full_url = f"{Config.SERVER_URL}/{slug}"
    qr = segno.make(full_url)
    buf = io.BytesIO()
    qr.save(buf, kind='png', scale=10)
    buf.seek(0)
    
    response = make_response(buf.getvalue())
    response.headers.set('Content-Type', 'image/png')
    response.headers.set('Content-Disposition', 'inline', filename=f'{slug}_qr.png')
    return response

@bp.route('/qr_view/<slug>')
@login_required
def qr_view(slug):
    link = Link.query.filter_by(slug=slug).first_or_404()
    return render_template('qr_view.html', link=link, server_url=Config.SERVER_URL)

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Global settings page."""
    
    # Path to data files
    data_dir = os.path.join(current_app.root_path, 'data')
    os.makedirs(data_dir, exist_ok=True)
    disposable_path = os.path.join(data_dir, 'disposable_domains.txt')
    
    # Ensure file exists
    if not os.path.exists(disposable_path):
        with open(disposable_path, 'w') as f: f.write('')

    if request.method == 'POST':
        # 1. Update .env (System Settings)
        from ...utils import update_env_file
        
        env_updates = {
            'GEMINI_API_KEY': request.form.get('api_key'),
            'SERVER_URL': request.form.get('server_url'),
            'HOLEHE_CMD': request.form.get('holehe_cmd'),
            'GEMINI_MODEL': request.form.get('gemini_model'),
            'AI_SYSTEM_PROMPT': request.form.get('ai_prompt')
        }
        
        # Filter None and update
        keys_to_update = {k: v for k, v in env_updates.items() if v is not None}
        if keys_to_update:
            update_env_file(keys_to_update)
            
        # 2. Update Disposable Domains List
        disposable_domains = request.form.get('disposable_domains', '')
        # Clean and validate
        clean_domains = [d.strip().lower() for d in disposable_domains.split('\n') if d.strip()]
        try:
            with open(disposable_path, 'w') as f:
                f.write('\n'.join(clean_domains))
        except Exception as e:
            flash(f'Error saving domains: {e}', 'error')

        flash('Settings saved. Restart required for system changes.', 'success')
        return redirect(url_for('dashboard.dashboard_links.settings'))
    
    # Load current values
    try:
        with open(disposable_path, 'r') as f:
            disposable_content = f.read()
    except:
        disposable_content = ""
        
    return render_template('settings.html',
                         api_key=Config.GEMINI_API_KEY,
                         server_url=Config.SERVER_URL,
                         holehe_cmd=os.getenv('HOLEHE_CMD', 'holehe'),
                         gemini_model=os.getenv('GEMINI_MODEL', 'gemini-1.5-pro'),
                         ai_prompt=os.getenv('AI_SYSTEM_PROMPT', ''),
                         disposable_domains=disposable_content)
