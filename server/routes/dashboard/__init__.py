"""
Dashboard Module Aggregator
Combines all dashboard sub-blueprints into single blueprint for registration.
"""
from flask import Blueprint
import hashlib

# Import all sub-blueprints
from .links import bp as links_bp
from .leads import bp as leads_bp
from .ai_routes import bp as ai_bp
from .architect import bp as architect_bp
from .exports import bp as exports_bp
from .stats import bp as stats_bp
from .security import bp as security_bp

# Create main dashboard blueprint
bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

# Register all sub-blueprints with main blueprint
bp.register_blueprint(links_bp)
bp.register_blueprint(leads_bp)
bp.register_blueprint(ai_bp)
bp.register_blueprint(architect_bp)
bp.register_blueprint(exports_bp)
bp.register_blueprint(stats_bp)
bp.register_blueprint(security_bp)

# Add shared template filter
def md5_filter(s):
    if not s: return ""
    return hashlib.md5(s.lower().encode('utf-8')).hexdigest()

bp.add_app_template_filter(md5_filter, 'md5')
