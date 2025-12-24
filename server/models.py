from . import db
from datetime import datetime
from typing import Optional, List, Dict, Any
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Integer, Boolean, Float, DateTime, ForeignKey
import json

class DatabaseModel(db.Model):
    """Base model with common helpers."""
    __abstract__ = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Lead(DatabaseModel):
    """Lead model with improved type hinting and JSON handling."""
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(100))
    notes: Mapped[Optional[str]] = mapped_column(Text)
    
    # JSON Fields
    holehe_data: Mapped[Optional[str]] = mapped_column(Text) 
    scan_status: Mapped[str] = mapped_column(String(20), default='idle')
    last_scan: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    tags: Mapped[Optional[str]] = mapped_column(String(256), default='')
    custom_fields: Mapped[Optional[str]] = mapped_column(Text, default='{}')
    
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    @property
    def custom_fields_data(self) -> Dict[str, Any]:
        """Auto-deserialized custom fields."""
        if not self.custom_fields: return {}
        try: return json.loads(self.custom_fields)
        except: return {}

    @custom_fields_data.setter
    def custom_fields_data(self, value: Dict[str, Any]):
        self.custom_fields = json.dumps(value)

    @property
    def holehe_sites(self) -> List[str]:
        """Auto-deserialized holehe sites."""
        if not self.holehe_data: return []
        try: return json.loads(self.holehe_data)
        except: return []

class Link(DatabaseModel):
    """Link model with full typing."""
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    destination: Mapped[str] = mapped_column(String(2048), nullable=False)
    
    # Security
    password_hash: Mapped[Optional[str]] = mapped_column(String(128))
    enable_captcha: Mapped[bool] = mapped_column(Boolean, default=False)
    max_clicks: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    expire_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    expiration_minutes: Mapped[int] = mapped_column(Integer, default=0)
    
    # Routing / Cloaking
    ios_url: Mapped[Optional[str]] = mapped_column(String(2048))
    android_url: Mapped[Optional[str]] = mapped_column(String(2048))
    safe_url: Mapped[Optional[str]] = mapped_column(String(2048))
    block_vpn: Mapped[bool] = mapped_column(Boolean, default=False)
    block_bots: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_no_js: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Scheduling
    schedule_start_hour: Mapped[Optional[int]] = mapped_column(Integer)
    schedule_end_hour: Mapped[Optional[int]] = mapped_column(Integer)
    schedule_timezone: Mapped[str] = mapped_column(String(32), default='UTC')
    
    # Filters
    block_adblock: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_countries: Mapped[Optional[str]] = mapped_column(String(50))
    
    # Parity
    public_masked_url: Mapped[Optional[str]] = mapped_column(String(512))
    
    # Email Gate
    require_email: Mapped[bool] = mapped_column(Boolean, default=False)
    email_policy: Mapped[str] = mapped_column(String(20), default='all')
    
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    
    # Custom HTML
    custom_html: Mapped[Optional[str]] = mapped_column(Text)
    
    # Relationships
    visits: Mapped[List["Visit"]] = relationship(back_populates="link", lazy=True)

class Visit(DatabaseModel):
    id: Mapped[int] = mapped_column(primary_key=True)
    link_id: Mapped[int] = mapped_column(ForeignKey('link.id'), nullable=False)
    
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(500))
    referrer: Mapped[Optional[str]] = mapped_column(String(500))
    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Environment
    os_family: Mapped[Optional[str]] = mapped_column(String(64))
    device_type: Mapped[Optional[str]] = mapped_column(String(64))
    
    # Geo / Network
    isp: Mapped[Optional[str]] = mapped_column(String(128))
    org: Mapped[Optional[str]] = mapped_column(String(128))
    hostname: Mapped[Optional[str]] = mapped_column(String(256))
    city: Mapped[Optional[str]] = mapped_column(String(64))
    country: Mapped[Optional[str]] = mapped_column(String(64))
    lat: Mapped[Optional[float]] = mapped_column(Float)
    lon: Mapped[Optional[float]] = mapped_column(Float)
    
    # Fingerprinting
    screen_res: Mapped[Optional[str]] = mapped_column(String(32))
    timezone: Mapped[Optional[str]] = mapped_column(String(64))
    browser_bot: Mapped[bool] = mapped_column(Boolean, default=False)
    browser_language: Mapped[Optional[str]] = mapped_column(String(10))
    adblock: Mapped[bool] = mapped_column(Boolean, default=False)
    
    ai_summary: Mapped[Optional[str]] = mapped_column(String(512))
    canvas_hash: Mapped[Optional[str]] = mapped_column(String(64))
    webgl_renderer: Mapped[Optional[str]] = mapped_column(String(256))
    email: Mapped[Optional[str]] = mapped_column(String(256))
    
    # Pro Fingerprinting
    battery_level: Mapped[Optional[str]] = mapped_column(String(20))
    cpu_cores: Mapped[Optional[int]] = mapped_column(Integer)
    ram_gb: Mapped[Optional[float]] = mapped_column(Float)
    etag: Mapped[Optional[str]] = mapped_column(String(64))
    fpjs_confidence: Mapped[Optional[float]] = mapped_column(Float)

    # Session Detector
    detected_sessions: Mapped[Optional[str]] = mapped_column(Text)
    
    link: Mapped["Link"] = relationship(back_populates="visits")

class User(UserMixin, DatabaseModel):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    
    # 2FA
    totp_secret: Mapped[Optional[str]] = mapped_column(String(32))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    backup_codes: Mapped[Optional[str]] = mapped_column(Text)
    passkey_credentials: Mapped[Optional[str]] = mapped_column(Text)

    @property
    def passkeys(self) -> List[Dict]:
        if not self.passkey_credentials: return []
        try: return json.loads(self.passkey_credentials)
        except: return []

    @passkeys.setter
    def passkeys(self, value: List[Dict]):
        self.passkey_credentials = json.dumps(value)
