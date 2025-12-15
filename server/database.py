from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# SQLite database setup
# Persistence: Use /app/data in Docker, or local ./server_data if running locally
DATA_DIR = os.getenv("DATA_DIR", "server_data")
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)
    
DATABASE_URL = f"sqlite:///{DATA_DIR}/shortener.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Link(Base):
    __tablename__ = "links"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, index=True, nullable=False)
    target_url = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # V3 Features
    expiration_date = Column(DateTime, nullable=True)
    max_clicks = Column(Integer, nullable=True)
    
    # V6 Ultimate Features
    is_active = Column(Boolean, default=True)
    
    # Security
    password_hash = Column(String, nullable=True)
    enable_captcha = Column(Boolean, default=False)
    block_vpn = Column(Boolean, default=False)
    
    # Smart Routing
    ios_target_url = Column(String, nullable=True)
    android_target_url = Column(String, nullable=True)
    
    # Time Routing (Simple: UTC Start-End hour)
    time_target_url = Column(String, nullable=True)
    time_start_hour = Column(Integer, nullable=True) # 0-23
    time_end_hour = Column(Integer, nullable=True)   # 0-23
    
    # Notifications
    webhook_url = Column(String, nullable=True)

class Visit(Base):
    __tablename__ = "visits"

    id = Column(Integer, primary_key=True, index=True)
    link_slug = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String)
    referrer = Column(String, nullable=True)
    is_bot = Column(Integer, default=0)
    # V3 Features
    is_mobile = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
 # 0=Human, 1=Bot

def init_db():
    Base.metadata.create_all(bind=engine)
