"""Database models for PromptGuard."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class AuditEvent(Base):
    """Audit log entry for guard decisions."""
    
    __tablename__ = "audit_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    channel = Column(String(50), nullable=False)
    decision = Column(String(20), nullable=False)
    score = Column(Float, nullable=False)
    threshold = Column(Integer, nullable=False)
    text_snippet = Column(Text, nullable=False)
    matched_rules = Column(Text, nullable=True)
    reasons = Column(Text, nullable=True)
    

class ConfigHistory(Base):
    """Configuration change history."""
    
    __tablename__ = "config_history"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    key = Column(String(100), nullable=False)
    old_value = Column(String(200), nullable=True)
    new_value = Column(String(200), nullable=False)
    changed_by = Column(String(100), nullable=True)


def init_db(database_url: str):
    """Initialize database and create tables."""
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return engine


def get_session_maker(engine):
    """Create session maker for database."""
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)
