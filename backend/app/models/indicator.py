from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON, Float
from app.core.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(String, primary_key=True, index=True)
    indicator_value = Column(String, index=True, nullable=False)
    indicator_type = Column(String, index=True, nullable=False)  # ip, domain, url, hash, process
    
    reputation_score = Column(Float, default=0.0)  # 0.0 (clean) to 100.0 (malicious)
    risk_level = Column(String, default="unknown")  # clean, low, medium, high, critical, unknown
    threat_actor = Column(String, nullable=True)
    source_attribution = Column(String, nullable=True)
    
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    
    raw_enrichment = Column(JSON, nullable=True)  # Provider-specific details (VT, OTX, local mock)
    confidence = Column(Float, default=1.0)
    
    tenant_id = Column(String, default="tenant_default", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
