from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.core.database import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(String, primary_key=True, index=True)  # T1059.001
    name = Column(String, nullable=False, index=True)
    tactic = Column(String, nullable=True, index=True)
    tactics = Column(JSON, default=list)
    description = Column(Text, nullable=True)
    platforms = Column(JSON, default=list)
    data_sources = Column(JSON, default=list)
    keywords = Column(JSON, default=list)
    source_url = Column(String, nullable=True)
    stix_id = Column(String, nullable=True, index=True)
    data_version = Column(String, nullable=True)
    retrieved_at = Column(DateTime, nullable=True)
    is_bundled_fallback = Column(String, default="false")
    tenant_id = Column(String, default="global", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
