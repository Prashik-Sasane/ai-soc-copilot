from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON, Float
from app.core.database import Base


class InvestigationHistory(Base):
    __tablename__ = "investigation_history"

    id = Column(String, primary_key=True, index=True)
    query = Column(Text, nullable=False)
    incident_id = Column(String, index=True, nullable=True)
    alert_id = Column(String, index=True, nullable=True)
    user_id = Column(String, index=True, nullable=False)
    
    workflow_state = Column(String, default="completed")
    summary = Column(Text, nullable=True)
    response_json = Column(JSON, nullable=True)  # Structured response object
    cited_evidence = Column(JSON, default=list)  # List of evidence references
    mitre_mappings = Column(JSON, default=list)  # MITRE candidate mappings
    confidence = Column(Float, default=0.85)
    
    tenant_id = Column(String, default="tenant_default", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(String, primary_key=True, index=True)
    investigation_id = Column(String, index=True, nullable=False)
    user_id = Column(String, index=True, nullable=False)
    rating = Column(String, nullable=False)  # useful, incorrect, unsupported, incomplete
    notes = Column(Text, nullable=True)
    citations_json = Column(JSON, default=list)
    tenant_id = Column(String, default="tenant_default", index=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
