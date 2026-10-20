from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, index=True, default="high")  # low, medium, high, critical
    status = Column(String, index=True, default="new")  # new, triaged, investigating, containing, eradicated, closed
    
    lead_analyst_id = Column(String, nullable=True)
    alert_ids = Column(JSON, default=list)  # Associated alert IDs
    indicator_ids = Column(JSON, default=list)  # Associated threat intel indicator IDs
    mitre_techniques = Column(JSON, default=list)  # List of ATT&CK technique IDs e.g. ["T1059.001"]
    mitre_mappings = Column(JSON, default=list)  # structured candidate vs confirmed mappings
    severity_rationale = Column(Text, nullable=True)
    affected_assets = Column(JSON, default=list)
    affected_users = Column(JSON, default=list)
    change_history_json = Column(JSON, default=list)
    
    timeline_json = Column(JSON, default=list)  # Chronological array of timeline objects
    recommendations_json = Column(JSON, default=list)  # List of investigative & response recommendations
    
    tenant_id = Column(String, default="tenant_default", index=True)
    is_simulated = Column(String, default="false")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
