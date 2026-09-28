from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, index=True, default="medium")  # low, medium, high, critical
    status = Column(String, index=True, default="new")  # new, acknowledged, investigating, dismissed, resolved
    source = Column(String, index=True, nullable=False)
    rule_name = Column(String, index=True, nullable=True)
    
    event_ids = Column(JSON, default=list)  # List of related event UUIDs
    correlated_group_id = Column(String, index=True, nullable=True)
    correlation_reason = Column(Text, nullable=True)
    
    asset_id = Column(String, nullable=True)
    assigned_to = Column(String, nullable=True)  # User ID or email
    acknowledged_at = Column(DateTime, nullable=True)
    dismiss_reason = Column(Text, nullable=True)
    
    tenant_id = Column(String, default="tenant_default", index=True)
    is_simulated = Column(String, default="false")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
