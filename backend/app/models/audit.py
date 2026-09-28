from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id = Column(String, index=True, nullable=True)
    user_email = Column(String, index=True, nullable=True)
    
    action = Column(String, index=True, nullable=False)  # auth_login, alert_status_change, incident_created, action_approved
    resource_type = Column(String, index=True, nullable=False)  # alert, incident, copilot, system
    resource_id = Column(String, nullable=True)
    
    details_json = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    tenant_id = Column(String, default="tenant_default", index=True)
