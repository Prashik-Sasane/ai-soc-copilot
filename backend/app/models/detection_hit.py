from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, UniqueConstraint

from app.core.database import Base


class DetectionHit(Base):
    """Idempotency ledger for one tenant-scoped event/rule evaluation."""
    __tablename__ = "detection_hits"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_db_id", "rule_id", name="uq_detection_hit_tenant_event_rule"),
    )

    id = Column(String, primary_key=True)
    tenant_id = Column(String, nullable=False, index=True)
    event_db_id = Column(String, nullable=False, index=True)
    rule_id = Column(String, nullable=False, index=True)
    alert_id = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
