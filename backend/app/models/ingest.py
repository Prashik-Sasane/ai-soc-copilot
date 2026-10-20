from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON, Integer
from app.core.database import Base


class IngestSource(Base):
    __tablename__ = "ingest_sources"

    id = Column(String, primary_key=True, index=True)
    source_id = Column(String, index=True, nullable=False)
    display_name = Column(String, nullable=False)
    connector_type = Column(String, default="webhook")  # webhook, file, demo, vendor_poller
    vendor = Column(String, nullable=True)
    status = Column(String, default="waiting")  # waiting, connected, error, disabled
    last_event_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    events_accepted = Column(Integer, default=0)
    events_rejected = Column(Integer, default=0)
    tenant_id = Column(String, default="tenant_default", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class IngestParseError(Base):
    __tablename__ = "ingest_parse_errors"

    id = Column(String, primary_key=True, index=True)
    source_id = Column(String, index=True, nullable=True)
    job_id = Column(String, index=True, nullable=True)
    record_index = Column(Integer, nullable=True)
    error_type = Column(String, default="parse_error")
    message = Column(Text, nullable=False)
    raw_preview = Column(Text, nullable=True)
    tenant_id = Column(String, default="tenant_default", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
