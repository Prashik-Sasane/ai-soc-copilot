from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON, Integer
from app.core.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String, primary_key=True, index=True)
    event_id = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source = Column(String, index=True, nullable=False)  # edr, firewall, network, identity, dns, cloud, siem
    event_type = Column(String, index=True, nullable=False)  # process_creation, dns_query, network_conn, login
    severity = Column(String, default="low", index=True)  # low, medium, high, critical
    
    # Normalized Entity Fields
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    domain = Column(String, index=True, nullable=True)
    user = Column(String, index=True, nullable=True)
    process_name = Column(String, index=True, nullable=True)
    command_line = Column(Text, nullable=True)
    file_hash = Column(String, index=True, nullable=True)
    hostname = Column(String, index=True, nullable=True)
    
    # Metadata & Raw data
    raw_data = Column(Text, nullable=False)
    metadata_json = Column(JSON, nullable=True)
    tenant_id = Column(String, default="tenant_default", index=True)
    is_simulated = Column(String, default="false")  # "true" or "false"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
