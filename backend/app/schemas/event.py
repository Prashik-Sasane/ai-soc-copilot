from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class SecurityEventCreate(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    source: str = Field(..., json_schema_extra={"example": "edr"})  # edr, firewall, network, identity, dns, cloud, siem
    event_type: str = Field(..., json_schema_extra={"example": "process_creation"})
    severity: str = Field("low", json_schema_extra={"example": "medium"})
    
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_hash: Optional[str] = None
    hostname: Optional[str] = None
    
    raw_data: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None
    is_simulated: Optional[bool] = False


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_hash: Optional[str] = None
    hostname: Optional[str] = None
    
    raw_data: str
    metadata_json: Optional[Dict[str, Any]] = None
    ingest_source_id: Optional[str] = None
    parse_warnings: Optional[List[str]] = None
    tenant_id: str
    is_simulated: str
    created_at: datetime


class IngestionBatchResponse(BaseModel):
    total_received: int
    accepted_count: int
    rejected_count: int
    errors: List[str] = []
    job_id: str
    duplicate_count: int = 0
    alerts_created: int = 0
    incidents_created: int = 0
    ingest_source_id: Optional[str] = None
    is_simulated: bool = False
