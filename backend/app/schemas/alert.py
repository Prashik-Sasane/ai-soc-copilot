from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    source: str
    rule_name: Optional[str] = None
    event_ids: List[str] = []
    asset_id: Optional[str] = None
    is_simulated: Optional[bool] = False


class AlertUpdateStatus(BaseModel):
    status: str  # new, acknowledged, investigating, dismissed, resolved
    assigned_to: Optional[str] = None
    dismiss_reason: Optional[str] = None


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    source: str
    rule_name: Optional[str] = None
    
    event_ids: List[str] = []
    correlated_group_id: Optional[str] = None
    correlation_reason: Optional[str] = None
    link_reasons: Optional[List] = None
    incident_id: Optional[str] = None
    mitre_candidates: Optional[List] = None
    base_severity: Optional[str] = None
    risk_score: Optional[int] = None
    confidence: Optional[float] = None
    risk_factors: Optional[Dict[str, Any]] = None
    detection_rule_version: Optional[str] = None
    detection_rule_id: Optional[str] = None
    
    asset_id: Optional[str] = None
    affected_user: Optional[str] = None
    assigned_to: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    dismiss_reason: Optional[str] = None
    
    tenant_id: str
    is_simulated: str
    created_at: datetime
    updated_at: datetime


class AlertListResponse(BaseModel):
    items: List[AlertRead]
    total: int
    page: int
    size: int
