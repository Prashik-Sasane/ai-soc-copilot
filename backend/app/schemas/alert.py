from datetime import datetime
from typing import Optional, List
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
    
    asset_id: Optional[str] = None
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
