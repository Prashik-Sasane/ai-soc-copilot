from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "high"
    alert_ids: List[str] = []
    indicator_ids: List[str] = []
    is_simulated: Optional[bool] = False


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    lead_analyst_id: Optional[str] = None
    alert_ids: Optional[List[str]] = None
    indicator_ids: Optional[List[str]] = None


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    lead_analyst_id: Optional[str] = None
    alert_ids: List[str] = []
    indicator_ids: List[str] = []
    mitre_techniques: List[str] = []
    mitre_mappings: Optional[List[Dict[str, Any]]] = None
    severity_rationale: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    affected_users: Optional[List[str]] = None
    change_history_json: Optional[List[Dict[str, Any]]] = None
    
    timeline_json: List[Dict[str, Any]] = []
    recommendations_json: List[Dict[str, Any]] = []
    
    tenant_id: str
    is_simulated: str
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    items: List[IncidentRead]
    total: int
    page: int
    size: int
