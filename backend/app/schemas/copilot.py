from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class CopilotQueryRequest(BaseModel):
    query: str = Field(..., json_schema_extra={"example": "Explain this alert and suggest containment steps."})
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    indicator_value: Optional[str] = None
    include_mitre: Optional[bool] = True


class EvidenceCitation(BaseModel):
    citation_id: str
    source_type: str  # alert, event, knowledge_base, indicator
    source_id: str
    title: str
    snippet: str
    relevance_score: float = 0.90


class RecommendationItem(BaseModel):
    category: str  # investigative vs response
    title: str
    description: str
    priority: str  # high, medium, low
    requires_approval: bool = False


class CopilotResponse(BaseModel):
    investigation_id: str
    query: str
    summary: str
    findings: List[str]
    mitre_mappings: List[Dict[str, Any]] = []
    cited_evidence: List[EvidenceCitation] = []
    recommendations: List[RecommendationItem] = []
    confidence: float = 0.88
    limitations: List[str] = []
    timestamp: datetime


class InvestigationHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    query: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    workflow_state: str
    summary: Optional[str] = None
    confidence: float
    created_at: datetime
