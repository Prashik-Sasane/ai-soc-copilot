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
    # Set only for knowledge retrieval; event/alert citations are exact DB references.
    relevance_score: Optional[float] = None
    hostname: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_ref: Optional[str] = None


class RecommendationItem(BaseModel):
    category: str  # investigative vs response
    title: str
    description: str
    priority: str  # high, medium, low
    requires_approval: bool = False
    rationale: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)
    expected_outcome: Optional[str] = None
    status: str = "proposed"


class InvestigationContext(BaseModel):
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    hostname: Optional[str] = None
    affected_user: Optional[str] = None
    severity: Optional[str] = None
    alert_status: Optional[str] = None


class FindingDetail(BaseModel):
    finding_id: str
    title: str
    status: str
    severity: Optional[str] = None
    description: str
    rationale: str
    evidence_refs: List[str] = Field(default_factory=list)
    missing_data: List[str] = Field(default_factory=list)


class EvidenceTimelineItem(BaseModel):
    timestamp: Optional[datetime] = None
    title: str
    event_type: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    evidence_ref: Optional[str] = None


class CopilotResponse(BaseModel):
    investigation_id: str
    query: str
    summary: str
    findings: List[str]
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    cited_evidence: List[EvidenceCitation] = Field(default_factory=list)
    recommendations: List[RecommendationItem] = Field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = Field(default_factory=list)
    llm_used: bool = False
    embedding_mode: str = "offline_hash"
    timestamp: datetime
    status: str = "needs_validation"
    incident: InvestigationContext = Field(default_factory=InvestigationContext)
    executive_summary: Optional[str] = None
    finding_details: List[FindingDetail] = Field(default_factory=list)
    timeline: List[EvidenceTimelineItem] = Field(default_factory=list)
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    missing_data: List[str] = Field(default_factory=list)
    confidence_rationale: Optional[str] = None
    sources: List[Dict[str, Any]] = Field(default_factory=list)


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
