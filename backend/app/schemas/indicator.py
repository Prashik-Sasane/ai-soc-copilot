from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class IndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator_value: str
    indicator_type: str
    reputation_score: float
    risk_level: str
    threat_actor: Optional[str] = None
    source_attribution: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw_enrichment: Optional[Dict[str, Any]] = None
    confidence: float
    created_at: datetime
    updated_at: datetime


class IndicatorEnrichRequest(BaseModel):
    indicator_value: str
    indicator_type: Optional[str] = None  # auto-detected if empty
