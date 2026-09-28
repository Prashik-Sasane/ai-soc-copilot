from typing import Optional, List
from pydantic import BaseModel


class MitreTechniqueRead(BaseModel):
    technique_id: str  # e.g., T1059.001
    name: str  # e.g., PowerShell
    tactic: str  # e.g., Execution
    description: str
    platforms: List[str] = []
    data_sources: List[str] = []
    data_version: str = "v14.1"


class MitreMappingHypothesis(BaseModel):
    technique_id: str
    name: str
    tactic: str
    confidence: float  # 0.0 - 1.0
    rationale: str
    evidence_refs: List[str] = []
    requires_analyst_validation: bool = True
