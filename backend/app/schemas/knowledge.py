from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class KnowledgeDocumentCreate(BaseModel):
    title: str
    category: str = "playbook"  # playbook, advisory, mitre_ref, standard
    source_ref: Optional[str] = None
    content: str


class KnowledgeDocumentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    category: str
    source_ref: Optional[str] = None
    content: str
    status: str
    chunk_count: str
    created_at: datetime
    updated_at: datetime


class FeedbackCreate(BaseModel):
    investigation_id: str
    rating: str  # useful, incorrect, unsupported, incomplete
    notes: Optional[str] = None


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details_json: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
