import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.investigation import AnalystFeedback, InvestigationHistory
from app.models.audit import AuditLog
from app.schemas.knowledge import FeedbackCreate, AuditLogRead
from app.services.audit_service import write_audit

router = APIRouter()


@router.post("/feedback")
def submit_feedback(
    fb: FeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inv = (
        db.query(InvestigationHistory)
        .filter(
            InvestigationHistory.id == fb.investigation_id,
            InvestigationHistory.tenant_id == current_user.tenant_id,
        )
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found for this tenant.")
    entry = AnalystFeedback(
        id=f"fb_{uuid.uuid4().hex[:10]}",
        investigation_id=fb.investigation_id,
        user_id=current_user.id,
        rating=fb.rating,
        notes=fb.notes,
        citations_json=fb.citations or inv.cited_evidence or [],
        tenant_id=current_user.tenant_id,
    )
    db.add(entry)
    write_audit(
        db,
        action="feedback_submitted",
        resource_type="investigation",
        resource_id=fb.investigation_id,
        user=current_user,
        details={"rating": fb.rating},
        commit=True,
    )
    return {
        "status": "success",
        "message": "Analyst feedback recorded for review. It does not train or fine-tune a model.",
        "feedback_id": entry.id,
    }


@router.get("/audit", response_model=List[AuditLogRead])
def get_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.tenant_id == current_user.tenant_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return logs
