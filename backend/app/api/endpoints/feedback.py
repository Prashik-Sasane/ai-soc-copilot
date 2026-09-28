import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.investigation import AnalystFeedback
from app.models.audit import AuditLog
from app.schemas.knowledge import FeedbackCreate, AuditLogRead

router = APIRouter()


@router.post("/feedback")
def submit_feedback(
    fb: FeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    entry = AnalystFeedback(
        id=f"fb_{uuid.uuid4().hex[:10]}",
        investigation_id=fb.investigation_id,
        user_id=current_user.id,
        rating=fb.rating,
        notes=fb.notes
    )
    db.add(entry)
    db.commit()
    return {"status": "success", "message": "Analyst feedback recorded for model evaluation."}


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
