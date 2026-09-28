from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.investigation import InvestigationHistory
from app.schemas.copilot import CopilotQueryRequest, CopilotResponse, InvestigationHistoryRead
from app.services.ai_workflow import AISocCopilotWorkflow

router = APIRouter()


@router.post("/investigate", response_model=CopilotResponse)
@router.post("/query", response_model=CopilotResponse)
def run_investigation(
    query_req: CopilotQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not query_req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")

    res = AISocCopilotWorkflow.run_investigation(
        db=db,
        query=query_req.query,
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        incident_id=query_req.incident_id,
        alert_id=query_req.alert_id
    )
    return res


@router.get("/history", response_model=List[InvestigationHistoryRead])
def get_investigation_history(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    items = (
        db.query(InvestigationHistory)
        .filter(
            InvestigationHistory.tenant_id == current_user.tenant_id,
            InvestigationHistory.user_id == current_user.id
        )
        .order_by(InvestigationHistory.created_at.desc())
        .limit(limit)
        .all()
    )
    return items
