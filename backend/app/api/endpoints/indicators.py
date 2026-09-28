from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.indicator import Indicator
from app.schemas.indicator import IndicatorRead, IndicatorEnrichRequest
from app.services.threat_intel_service import ThreatIntelService

router = APIRouter()


@router.get("", response_model=List[IndicatorRead])
def list_indicators(
    indicator_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Indicator).filter(Indicator.tenant_id == current_user.tenant_id)
    if indicator_type:
        query = query.filter(Indicator.indicator_type == indicator_type)
    if risk_level:
        query = query.filter(Indicator.risk_level == risk_level)

    return query.order_by(Indicator.updated_at.desc()).limit(limit).all()


@router.post("/enrich", response_model=IndicatorRead)
def enrich_indicator(
    enrich_req: IndicatorEnrichRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not enrich_req.indicator_value.strip():
        raise HTTPException(status_code=400, detail="Indicator value cannot be empty.")

    ind = ThreatIntelService.enrich_indicator(
        db=db,
        indicator_val=enrich_req.indicator_value,
        indicator_type=enrich_req.indicator_type,
        tenant_id=current_user.tenant_id
    )
    return ind
