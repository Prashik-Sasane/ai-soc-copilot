import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.incident import Incident
from app.models.audit import AuditLog
from app.schemas.incident import IncidentRead, IncidentListResponse, IncidentCreate, IncidentUpdate
from app.services.correlation_engine import CorrelationEngine

router = APIRouter()


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    is_simulated: Optional[str] = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Incident).filter(Incident.tenant_id == current_user.tenant_id)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    if is_simulated:
        query = query.filter(Incident.is_simulated == is_simulated)

    total = query.count()
    items = query.order_by(Incident.created_at.desc()).offset((page - 1) * size).limit(size).all()

    return IncidentListResponse(items=items, total=total, page=page, size=size)


@router.post("", response_model=IncidentRead)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = Incident(
        id=f"inc_{uuid.uuid4().hex[:10]}",
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        status="new",
        alert_ids=incident_in.alert_ids,
        indicator_ids=incident_in.indicator_ids,
        tenant_id=current_user.tenant_id,
        is_simulated="true" if incident_in.is_simulated else "false"
    )
    db.add(inc)

    audit = AuditLog(
        id=f"audit_{uuid.uuid4().hex[:12]}",
        user_id=current_user.id,
        user_email=current_user.email,
        action="incident_created",
        resource_type="incident",
        resource_id=inc.id,
        details_json={"title": inc.title, "severity": inc.severity},
        tenant_id=current_user.tenant_id
    )
    db.add(audit)
    db.commit()
    db.refresh(inc)
    return inc


@router.post("/trigger-correlation")
def trigger_correlation(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incidents = CorrelationEngine.correlate_alerts(db=db, tenant_id=current_user.tenant_id)
    return {
        "message": f"Correlation job completed. Created {len(incidents)} new incident(s).",
        "new_incident_ids": [i.id for i in incidents]
    }


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id, Incident.tenant_id == current_user.tenant_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return inc


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: str,
    update_data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id, Incident.tenant_id == current_user.tenant_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if update_data.title is not None:
        inc.title = update_data.title
    if update_data.description is not None:
        inc.description = update_data.description
    if update_data.severity is not None:
        inc.severity = update_data.severity
    if update_data.status is not None:
        inc.status = update_data.status
    if update_data.lead_analyst_id is not None:
        inc.lead_analyst_id = update_data.lead_analyst_id

    audit = AuditLog(
        id=f"audit_{uuid.uuid4().hex[:12]}",
        user_id=current_user.id,
        user_email=current_user.email,
        action="incident_updated",
        resource_type="incident",
        resource_id=inc.id,
        details_json=update_data.model_dump(exclude_unset=True),
        tenant_id=current_user.tenant_id
    )
    db.add(audit)
    db.commit()
    db.refresh(inc)
    return inc
