import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from datetime import datetime, timezone
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.incident import Incident
from app.schemas.incident import IncidentRead, IncidentListResponse, IncidentCreate, IncidentUpdate
from app.services.correlation_engine import CorrelationEngine
from app.services.audit_service import write_audit

router = APIRouter()


def _append_timeline_entry(inc: Incident, entry: dict) -> None:
    """Append an analyst lifecycle entry to the incident timeline and keep it ordered."""
    timeline = list(inc.timeline_json or [])
    timeline.append(entry)
    timeline.sort(key=lambda row: row.get("timestamp") or "")
    inc.timeline_json = timeline


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
    write_audit(
        db,
        action="incident_created",
        resource_type="incident",
        resource_id=inc.id,
        user=current_user,
        after={"title": inc.title, "severity": inc.severity},
    )
    db.commit()
    db.refresh(inc)
    return inc


@router.post("/trigger-correlation")
def trigger_correlation(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incidents = CorrelationEngine.correlate_alerts(db=db, tenant_id=current_user.tenant_id)
    db.commit()
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

    before = {
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "lead_analyst_id": inc.lead_analyst_id,
    }
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
    after = {
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "lead_analyst_id": inc.lead_analyst_id,
    }
    history = list(inc.change_history_json or [])
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": current_user.email,
        "action": "analyst_update",
        "before": before,
        "after": after,
    })
    inc.change_history_json = history
    if update_data.status is not None and update_data.status != before["status"]:
        _append_timeline_entry(
            inc,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "kind": "analyst_action",
                "event_type": "status_change",
                "title": f"Status: {before['status']} -> {update_data.status}",
                "description": f"{current_user.email} set incident status to '{update_data.status}'.",
                "severity": "info",
                "source": current_user.email,
            },
        )
    write_audit(
        db,
        action="incident_updated",
        resource_type="incident",
        resource_id=inc.id,
        user=current_user,
        before=before,
        after=after,
    )
    db.commit()
    db.refresh(inc)
    return inc


@router.post("/{incident_id}/recommendations/{index}/approve", response_model=IncidentRead)
def approve_recommendation(
    incident_id: str,
    index: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot approve response recommendations.")
    inc = db.query(Incident).filter(Incident.id == incident_id, Incident.tenant_id == current_user.tenant_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    recs = list(inc.recommendations_json or [])
    if index < 0 or index >= len(recs):
        raise HTTPException(status_code=404, detail="Recommendation not found.")
    rec = dict(recs[index])
    rec["approved"] = True
    rec["approved_by"] = current_user.email
    rec["approved_at"] = datetime.now(timezone.utc).isoformat()
    rec["execution_status"] = "approved_pending_external_action"
    recs[index] = rec
    inc.recommendations_json = recs
    _append_timeline_entry(
        inc,
        {
            "timestamp": rec["approved_at"],
            "kind": "analyst_action",
            "event_type": "recommendation_approved",
            "title": f"Approved: {rec.get('title') or 'recommendation'}",
            "description": (
                f"{current_user.email} approved this recommendation. Approval is recorded "
                "only; no containment is executed by this platform."
            ),
            "severity": "info",
            "source": current_user.email,
        },
    )
    history = list(inc.change_history_json or [])
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": current_user.email,
        "action": "recommendation_approved",
        "after": rec,
        "note": "Approval recorded only. No host isolation or destructive action was executed by this platform.",
    })
    inc.change_history_json = history
    write_audit(
        db,
        action="recommendation_approved",
        resource_type="incident",
        resource_id=inc.id,
        user=current_user,
        after=rec,
        details={"note": "No containment action was executed."},
        commit=True,
    )
    db.refresh(inc)
    return inc
