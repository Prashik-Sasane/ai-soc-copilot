import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.alert import Alert
from app.schemas.alert import AlertRead, AlertListResponse, AlertUpdateStatus, AlertCreate
from app.services.audit_service import write_audit

router = APIRouter()


@router.get("", response_model=AlertListResponse)
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    assigned_to: Optional[str] = None,
    q: Optional[str] = None,
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    is_simulated: Optional[str] = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert).filter(Alert.tenant_id == current_user.tenant_id)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if source:
        query = query.filter(Alert.source == source)
    if is_simulated:
        query = query.filter(Alert.is_simulated == is_simulated)
    if assigned_to:
        query = query.filter(Alert.assigned_to == assigned_to)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Alert.title.ilike(like), Alert.description.ilike(like), Alert.asset_id.ilike(like)))

    sort_col = getattr(Alert, sort, Alert.created_at)
    query = query.order_by(sort_col.asc() if order == "asc" else sort_col.desc())
    total = query.count()
    items = query.offset((page - 1) * size).limit(size).all()

    return AlertListResponse(items=items, total=total, page=page, size=size)


@router.post("", response_model=AlertRead)
def create_alert(
    alert_in: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    new_alert = Alert(
        id=f"alt_{uuid.uuid4().hex[:10]}",
        title=alert_in.title,
        description=alert_in.description,
        severity=alert_in.severity,
        source=alert_in.source,
        rule_name=alert_in.rule_name,
        event_ids=alert_in.event_ids,
        asset_id=alert_in.asset_id,
        tenant_id=current_user.tenant_id,
        is_simulated="true" if alert_in.is_simulated else "false"
    )
    db.add(new_alert)
    write_audit(
        db,
        action="alert_created",
        resource_type="alert",
        resource_id=new_alert.id,
        user=current_user,
        after={"title": new_alert.title, "severity": new_alert.severity},
    )
    db.commit()
    db.refresh(new_alert)
    return new_alert


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert_detail(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertRead)
def update_alert_status(
    alert_id: str,
    status_update: AlertUpdateStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    allowed = {"new", "acknowledged", "investigating", "escalated", "dismissed", "resolved"}
    if status_update.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {sorted(allowed)}")
    old = {"status": alert.status, "assigned_to": alert.assigned_to}
    alert.status = status_update.status
    if status_update.assigned_to:
        alert.assigned_to = status_update.assigned_to
    if status_update.status == "acknowledged":
        alert.acknowledged_at = datetime.now(timezone.utc)
    if status_update.dismiss_reason:
        alert.dismiss_reason = status_update.dismiss_reason
    after = {"status": alert.status, "assigned_to": alert.assigned_to}
    write_audit(
        db,
        action="alert_status_change",
        resource_type="alert",
        resource_id=alert.id,
        user=current_user,
        before=old,
        after=after,
        details={"dismiss_reason": status_update.dismiss_reason},
    )
    db.commit()
    db.refresh(alert)
    return alert
