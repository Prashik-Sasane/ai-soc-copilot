from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.event import SecurityEvent

router = APIRouter()


@router.get("/metrics")
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_id = current_user.tenant_id

    # Alert Counts
    total_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).count()
    new_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.status == "new").count()
    investigating_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.status == "investigating").count()

    # Severity distribution
    severity_counts = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.tenant_id == tenant_id)
        .group_by(Alert.severity)
        .all()
    )
    severity_dist = {sev: cnt for sev, cnt in severity_counts}

    # Incident status
    total_incidents = db.query(Incident).filter(Incident.tenant_id == tenant_id).count()
    active_incidents = db.query(Incident).filter(
        Incident.tenant_id == tenant_id,
        Incident.status.in_(["new", "triaged", "investigating", "containing"])
    ).count()

    # Event count
    total_events = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == tenant_id).count()

    # Recent high-severity alerts
    recent_alerts = (
        db.query(Alert)
        .filter(Alert.tenant_id == tenant_id)
        .order_by(Alert.created_at.desc())
        .limit(5)
        .all()
    )

    return {
        "alerts": {
            "total": total_alerts,
            "new": new_alerts,
            "investigating": investigating_alerts,
            "severity_distribution": {
                "critical": severity_dist.get("critical", 0),
                "high": severity_dist.get("high", 0),
                "medium": severity_dist.get("medium", 0),
                "low": severity_dist.get("low", 0),
            }
        },
        "incidents": {
            "total": total_incidents,
            "active": active_incidents
        },
        "events": {
            "total": total_events
        },
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "source": a.source,
                "created_at": a.created_at,
                "is_simulated": a.is_simulated
            } for a in recent_alerts
        ]
    }
