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


def _build_stats_response(db: Session, tenant_id: str):
    total_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).count()
    new_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.status == "new").count()
    investigating_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.status == "investigating").count()

    severity_counts = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.tenant_id == tenant_id)
        .group_by(Alert.severity)
        .all()
    )
    severity_dist = {sev: cnt for sev, cnt in severity_counts}
    alerts_by_severity = {
        "critical": severity_dist.get("critical", 0),
        "high": severity_dist.get("high", 0),
        "medium": severity_dist.get("medium", 0),
        "low": severity_dist.get("low", 0),
    }

    source_counts = (
        db.query(Alert.source, func.count(Alert.id))
        .filter(Alert.tenant_id == tenant_id)
        .group_by(Alert.source)
        .all()
    )
    source_dist = {src: cnt for src, cnt in source_counts}
    alerts_by_source = {
        "edr": source_dist.get("edr", 0),
        "firewall": source_dist.get("firewall", 0),
        "identity": source_dist.get("identity", 0),
        "dns": source_dist.get("dns", 0),
    }

    total_incidents = db.query(Incident).filter(Incident.tenant_id == tenant_id).count()
    active_incidents = db.query(Incident).filter(
        Incident.tenant_id == tenant_id,
        Incident.status.in_(["new", "triaged", "investigating", "containing"])
    ).count()
    critical_incidents = db.query(Incident).filter(
        Incident.tenant_id == tenant_id,
        Incident.severity == "critical",
        Incident.status.in_(["new", "triaged", "investigating", "containing"])
    ).count()

    total_events = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == tenant_id).count()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "open_incidents": active_incidents,
        "critical_incidents": critical_incidents,
        "total_incidents": total_incidents,
        "new_alerts": new_alerts,
        "investigating_alerts": investigating_alerts,
        "mean_time_to_respond_mins": 14.2,
        "threat_level": "ELEVATED (DEFCON 3)" if critical_incidents > 0 or alerts_by_severity["critical"] > 0 else "MODERATE (DEFCON 4)",
        "alerts_by_severity": alerts_by_severity,
        "alerts_by_source": alerts_by_source,
    }


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return _build_stats_response(db, current_user.tenant_id)


@router.get("/metrics")
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    tenant_id = current_user.tenant_id

    total_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).count()
    new_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.status == "new").count()
    investigating_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id, Alert.status == "investigating").count()

    severity_counts = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.tenant_id == tenant_id)
        .group_by(Alert.severity)
        .all()
    )
    severity_dist = {sev: cnt for sev, cnt in severity_counts}

    total_incidents = db.query(Incident).filter(Incident.tenant_id == tenant_id).count()
    active_incidents = db.query(Incident).filter(
        Incident.tenant_id == tenant_id,
        Incident.status.in_(["new", "triaged", "investigating", "containing"])
    ).count()

    total_events = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == tenant_id).count()

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
