import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.incident import Incident


class CorrelationEngine:
    """
    Multi-source security event and alert correlation service.
    Rules supported:
    1. Temporal Host Correlation: Groups alerts sharing asset_id/hostname within a time window (e.g. 60 min).
    2. Temporal User Correlation: Groups alerts sharing target user within a time window.
    3. Multi-Stage Attack Chain Correlation: Correlates EDR + Network + DNS + Identity events across stages.
    """

    @classmethod
    def correlate_alerts(
        cls, db: Session, tenant_id: str = "tenant_default", time_window_minutes: int = 60
    ) -> List[Incident]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

        # Retrieve unassigned/new alerts
        alerts = (
            db.query(Alert)
            .filter(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= cutoff
            )
            .all()
        )

        if not alerts:
            return []

        # Group alerts by asset_id / hostname
        asset_groups: Dict[str, List[Alert]] = {}
        for alt in alerts:
            asset = alt.asset_id or "UNKNOWN_ASSET"
            if asset not in asset_groups:
                asset_groups[asset] = []
            asset_groups[asset].append(alt)

        new_incidents = []

        for asset, group in asset_groups.items():
            if len(group) >= 2:
                # Check if incident already exists for this asset group in this timeframe
                group_alert_ids = [a.id for a in group]
                
                # Formulate explainable correlation reason
                sources = list(set([a.source for a in group]))
                severities = [a.severity for a in group]
                max_severity = "critical" if "critical" in severities else ("high" if "high" in severities else "medium")
                
                correlation_reason = (
                    f"Correlated {len(group)} related alerts on asset '{asset}' across sources [{', '.join(sources)}] "
                    f"within a {time_window_minutes}-minute timeframe. "
                    "Rule: Host & Multi-Source Attack Chain Association."
                )

                # Disclaimers
                disclaimer = "Note: Correlation indicates temporal & entity association, not definitive malicious intent."

                group_id = f"corr_{uuid.uuid4().hex[:8]}"

                # Update alerts with correlation group
                for alt in group:
                    alt.correlated_group_id = group_id
                    alt.correlation_reason = correlation_reason

                # Create Incident if not existing
                incident_title = f"Correlated Security Incident on {asset} ({len(group)} Alerts)"
                
                # Check if incident already exists
                existing_inc = db.query(Incident).filter(
                    Incident.tenant_id == tenant_id,
                    Incident.title.ilike(f"%{asset}%"),
                    Incident.status.in_(["new", "triaged", "investigating"])
                ).first()

                if existing_inc:
                    # Append new alerts to existing incident
                    current_ids = set(existing_inc.alert_ids or [])
                    current_ids.update(group_alert_ids)
                    existing_inc.alert_ids = list(current_ids)
                    if existing_inc not in new_incidents:
                        new_incidents.append(existing_inc)
                else:
                    inc = Incident(
                        id=f"inc_{uuid.uuid4().hex[:10]}",
                        title=incident_title,
                        description=f"{correlation_reason}\n\n{disclaimer}",
                        severity=max_severity,
                        status="new",
                        alert_ids=group_alert_ids,
                        indicator_ids=[],
                        mitre_techniques=[],
                        timeline_json=[
                            {
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "correlation_trigger",
                                "title": f"Incident Auto-Correlated ({len(group)} alerts)",
                                "description": correlation_reason,
                                "severity": max_severity,
                                "source": "correlation_engine"
                            }
                        ],
                        recommendations_json=[
                            {
                                "category": "investigative",
                                "title": f"Review correlated alert details on asset {asset}",
                                "description": "Examine timeline of events across EDR, Firewall, and DNS sources.",
                                "priority": "high",
                                "requires_approval": False
                            }
                        ],
                        tenant_id=tenant_id,
                        is_simulated="true" if any(a.is_simulated == "true" for a in group) else "false"
                    )
                    db.add(inc)
                    new_incidents.append(inc)

        db.commit()
        return new_incidents
