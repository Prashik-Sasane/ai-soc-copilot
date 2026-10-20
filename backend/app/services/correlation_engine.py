import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.services.mitre_service import MitreService


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _json_or_none(value: Optional[str]):
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


class CorrelationEngine:
    """
    Groups alerts using configurable time-window and entity overlap.
    Linking is association, not proof of a single actor.
    """

    @staticmethod
    def _load_events(db: Session, alert: Alert, tenant_id: str) -> List[SecurityEvent]:
        ids = alert.event_ids or []
        if not ids:
            return []
        return (
            db.query(SecurityEvent)
            .filter(SecurityEvent.id.in_(ids), SecurityEvent.tenant_id == tenant_id)
            .all()
        )

    @staticmethod
    def _entities(alert: Alert, events: List[SecurityEvent]) -> Dict[str, Set[str]]:
        hosts: Set[str] = set()
        users: Set[str] = set()
        ips: Set[str] = set()
        if alert.asset_id:
            hosts.add(alert.asset_id.lower())
        if getattr(alert, "affected_user", None):
            users.add(alert.affected_user.lower())
        for event in events:
            if event.hostname:
                hosts.add(event.hostname.lower())
            if event.user:
                users.add(event.user.lower())
            if event.src_ip:
                ips.add(event.src_ip)
            if event.dst_ip:
                ips.add(event.dst_ip)
        return {"hosts": hosts, "users": users, "ips": ips}

    @staticmethod
    def _aware(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

    @classmethod
    def _within_window(cls, a: Alert, b: Alert, window: int) -> bool:
        ta, tb = cls._aware(a.created_at), cls._aware(b.created_at)
        if ta is None or tb is None:
            return True
        return abs((ta - tb).total_seconds()) <= window * 60

    @classmethod
    def _link_reason(cls, a: Alert, b: Alert, a_ent: Dict[str, Set[str]], b_ent: Dict[str, Set[str]], window: int) -> Optional[str]:
        shared_hosts = a_ent["hosts"] & b_ent["hosts"]
        shared_users = a_ent["users"] & b_ent["users"]
        shared_ips = a_ent["ips"] & b_ent["ips"]
        reasons = []
        if shared_hosts:
            reasons.append(f"shared host {', '.join(sorted(shared_hosts)[:3])}")
        if shared_users:
            reasons.append(f"shared user {', '.join(sorted(shared_users)[:3])}")
        if shared_ips:
            reasons.append(f"shared IP {', '.join(sorted(shared_ips)[:3])}")
        if not reasons:
            return None
        return (
            f"Linked to `{b.id}` ({b.title}) via {'; '.join(reasons)} "
            f"inside a {window}-minute window. This is entity/time association, not confirmed attribution."
        )

    @classmethod
    def _extract_indicators(cls, db: Session, events: List[SecurityEvent], tenant_id: str) -> List[str]:
        ids: List[str] = []
        seen: Set[str] = set()
        for event in events:
            candidates = []
            if event.dst_ip:
                candidates.append(("ip", event.dst_ip))
            if event.domain:
                candidates.append(("domain", event.domain))
            if event.file_hash:
                candidates.append(("hash", event.file_hash))
            for kind, value in candidates:
                key = f"{kind}:{value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                existing = (
                    db.query(Indicator)
                    .filter(Indicator.tenant_id == tenant_id, Indicator.indicator_value == value)
                    .first()
                )
                if existing:
                    ids.append(existing.id)
                    continue
                ind = Indicator(
                    id=f"ind_{uuid.uuid4().hex[:10]}",
                    indicator_value=value,
                    indicator_type=kind,
                    reputation_score=0.0,
                    risk_level="unknown",
                    lookup_status="unknown",
                    source_attribution="Extracted from incident evidence; not live-enriched",
                    confidence=0.0,
                    raw_enrichment={"status": "not_enriched", "extracted_from_event": event.id},
                    tenant_id=tenant_id,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                )
                db.add(ind)
                db.flush()
                ids.append(ind.id)
        return ids

    @staticmethod
    def _event_summary(event: SecurityEvent) -> str:
        """Human-readable one-line summary built from structured fields.

        The previous version dumped the whole normalized event (raw JSON) into the
        timeline description, which was unreadable. We now describe the observable
        facts; the unmodified event remains retrievable via its event_id.
        """
        parts: List[str] = []
        if event.process_name:
            parts.append(f"Process: {event.process_name}")
        if event.command_line:
            command = " ".join(event.command_line.split())
            if len(command) > 300:
                command = command[:297] + "..."
            parts.append(f"Command: {command}")
        if event.user and event.user not in {"-", "unknown", "null"}:
            parts.append(f"User: {event.user}")
        if event.src_ip or event.dst_ip:
            parts.append(f"Network: {event.src_ip or '-'} -> {event.dst_ip or '-'}")
        if event.domain:
            parts.append(f"Domain: {event.domain}")
        if event.file_hash:
            parts.append(f"Hash: {event.file_hash}")
        if not parts:
            parts.append(f"{event.event_type.replace('_', ' ')} recorded on {event.hostname or 'unknown host'}")
        return " | ".join(parts)

    @staticmethod
    def _event_signature(event: SecurityEvent) -> tuple:
        """Key used to collapse repeated identical activity into a single timeline step."""
        command = " ".join((event.command_line or "").split()).replace('"', "").lower()
        return (
            event.event_type,
            (event.hostname or "").lower(),
            (event.process_name or "").lower(),
            command,
            (event.user or "").lower(),
            event.src_ip or "",
            event.dst_ip or "",
            event.domain or "",
            event.file_hash or "",
        )

    @staticmethod
    def _event_origin(event: SecurityEvent) -> Dict[str, Any]:
        """Describe where the event came from, so similar-looking steps stay distinguishable."""
        origin: Dict[str, Any] = {
            "source": event.source,
            "event_ref": event.event_id,
            "provider": None,
            "channel": None,
            "windows_event_id": None,
            "record_id": None,
        }
        data = _json_or_none(event.raw_data)
        if isinstance(data, dict):
            # Some sources store the vendor payload nested as its own JSON string.
            inner = data
            nested = _json_or_none(data.get("raw_data")) if isinstance(data.get("raw_data"), str) else None
            if isinstance(nested, dict):
                inner = {**data, **nested}
            origin["provider"] = inner.get("provider")
            origin["channel"] = inner.get("channel")
            origin["windows_event_id"] = inner.get("windows_event_id")
            origin["record_id"] = inner.get("record_id")
        return origin

    @classmethod
    def _stage(cls, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Ground an attack-stage label for a step using the ATT&CK candidate mapping."""
        evidence = " ".join(filter(None, [events[0].command_line, events[0].raw_data]))
        mappings = MitreService.map_evidence_to_mitre(evidence)
        if not mappings:
            return {"stage": "Unmapped activity", "technique_id": None, "technique_name": None, "confidence": None}
        top = mappings[0]
        return {
            "stage": top["tactic"] or "Unmapped activity",
            "technique_id": top["technique_id"],
            "technique_name": top["name"],
            "confidence": top["confidence"],
        }

    @classmethod
    def _timeline(cls, alerts: List[Alert], events: List[SecurityEvent], reason: str) -> List[dict]:
        # Collapse repeated identical activity (e.g. the same command run 8 times) into one
        # step that discloses how many times it occurred, instead of 8 duplicate rows.
        grouped: Dict[tuple, List[SecurityEvent]] = {}
        for event in events:
            grouped.setdefault(cls._event_signature(event), []).append(event)

        items = []
        for group in grouped.values():
            group.sort(key=lambda e: e.timestamp or datetime.now(timezone.utc))
            first, last = group[0], group[-1]
            occurrences = len(group)
            alert_ids = sorted(
                {a.id for a in alerts for e in group if e.id in (a.event_ids or [])}
            )
            stage = cls._stage(group)
            title = f"{first.event_type.replace('_', ' ')} on {first.hostname or 'unknown host'}"
            if occurrences > 1:
                title = f"{title} (x{occurrences})"
            items.append(
                {
                    "timestamp": (first.timestamp or datetime.now(timezone.utc)).isoformat(),
                    "kind": "event",
                    "event_type": first.event_type,
                    "title": title,
                    "description": cls._event_summary(first),
                    "severity": first.severity,
                    "source": first.source,
                    "event_id": first.id,
                    "event_ids": [e.id for e in group],
                    "alert_ids": alert_ids,
                    "occurrences": occurrences,
                    "first_seen": (first.timestamp or datetime.now(timezone.utc)).isoformat(),
                    "last_seen": (last.timestamp or first.timestamp or datetime.now(timezone.utc)).isoformat(),
                    "origin": cls._event_origin(first),
                    "is_simulated": first.is_simulated,
                    **stage,
                }
            )
        items.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "kind": "correlation",
                "event_type": "correlation_trigger",
                "title": "Alerts correlated into incident",
                "description": reason,
                "severity": "medium",
                "source": "correlation_engine",
                "stage": "Correlation",
                "technique_id": None,
                "technique_name": None,
                "confidence": None,
            }
        )
        items.sort(key=lambda row: row["timestamp"])
        return items

    @classmethod
    def correlate_alerts(
        cls, db: Session, tenant_id: str = "tenant_default", time_window_minutes: Optional[int] = None
    ) -> List[Incident]:
        window = time_window_minutes or settings.CORRELATION_WINDOW_MINUTES
        min_alerts = settings.CORRELATION_MIN_ALERTS

        # Select alerts by their own timestamps instead of wall-clock time. Forwarded /
        # replayed telemetry keeps the original event time, so a "now - window" cutoff
        # excluded everything and incidents could never form. The window is now enforced
        # per alert pair (see _within_window), which correlates backfilled data correctly.
        alerts = (
            db.query(Alert)
            .filter(Alert.tenant_id == tenant_id)
            .order_by(Alert.created_at.desc())
            .all()
        )
        if len(alerts) < min_alerts:
            return []

        event_cache: Dict[str, List[SecurityEvent]] = {}
        entity_cache: Dict[str, Dict[str, Set[str]]] = {}
        for alert in alerts:
            evts = cls._load_events(db, alert, tenant_id)
            event_cache[alert.id] = evts
            entity_cache[alert.id] = cls._entities(alert, evts)

        parent: Dict[str, str] = {a.id: a.id for a in alerts}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        links: Dict[str, List[str]] = {a.id: [] for a in alerts}
        for i, a in enumerate(alerts):
            for b in alerts[i + 1 :]:
                if not cls._within_window(a, b, window):
                    continue
                reason = cls._link_reason(a, b, entity_cache[a.id], entity_cache[b.id], window)
                if reason:
                    union(a.id, b.id)
                    links[a.id].append(reason)
                    links[b.id].append(
                        cls._link_reason(b, a, entity_cache[b.id], entity_cache[a.id], window) or reason
                    )

        groups: Dict[str, List[Alert]] = {}
        for alert in alerts:
            groups.setdefault(find(alert.id), []).append(alert)

        created_or_updated: List[Incident] = []
        for group in groups.values():
            if len(group) < min_alerts:
                continue
            group_events: List[SecurityEvent] = []
            for alert in group:
                group_events.extend(event_cache[alert.id])
            hosts = sorted({e.hostname for e in group_events if e.hostname} | {a.asset_id for a in group if a.asset_id})
            users = sorted({e.user for e in group_events if e.user} | {getattr(a, "affected_user", None) for a in group if getattr(a, "affected_user", None)})
            sources = sorted({a.source for a in group})
            max_sev = "low"
            for alert in group:
                if SEVERITY_RANK.get(alert.severity, 0) > SEVERITY_RANK.get(max_sev, 0):
                    max_sev = alert.severity
            asset_label = hosts[0] if hosts else "unattributed entity"
            correlation_reason = (
                f"Correlated {len(group)} alerts on entities [{', '.join(hosts[:5]) or 'unknown'}] "
                f"across sources [{', '.join(sources)}] within {window} minutes using host/user/IP overlap. "
                "Correlation indicates temporal and entity association, not definitive malicious intent."
            )
            group_id = f"corr_{uuid.uuid4().hex[:8]}"
            for alert in group:
                alert.correlated_group_id = group_id
                alert.correlation_reason = correlation_reason
                alert.link_reasons = links.get(alert.id, [])

            evidence_text = " ".join(
                filter(None, [e.command_line for e in group_events] + [e.raw_data for e in group_events] + [a.title for a in group])
            )
            mitre = MitreService.map_evidence_to_mitre(evidence_text)
            mappings = [
                {
                    "technique_id": m["technique_id"],
                    "name": m["name"],
                    "tactic": m["tactic"],
                    "status": "candidate",
                    "confidence": m["confidence"],
                    "rationale": m["rationale"],
                    "evidence_refs": m.get("evidence_refs", []),
                    "data_version": m.get("data_version"),
                    "source": m.get("source"),
                    "requires_analyst_validation": True,
                }
                for m in mitre
            ]
            indicator_ids = cls._extract_indicators(db, group_events, tenant_id)
            timeline = cls._timeline(group, group_events, correlation_reason)
            is_sim = "true" if any(a.is_simulated == "true" for a in group) else "false"
            title = f"Correlated security incident on {asset_label} ({len(group)} alerts)"

            existing_inc = None
            for alert in group:
                if alert.incident_id:
                    existing_inc = (
                        db.query(Incident)
                        .filter(Incident.id == alert.incident_id, Incident.tenant_id == tenant_id)
                        .first()
                    )
                    if existing_inc:
                        break
            if not existing_inc:
                existing_inc = (
                    db.query(Incident)
                    .filter(
                        Incident.tenant_id == tenant_id,
                        Incident.status.in_(["new", "triaged", "investigating"]),
                    )
                    .all()
                )
                match = None
                for inc in existing_inc:
                    if asset_label != "unattributed entity" and asset_label.lower() in (inc.title or "").lower():
                        match = inc
                        break
                existing_inc = match

            alert_ids = [a.id for a in group]
            if existing_inc:
                current_ids = list(dict.fromkeys((existing_inc.alert_ids or []) + alert_ids))
                existing_inc.alert_ids = current_ids
                existing_inc.indicator_ids = list(dict.fromkeys((existing_inc.indicator_ids or []) + indicator_ids))
                # Refresh the attack-chain evidence but keep analyst lifecycle entries so
                # the timeline stays cumulative instead of resetting on each re-correlation.
                preserved = [it for it in (existing_inc.timeline_json or []) if it.get("kind") == "analyst_action"]
                merged_timeline = timeline + preserved
                merged_timeline.sort(key=lambda row: row.get("timestamp") or "")
                existing_inc.timeline_json = merged_timeline
                merged = {m["technique_id"]: m for m in (existing_inc.mitre_mappings or [])}
                for m in mappings:
                    merged[m["technique_id"]] = m
                existing_inc.mitre_mappings = list(merged.values())
                existing_inc.mitre_techniques = list(merged.keys())
                existing_inc.affected_assets = hosts
                existing_inc.affected_users = users
                existing_inc.severity_rationale = (
                    f"Highest alert severity in the correlated set is `{max_sev}` "
                    f"from {len(group)} alerts and {len(group_events)} events."
                )
                history = list(existing_inc.change_history_json or [])
                history.append(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "actor": "correlation_engine",
                        "action": "alerts_merged",
                        "after": {"alert_ids": current_ids},
                    }
                )
                existing_inc.change_history_json = history
                if SEVERITY_RANK.get(max_sev, 0) > SEVERITY_RANK.get(existing_inc.severity, 0):
                    existing_inc.severity = max_sev
                for alert in group:
                    alert.incident_id = existing_inc.id
                created_or_updated.append(existing_inc)
            else:
                recs = [
                    {
                        "category": "investigative",
                        "title": "Review the linked evidence timeline",
                        "description": (
                            "Inspect each linked alert and cited event. Confirm the shared host/user/IP "
                            "overlap before treating this as a single intrusion."
                        ),
                        "priority": "high",
                        "requires_approval": False,
                        "citation": "correlation_engine",
                    }
                ]
                inc = Incident(
                    id=f"inc_{uuid.uuid4().hex[:10]}",
                    title=title,
                    description=correlation_reason,
                    severity=max_sev,
                    status="new",
                    alert_ids=alert_ids,
                    indicator_ids=indicator_ids,
                    mitre_techniques=[m["technique_id"] for m in mappings],
                    mitre_mappings=mappings,
                    severity_rationale=(
                        f"Highest alert severity in the correlated set is `{max_sev}` "
                        f"from {len(group)} alerts and {len(group_events)} events."
                    ),
                    affected_assets=hosts,
                    affected_users=users,
                    timeline_json=timeline,
                    recommendations_json=recs,
                    change_history_json=[
                        {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "actor": "correlation_engine",
                            "action": "created",
                            "after": {"alert_ids": alert_ids, "severity": max_sev},
                        }
                    ],
                    tenant_id=tenant_id,
                    is_simulated=is_sim,
                )
                db.add(inc)
                db.flush()
                for alert in group:
                    alert.incident_id = inc.id
                created_or_updated.append(inc)

        db.commit()
        return created_or_updated
