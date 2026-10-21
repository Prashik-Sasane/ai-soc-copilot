"""Safe evaluator for versioned declarative detection rules."""
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.detection_hit import DetectionHit
from app.models.event import SecurityEvent
from app.services.mitre_service import MitreService
from app.services.risk_engine import CONFIDENCE_BY_POLICY, RiskEngine

RULE_FILE = Path(__file__).resolve().parents[1] / "detection" / "rules.v1.json"
OPS = {"all", "any", "event_type_in", "source_in", "text_any", "text_all", "text_none", "token_any", "process_or_command_has"}
SEVERITIES = {"low", "medium", "high", "critical"}


def _text(event: SecurityEvent) -> str:
    return " ".join(filter(None, [event.process_name, event.command_line, event.raw_data,
                                  event.event_type, event.domain, event.file_hash])).lower()


def _validate(node: Any) -> None:
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError("Condition must be a single supported operator.")
    op, value = next(iter(node.items()))
    if op not in OPS:
        raise ValueError(f"Unsupported condition operator: {op}")
    if op in {"all", "any"}:
        if not isinstance(value, list) or not value:
            raise ValueError(f"{op} requires conditions.")
        for child in value:
            _validate(child)
    elif op == "process_or_command_has":
        if not isinstance(value, str) or not value:
            raise ValueError(f"{op} requires a string.")
    elif not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{op} requires a list of strings.")


def load_rules() -> tuple[str, List[Dict[str, Any]]]:
    try:
        config = json.loads(RULE_FILE.read_text(encoding="utf-8"))
        version, rules = config["version"], config["rules"]
        seen = set()
        if set(config) != {"version", "rules"} or not isinstance(version, str) or not version or not isinstance(rules, list):
            raise ValueError("Expected version and rules.")
        for rule in rules:
            required = {"id", "name", "title", "description", "base_severity", "source", "confidence_policy", "mitre", "conditions"}
            if not isinstance(rule, dict) or not required.issubset(rule) or set(rule) != required:
                raise ValueError("Rule missing required fields.")
            if not isinstance(rule["id"], str) or not rule["id"] or rule["id"] in seen or rule["base_severity"] not in SEVERITIES:
                raise ValueError(f"Duplicate ID or invalid severity: {rule.get('id')}")
            if rule["confidence_policy"] not in CONFIDENCE_BY_POLICY:
                raise ValueError(f"Unknown confidence policy in {rule['id']}.")
            seen.add(rule["id"])
            if not isinstance(rule["mitre"], list) or not all(re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(t)) for t in rule["mitre"]):
                raise ValueError(f"Invalid ATT&CK ID: {rule['id']}")
            _validate(rule["conditions"])
        return version, rules
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        # Fail closed; never turn a malformed rule into permissive matching.
        raise RuntimeError(f"Detection rule configuration is invalid: {exc}") from exc


def _matches(node: Dict[str, Any], event: SecurityEvent) -> bool:
    op, value = next(iter(node.items()))
    text = _text(event)
    if op == "all":
        return all(_matches(child, event) for child in value)
    if op == "any":
        return any(_matches(child, event) for child in value)
    if op == "event_type_in":
        return (event.event_type or "").lower() in {v.lower() for v in value}
    if op == "source_in":
        return (event.source or "").lower() in {v.lower() for v in value}
    if op == "text_any":
        return any(v.lower() in text for v in value)
    if op == "text_all":
        return all(v.lower() in text for v in value)
    if op == "text_none":
        return not any(v.lower() in text for v in value)
    if op == "token_any":
        return any(re.search(rf"(?<![a-z0-9]){re.escape(v.lower())}(?![a-z0-9])", text) for v in value)
    if op == "process_or_command_has":
        return value.lower() in " ".join(filter(None, [event.process_name, event.command_line])).lower()
    return False


class DetectionService:
    @classmethod
    def evaluate_event(cls, event: SecurityEvent) -> List[Dict[str, Any]]:
        version, rules = load_rules()
        hits = [{**r, "severity": r["base_severity"], "version": version}
                for r in rules if _matches(r["conditions"], event)]
        if not hits and event.severity in {"high", "critical"}:
            hits.append({
                "id": "DET_SEVERITY_THRESHOLD", "name": "High-severity source event",
                "title": f"High-severity {event.event_type} from {event.source}",
                "description": "Source-provided severity is high or critical; validate source evidence.",
                "base_severity": event.severity, "severity": event.severity, "source": event.source,
                "confidence_policy": "source_severity", "mitre": [], "version": version,
                "conditions": {"event_type_in": [event.event_type]},
            })
        return hits

    @classmethod
    def process_events(cls, db: Session, events: List[SecurityEvent], tenant_id: str) -> List[Alert]:
        created = []
        for event in events:
            if event.tenant_id != tenant_id:
                raise ValueError("Cannot evaluate an event outside the requested tenant.")
            for rule in cls.evaluate_event(event):
                duplicate = db.query(DetectionHit.id).filter_by(
                    tenant_id=tenant_id, event_db_id=event.id, rule_id=rule["id"]
                ).first()
                if duplicate:
                    continue
                risk = RiskEngine.score(rule["base_severity"], rule["confidence_policy"])
                evidence = " ".join(filter(None, [event.command_line, event.raw_data,
                                                   event.process_name, event.event_type]))
                # Use the bundled, version-labelled catalog here so MITRE enrichment
                # cannot commit the shared ingestion transaction as a side effect.
                mapped = MitreService.map_evidence_to_mitre(evidence)
                allowed = set(rule.get("mitre", []))
                candidates = [{
                    "technique_id": m["technique_id"], "name": m["name"], "status": "candidate",
                    "confidence": m["confidence"], "rationale": m["rationale"],
                    "evidence_refs": m.get("evidence_refs", []), "data_version": m.get("data_version"),
                    "source": m.get("source"), "requires_analyst_validation": True,
                } for m in mapped if m["technique_id"] in allowed][:5]
                aid = f"alt_{uuid.uuid4().hex[:10]}"
                alert = Alert(
                    id=aid, title=rule["title"],
                    description=(f"Detection rule {rule['name']} matched event {event.event_id} "
                                 f"on asset {event.hostname or 'unknown'}. Evidence: {(event.raw_data or '')[:400]}"),
                    severity=risk["severity"], base_severity=risk["base_severity"],
                    risk_score=risk["risk_score"], confidence=risk["confidence"],
                    risk_factors=risk["risk_factors"], detection_rule_version=rule["version"],
                    status="new", source=event.source or rule["source"], rule_name=rule["name"],
                    detection_rule_id=rule["id"], event_ids=[event.id], asset_id=event.hostname,
                    affected_user=event.user, mitre_candidates=candidates, tenant_id=tenant_id,
                    is_simulated=event.is_simulated, created_at=event.timestamp or datetime.now(timezone.utc),
                )
                # Unique constraint handles races; savepoint avoids rolling back other events.
                try:
                    with db.begin_nested():
                        db.add(alert)
                        db.flush()
                        db.add(DetectionHit(id=f"dh_{uuid.uuid4().hex[:16]}", tenant_id=tenant_id,
                                            event_db_id=event.id, rule_id=rule["id"], alert_id=aid))
                        db.flush()
                    created.append(alert)
                except IntegrityError:
                    continue
        # The caller owns commit/rollback for the shared SQLAlchemy session.
        db.flush()
        return created
