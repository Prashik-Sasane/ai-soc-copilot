from datetime import datetime, timezone
import uuid

from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.schemas.alert import AlertRead
from app.services.detection_service import DetectionService, load_rules
from app.services.risk_engine import RiskEngine


def event(event_type="activity", **kwargs):
    values = dict(
        id="evt_db_" + uuid.uuid4().hex,
        event_id="event-" + uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc),
        source="edr",
        event_type=event_type,
        severity="low",
        raw_data="{}",
        tenant_id="tenant_default",
        is_simulated="false",
    )
    values.update(kwargs)
    return SecurityEvent(**values)


def test_versioned_rules_validate_and_reject_broad_network_email_web_and_ifm():
    version, rules = load_rules()
    assert version
    assert rules
    for item in (
        event("network_conn", raw_data='{"message":"normal HTTPS connection"}'),
        event("email", source="email_gateway", raw_data='{"subject":"weekly newsletter"}'),
        event("file_create", process_name="w3wp.exe", raw_data='{"path":"site.aspx"}'),
        event("process_creation", command_line="tool.exe /ifm"),
        event("email", source="email_gateway", raw_data='{"subject":"monthly newsletter about anti-phishing policy"}'),
    ):
        assert DetectionService.evaluate_event(item) == []


def test_invalid_rule_operator_fails_closed(monkeypatch, tmp_path):
    import json
    import pytest
    from app.services import detection_service
    malformed = {
        "version": "bad",
        "rules": [{
            "id": "DET_TEST", "name": "Test", "title": "Test", "description": "Test",
            "base_severity": "high", "source": "test", "confidence_policy": "explicit_event_type",
            "mitre": [], "conditions": {"python": "arbitrary code"},
        }],
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(malformed), encoding="utf-8")
    monkeypatch.setattr(detection_service, "RULE_FILE", path)
    with pytest.raises(RuntimeError, match="invalid"):
        load_rules()


def test_specific_encoded_powershell_and_lsass_still_match():
    powershell = event(
        "process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
    )
    lsass = event(
        "process_creation",
        process_name="rundll32.exe",
        command_line="rundll32.exe comsvcs.dll MiniDump lsass.exe",
    )
    assert "DET_POWERSHELL_ENC" in {r["id"] for r in DetectionService.evaluate_event(powershell)}
    assert "DET_LSASS_DUMP" in {r["id"] for r in DetectionService.evaluate_event(lsass)}


def test_detection_hit_prevents_duplicate_alert_and_stays_tenant_scoped(db_session):
    item = event("process_creation", process_name="powershell.exe",
                 command_line="powershell.exe -EncodedCommand ABCD")
    first = DetectionService.process_events(db_session, [item], "tenant_default")
    second = DetectionService.process_events(db_session, [item], "tenant_default")
    assert first
    assert second == []
    assert first[0].risk_score is not None
    assert first[0].risk_factors["score_label"] == "heuristic_not_calibrated_probability"
    assert first[0].detection_rule_version
    response_model = AlertRead.model_validate(first[0])
    assert response_model.risk_score == first[0].risk_score


def test_risk_score_clamps_and_preserves_base_severity_floor():
    critical = RiskEngine.score("critical", "structured_text", evidence_present=False)
    assert 0 <= critical["risk_score"] <= 100
    assert critical["severity"] == "critical"
    assert critical["confidence"] == 0
    assert critical["risk_factors"]["asset_criticality"] == "unknown"


def test_risk_engine_rejects_misordered_threshold_configuration(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "RISK_MEDIUM_THRESHOLD", 60)
    monkeypatch.setattr(settings, "RISK_HIGH_THRESHOLD", 50)
    try:
        RiskEngine.score("medium", "explicit_event_type")
    except ValueError as exc:
        assert "thresholds must be ordered" in str(exc)
    else:
        raise AssertionError("Invalid threshold configuration must be rejected.")


def test_event_tenant_cannot_be_overridden_by_detection_caller():
    item = event("failed_login", tenant_id="tenant_other")
    try:
        DetectionService.process_events(None, [item], "tenant_default")
    except ValueError as exc:
        assert "outside the requested tenant" in str(exc)
    else:
        raise AssertionError("Cross-tenant event evaluation should be rejected.")
