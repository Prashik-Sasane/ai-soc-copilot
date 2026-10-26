from datetime import datetime, timezone
import uuid

from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.schemas.copilot import CopilotResponse
from app.services.ai_workflow import AISocCopilotWorkflow


def add_alert_with_event(db, *, tenant="tenant_default", hostname="WORKSTATION-089"):
    suffix = uuid.uuid4().hex[:10]
    event = SecurityEvent(
        id=f"evt_db_{suffix}",
        event_id=f"source_evt_{suffix}",
        timestamp=datetime.now(timezone.utc),
        source="edr",
        event_type="process_creation",
        severity="high",
        hostname=hostname,
        user="analyst-test",
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand ABCD",
        raw_data='{"test":"sanitized fixture"}',
        metadata_json={},
        tenant_id=tenant,
        is_simulated="false",
    )
    alert = Alert(
        id=f"alt_{suffix}",
        title="Encoded PowerShell execution",
        description="Fixture alert",
        severity="high",
        status="new",
        source="edr",
        rule_name="Encoded PowerShell",
        detection_rule_id="DET_TEST",
        event_ids=[event.id],
        asset_id=hostname,
        affected_user="analyst-test",
        tenant_id=tenant,
        is_simulated="false",
        created_at=event.timestamp,
    )
    db.add_all([event, alert])
    db.flush()
    return alert, event


def base_state(query, tenant="tenant_default", alert_id=None):
    return {
        "query": query,
        "tenant_id": tenant,
        "user_id": "user_test",
        "incident_id": None,
        "alert_id": alert_id,
        "indicator_value": None,
        "target_hostname": None,
        "target_user": None,
        "incident_context": {},
        "excluded_evidence": [],
        "retrieved_events": [],
        "retrieved_alerts": [],
        "retrieved_indicators": [],
        "retrieved_rag_chunks": [],
        "mitre_hypotheses": [],
        "summary": "",
        "findings": [],
        "cited_evidence": [],
        "recommendations": [],
        "finding_details": [],
        "timeline": [],
        "missing_data": [],
        "confidence": 0.0,
        "confidence_rationale": "",
        "status": "no_evidence",
        "limitations": [],
        "investigation_id": "",
        "error": None,
    }


def test_hostname_query_fetches_only_exact_host_alert_and_event(db_session):
    alert, event = add_alert_with_event(db_session)
    add_alert_with_event(db_session, hostname="DC01.doazlab.com")
    state = base_state("Explain LSASS alert on WORKSTATION-089")

    state = AISocCopilotWorkflow.node_query_understanding(state)
    state = AISocCopilotWorkflow.node_evidence_retrieval(state, db_session)

    assert state["target_hostname"] == "WORKSTATION-089"
    assert [item["id"] for item in state["retrieved_alerts"]] == [alert.id]
    assert [item["id"] for item in state["retrieved_events"]] == [event.id]


def test_alert_from_other_host_is_excluded_for_requested_host(db_session):
    alert, _ = add_alert_with_event(db_session, hostname="DC01.doazlab.com")
    state = base_state("Investigate alert on WORKSTATION-089", alert_id=alert.id)

    state = AISocCopilotWorkflow.node_query_understanding(state)
    state = AISocCopilotWorkflow.node_evidence_retrieval(state, db_session)

    assert state["retrieved_alerts"] == []
    assert state["retrieved_events"] == []
    assert state["excluded_evidence"][0]["source_id"] == alert.id
    assert "another or unknown host was excluded" in state["limitations"][0]


def test_alert_id_lookup_is_exact_and_tenant_scoped(db_session):
    alert, event = add_alert_with_event(db_session, tenant="tenant_a")
    state = base_state(f"Investigate alert {alert.id}", tenant="tenant_a")

    state = AISocCopilotWorkflow.node_query_understanding(state)
    state = AISocCopilotWorkflow.node_evidence_retrieval(state, db_session)
    assert [item["id"] for item in state["retrieved_alerts"]] == [alert.id]
    assert [item["id"] for item in state["retrieved_events"]] == [event.id]

    wrong_tenant = base_state(f"Investigate alert {alert.id}", tenant="tenant_b")
    wrong_tenant = AISocCopilotWorkflow.node_query_understanding(wrong_tenant)
    wrong_tenant = AISocCopilotWorkflow.node_evidence_retrieval(wrong_tenant, db_session)
    assert wrong_tenant["retrieved_alerts"] == []
    assert wrong_tenant["retrieved_events"] == []


def test_langgraph_returns_validated_structured_report(db_session):
    alert, _ = add_alert_with_event(db_session)
    report = AISocCopilotWorkflow.run_investigation(
        db_session,
        query=f"Investigate alert {alert.id}",
        user_id="user_test",
        tenant_id="tenant_default",
    )

    assert report["status"] == "needs_validation"
    CopilotResponse.model_validate(report)
    assert not any(item.startswith("Intent:") for item in report["findings"])
    assert report["incident"]["alert_id"] == alert.id
    assert report["finding_details"]
    citation_ids = {item["citation_id"] for item in report["cited_evidence"]}
    assert all(
        ref in citation_ids
        for finding in report["finding_details"]
        for ref in finding["evidence_refs"]
    )
    assert all(
        ref in citation_ids
        for recommendation in report["recommendations"]
        for ref in recommendation.get("evidence_refs", [])
    )
    assert "not a probability" in report["confidence_rationale"]
