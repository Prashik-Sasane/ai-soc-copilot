from fastapi.testclient import TestClient


def get_auth_header(client: TestClient) -> dict:
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@aisoc.io", "password": "AnalystSOC123!"}
    )
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_seed_playbooks(client: TestClient):
    headers = get_auth_header(client)
    res = client.post("/api/v1/knowledge/seed-playbooks", headers=headers)
    assert res.status_code == 200
    assert "message" in res.json()


def test_copilot_investigation_rag(client: TestClient):
    headers = get_auth_header(client)
    client.post("/api/v1/events/seed-demo", headers=headers)
    client.post("/api/v1/knowledge/seed-playbooks", headers=headers)

    inc_resp = client.get("/api/v1/incidents", headers=headers)
    incidents = inc_resp.json()["items"]
    incident_id = incidents[0]["id"] if incidents else None

    query_resp = client.post(
        "/api/v1/copilot/investigate",
        json={
            "query": "Explain this LSASS memory dump alert and recommend containment steps.",
            "incident_id": incident_id
        },
        headers=headers
    )
    assert query_resp.status_code == 200
    data = query_resp.json()
    assert "summary" in data
    assert "cited_evidence" in data
    assert "recommendations" in data
    assert len(data["cited_evidence"]) > 0
    assert data["investigation_id"].startswith("inv_")
    assert data.get("llm_used") is False
    source_types = {c["source_type"] for c in data["cited_evidence"]}
    assert source_types & {"event", "alert", "knowledge_base", "indicator"}


def test_copilot_weak_evidence_low_confidence(client: TestClient):
    headers = get_auth_header(client)
    query_resp = client.post(
        "/api/v1/copilot/investigate",
        json={"query": "What is happening with an incident that does not exist?"},
        headers=headers,
    )
    assert query_resp.status_code == 200
    data = query_resp.json()
    assert data["confidence"] <= 0.4
    assert any("weak" in x.lower() or "unavailable" in x.lower() or "Insufficient" in x for x in data["findings"] + data["limitations"])


def test_feedback_persists_for_investigation(client: TestClient):
    headers = get_auth_header(client)
    client.post("/api/v1/knowledge/seed-playbooks", headers=headers)
    query_resp = client.post(
        "/api/v1/copilot/investigate",
        json={"query": "Summarize current tenant evidence."},
        headers=headers,
    )
    inv_id = query_resp.json()["investigation_id"]
    fb = client.post(
        "/api/v1/feedback",
        json={"investigation_id": inv_id, "rating": "useful", "notes": "Grounded citations were usable."},
        headers=headers,
    )
    assert fb.status_code == 200
    assert "does not train" in fb.json()["message"].lower()
    audit = client.get("/api/v1/audit", headers=headers)
    assert audit.status_code == 200
    actions = [row["action"] for row in audit.json()]
    assert "feedback_submitted" in actions


def test_audit_is_tenant_scoped(client: TestClient):
    headers = get_auth_header(client)
    logs = client.get("/api/v1/audit", headers=headers).json()
    assert isinstance(logs, list)


def test_mitre_techniques(client: TestClient):
    response = client.get("/api/v1/mitre/techniques")
    assert response.status_code == 200
    techs = response.json()
    assert len(techs) > 0
    assert any(t["technique_id"] == "T1059.001" for t in techs)


def test_mitre_mapping(client: TestClient):
    response = client.post(
        "/api/v1/mitre/map",
        json={"text": "powershell.exe -enc SQBFAA comsvcs.dll MiniDump lsass.exe"}
    )
    assert response.status_code == 200
    mappings = response.json()
    assert len(mappings) >= 2
    technique_ids = [m["technique_id"] for m in mappings]
    assert "T1059.001" in technique_ids
    assert "T1003.001" in technique_ids
    assert all(m.get("status") == "candidate" for m in mappings)
