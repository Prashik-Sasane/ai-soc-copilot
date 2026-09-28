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
    # Seed scenario & playbooks first
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
