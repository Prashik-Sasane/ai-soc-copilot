from fastapi.testclient import TestClient


def get_auth_header(client: TestClient) -> dict:
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@aisoc.io", "password": "AnalystSOC123!"}
    )
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_trigger_correlation(client: TestClient):
    headers = get_auth_header(client)
    # Seed demo scenario first
    client.post("/api/v1/events/seed-demo", headers=headers)

    corr_resp = client.post("/api/v1/incidents/trigger-correlation", headers=headers)
    assert corr_resp.status_code == 200
    assert "message" in corr_resp.json()


def test_list_incidents(client: TestClient):
    headers = get_auth_header(client)
    response = client.get("/api/v1/incidents", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] > 0


def test_enrich_indicator(client: TestClient):
    headers = get_auth_header(client)
    resp = client.post(
        "/api/v1/indicators/enrich",
        json={"indicator_value": "198.51.100.44"},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["indicator_value"] == "198.51.100.44"
    assert data["risk_level"] in ["high", "critical"]
