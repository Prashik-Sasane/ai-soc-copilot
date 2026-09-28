import json
from fastapi.testclient import TestClient


def get_auth_header(client: TestClient) -> dict:
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@aisoc.io", "password": "AnalystSOC123!"}
    )
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_seed_demo_scenario(client: TestClient):
    headers = get_auth_header(client)
    response = client.post("/api/v1/events/seed-demo", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "details" in data
    assert data["details"]["is_simulated"] is True


def test_list_events(client: TestClient):
    headers = get_auth_header(client)
    response = client.get("/api/v1/events", headers=headers)
    assert response.status_code == 200
    items = response.json()
    assert isinstance(items, list)
    assert len(items) > 0


def test_list_alerts(client: TestClient):
    headers = get_auth_header(client)
    response = client.get("/api/v1/alerts", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] > 0


def test_update_alert_status(client: TestClient):
    headers = get_auth_header(client)
    alerts_resp = client.get("/api/v1/alerts", headers=headers)
    alert_id = alerts_resp.json()["items"][0]["id"]

    patch_resp = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "acknowledged", "assigned_to": "analyst@aisoc.io"},
        headers=headers
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "acknowledged"
    assert patch_resp.json()["assigned_to"] == "analyst@aisoc.io"


def test_dashboard_metrics(client: TestClient):
    headers = get_auth_header(client)
    response = client.get("/api/v1/dashboard/metrics", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert "incidents" in data
    assert data["alerts"]["total"] > 0
