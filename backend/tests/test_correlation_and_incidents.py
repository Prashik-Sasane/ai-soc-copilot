from unittest.mock import patch
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
    client.post("/api/v1/events/seed-demo", headers=headers)
    corr_resp = client.post("/api/v1/incidents/trigger-correlation", headers=headers)
    assert corr_resp.status_code == 200
    assert "message" in corr_resp.json()


def test_list_incidents_and_link_reasons(client: TestClient):
    headers = get_auth_header(client)
    response = client.get("/api/v1/incidents", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    if data["total"] > 0:
        incident = client.get(f"/api/v1/incidents/{data['items'][0]['id']}", headers=headers).json()
        assert incident.get("severity_rationale") or incident.get("description")
        assert "change_history_json" in incident


def test_incident_update_persists_history(client: TestClient):
    headers = get_auth_header(client)
    listing = client.get("/api/v1/incidents", headers=headers).json()
    if listing["total"] == 0:
        client.post("/api/v1/events/seed-demo", headers=headers)
        listing = client.get("/api/v1/incidents", headers=headers).json()
    incident_id = listing["items"][0]["id"]
    patched = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
        headers=headers,
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "investigating"
    history = patched.json().get("change_history_json") or []
    assert any(h.get("action") == "analyst_update" for h in history)


def test_enrich_indicator_unknown_without_providers(client: TestClient):
    headers = get_auth_header(client)
    resp = client.post(
        "/api/v1/indicators/enrich",
        json={"indicator_value": "198.51.100.44"},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["indicator_value"] == "198.51.100.44"
    assert data["risk_level"] in {"unknown", "not_found"}
    assert data.get("lookup_status") in {"not_configured", "not_found", "unknown", "provider_unavailable"}
    assert data["risk_level"] != "clean"


def test_enrich_indicator_mocked_virustotal(client: TestClient):
    headers = get_auth_header(client)

    class DummyResp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 40, "suspicious": 2, "harmless": 10, "undetected": 8},
                        "tags": ["c2"],
                    }
                }
            }

    from app.core.config import settings
    previous = settings.VT_API_KEY
    settings.VT_API_KEY = "test-vt-key"
    try:
        with patch("app.services.threat_intel_service.httpx.get", return_value=DummyResp()):
            resp = client.post(
                "/api/v1/indicators/enrich",
                json={"indicator_value": "203.0.113.10"},
                headers=headers,
            )
    finally:
        settings.VT_API_KEY = previous
    assert resp.status_code == 200
    assert resp.json()["lookup_status"] in {"ok", "not_found"}


def test_provider_http_failure_is_unavailable(client: TestClient):
    headers = get_auth_header(client)
    import httpx

    def boom(*_args, **_kwargs):
        raise httpx.ConnectError("refused")

    from app.core.config import settings
    previous = settings.VT_API_KEY
    settings.VT_API_KEY = "test-vt-key"
    try:
        with patch("app.services.threat_intel_service.httpx.get", side_effect=boom):
            resp = client.post(
                "/api/v1/indicators/enrich",
                json={"indicator_value": "203.0.113.99"},
                headers=headers,
            )
    finally:
        settings.VT_API_KEY = previous
    assert resp.status_code == 200
    assert resp.json()["lookup_status"] in {"provider_unavailable", "not_found", "unknown"}
    assert resp.json()["risk_level"] != "clean"
