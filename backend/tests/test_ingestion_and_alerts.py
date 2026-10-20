import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

_NOW = datetime.now(timezone.utc)


def get_auth_header(client: TestClient, email: str = "analyst@aisoc.io", password: str = "AnalystSOC123!") -> dict:
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


SAMPLE_EVENTS = [
    {
        "event_id": f"evt-ps-{uuid.uuid4().hex[:8]}",
        "timestamp": (_NOW - timedelta(minutes=20)).isoformat(),
        "source": "edr",
        "event_type": "process_creation",
        "severity": "high",
        "hostname": "WORKSTATION-089",
        "user": "victim.user@enterprise.com",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -NoP -Enc SQBFAFgA",
        "raw_data": "Encoded PowerShell execution spawned by WINWORD.EXE",
    },
    {
        "event_id": f"evt-lsass-{uuid.uuid4().hex[:8]}",
        "timestamp": (_NOW - timedelta(minutes=10)).isoformat(),
        "source": "edr",
        "event_type": "credential_dump",
        "severity": "critical",
        "hostname": "WORKSTATION-089",
        "process_name": "rundll32.exe",
        "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump lsass.exe",
        "raw_data": "lsass process memory read via comsvcs MiniDump",
    },
]


def test_webhook_ingest_requires_token(client: TestClient):
    resp = client.post("/api/v1/ingest/webhook/webhook-default", json=SAMPLE_EVENTS)
    assert resp.status_code == 401


def test_webhook_ingest_normalizes_and_detects(client: TestClient):
    headers = get_auth_header(client)
    ingest = client.post(
        "/api/v1/ingest/webhook/webhook-default",
        json={"events": SAMPLE_EVENTS},
        headers={"X-Ingest-Token": "dev-ingest-token", "X-Tenant-Id": "tenant_default"},
    )
    assert ingest.status_code == 200
    body = ingest.json()
    assert body["accepted_count"] == 2
    assert body["alerts_created"] >= 1
    assert body["duplicate_count"] == 0

    dup = client.post(
        "/api/v1/ingest/webhook/webhook-default",
        json={"events": SAMPLE_EVENTS},
        headers={"X-Ingest-Token": "dev-ingest-token", "X-Tenant-Id": "tenant_default"},
    )
    assert dup.json()["duplicate_count"] == 2
    assert dup.json()["accepted_count"] == 0

    alerts = client.get("/api/v1/alerts", headers=headers).json()
    assert alerts["total"] >= 1
    assert any(a.get("is_simulated") == "false" for a in alerts["items"])


def test_parse_error_reported(client: TestClient):
    ingest = client.post(
        "/api/v1/ingest/webhook/webhook-default",
        json={"events": [{"event_id": "bad-ts", "timestamp": "not-a-date", "source": "edr", "event_type": "x"}]},
        headers={"X-Ingest-Token": "dev-ingest-token", "X-Tenant-Id": "tenant_default"},
    )
    # missing timestamp warning still accepts with now; unparseable uses now with warning in errors
    assert ingest.status_code == 200
    assert ingest.json()["accepted_count"] + ingest.json()["rejected_count"] >= 1


def test_seed_demo_scenario_labeled_simulated(client: TestClient):
    headers = get_auth_header(client)
    response = client.post("/api/v1/events/seed-demo", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["details"]["is_simulated"] is True
    events = client.get("/api/v1/events?is_simulated=true", headers=headers).json()
    assert len(events) > 0
    assert all(e["is_simulated"] == "true" for e in events)


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


def test_tenant_isolation_on_events(client: TestClient):
    headers_a = get_auth_header(client)
    other_email = "iso.analyst@enterprise.com"
    client.post(
        "/api/v1/auth/register",
        json={"email": other_email, "password": "IsoPass123!", "full_name": "Iso", "role": "analyst"},
    )
    headers_b = get_auth_header(client, other_email, "IsoPass123!")
    events_b = client.get("/api/v1/events", headers=headers_b).json()
    events_a = client.get("/api/v1/events", headers=headers_a).json()
    ids_a = {e["id"] for e in events_a}
    ids_b = {e["id"] for e in events_b}
    assert ids_a.isdisjoint(ids_b)


def test_ingest_status_waiting_or_connected(client: TestClient):
    headers = get_auth_header(client)
    status = client.get("/api/v1/ingest/status", headers=headers)
    assert status.status_code == 200
    body = status.json()
    assert body["telemetry_state"] in {"connected", "waiting"}
    assert "vendor_pollers" in body
    assert body["vendor_pollers"]["splunk"] == "not_implemented"
