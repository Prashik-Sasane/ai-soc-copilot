import uuid
import time
from urllib.parse import parse_qs, urlparse
from fastapi.testclient import TestClient

from app.core.auth_security import totp_code


def complete_first_login_with_mfa(client: TestClient, email: str, password: str, monkeypatch):
    monkeypatch.setattr("app.api.endpoints.auth.build_totp_qr_data_uri", lambda uri: "data:image/png;base64,dGVzdA==")
    challenge = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert challenge.status_code == 200
    challenge_data = challenge.json()
    assert challenge_data["mfa_setup_required"] is True
    assert challenge_data.get("access_token") is None
    setup = client.post("/api/v1/auth/login/mfa/setup", json={"mfa_token": challenge_data["mfa_token"]})
    assert setup.status_code == 200
    secret = parse_qs(urlparse(setup.json()["otpauth_uri"]).query)["secret"][0]
    code = totp_code(secret, int(time.time() // 30))
    enabled = client.post(
        "/api/v1/auth/login/mfa/enable",
        json={"mfa_token": challenge_data["mfa_token"], "code": code},
    )
    assert enabled.status_code == 200
    return enabled.json()


def test_healthz(client: TestClient):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_register_then_login_success(client: TestClient, monkeypatch):
    random_email = f"test.analyst.{uuid.uuid4().hex[:8]}@enterprise.com"
    random_name = "Test Analyst " + uuid.uuid4().hex[:6]
    password = "TestPass123!"

    # Register new user
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": random_email,
            "password": password,
            "full_name": random_name,
            "role": "analyst"
        }
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["email"] == random_email
    assert reg_data["role"] == "analyst"
    assert reg_data["full_name"] == random_name
    assert reg_data["tenant_id"].startswith("tenant_")
    assert reg_data["tenant_id"] != "tenant_default"
    user_uuid_suffix = reg_data["id"].replace("user_", "")
    assert reg_data["tenant_id"] == f"tenant_{user_uuid_suffix}"
    assert reg_data["is_active"] is True
    assert reg_data["id"].startswith("user_")

    # Now login with the newly registered user
    login_data = complete_first_login_with_mfa(client, random_email, password, monkeypatch)
    assert "access_token" in login_data
    assert len(login_data["access_token"]) > 40
    assert login_data["token_type"] == "bearer"
    assert login_data["user"]["email"] == random_email
    assert login_data["user"]["role"] == "analyst"
    assert login_data["user"]["full_name"] == random_name

    # Verify /me works with this new user's token
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {login_data['access_token']}"}
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["email"] == random_email
    assert me_data["role"] == "analyst"
    assert me_data["full_name"] == random_name


def test_public_registration_cannot_grant_admin_role(client: TestClient, monkeypatch):
    random_email = f"test.admin.{uuid.uuid4().hex[:8]}@enterprise.com"
    password = "AdminTestPass456!"

    # Register admin user
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": random_email,
            "password": password,
            "full_name": "Admin Test User",
            "role": "admin"
        }
    )
    assert reg_resp.status_code == 200
    assert reg_resp.json()["role"] == "analyst"

    # Login admin
    token = complete_first_login_with_mfa(client, random_email, password, monkeypatch)["access_token"]

    # The requested public role is ignored; the new account receives analyst permissions.
    dash_resp = client.get(
        "/api/v1/dashboard/stats",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert dash_resp.status_code == 200
    assert "total_alerts" in dash_resp.json()


def test_register_duplicate_email_fails(client: TestClient):
    email = "analyst@aisoc.io"  # Default seeded user

    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "AnyPass1234!",
            "full_name": "Should Fail",
            "role": "analyst"
        }
    )
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"].lower()


def test_register_invalid_role_defaults_to_analyst(client: TestClient):
    random_email = f"test.invalidrole.{uuid.uuid4().hex[:8]}@enterprise.com"
    password = "TestPass789!"

    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": random_email,
            "password": password,
            "role": "superuser_invalid"
        }
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "analyst"


def test_login_success_requires_first_time_mfa_enrollment(client: TestClient):
    response = client.post("/api/v1/auth/login", json={"email": "analyst@aisoc.io", "password": "AnalystSOC123!"})
    assert response.status_code == 200
    data = response.json()
    assert data["mfa_setup_required"] is True
    assert data.get("access_token") is None


def test_login_invalid_password(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@aisoc.io", "password": "WrongPassword!"}
    )
    assert response.status_code == 401


def test_login_nonexistent_user(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": f"nonexistent-{uuid.uuid4().hex[:8]}@nowhere.com", "password": "Whatever!"}
    )
    assert response.status_code == 401


def test_read_me(client: TestClient, monkeypatch):
    token = complete_first_login_with_mfa(client, "admin@aisoc.io", "AdminSOC123!", monkeypatch)["access_token"]
    
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "admin@aisoc.io"
    assert data["role"] == "admin"
