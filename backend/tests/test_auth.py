from fastapi.testclient import TestClient


def test_healthz(client: TestClient):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_success(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@aisoc.io", "password": "AnalystSOC123!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == "analyst@aisoc.io"
    assert data["user"]["role"] == "analyst"


def test_login_invalid_password(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@aisoc.io", "password": "WrongPassword!"}
    )
    assert response.status_code == 401


def test_read_me(client: TestClient):
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@aisoc.io", "password": "AdminSOC123!"}
    )
    token = login_resp.json()["access_token"]
    
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "admin@aisoc.io"
    assert data["role"] == "admin"
