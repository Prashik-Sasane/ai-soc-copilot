import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError
from starlette.requests import Request

from app.api.endpoints import auth
from app.core.auth_security import totp_code
from app.core.config import settings
from app.core.deps import get_current_user
from app.schemas.auth import LoginRequest, MfaEnrollmentRequest, MfaLoginRequest, MfaSetupLoginRequest, UserCreate


def test_password_policy_rejects_weak_or_bcrypt_oversized_password():
    with pytest.raises(ValidationError):
        UserCreate(email="weak@example.com", password="password1")
    with pytest.raises(ValidationError):
        UserCreate(email="long@example.com", password="Abcdefghij12!" * 7)
    accepted = UserCreate(email="good@example.com", password="LongEnoughPass123!")
    assert accepted.password == "LongEnoughPass123!"


def test_totp_setup_login_replay_protection_and_revocable_logout(db_session, monkeypatch):
    monkeypatch.setattr(auth, "build_totp_qr_data_uri", lambda uri: "data:image/png;base64,dGVzdA==")
    email = f"mfa.{uuid.uuid4().hex[:8]}@enterprise.com"
    password = "MfaSecurityTest789!"
    user = auth.register_user(UserCreate(email=email, password=password, role="admin"), db_session)
    assert user.role == "analyst"
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": [], "client": ("127.0.0.1", 1234)})

    first_login = auth.login(LoginRequest(email=email, password=password), request, db_session)
    assert first_login["mfa_setup_required"] is True
    assert "access_token" not in first_login
    with pytest.raises(HTTPException) as pre_mfa_access:
        get_current_user(
            db_session,
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=auth._access_token(user)),
        )
    assert pre_mfa_access.value.status_code == 401
    setup = auth.begin_login_mfa_setup(MfaSetupLoginRequest(mfa_token=first_login["mfa_token"]), request, db_session)
    assert setup["qr_code_data_uri"].startswith("data:image/png;base64,")
    secret = parse_qs(urlparse(setup["otpauth_uri"]).query)["secret"][0]

    enrollment_code = totp_code(secret, int(time.time() // 30))
    enabled = auth.finish_login_mfa_setup(
        MfaEnrollmentRequest(mfa_token=first_login["mfa_token"], code=enrollment_code),
        request,
        db_session,
    )
    assert enabled["user"].mfa_enabled is True
    assert len(enabled["recovery_codes"]) == 10
    assert enabled["access_token"]

    password_login = auth.login(LoginRequest(email=email, password=password), request, db_session)
    assert password_login["mfa_required"] is True
    assert "access_token" not in password_login
    with pytest.raises(HTTPException) as challenge_is_not_session:
        get_current_user(db_session, HTTPAuthorizationCredentials(scheme="Bearer", credentials=password_login["mfa_token"]))
    assert challenge_is_not_session.value.status_code == 401

    one_time_code = totp_code(secret, int(time.time() // 30) + 1)
    result = auth.complete_mfa_login(
        MfaLoginRequest(mfa_token=password_login["mfa_token"], code=one_time_code),
        request,
        db_session,
    )
    assert result["access_token"]
    assert result["user"].mfa_enabled is True
    session_user = get_current_user(db_session, HTTPAuthorizationCredentials(scheme="Bearer", credentials=result["access_token"]))
    assert session_user.id == user.id

    with pytest.raises(HTTPException) as replay:
        auth.complete_mfa_login(
            MfaLoginRequest(mfa_token=password_login["mfa_token"], code=one_time_code),
            request,
            db_session,
        )
    assert replay.value.status_code == 401

    recovery_challenge = auth.login(LoginRequest(email=email, password=password), request, db_session)
    recovery_code = enabled["recovery_codes"][0]
    recovery_login = auth.complete_mfa_login(
        MfaLoginRequest(mfa_token=recovery_challenge["mfa_token"], code=recovery_code),
        request,
        db_session,
    )
    assert recovery_login["access_token"]
    with pytest.raises(HTTPException) as recovery_replay:
        auth.complete_mfa_login(
            MfaLoginRequest(mfa_token=recovery_challenge["mfa_token"], code=recovery_code),
            request,
            db_session,
        )
    assert recovery_replay.value.status_code == 401

    old_token_version = user.auth_token_version
    auth.logout(request, db_session, user)
    assert user.auth_token_version == old_token_version + 1
    with pytest.raises(HTTPException) as revoked:
        get_current_user(db_session, HTTPAuthorizationCredentials(scheme="Bearer", credentials=result["access_token"]))
    assert revoked.value.status_code == 401


def test_login_rate_limit_buckets_failed_credentials(db_session, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_LOGIN_MAX_ATTEMPTS", 3)
    email = f"throttle.{uuid.uuid4().hex[:8]}@example.com"
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": [], "client": ("192.0.2.44", 1234)})
    for _ in range(3):
        with pytest.raises(HTTPException) as failed:
            auth.login(LoginRequest(email=email, password="WrongPassword123!"), request, db_session)
        assert failed.value.status_code == 401
    with pytest.raises(HTTPException) as limited:
        auth.login(LoginRequest(email=email, password="WrongPassword123!"), request, db_session)
    assert limited.value.status_code == 429
