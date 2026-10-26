import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.auth_security import (
    build_totp_qr_data_uri,
    check_auth_rate_limit,
    clear_auth_failures,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    matching_totp_counter,
    record_auth_failure,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.deps import get_current_user
from app.models.user import User, UserRole
from app.services.audit_service import write_audit
from app.schemas.auth import (
    LoginRequest, MfaCodeRequest, MfaDisableRequest, MfaEnabledResponse,
    MfaEnrollmentRequest, MfaLoginRequest, MfaSetupLoginRequest,
    MfaSetupResponse, Token, UserCreate, UserRead,
)

router = APIRouter()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _login_scopes(ip: str, email: str) -> list[str]:
    return [f"login-ip:{ip}", f"login-email:{email.strip().casefold()}"]


def _mfa_scopes(ip: str, user_id: str) -> list[str]:
    return [f"mfa-ip:{ip}", f"mfa-user:{user_id}"]


def _access_token(user: User) -> str:
    return create_access_token(
        subject=user.id,
        role=user.role,
        token_version=user.auth_token_version or 0,
    )


def _check_mfa_code(user: User, code: str) -> bool:
    if user.mfa_secret_enc and code.isdigit() and len(code) == 6:
        secret = decrypt_totp_secret(user.mfa_secret_enc)
        counter = matching_totp_counter(secret, code, user.mfa_last_counter or -1)
        if counter is not None:
            user.mfa_last_counter = counter
            return True

    hashes = list(user.mfa_recovery_hashes or [])
    supplied_hash = hash_recovery_code(code)
    for index, stored_hash in enumerate(hashes):
        if secrets.compare_digest(supplied_hash, stored_hash):
            hashes.pop(index)
            user.mfa_recovery_hashes = hashes
            return True
    return False


def _validate_challenge(db: Session, token: str, purpose: str) -> User:
    try:
        claims = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = claims.get("sub")
        if claims.get("purpose") != purpose or not user_id:
            raise JWTError("Invalid challenge purpose")
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge") from exc
    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user or claims.get("ver", 0) != (user.auth_token_version or 0):
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")
    return user


def _begin_mfa_enrollment(db: Session, user: User) -> dict:
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = generate_totp_secret()
    now = datetime.now(timezone.utc)
    user.mfa_pending_secret_enc = encrypt_totp_secret(secret)
    user.mfa_pending_expires_at = now + timedelta(minutes=10)
    db.commit()
    label = quote(f"AI SOC Copilot:{user.email}")
    issuer = quote("AI SOC Copilot")
    uri = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    try:
        qr_data_uri = build_totp_qr_data_uri(uri)
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="QR code support is missing. Install backend requirements and retry.") from exc
    return {"otpauth_uri": uri, "qr_code_data_uri": qr_data_uri, "expires_at": user.mfa_pending_expires_at.isoformat()}


def _confirm_mfa_enrollment(db: Session, user: User, code: str) -> list[str]:
    expires_at = user.mfa_pending_expires_at
    if not user.mfa_pending_secret_enc or not expires_at:
        raise HTTPException(status_code=409, detail="Start MFA setup before confirming a code")
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    secret = decrypt_totp_secret(user.mfa_pending_secret_enc)
    counter = matching_totp_counter(secret, code, user.mfa_last_counter or -1) if code.isdigit() else None
    if expires_at <= datetime.now(timezone.utc) or counter is None:
        raise HTTPException(status_code=400, detail="Invalid code or MFA setup expired. Generate a new QR code and try again.")
    recovery_codes = generate_recovery_codes()
    user.mfa_secret_enc = user.mfa_pending_secret_enc
    user.mfa_pending_secret_enc = None
    user.mfa_pending_expires_at = None
    user.mfa_last_counter = counter
    user.mfa_recovery_hashes = [hash_recovery_code(value) for value in recovery_codes]
    user.mfa_enabled = True
    db.commit()
    return recovery_codes


@router.post("/login", response_model=Token)
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    scopes = _login_scopes(_client_ip(request), login_data.email)
    for scope in scopes:
        check_auth_rate_limit(db, scope, settings.AUTH_LOGIN_MAX_ATTEMPTS, settings.AUTH_LOGIN_WINDOW_MINUTES)
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not user.is_active or not verify_password(login_data.password, user.hashed_password):
        for scope in scopes:
            record_auth_failure(db, scope, settings.AUTH_LOGIN_MAX_ATTEMPTS, settings.AUTH_LOGIN_WINDOW_MINUTES)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clear_auth_failures(db, scopes)
    if user.mfa_enabled:
        mfa_token = create_access_token(
            subject=user.id,
            expires_delta=timedelta(minutes=5),
            role="mfa_challenge",
            token_version=user.auth_token_version or 0,
            purpose="mfa_login",
        )
        write_audit(
            db, action="auth_password_verified_mfa_required", resource_type="auth",
            resource_id=user.id, user=user, ip_address=_client_ip(request), commit=True,
        )
        return {"mfa_required": True, "mfa_token": mfa_token, "token_type": "bearer"}

    setup_token = create_access_token(
        subject=user.id,
        expires_delta=timedelta(minutes=10),
        role="mfa_enrollment",
        token_version=user.auth_token_version or 0,
        purpose="mfa_setup",
    )
    write_audit(
        db, action="auth_mfa_enrollment_required", resource_type="auth",
        resource_id=user.id, user=user, ip_address=_client_ip(request), commit=True,
    )
    return {"mfa_setup_required": True, "mfa_token": setup_token, "token_type": "bearer"}


@router.post("/login/mfa", response_model=Token)
def complete_mfa_login(payload: MfaLoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    ip_scope = f"mfa-login-ip:{ip}"
    check_auth_rate_limit(db, ip_scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    try:
        claims = jwt.decode(payload.mfa_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = claims.get("sub")
        if claims.get("purpose") != "mfa_login" or not user_id:
            raise JWTError("Invalid MFA challenge")
    except JWTError:
        record_auth_failure(db, ip_scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user or not user.mfa_enabled or claims.get("ver", 0) != (user.auth_token_version or 0):
        record_auth_failure(db, ip_scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")
    scopes = [ip_scope, *_mfa_scopes(ip, user.id)]
    for scope in scopes:
        check_auth_rate_limit(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    if not _check_mfa_code(user, payload.code):
        for scope in scopes:
            record_auth_failure(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
        raise HTTPException(status_code=401, detail="Invalid or expired MFA code")

    clear_auth_failures(db, scopes)
    db.commit()
    write_audit(
        db, action="auth_login_mfa_success", resource_type="auth", resource_id=user.id,
        user=user, ip_address=ip, commit=True,
    )
    return {"access_token": _access_token(user), "token_type": "bearer", "user": user}


@router.post("/login/mfa/setup", response_model=MfaSetupResponse)
def begin_login_mfa_setup(payload: MfaSetupLoginRequest, request: Request, db: Session = Depends(get_db)):
    user = _validate_challenge(db, payload.mfa_token, "mfa_setup")
    ip = _client_ip(request)
    scopes = [f"mfa-enroll-ip:{ip}", f"mfa-enroll-user:{user.id}"]
    for scope in scopes:
        check_auth_rate_limit(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    return _begin_mfa_enrollment(db, user)


@router.post("/login/mfa/enable", response_model=Token)
def finish_login_mfa_setup(payload: MfaEnrollmentRequest, request: Request, db: Session = Depends(get_db)):
    user = _validate_challenge(db, payload.mfa_token, "mfa_setup")
    ip = _client_ip(request)
    scopes = [f"mfa-enroll-ip:{ip}", f"mfa-enroll-user:{user.id}"]
    for scope in scopes:
        check_auth_rate_limit(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    try:
        recovery_codes = _confirm_mfa_enrollment(db, user, payload.code)
    except HTTPException as exc:
        if exc.status_code == 400:
            for scope in scopes:
                record_auth_failure(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
        raise
    clear_auth_failures(db, scopes)
    write_audit(
        db, action="auth_mfa_enabled_at_login", resource_type="auth", resource_id=user.id,
        user=user, ip_address=ip, commit=True,
    )
    return {
        "access_token": _access_token(user),
        "token_type": "bearer",
        "user": user,
        "recovery_codes": recovery_codes,
    }


@router.get("/me", response_model=UserRead)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/register", response_model=UserRead)
def register_user(
    user_in: UserCreate,
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    
    user_uuid = uuid.uuid4().hex[:12]
    new_user = User(
        id=f"user_{user_uuid}",
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        # Public self-registration cannot grant administrative privileges.
        role=UserRole.ANALYST.value,
        tenant_id=f"tenant_{user_uuid}"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.get("/mfa/status")
def mfa_status(current_user: User = Depends(get_current_user)):
    return {"enabled": bool(current_user.mfa_enabled), "setup_pending": bool(current_user.mfa_pending_secret_enc)}


@router.post("/mfa/setup", response_model=MfaSetupResponse)
def setup_mfa(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ip = _client_ip(request)
    scope = f"mfa-setup:{current_user.id}:{ip}"
    check_auth_rate_limit(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    if current_user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = generate_totp_secret()
    now = datetime.now(timezone.utc)
    current_user.mfa_pending_secret_enc = encrypt_totp_secret(secret)
    current_user.mfa_pending_expires_at = now + timedelta(minutes=10)
    db.commit()
    label = quote(f"AI SOC Copilot:{current_user.email}")
    issuer = quote("AI SOC Copilot")
    uri = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    try:
        qr_data_uri = build_totp_qr_data_uri(uri)
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="QR code support is missing. Install backend requirements and retry.") from exc
    return {"otpauth_uri": uri, "qr_code_data_uri": qr_data_uri, "expires_at": current_user.mfa_pending_expires_at.isoformat()}


@router.post("/mfa/enable", response_model=MfaEnabledResponse)
def enable_mfa(payload: MfaCodeRequest, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ip = _client_ip(request)
    scopes = [f"mfa-enroll-ip:{ip}", f"mfa-enroll-user:{current_user.id}"]
    for scope in scopes:
        check_auth_rate_limit(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    expires_at = current_user.mfa_pending_expires_at
    if not current_user.mfa_pending_secret_enc or not expires_at:
        raise HTTPException(status_code=409, detail="Start MFA setup before confirming a code")
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    secret = decrypt_totp_secret(current_user.mfa_pending_secret_enc)
    counter = matching_totp_counter(secret, payload.code, current_user.mfa_last_counter or -1) if payload.code.isdigit() else None
    if expires_at <= datetime.now(timezone.utc) or counter is None:
        for scope in scopes:
            record_auth_failure(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
        raise HTTPException(status_code=400, detail="Invalid code or MFA setup expired. Generate a new QR code and try again.")

    recovery_codes = generate_recovery_codes()
    current_user.mfa_secret_enc = current_user.mfa_pending_secret_enc
    current_user.mfa_pending_secret_enc = None
    current_user.mfa_pending_expires_at = None
    current_user.mfa_last_counter = counter
    current_user.mfa_recovery_hashes = [hash_recovery_code(code) for code in recovery_codes]
    current_user.mfa_enabled = True
    db.commit()
    clear_auth_failures(db, scopes)
    write_audit(db, action="auth_mfa_enabled", resource_type="auth", resource_id=current_user.id, user=current_user, ip_address=ip, commit=True)
    return {"enabled": True, "recovery_codes": recovery_codes}


@router.post("/mfa/disable")
def disable_mfa(payload: MfaDisableRequest, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ip = _client_ip(request)
    scopes = [f"mfa-disable-ip:{ip}", f"mfa-disable-user:{current_user.id}"]
    for scope in scopes:
        check_auth_rate_limit(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
    if not current_user.mfa_enabled or not verify_password(payload.password, current_user.hashed_password) or not _check_mfa_code(current_user, payload.code):
        for scope in scopes:
            record_auth_failure(db, scope, settings.AUTH_MFA_MAX_ATTEMPTS, settings.AUTH_MFA_WINDOW_MINUTES)
        raise HTTPException(status_code=401, detail="Password or MFA code is incorrect")
    current_user.mfa_enabled = False
    current_user.mfa_secret_enc = None
    current_user.mfa_recovery_hashes = []
    current_user.auth_token_version = (current_user.auth_token_version or 0) + 1
    db.commit()
    clear_auth_failures(db, scopes)
    write_audit(db, action="auth_mfa_disabled", resource_type="auth", resource_id=current_user.id, user=current_user, ip_address=ip, commit=True)
    return {"enabled": False, "message": "MFA disabled; all existing access tokens have been revoked. Sign in again."}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.auth_token_version = (current_user.auth_token_version or 0) + 1
    db.commit()
    write_audit(db, action="auth_logout_all_sessions", resource_type="auth", resource_id=current_user.id, user=current_user, ip_address=_client_ip(request), commit=True)
    return {"message": "Signed out; all active sessions have been revoked."}
