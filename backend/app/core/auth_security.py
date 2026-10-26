import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.auth_throttle import AuthThrottle


def _encryption_key() -> bytes:
    return hashlib.sha256((settings.SECRET_KEY + ":totp-encryption").encode()).digest()


def encrypt_totp_secret(secret: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_encryption_key()).encrypt(nonce, secret.encode(), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_totp_secret(value: str) -> str:
    payload = base64.urlsafe_b64decode(value.encode())
    return AESGCM(_encryption_key()).decrypt(payload[:12], payload[12:], None).decode()


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, counter: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def matching_totp_counter(secret: str, code: str, last_counter: int = -1, now: float | None = None) -> int | None:
    current = int((now if now is not None else time.time()) // 30)
    for counter in (current - 1, current, current + 1):
        if counter > last_counter and hmac.compare_digest(totp_code(secret, counter), code):
            return counter
    return None


def build_totp_qr_data_uri(otpauth_uri: str) -> str:
    import qrcode

    image = qrcode.make(otpauth_uri)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode()


def generate_recovery_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(5).upper() for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    return hmac.new(_encryption_key(), code.strip().replace("-", "").upper().encode(), hashlib.sha256).hexdigest()


def _bucket_key(scope: str) -> str:
    return hmac.new(settings.SECRET_KEY.encode(), scope.encode(), hashlib.sha256).hexdigest()


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def check_auth_rate_limit(db: Session, scope: str, max_attempts: int, window_minutes: int) -> None:
    row = db.query(AuthThrottle).filter(AuthThrottle.bucket_key == _bucket_key(scope)).first()
    if not row:
        return
    now = datetime.now(timezone.utc)
    locked_until = _utc(row.locked_until)
    if locked_until and locked_until > now:
        retry = max(1, int((locked_until - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Try again later.",
            headers={"Retry-After": str(retry)},
        )
    window_started = _utc(row.window_started_at)
    if window_started and (now - window_started).total_seconds() < window_minutes * 60 and row.failures >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Try again later.",
            headers={"Retry-After": str(max(1, window_minutes * 60 - int((now - window_started).total_seconds())))},
        )


def record_auth_failure(db: Session, scope: str, max_attempts: int, window_minutes: int) -> None:
    key = _bucket_key(scope)
    row = db.query(AuthThrottle).filter(AuthThrottle.bucket_key == key).first()
    now = datetime.now(timezone.utc)
    if not row:
        row = AuthThrottle(bucket_key=key, failures=0, window_started_at=now)
        db.add(row)
        db.flush()
    started = _utc(row.window_started_at)
    if not started or (now - started).total_seconds() >= window_minutes * 60:
        row.failures = 0
        row.window_started_at = now
        row.locked_until = None
    row.failures += 1
    if row.failures >= max_attempts:
        from datetime import timedelta
        row.locked_until = now + timedelta(minutes=window_minutes)
    db.commit()


def clear_auth_failures(db: Session, scopes: list[str]) -> None:
    keys = [_bucket_key(scope) for scope in scopes]
    db.query(AuthThrottle).filter(AuthThrottle.bucket_key.in_(keys)).delete(synchronize_session=False)
    db.commit()
