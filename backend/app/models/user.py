import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum, Integer, JSON
from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    role = Column(String, default=UserRole.ANALYST.value, nullable=False)
    tenant_id = Column(String, default="tenant_default", index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False, nullable=True, server_default="false")
    mfa_secret_enc = Column(String, nullable=True)
    mfa_pending_secret_enc = Column(String, nullable=True)
    mfa_pending_expires_at = Column(DateTime, nullable=True)
    mfa_last_counter = Column(Integer, default=-1, nullable=True, server_default="-1")
    mfa_recovery_hashes = Column(JSON, default=list, nullable=True)
    auth_token_version = Column(Integer, default=0, nullable=True, server_default="0")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
