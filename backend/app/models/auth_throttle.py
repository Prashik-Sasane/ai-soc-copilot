from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String
from app.core.database import Base


class AuthThrottle(Base):
    """Hashed subject buckets for persistent auth endpoint rate limits."""
    __tablename__ = "auth_throttles"

    bucket_key = Column(String, primary_key=True)
    failures = Column(Integer, default=0, nullable=False)
    window_started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    locked_until = Column(DateTime, nullable=True)
