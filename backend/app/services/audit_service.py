import uuid
from typing import Any, Optional
from sqlalchemy.orm import Session

from app.core.request_context import get_request_id
from app.models.audit import AuditLog
from app.models.user import User


def write_audit(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    user: Optional[User] = None,
    tenant_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    before: Optional[dict[str, Any]] = None,
    after: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    commit: bool = False,
) -> AuditLog:
    payload = dict(details or {})
    if before is not None:
        payload["before"] = before
    if after is not None:
        payload["after"] = after
    entry = AuditLog(
        id=f"audit_{uuid.uuid4().hex[:12]}",
        user_id=user.id if user else None,
        user_email=user.email if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details_json=payload or None,
        ip_address=ip_address,
        tenant_id=tenant_id or (user.tenant_id if user else "tenant_default"),
        request_id=get_request_id(),
        before_json=before,
        after_json=after,
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry
