import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.event import SecurityEvent
from app.models.ingest import IngestSource, IngestParseError
from app.schemas.event import IngestionBatchResponse
from app.services.ingestion_service import EventIngestionService
from app.services.audit_service import write_audit
from app.services.llm_service import LLMService
from app.services.vector_service import VectorService
from app.core.config import settings as app_settings

router = APIRouter()


class WebhookIngestBody(BaseModel):
    events: Optional[List[Dict[str, Any]]] = None


def _extract_records(payload: Any) -> List[Dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if isinstance(payload.get("events"), list):
            return payload["events"]
        if isinstance(payload.get("records"), list):
            return payload["records"]
        return [payload]
    return []


def _token_ok(source_id: str, authorization: Optional[str], x_ingest_token: Optional[str]) -> bool:
    tokens = settings.webhook_tokens
    expected = tokens.get(source_id)
    if not expected:
        return False
    presented = x_ingest_token
    if not presented and authorization and authorization.lower().startswith("bearer "):
        presented = authorization.split(" ", 1)[1].strip()
    return bool(presented) and presented == expected


@router.post("/webhook/{source_id}", response_model=IngestionBatchResponse)
async def ingest_webhook(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
    x_ingest_token: Optional[str] = Header(default=None, alias="X-Ingest-Token"),
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
):
    if source_id not in settings.webhook_tokens:
        raise HTTPException(status_code=404, detail=f"Unknown ingest source `{source_id}`. Configure INGEST_WEBHOOK_TOKENS.")
    if not _token_ok(source_id, authorization, x_ingest_token):
        raise HTTPException(status_code=401, detail="Invalid ingest token.")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be JSON.")
    records = _extract_records(payload)
    if not records:
        raise HTTPException(status_code=400, detail="No events supplied. Send an object, an array, or {\"events\": [...]}.")
    tenant_id = x_tenant_id or "tenant_default"
    result = EventIngestionService.ingest_records(
        db=db,
        records=records,
        tenant_id=tenant_id,
        is_simulated=False,
        ingest_source_id=source_id,
        connector_type="webhook",
    )
    write_audit(
        db,
        action="events_ingested",
        resource_type="ingest",
        resource_id=result.job_id,
        tenant_id=tenant_id,
        details={"source_id": source_id, "accepted": result.accepted_count, "rejected": result.rejected_count},
        commit=True,
    )
    return result


@router.get("/status")
def ingest_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sources = (
        db.query(IngestSource)
        .filter(IngestSource.tenant_id == current_user.tenant_id)
        .all()
    )
    last_event = (
        db.query(func.max(SecurityEvent.timestamp))
        .filter(SecurityEvent.tenant_id == current_user.tenant_id)
        .scalar()
    )
    event_count = (
        db.query(func.count(SecurityEvent.id))
        .filter(SecurityEvent.tenant_id == current_user.tenant_id)
        .scalar()
    )
    errors = (
        db.query(IngestParseError)
        .filter(IngestParseError.tenant_id == current_user.tenant_id)
        .order_by(IngestParseError.created_at.desc())
        .limit(10)
        .all()
    )
    configured = list(settings.webhook_tokens.keys())
    connected = any(s.status == "connected" for s in sources) or (event_count or 0) > 0
    return {
        "telemetry_state": "connected" if connected else "waiting",
        "message": (
            "Receiving events."
            if connected
            else "No source connected / waiting for data. POST JSON events to /api/v1/ingest/webhook/{source_id}."
        ),
        "configured_webhook_sources": configured,
        "last_event_at": last_event.isoformat() if last_event else None,
        "event_count": event_count or 0,
        "sources": [
            {
                "source_id": s.source_id,
                "display_name": s.display_name,
                "connector_type": s.connector_type,
                "vendor": s.vendor,
                "status": s.status,
                "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
                "last_error": s.last_error,
                "events_accepted": s.events_accepted,
                "events_rejected": s.events_rejected,
            }
            for s in sources
        ],
        "recent_parse_errors": [
            {"id": e.id, "source_id": e.source_id, "message": e.message, "created_at": e.created_at.isoformat()}
            for e in errors
        ],
        "vendor_pollers": {
            "splunk": "not_implemented",
            "elastic": "not_implemented",
            "sentinel": "not_implemented",
            "note": "Use the authenticated webhook. A vendor poller can implement IngestConnector.pull().",
        },
        "demo_seeding_enabled": settings.demo_seeding_enabled,
        "environment": settings.ENVIRONMENT,
        "embeddings": {
            "provider": settings.EMBEDDING_PROVIDER,
            "mode": VectorService.embedding_mode(),
            "semantic": settings.embeddings_semantic,
        },
        "llm": LLMService.status(),
        "threat_intel": {
            "virustotal_configured": bool(settings.VT_API_KEY),
            "otx_configured": bool(settings.OTX_API_KEY),
            "cache_ttl_minutes": settings.TI_CACHE_TTL_MINUTES,
        },
    }


@router.get("/stream")
async def ingest_stream(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    import asyncio

    tenant_id = current_user.tenant_id

    async def event_gen():
        while True:
            if await request.is_disconnected():
                break
            last_event = (
                db.query(func.max(SecurityEvent.timestamp))
                .filter(SecurityEvent.tenant_id == tenant_id)
                .scalar()
            )
            count = (
                db.query(func.count(SecurityEvent.id))
                .filter(SecurityEvent.tenant_id == tenant_id)
                .scalar()
            )
            payload = json.dumps(
                {
                    "last_event_at": last_event.isoformat() if last_event else None,
                    "event_count": count or 0,
                    "telemetry_state": "connected" if count else "waiting",
                    "server_time": datetime.now(timezone.utc).isoformat(),
                }
            )
            yield f"event: telemetry\ndata: {payload}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(event_gen(), media_type="text/event-stream")
