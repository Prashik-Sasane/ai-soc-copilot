import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.event import SecurityEvent
from app.schemas.event import SecurityEventRead, IngestionBatchResponse
from app.services.ingestion_service import EventIngestionService
from app.services.synthetic_data_generator import generate_synthetic_attack_scenario
from app.services.audit_service import write_audit
from app.services.windows_event_parser import parse_windows_event_xml

router = APIRouter()


class LiveTelemetryBatch(BaseModel):
    events: List[Dict[str, Any]]


@router.post("/ingest", response_model=IngestionBatchResponse)
async def ingest_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    content_bytes = await file.read()
    try:
        content_str = content_bytes.decode("utf-8")
    except Exception:
        content_str = content_bytes.decode("latin-1")

    records = EventIngestionService.parse_file_content(content_str, file.filename)
    if not records:
        raise HTTPException(status_code=400, detail="Uploaded file contained no valid security records.")

    result = EventIngestionService.ingest_records(
        db=db,
        records=records,
        tenant_id=current_user.tenant_id,
        is_simulated=False,
        ingest_source_id="file-upload",
        connector_type="file",
    )
    write_audit(
        db,
        action="events_ingested",
        resource_type="ingest",
        resource_id=result.job_id,
        user=current_user,
        details={"filename": file.filename, "accepted": result.accepted_count},
        commit=True,
    )
    return result


@router.post("/telemetry/windows", response_model=IngestionBatchResponse)
def ingest_windows_telemetry(
    body: LiveTelemetryBatch,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Accept real Windows endpoint events and derive tenant from the JWT user."""
    if not body.events:
        raise HTTPException(status_code=400, detail="Send a non-empty events array.")
    if len(body.events) > 500:
        raise HTTPException(status_code=413, detail="A telemetry batch may contain at most 500 events.")
    result = EventIngestionService.ingest_records(
        db=db,
        records=body.events,
        tenant_id=current_user.tenant_id,
        is_simulated=False,
        ingest_source_id="windows-laptop",
        connector_type="windows_event_log",
    )
    write_audit(
        db,
        action="events_ingested",
        resource_type="ingest",
        resource_id=result.job_id,
        user=current_user,
        details={
            "source_id": "windows-laptop",
            "accepted": result.accepted_count,
            "rejected": result.rejected_count,
            "connector_type": "windows_event_log",
            "simulated": False,
        },
        commit=True,
    )
    return result


@router.post("/replay", response_model=IngestionBatchResponse)
async def replay_public_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Replay an uploaded public dataset; every imported event remains marked simulated."""
    content_bytes = await file.read(25 * 1024 * 1024 + 1)
    if len(content_bytes) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Replay files may not exceed 25 MiB.")
    try:
        content = content_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        content = content_bytes.decode("latin-1")

    filename = (file.filename or "dataset.log").lower()
    try:
        if filename.endswith((".xml", ".log")) and "<Event" in content:
            records = parse_windows_event_xml(content)
        elif filename.endswith(".log"):
            try:
                parsed = json.loads(content)
                records = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                records = [json.loads(line) for line in content.splitlines() if line.strip()]
                if not records:
                    raise ValueError("log file contains no JSON records")
        else:
            records = EventIngestionService.parse_file_content(content, filename)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse replay file: {exc}") from exc
    if not records:
        raise HTTPException(status_code=400, detail="Replay file contained no supported security events.")

    result = EventIngestionService.ingest_records(
        db=db,
        records=records,
        tenant_id=current_user.tenant_id,
        is_simulated=True,
        ingest_source_id="public-dataset-replay",
        connector_type="dataset_replay",
    )
    write_audit(
        db,
        action="dataset_replayed",
        resource_type="ingest",
        resource_id=result.job_id,
        user=current_user,
        details={
            "filename": file.filename,
            "source": "Splunk Attack Data / public replay upload",
            "accepted": result.accepted_count,
            "rejected": result.rejected_count,
            "simulated": True,
        },
        commit=True,
    )
    return result


def _require_demo_seeding(current_user: User):
    if not settings.demo_seeding_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                "Demo seeding is disabled. This endpoint only creates simulated records; "
                "it is not a real data source. Send real events to the ingestion webhook "
                "(POST /api/v1/ingest/webhook/{source_id}), or set ENABLE_DEMO_SEEDING=true "
                "for an explicit local simulated demo."
            ),
        )
    if current_user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot seed demo data.")


@router.post("/simulate-scenario")
def simulate_attack_scenario(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _require_demo_seeding(current_user)
    res = generate_synthetic_attack_scenario(db=db, tenant_id=current_user.tenant_id)
    write_audit(
        db,
        action="demo_scenario_seeded",
        resource_type="ingest",
        user=current_user,
        details={"simulated": True, **{k: res.get(k) for k in ("scenario", "variant", "incident_id")}},
        commit=True,
    )
    return {
        "status": "success",
        "message": "Simulated multi-stage attack scenario generated. All records are labeled simulated.",
        "scenario": res.get("scenario"),
        "details": res
    }


@router.post("/seed-demo")
def seed_demo_scenario(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    _require_demo_seeding(current_user)
    res = generate_synthetic_attack_scenario(db=db, tenant_id=current_user.tenant_id)
    write_audit(
        db,
        action="demo_scenario_seeded",
        resource_type="ingest",
        user=current_user,
        details={"simulated": True, "incident_id": res.get("incident_id")},
        commit=True,
    )
    return {
        "message": "Simulated attack scenario seeded. Records are labeled is_simulated=true.",
        "details": res
    }


@router.get("", response_model=List[SecurityEventRead])
def list_events(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    user: Optional[str] = None,
    src_ip: Optional[str] = None,
    is_simulated: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(SecurityEvent).filter(SecurityEvent.tenant_id == current_user.tenant_id)
    if source:
        query = query.filter(SecurityEvent.source == source)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if user:
        query = query.filter(SecurityEvent.user.ilike(f"%{user}%"))
    if src_ip:
        query = query.filter(SecurityEvent.src_ip == src_ip)
    if is_simulated:
        query = query.filter(SecurityEvent.is_simulated == is_simulated)

    return query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    evt = db.query(SecurityEvent).filter(
        (SecurityEvent.id == event_id) | (SecurityEvent.event_id == event_id),
        SecurityEvent.tenant_id == current_user.tenant_id
    ).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Security event not found.")
    return evt
