from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Query, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.user import User
from app.models.event import SecurityEvent
from app.schemas.event import SecurityEventRead, IngestionBatchResponse
from app.services.ingestion_service import EventIngestionService
from app.services.synthetic_data_generator import generate_synthetic_attack_scenario

router = APIRouter()


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
        is_simulated=False
    )
    return result


@router.post("/seed-demo")
def seed_demo_scenario(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    res = generate_synthetic_attack_scenario(db=db, tenant_id=current_user.tenant_id)
    return {
        "message": "Synthetic attack scenario seeded successfully.",
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
