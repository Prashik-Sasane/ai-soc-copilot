from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.services.audit_service import write_audit
from app.models.user import User
from app.models.knowledge import KnowledgeDocument
from app.schemas.knowledge import KnowledgeDocumentRead, KnowledgeDocumentCreate
from app.services.rag_service import RAGService
from app.data.seed_playbooks.soc_playbooks import SEED_PLAYBOOKS

router = APIRouter()


@router.get("", response_model=List[KnowledgeDocumentRead])
def list_knowledge_documents(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(KnowledgeDocument).filter(KnowledgeDocument.tenant_id == current_user.tenant_id)
    if category:
        query = query.filter(KnowledgeDocument.category == category)
    return query.order_by(KnowledgeDocument.updated_at.desc()).all()


@router.post("", response_model=KnowledgeDocumentRead)
def ingest_knowledge_doc(
    doc_in: KnowledgeDocumentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    doc = RAGService.ingest_document(
        db=db,
        title=doc_in.title,
        content=doc_in.content,
        category=doc_in.category,
        source_ref=doc_in.source_ref,
        tenant_id=current_user.tenant_id,
        owner=doc_in.owner or current_user.email,
        version=doc_in.version or "1",
    )
    write_audit(
        db,
        action="knowledge_ingested",
        resource_type="knowledge",
        resource_id=doc.id,
        user=current_user,
        details={"title": doc.title, "owner": doc.owner, "version": doc.version},
        commit=True,
    )
    return doc


@router.post("/seed-playbooks")
def seed_knowledge_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not settings.demo_seeding_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                "Demo playbook seeding is disabled. Upload your own approved playbooks/advisories "
                "via POST /api/v1/knowledge, or set ENABLE_DEMO_SEEDING=true for an explicit local demo."
            ),
        )
    created = []
    for pb in SEED_PLAYBOOKS:
        existing = db.query(KnowledgeDocument).filter(
            KnowledgeDocument.title == pb["title"],
            KnowledgeDocument.tenant_id == current_user.tenant_id
        ).first()
        if not existing:
            doc = RAGService.ingest_document(
                db=db,
                title=pb["title"],
                content=pb["content"],
                category=pb["category"],
                source_ref=pb["source_ref"],
                tenant_id=current_user.tenant_id,
                owner="demo-playbook",
                version="demo",
            )
            created.append(doc.id)

    return {
        "message": f"Successfully ingested and indexed {len(created)} seed playbook(s).",
        "document_ids": created
    }


@router.post("/sync-cisa-kev")
def sync_cisa_kev_catalog(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch and index current vulnerability records from the public CISA KEV feed."""
    try:
        document = RAGService.sync_cisa_kev(db, current_user.tenant_id, limit=limit)
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"Could not sync CISA KEV catalog: {exc}") from exc
    return {
        "message": f"Indexed {document.chunk_count} chunks from {document.title}.",
        "document_id": document.id,
        "source_ref": document.source_ref,
        "chunk_count": document.chunk_count,
    }


@router.post("/reindex")
def reindex_knowledge_vectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        count = RAGService.reindex_embeddings(db, current_user.tenant_id)
    except (httpx.HTTPError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"Could not re-index knowledge embeddings: {exc}") from exc
    return {"message": f"Re-indexed {count} knowledge chunks.", "chunk_count": count}
