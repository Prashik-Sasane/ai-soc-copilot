from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
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
        tenant_id=current_user.tenant_id
    )
    return doc


@router.post("/seed-playbooks")
def seed_knowledge_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
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
                tenant_id=current_user.tenant_id
            )
            created.append(doc.id)

    return {
        "message": f"Successfully ingested and indexed {len(created)} seed playbook(s).",
        "document_ids": created
    }
