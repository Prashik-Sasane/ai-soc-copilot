import uuid
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone
import httpx
from sqlalchemy.orm import Session

from app.models.knowledge import KnowledgeDocument, DocumentChunk
from app.services.vector_service import VectorService


class RAGService:
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @classmethod
    def sync_cisa_kev(cls, db: Session, tenant_id: str, limit: int = 100) -> KnowledgeDocument:
        """Index recent records from CISA's public Known Exploited Vulnerabilities catalog."""
        response = httpx.get(cls.CISA_KEV_URL, timeout=45.0, follow_redirects=True)
        response.raise_for_status()
        catalog = response.json()
        vulnerabilities = sorted(
            catalog.get("vulnerabilities", []),
            key=lambda item: item.get("dateAdded", ""),
            reverse=True,
        )[:limit]
        if not vulnerabilities:
            raise ValueError("CISA KEV feed returned no vulnerability records")

        entries = []
        for item in vulnerabilities:
            entries.append(
                "\n".join([
                    f"### {item.get('cveID', 'CVE unknown')} — {item.get('vulnerabilityName', 'Known exploited vulnerability')}",
                    f"Vendor and product: {item.get('vendorProject', 'Unknown')} / {item.get('product', 'Unknown')}",
                    f"Added to CISA KEV: {item.get('dateAdded', 'Unknown')}",
                    f"Description: {item.get('shortDescription', 'No description supplied.')}",
                    f"Required Action: {item.get('requiredAction', 'Follow vendor remediation guidance.')}",
                    f"Due date: {item.get('dueDate', 'Not specified')}",
                    f"Ransomware campaign use: {item.get('knownRansomwareCampaignUse', 'Unknown')}",
                ])
            )
        content = "# CISA Known Exploited Vulnerabilities (KEV) Catalog\n\n" + "\n\n".join(entries)
        title = "CISA Known Exploited Vulnerabilities Catalog"
        retrieved = datetime.now(timezone.utc)
        source_ref = f"{cls.CISA_KEV_URL} (retrieved {retrieved.isoformat()}; {len(vulnerabilities)} records)"
        return cls.ingest_document(
            db=db,
            title=title,
            content=content,
            category="advisory",
            source_ref=source_ref,
            tenant_id=tenant_id,
            owner="CISA",
            version=str(catalog.get("catalogVersion") or retrieved.date().isoformat()),
            retrieved_at=retrieved,
            replace_existing=True,
        )

    @classmethod
    def reindex_embeddings(cls, db: Session, tenant_id: str) -> int:
        """Recompute a tenant's saved vectors with the currently configured provider/model."""
        chunks = db.query(DocumentChunk).filter(DocumentChunk.tenant_id == tenant_id).all()
        for chunk in chunks:
            chunk.embedding_json = VectorService.get_embedding(chunk.content, task_type="RETRIEVAL_DOCUMENT")
            chunk.embedding_provider = VectorService.embedding_mode()
        db.commit()
        return len(chunks)

    @classmethod
    def ingest_document(
        cls,
        db: Session,
        title: str,
        content: str,
        category: str = "playbook",
        source_ref: Optional[str] = None,
        tenant_id: str = "tenant_default",
        owner: Optional[str] = None,
        version: Optional[str] = None,
        retrieved_at: Optional[datetime] = None,
        replace_existing: bool = False,
    ) -> KnowledgeDocument:
        existing = db.query(KnowledgeDocument).filter(
            KnowledgeDocument.title == title,
            KnowledgeDocument.tenant_id == tenant_id,
        ).first()
        if existing and replace_existing:
            db.query(DocumentChunk).filter(DocumentChunk.document_id == existing.id).delete(synchronize_session=False)
            doc = existing
            doc.content = content
            doc.category = category
            doc.source_ref = source_ref or existing.source_ref
            doc.status = "indexing"
            doc.owner = owner or existing.owner
            doc.version = version or existing.version
            doc.retrieved_at = retrieved_at or datetime.now(timezone.utc)
        elif existing and not replace_existing:
            return existing
        else:
            doc = KnowledgeDocument(
                id=f"doc_{uuid.uuid4().hex[:10]}",
                title=title,
                category=category,
                source_ref=source_ref or f"ref_{uuid.uuid4().hex[:6]}",
                content=content,
                status="indexing",
                chunk_count="0",
                owner=owner,
                version=version,
                retrieved_at=retrieved_at or datetime.now(timezone.utc),
                tenant_id=tenant_id,
            )
            db.add(doc)
        db.commit()

        raw_chunks = VectorService.chunk_text(content, chunk_size=900, overlap=100)
        chunk_objs = []
        mode = VectorService.embedding_mode()
        for idx, (section, chunk_text) in enumerate(raw_chunks):
            emb = VectorService.get_embedding(chunk_text, task_type="RETRIEVAL_DOCUMENT")
            chunk_obj = DocumentChunk(
                id=f"chk_{uuid.uuid4().hex[:10]}",
                document_id=doc.id,
                title=title,
                section=section,
                content=chunk_text,
                embedding_json=emb,
                embedding_provider=mode,
                chunk_index=str(idx),
                tenant_id=tenant_id
            )
            chunk_objs.append(chunk_obj)

        db.add_all(chunk_objs)
        doc.status = "indexed"
        doc.chunk_count = str(len(chunk_objs))
        db.commit()
        db.refresh(doc)
        return doc

    @classmethod
    def search_similar_chunks(
        cls, db: Session, query: str, top_k: int = 3, tenant_id: str = "tenant_default"
    ) -> List[Dict[str, Any]]:
        query_emb = VectorService.get_embedding(query, task_type="RETRIEVAL_QUERY")
        chunks = db.query(DocumentChunk).filter(DocumentChunk.tenant_id == tenant_id).all()

        scored = []
        for chk in chunks:
            if chk.embedding_json and len(chk.embedding_json) == len(query_emb):
                sim = VectorService.cosine_similarity(query_emb, chk.embedding_json)
                scored.append((sim, chk))

        scored.sort(key=lambda x: x[0], reverse=True)
        document_ids = {chunk.document_id for _, chunk in scored[:top_k]}
        documents = {
            document.id: document
            for document in db.query(KnowledgeDocument).filter(
                KnowledgeDocument.tenant_id == tenant_id,
                KnowledgeDocument.id.in_(document_ids),
            ).all()
        } if document_ids else {}
        results = []
        for sim, chk in scored[:top_k]:
            document = documents.get(chk.document_id)
            results.append({
                "chunk_id": chk.id,
                "document_id": chk.document_id,
                "title": chk.title,
                "section": chk.section,
                "content": chk.content,
                "relevance_score": round(sim, 4),
                "embedding_mode": chk.embedding_provider or VectorService.embedding_mode(),
                "source_ref": document.source_ref if document else None,
                "owner": document.owner if document else None,
                "version": document.version if document else None,
                "retrieved_at": document.retrieved_at.isoformat() if document and document.retrieved_at else None,
            })
        return results
