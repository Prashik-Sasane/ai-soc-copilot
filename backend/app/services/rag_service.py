import uuid
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session

from app.models.knowledge import KnowledgeDocument, DocumentChunk
from app.services.vector_service import VectorService


class RAGService:
    @classmethod
    def ingest_document(
        cls, db: Session, title: str, content: str, category: str = "playbook", source_ref: Optional[str] = None, tenant_id: str = "tenant_default"
    ) -> KnowledgeDocument:
        doc_id = f"doc_{uuid.uuid4().hex[:10]}"
        doc = KnowledgeDocument(
            id=doc_id,
            title=title,
            category=category,
            source_ref=source_ref or f"ref_{uuid.uuid4().hex[:6]}",
            content=content,
            status="indexing",
            chunk_count="0",
            tenant_id=tenant_id
        )
        db.add(doc)
        db.commit()

        # Chunk and vector embed
        raw_chunks = VectorService.chunk_text(content, chunk_size=350, overlap=50)
        chunk_objs = []
        for idx, (section, chunk_text) in enumerate(raw_chunks):
            emb = VectorService.get_embedding(chunk_text)
            chunk_obj = DocumentChunk(
                id=f"chk_{uuid.uuid4().hex[:10]}",
                document_id=doc.id,
                title=title,
                section=section,
                content=chunk_text,
                embedding_json=emb,
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
        query_emb = VectorService.get_embedding(query)
        chunks = db.query(DocumentChunk).filter(DocumentChunk.tenant_id == tenant_id).all()

        scored = []
        for chk in chunks:
            if chk.embedding_json:
                sim = VectorService.cosine_similarity(query_emb, chk.embedding_json)
                scored.append((sim, chk))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for sim, chk in scored[:top_k]:
            results.append({
                "chunk_id": chk.id,
                "document_id": chk.document_id,
                "title": chk.title,
                "section": chk.section,
                "content": chk.content,
                "relevance_score": round(sim, 4)
            })
        return results
