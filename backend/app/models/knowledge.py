from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, JSON
from app.core.database import Base


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    category = Column(String, index=True, default="playbook")  # playbook, advisory, mitre_ref, standard
    source_ref = Column(String, nullable=True)
    content = Column(Text, nullable=False)
    status = Column(String, default="indexed")  # pending, indexing, indexed, error
    chunk_count = Column(String, default="0")
    owner = Column(String, nullable=True)
    version = Column(String, nullable=True)
    retrieved_at = Column(DateTime, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    
    tenant_id = Column(String, default="tenant_default", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class DocumentChunk(Base):
    __tablename__ = "document_chunks"

    id = Column(String, primary_key=True, index=True)
    document_id = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    section = Column(String, nullable=True)
    content = Column(Text, nullable=False)
    
    # Store embedding array as JSON for portability across SQLite and PostgreSQL
    embedding_json = Column(JSON, nullable=True)
    embedding_provider = Column(String, nullable=True)
    chunk_index = Column(String, default="0")
    
    tenant_id = Column(String, default="tenant_default", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
