import uuid
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from app.core.database import engine, Base
from app.core.security import get_password_hash
from app.core.logging import logger
from app.models import User, UserRole
from app.services.mitre_service import MitreService


def reconcile_schema() -> None:
    """Add missing columns to pre-existing tables.

    This project has no migration framework and relies on `create_all()`, which
    only creates *new* tables and never alters existing ones. That leaves older
    development/deployment databases without columns added later (e.g. audit
    before/after values), which crashes at runtime. This performs safe, additive
    `ALTER TABLE ADD COLUMN` statements only; it never drops or retypes columns.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        existing_cols = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing_cols:
                continue
            col_type = column.type.compile(dialect=engine.dialect)
            ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}'
            with engine.begin() as conn:
                conn.execute(text(ddl))
            logger.warning(f"Schema reconciliation: added column {table.name}.{column.name} ({col_type})")


def init_db(db: Session) -> None:
    # Create all tables
    Base.metadata.create_all(bind=engine)
    # Add any columns introduced after the database was first created
    reconcile_schema()

    # Seeded operators share a demo tenant so the walkthrough works; new registrations stay isolated.
    admin_email = "admin@aisoc.io"
    user = db.query(User).filter(User.email == admin_email).first()
    if not user:
        admin_user = User(
            id="user_admin_001",
            email=admin_email,
            hashed_password=get_password_hash("AdminSOC123!"),
            full_name="Lead SOC Admin",
            role=UserRole.ADMIN.value,
            tenant_id="tenant_default"
        )
        db.add(admin_user)

    analyst_email = "analyst@aisoc.io"
    analyst = db.query(User).filter(User.email == analyst_email).first()
    if not analyst:
        analyst_user = User(
            id="user_analyst_001",
            email=analyst_email,
            hashed_password=get_password_hash("AnalystSOC123!"),
            full_name="Tier 2 SOC Analyst",
            role=UserRole.ANALYST.value,
            tenant_id="tenant_default"
        )
        db.add(analyst_user)

    db.commit()
    MitreService.ensure_bundled(db)
