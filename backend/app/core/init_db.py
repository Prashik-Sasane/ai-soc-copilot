import uuid
from sqlalchemy.orm import Session
from app.core.database import engine, Base
from app.core.security import get_password_hash
from app.models import User, UserRole


def init_db(db: Session) -> None:
    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Check if default admin exists
    admin_email = "admin@aisoc.io"
    user = db.query(User).filter(User.email == admin_email).first()
    if not user:
        admin_user = User(
            id="user_admin_001",
            email=admin_email,
            hashed_password=get_password_hash("AdminSOC123!"),
            full_name="Lead SOC Admin",
            role=UserRole.ADMIN.value,
            tenant_id="tenant_admin_001"
        )
        db.add(admin_user)

    # Check if default analyst exists
    analyst_email = "analyst@aisoc.io"
    analyst = db.query(User).filter(User.email == analyst_email).first()
    if not analyst:
        analyst_user = User(
            id="user_analyst_001",
            email=analyst_email,
            hashed_password=get_password_hash("AnalystSOC123!"),
            full_name="Tier 2 SOC Analyst",
            role=UserRole.ANALYST.value,
            tenant_id="tenant_analyst_001"
        )
        db.add(analyst_user)

    db.commit()
