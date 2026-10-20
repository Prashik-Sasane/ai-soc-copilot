import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.deps import get_current_user
from app.models.user import User, UserRole
from app.models.audit import AuditLog
from app.services.audit_service import write_audit
from app.schemas.auth import Token, LoginRequest, UserCreate, UserRead

router = APIRouter()


@router.post("/login", response_model=Token)
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    write_audit(
        db,
        action="auth_login",
        resource_type="auth",
        resource_id=user.id,
        user=user,
        details={"message": "User logged in successfully"},
        commit=True,
    )

    access_token = create_access_token(subject=user.id, role=user.role)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }


@router.get("/me", response_model=UserRead)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/register", response_model=UserRead)
def register_user(
    user_in: UserCreate,
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    
    user_uuid = uuid.uuid4().hex[:12]
    new_user = User(
        id=f"user_{user_uuid}",
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role if user_in.role in [r.value for r in UserRole] else UserRole.ANALYST.value,
        tenant_id=f"tenant_{user_uuid}"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user
