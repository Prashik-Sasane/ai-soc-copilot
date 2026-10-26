from typing import Optional
from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_validator


class Token(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional["UserRead"] = None
    mfa_required: bool = False
    mfa_setup_required: bool = False
    mfa_token: Optional[str] = None
    recovery_codes: list[str] = Field(default_factory=list)


class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=72)


class MfaLoginRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=20)


class MfaSetupLoginRequest(BaseModel):
    mfa_token: str


class MfaEnrollmentRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=20)


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class MfaDisableRequest(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=20)


class MfaSetupResponse(BaseModel):
    otpauth_uri: str
    qr_code_data_uri: str
    expires_at: str


class MfaEnabledResponse(BaseModel):
    enabled: bool
    recovery_codes: list[str] = Field(default_factory=list)


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)
    full_name: Optional[str] = None
    role: str = "analyst"

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 UTF-8 bytes.")
        classes = sum((
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() and not char.isspace() for char in value),
        ))
        if len(value) < 12 or classes < 2:
            raise ValueError("Choose a password at least 12 characters long using at least two character types.")
        return value


class UserRead(BaseModel):
    id: str
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    tenant_id: str
    is_active: bool
    mfa_enabled: Optional[bool] = False

    model_config = ConfigDict(from_attributes=True)



Token.model_rebuild()
