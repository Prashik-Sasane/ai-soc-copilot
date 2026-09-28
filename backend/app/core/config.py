import json
from typing import Any, List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI SOC Copilot"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Security
    SECRET_KEY: str = "dev_secret_key_change_in_production_min_32_bytes_long_key_soc"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # Databases
    DATABASE_URL: str = "sqlite:///./ai_soc_dev.db"
    TEST_DATABASE_URL: str = "sqlite:///./test_ai_soc.db"

    # AI & LLM Adapter Config
    LLM_PROVIDER: str = "mock"  # mock, openai, ollama
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # Embeddings
    EMBEDDING_PROVIDER: str = "mock"  # mock, sentence-transformers, openai
    EMBEDDING_MODEL: str = "text-embedding-3-small"

    # External Threat Intelligence
    VT_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # CORS - typed as Any to prevent pydantic-settings from auto JSON-decoding
    # the env var before our validator runs (handles comma-separated and JSON formats)
    CORS_ORIGINS: Any = ["http://localhost:3000", "http://127.0.0.1:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        if v is None:
            return ["http://localhost:3000", "http://127.0.0.1:3000"]
        if isinstance(v, list):
            return [str(i).strip() for i in v]
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return ["http://localhost:3000", "http://127.0.0.1:3000"]
            if stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [str(i).strip() for i in parsed]
                except json.JSONDecodeError:
                    pass
            return [i.strip() for i in stripped.split(",") if i.strip()]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )


settings = Settings()
