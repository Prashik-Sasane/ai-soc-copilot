import json
from pathlib import Path
from typing import Any, Dict, List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env regardless of the working directory: backend/app/core/config.py -> repo root.
# The documented local flow runs uvicorn from backend/, so the shared .env at the repo root
# must still be picked up (a backend/.env, if present, overrides it).
_BACKEND_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_DIR.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI SOC Copilots"
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
    LLM_PROVIDER: str = "mock"  # mock, openai, gemini, ollama
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3.5-flash"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    LLM_TIMEOUT_SECONDS: float = 30.0

    # Embeddings: mock is an explicit offline/demo mode (hash vectors). Never presented as semantic search.
    EMBEDDING_PROVIDER: str = "mock"  # mock, gemini
    EMBEDDING_MODEL: str = "gemini-embedding-001"

    # External Threat Intelligence
    VT_API_KEY: str = ""
    OTX_API_KEY: str = ""
    TI_CACHE_TTL_MINUTES: int = 60

    # Ingestion
    # Comma-separated source_id:token pairs, e.g. "webhook-default:dev-ingest-token"
    INGEST_WEBHOOK_TOKENS: str = "webhook-default:dev-ingest-token"
    MAX_EVENT_FUTURE_HOURS: int = 24
    MAX_EVENT_AGE_DAYS: int = 1825
    # Demo seeding is an explicit opt-in development feature (simulated records only).
    # Default off so the normal data path is real, source-agnostic ingestion.
    ENABLE_DEMO_SEEDING: bool = False

    # Correlation
    CORRELATION_WINDOW_MINUTES: int = 60
    CORRELATION_MIN_ALERTS: int = 2
    CORRELATION_MAX_ALERTS: int = 2000

    # Provisional heuristic risk boundaries; tune only with analyst-reviewed outcomes.
    RISK_MEDIUM_THRESHOLD: int = 25
    RISK_HIGH_THRESHOLD: int = 50
    RISK_CRITICAL_THRESHOLD: int = 75

    # CORS - typed as Any to prevent pydantic-settings from auto JSON-decoding
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
        env_file=(str(_REPO_ROOT / ".env"), str(_BACKEND_DIR / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() in {"production", "prod"}

    @property
    def demo_seeding_enabled(self) -> bool:
        if self.is_production:
            return False
        return bool(self.ENABLE_DEMO_SEEDING)

    @property
    def webhook_tokens(self) -> Dict[str, str]:
        tokens: Dict[str, str] = {}
        raw = (self.INGEST_WEBHOOK_TOKENS or "").strip()
        if not raw:
            return tokens
        if raw.startswith("{"):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return {str(k): str(v) for k, v in parsed.items()}
            except json.JSONDecodeError:
                pass
        for part in raw.split(","):
            if ":" not in part:
                continue
            source_id, token = part.split(":", 1)
            source_id = source_id.strip()
            token = token.strip()
            if source_id and token:
                tokens[source_id] = token
        return tokens

    @property
    def llm_configured(self) -> bool:
        provider = (self.LLM_PROVIDER or "mock").lower()
        if provider == "gemini":
            return bool(self.GEMINI_API_KEY)
        if provider == "openai":
            return bool(self.OPENAI_API_KEY)
        if provider == "ollama":
            return bool(self.OLLAMA_BASE_URL)
        return False

    @property
    def embeddings_semantic(self) -> bool:
        return (self.EMBEDDING_PROVIDER or "").lower() == "gemini" and bool(self.GEMINI_API_KEY)

    @property
    def threat_intel_configured(self) -> bool:
        return bool(self.VT_API_KEY or self.OTX_API_KEY)


settings = Settings()
