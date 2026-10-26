import time
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal, engine
from app.core.init_db import init_db
from app.core.logging import logger
from app.core.request_context import set_request_id
from app.api.endpoints import auth, dashboard, events, alerts, incidents, indicators, copilot, knowledge, mitre, feedback, ingest


def _wait_for_db_ready(max_retries: int = 20, retry_delay: float = 2.0):
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info(f"Database connection established on attempt {attempt}")
            return True
        except Exception as e:
            if attempt == max_retries:
                logger.error(f"FATAL: Could not connect to database after {max_retries} attempts: {e}")
                raise
            logger.warning(f"Database connection attempt {attempt}/{max_retries} failed: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Wait for DB socket to be ready (especially important in Docker Compose)
    _wait_for_db_ready()

    # Initialize DB schema & default users on startup
    db = SessionLocal()
    try:
        init_db(db)
        logger.info("Database initialized successfully with default admin/analyst users.")
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers_and_logging(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    set_request_id(request_id)
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.url.path.startswith(f"{settings.API_V1_STR}/auth/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    
    logger.info(
        f"{request.method} {request.url.path} Completed in {process_time:.2f}ms with status {response.status_code}"
    )
    return response


# API v1 Router inclusion
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(dashboard.router, prefix=f"{settings.API_V1_STR}/dashboard", tags=["dashboard"])
app.include_router(events.router, prefix=f"{settings.API_V1_STR}/events", tags=["events"])
app.include_router(alerts.router, prefix=f"{settings.API_V1_STR}/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix=f"{settings.API_V1_STR}/incidents", tags=["incidents"])
app.include_router(indicators.router, prefix=f"{settings.API_V1_STR}/indicators", tags=["indicators"])
app.include_router(copilot.router, prefix=f"{settings.API_V1_STR}/copilot", tags=["copilot"])
app.include_router(knowledge.router, prefix=f"{settings.API_V1_STR}/knowledge", tags=["knowledge"])
app.include_router(mitre.router, prefix=f"{settings.API_V1_STR}/mitre", tags=["mitre"])
app.include_router(feedback.router, prefix=f"{settings.API_V1_STR}", tags=["feedback_audit"])
app.include_router(ingest.router, prefix=f"{settings.API_V1_STR}/ingest", tags=["ingest"])


@app.get("/healthz")
def health_check():
    return {"status": "ok", "service": settings.PROJECT_NAME, "environment": settings.ENVIRONMENT}


@app.get("/readyz")
def readiness_check():
    ready = True
    db_error = None
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        ready = False
        db_error = str(e)
    return {
        "status": "ready" if ready else "degraded",
        "database": "connected" if ready else "disconnected",
        "database_error": db_error
    }
