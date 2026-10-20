import sys
import os
from pathlib import Path

# Force deterministic, offline settings BEFORE the app/config module is imported.
# The test suite must never require real credentials or make external network calls,
# even when a developer's local .env configures live providers.
os.environ["ENVIRONMENT"] = "test"
os.environ["ENABLE_DEMO_SEEDING"] = "true"
os.environ["LLM_PROVIDER"] = "mock"
os.environ["EMBEDDING_PROVIDER"] = "mock"
os.environ["GEMINI_API_KEY"] = ""
os.environ["VT_API_KEY"] = ""
os.environ["OTX_API_KEY"] = ""

# Add backend directory to sys.path
backend_dir = str(Path(__file__).parent.parent.resolve())
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import Base, get_db
from app.core.init_db import init_db
from app.main import app

engine = create_engine(settings.TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    init_db(db)
    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    def _get_test_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _get_test_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
