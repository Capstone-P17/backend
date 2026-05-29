from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("OPENAI_API_KEY", "")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-bytes")

import pytest
from fastapi.testclient import TestClient

import src.app.factory as factory_module
from src.app.api import deps
from src.app.api.deps import get_analysis_job_store, get_analysis_service, get_current_user
from src.app.core.config import get_settings
from src.app.factory import create_app
from src.app.schemas.auth import UserResponse
from src.app.services.analysis_service import AnalysisService
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.job_store import AnalysisJobStore
from src.app.services.result_store import AnalysisResultStore


@pytest.fixture(autouse=True)
def clear_dependency_caches(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-bytes")
    get_settings.cache_clear()
    deps.get_agent_service.cache_clear()
    deps.get_analysis_result_store.cache_clear()
    deps.get_analysis_job_store.cache_clear()
    deps.get_analyzer_service.cache_clear()
    deps.get_analysis_service.cache_clear()
    yield
    get_settings.cache_clear()
    deps.get_agent_service.cache_clear()
    deps.get_analysis_result_store.cache_clear()
    deps.get_analysis_job_store.cache_clear()
    deps.get_analyzer_service.cache_clear()
    deps.get_analysis_service.cache_clear()


@pytest.fixture
def result_store() -> AnalysisResultStore:
    return AnalysisResultStore()


@pytest.fixture
def job_store() -> AnalysisJobStore:
    return AnalysisJobStore()


@pytest.fixture
def analysis_service(result_store: AnalysisResultStore) -> AnalysisService:
    settings = get_settings()
    return AnalysisService(
        settings=settings,
        analyzer_service=AnalyzerService(settings.workspace_root),
        result_store=result_store,
    )


@pytest.fixture
def client(
    analysis_service: AnalysisService,
    job_store: AnalysisJobStore,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    monkeypatch.setattr(factory_module, "init_db", lambda: None)
    app = create_app()

    def fake_current_user() -> UserResponse:
        return UserResponse(
            id=1,
            github_id="gh-1",
            github_login="tester",
            email=None,
            display_name="Tester",
            avatar_url=None,
            created_at="2026-01-01T00:00:00",  # type: ignore[arg-type]
        )

    app.dependency_overrides[get_current_user] = fake_current_user
    app.dependency_overrides[get_analysis_service] = lambda: analysis_service
    app.dependency_overrides[get_analysis_job_store] = lambda: job_store
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def unauthenticated_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(factory_module, "init_db", lambda: None)
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
