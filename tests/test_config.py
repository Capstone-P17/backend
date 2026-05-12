from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from src.app.core.config import Settings, get_settings
from src.app.factory import create_app


def test_settings_rejects_short_jwt_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(JWT_SECRET_KEY="short")


def test_prod_settings_rejects_wildcard_cors_with_credentials() -> None:
    with pytest.raises(ValidationError):
        Settings(
            ENVIRONMENT="prod",
            JWT_SECRET_KEY="test-secret-key-with-at-least-32-bytes",
            ALLOWED_ORIGINS=["*"],
            CORS_ALLOW_CREDENTIALS=True,
        )


def test_docs_can_be_disabled_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCS_ENABLED", "false")
    get_settings.cache_clear()

    client = TestClient(create_app())

    assert client.get("/docs").status_code == 404
    assert "docs" not in client.get("/").json()
