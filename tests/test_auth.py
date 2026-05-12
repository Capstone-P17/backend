from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from src.app.api import deps
from src.app.api.deps import get_auth_service
from src.app.api.routes import auth as auth_routes
from src.app.core.config import get_settings
from src.app.core.security import create_access_token
from src.app.factory import create_app
from src.app.schemas.auth import TokenResponse, UserResponse


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload


class FakeAsyncClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, *args, **kwargs) -> FakeResponse:
        return FakeResponse({"access_token": "github-token"})

    async def get(self, *args, **kwargs) -> FakeResponse:
        return FakeResponse(
            {
                "id": 123,
                "login": "octocat",
                "email": "octocat@example.com",
                "name": "Octocat",
                "avatar_url": "https://example.com/octocat.png",
            }
        )


class FakeAuthService:
    def upsert_github_user(self, github_user: dict[str, object]) -> TokenResponse:
        return TokenResponse(
            access_token="jwt-token",
            user=UserResponse(
                id=1,
                github_id=str(github_user["id"]),
                github_login=str(github_user["login"]),
                email="octocat@example.com",
                display_name="Octocat",
                avatar_url="https://example.com/octocat.png",
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
        )

    def get_user_by_id(self, user_id: int):
        return SimpleNamespace(
            id=user_id,
            github_id="123",
            github_login="octocat",
            email="octocat@example.com",
            display_name="Octocat",
            avatar_url="https://example.com/octocat.png",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def configure_auth_env(monkeypatch, *, secure: bool = True) -> None:
    monkeypatch.setenv("GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("GITHUB_REDIRECT_URI", "http://localhost:8000/auth/github/callback")
    monkeypatch.setenv("FRONTEND_AUTH_CALLBACK_URL", "http://localhost:3000/")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true" if secure else "false")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-bytes")
    get_settings.cache_clear()
    deps.get_agent_service.cache_clear()
    deps.get_analysis_result_store.cache_clear()
    deps.get_analysis_job_store.cache_clear()
    deps.get_analyzer_service.cache_clear()
    deps.get_analysis_service.cache_clear()


def test_github_login_redirect_sets_oauth_state_cookie(monkeypatch) -> None:
    configure_auth_env(monkeypatch, secure=True)
    client = TestClient(create_app())

    response = client.get("/auth/github", follow_redirects=False)

    assert response.status_code == 307
    location = response.headers["location"]
    parsed = urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "https://github.com/login/oauth/authorize"
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["client-id"]
    assert query["redirect_uri"] == ["http://localhost:8000/auth/github/callback"]
    assert query["state"][0]
    set_cookie = response.headers["set-cookie"]
    assert "github_oauth_state=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=lax" in set_cookie


def test_github_callback_redirects_to_frontend_with_http_only_access_cookie(monkeypatch) -> None:
    configure_auth_env(monkeypatch, secure=True)
    monkeypatch.setattr(auth_routes.httpx, "AsyncClient", FakeAsyncClient)
    app = create_app()
    app.dependency_overrides[get_auth_service] = lambda: FakeAuthService()
    client = TestClient(app)

    response = client.get(
        "/auth/github/callback?code=abc&state=state-123",
        headers={"cookie": "github_oauth_state=state-123"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "http://localhost:3000/?auth=success"
    set_cookies = response.headers.get_list("set-cookie")
    access_cookie = next(cookie for cookie in set_cookies if cookie.startswith("access_token="))
    assert "jwt-token" in access_cookie
    assert "HttpOnly" in access_cookie
    assert "Secure" in access_cookie
    assert "SameSite=lax" in access_cookie
    assert any(cookie.startswith("github_oauth_state=") and "Max-Age=0" in cookie for cookie in set_cookies)


def test_github_callback_rejects_invalid_oauth_state(monkeypatch) -> None:
    configure_auth_env(monkeypatch, secure=False)
    client = TestClient(create_app())

    response = client.get(
        "/auth/github/callback?code=abc&state=expected",
        headers={"cookie": "github_oauth_state=other"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "http://localhost:3000/?auth_error=auth_failed"
    set_cookies = response.headers.get_list("set-cookie")
    assert any(cookie.startswith("github_oauth_state=") and "Max-Age=0" in cookie for cookie in set_cookies)


def test_frontend_auth_redirect_preserves_existing_callback_query(monkeypatch) -> None:
    configure_auth_env(monkeypatch, secure=True)
    monkeypatch.setenv("FRONTEND_AUTH_CALLBACK_URL", "http://localhost:3000/?from=github")
    get_settings.cache_clear()

    assert auth_routes._frontend_redirect_url(auth="success") == "http://localhost:3000/?from=github&auth=success"


def test_me_accepts_http_only_cookie_token(monkeypatch) -> None:
    configure_auth_env(monkeypatch, secure=False)
    app = create_app()
    app.dependency_overrides[get_auth_service] = lambda: FakeAuthService()
    client = TestClient(app)
    token = create_access_token(user_id=1)

    response = client.get("/auth/me", headers={"cookie": f"access_token={token}"})

    assert response.status_code == 200
    assert response.json()["github_login"] == "octocat"


def test_logout_clears_auth_and_oauth_state_cookies(monkeypatch) -> None:
    configure_auth_env(monkeypatch, secure=True)
    client = TestClient(create_app())

    response = client.post(
        "/auth/logout",
        headers={"cookie": "access_token=jwt-token; github_oauth_state=state-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"message": "로그아웃되었습니다"}
    set_cookies = response.headers.get_list("set-cookie")
    assert any(cookie.startswith("access_token=") and "Max-Age=0" in cookie for cookie in set_cookies)
    assert any(cookie.startswith("github_oauth_state=") and "Max-Age=0" in cookie for cookie in set_cookies)
    assert all("Secure" in cookie for cookie in set_cookies)
    assert all("SameSite=lax" in cookie for cookie in set_cookies)
