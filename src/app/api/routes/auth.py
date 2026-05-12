from __future__ import annotations

from secrets import token_urlsafe
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from src.app.api.deps import get_auth_service, get_current_user
from src.app.core.config import get_settings
from src.app.schemas.auth import GithubLoginUrlResponse, UserResponse
from src.app.services.auth_service import (
    AuthService,
    InvalidGithubUserError,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def build_github_authorization_url(state: str | None = None) -> str:
    settings = get_settings()
    query_params = {
        "client_id": settings.github_client_id,
        "redirect_uri": settings.github_redirect_uri,
        "scope": "read:user user:email",
    }
    if state:
        query_params["state"] = state
    query = urlencode(query_params)
    return f"{settings.github_authorize_url}?{query}"


def _create_oauth_state() -> str:
    return token_urlsafe(32)


def _set_oauth_state_cookie(response: Response, state: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.oauth_state_cookie_name,
        value=state,
        max_age=settings.oauth_state_cookie_max_age_seconds,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        path="/",
    )


def _set_access_token_cookie(response: Response, access_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=access_token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        path="/",
    )


def _clear_oauth_state_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.oauth_state_cookie_name,
        path="/",
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
    )


def _frontend_redirect_url(**params: str) -> str:
    settings = get_settings()
    parsed = urlsplit(settings.frontend_auth_callback_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            parsed.fragment,
        )
    )


def _redirect_to_frontend_auth_error(error: str = "auth_failed") -> RedirectResponse:
    response = RedirectResponse(
        url=_frontend_redirect_url(auth_error=error),
        status_code=status.HTTP_302_FOUND,
    )
    _clear_oauth_state_cookie(response)
    return response


@router.get("/github/login", response_model=GithubLoginUrlResponse)
def github_login_url(response: Response) -> GithubLoginUrlResponse:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GitHub OAuth 설정이 비어 있습니다")
    oauth_state = _create_oauth_state()
    _set_oauth_state_cookie(response, oauth_state)
    return GithubLoginUrlResponse(authorization_url=build_github_authorization_url(oauth_state))


@router.get("/github")
def github_login_redirect() -> RedirectResponse:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GitHub OAuth 설정이 비어 있습니다")
    oauth_state = _create_oauth_state()
    response = RedirectResponse(
        url=build_github_authorization_url(oauth_state),
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )
    _set_oauth_state_cookie(response, oauth_state)
    return response


@router.get("/github/callback", response_model=None)
async def github_callback(
    request: Request,
    code: str = Query(min_length=1),
    state: str = Query(min_length=1),
    service: AuthService = Depends(get_auth_service),
) -> RedirectResponse:
    settings = get_settings()
    if not settings.github_client_id or not settings.github_client_secret:
        return _redirect_to_frontend_auth_error()
    oauth_state_cookie = request.cookies.get(settings.oauth_state_cookie_name)
    if not oauth_state_cookie or oauth_state_cookie != state:
        return _redirect_to_frontend_auth_error()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_response = await client.post(
                settings.github_token_url,
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                    "redirect_uri": settings.github_redirect_uri,
                },
            )
            if token_response.status_code >= 400:
                return _redirect_to_frontend_auth_error()

            token_payload = token_response.json()
            github_access_token = token_payload.get("access_token")
            if not isinstance(github_access_token, str) or not github_access_token:
                return _redirect_to_frontend_auth_error()

            user_response = await client.get(
                settings.github_user_api_url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {github_access_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if user_response.status_code >= 400:
                return _redirect_to_frontend_auth_error()

        token_response = service.upsert_github_user(user_response.json())
    except (httpx.HTTPError, InvalidGithubUserError, ValueError):
        return _redirect_to_frontend_auth_error()

    response = RedirectResponse(
        url=_frontend_redirect_url(auth="success"),
        status_code=status.HTTP_302_FOUND,
    )
    _set_access_token_cookie(response, token_response.access_token)
    _clear_oauth_state_cookie(response)
    return response


@router.get("/me", response_model=UserResponse)
def me(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    return current_user


@router.post("/logout")
def logout() -> JSONResponse:
    settings = get_settings()
    response = JSONResponse(content={"message": "로그아웃되었습니다"})
    response.delete_cookie(
        key=settings.auth_cookie_name,
        path="/",
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
    )
    response.delete_cookie(
        key=settings.oauth_state_cookie_name,
        path="/",
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
    )
    return response
