from __future__ import annotations

from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse

from src.app.api.deps import get_auth_service, get_current_user
from src.app.core.config import get_settings
from src.app.schemas.auth import GithubLoginUrlResponse, TokenResponse, UserResponse
from src.app.services.auth_service import (
    AuthService,
    InvalidGithubUserError,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def build_github_authorization_url() -> str:
    settings = get_settings()
    query = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_redirect_uri,
            "scope": "read:user user:email",
        }
    )
    return f"{settings.github_authorize_url}?{query}"


@router.get("/github/login", response_model=GithubLoginUrlResponse)
def github_login_url() -> GithubLoginUrlResponse:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GitHub OAuth 설정이 비어 있습니다")
    return GithubLoginUrlResponse(authorization_url=build_github_authorization_url())


@router.get("/github")
def github_login_redirect() -> RedirectResponse:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GitHub OAuth 설정이 비어 있습니다")
    return RedirectResponse(url=build_github_authorization_url(), status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/github/callback", response_model=TokenResponse)
async def github_callback(
    code: str = Query(min_length=1),
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    settings = get_settings()
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GitHub OAuth 설정이 비어 있습니다")

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
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub 토큰 발급에 실패했습니다")

        token_payload = token_response.json()
        github_access_token = token_payload.get("access_token")
        if not isinstance(github_access_token, str) or not github_access_token:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub access token이 없습니다")

        user_response = await client.get(
            settings.github_user_api_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {github_access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if user_response.status_code >= 400:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub 사용자 조회에 실패했습니다")

    try:
        return service.upsert_github_user(user_response.json())
    except InvalidGithubUserError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

@router.get("/me", response_model=UserResponse)
def me(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    return current_user
