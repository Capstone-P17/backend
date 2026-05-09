from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.app.core.security import decode_access_token
from src.app.core.config import get_settings
from src.app.db.session import SessionLocal, get_db_session
from src.app.schemas.auth import UserResponse
from src.app.services.agent_service import AgentService
from src.app.services.analysis_service import AnalysisService
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.auth_service import AuthService
from src.app.services.job_store import AnalysisJobStore
from src.app.services.result_store import AnalysisResultStore, DatabaseAnalysisResultStore


bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache
def get_agent_service() -> AgentService:
    return AgentService(
        settings=get_settings(),
        analysis_service=get_analysis_service(),
    )


@lru_cache
def get_analysis_result_store() -> DatabaseAnalysisResultStore:
    return DatabaseAnalysisResultStore(SessionLocal)


@lru_cache
def get_analysis_job_store() -> AnalysisJobStore:
    return AnalysisJobStore()


@lru_cache
def get_analyzer_service() -> AnalyzerService:
    return AnalyzerService(workspace_root=get_settings().workspace_root)


@lru_cache
def get_analysis_service() -> AnalysisService:
    return AnalysisService(
        settings=get_settings(),
        analyzer_service=get_analyzer_service(),
        result_store=get_analysis_result_store(),
    )


def get_auth_service(db: Session = Depends(get_db_session)) -> AuthService:
    return AuthService(db=db)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    service: AuthService = Depends(get_auth_service),
) -> UserResponse:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="인증 토큰이 필요합니다")

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 토큰입니다") from exc

    user = service.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다")

    return UserResponse.model_validate(user)
