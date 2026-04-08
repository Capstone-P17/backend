from functools import lru_cache

from fastapi import Depends
from sqlalchemy.orm import Session

from src.app.core.config import get_settings
from src.app.db.session import get_db_session
from src.app.services.agent_service import AgentService
from src.app.services.analysis_service import AnalysisService
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.auth_service import AuthService
from src.app.services.result_store import AnalysisResultStore


@lru_cache
def get_agent_service() -> AgentService:
    return AgentService(
        settings=get_settings(),
        analysis_service=get_analysis_service(),
    )


@lru_cache
def get_analysis_result_store() -> AnalysisResultStore:
    return AnalysisResultStore()


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
