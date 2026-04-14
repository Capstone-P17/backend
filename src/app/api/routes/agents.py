from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from src.app.api.deps import get_agent_service
from src.app.core.config import get_settings
from src.app.schemas.agent import AgentProfileResponse, AgentRunRequest, AgentRunResponse
from src.app.schemas.repository import GitHubRunRequest
from src.app.services.agent_service import AgentService
from src.app.services.analysis_service import (
    AnalysisExecutionError,
    GitHubRepositoryCloneError,
    InvalidGitHubRepositoryError,
    InvalidJavaFileError,
    InvalidRepositoryArchiveError,
    RepositoryArchiveExtractionError,
)

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("/profile", response_model=AgentProfileResponse)
def get_agent_profile() -> AgentProfileResponse:
    settings = get_settings()
    try:
        default_target_path = str(settings.analysis_default_target.relative_to(settings.workspace_root))
    except ValueError:
        default_target_path = str(settings.analysis_default_target)

    return AgentProfileResponse(
        agent_name=settings.default_agent_name,
        environment=settings.environment,
        api_prefix=settings.api_prefix,
        llm_provider="openai",
        llm_model=settings.openai_model,
        graph_nodes=[
            "run_static_analysis",
            "generate_natural_language_report",
        ],
        capabilities=[
            "langgraph-security-audit-workflow",
            "existing-java-analyzer-integration",
            "openai-powered-natural-language-reporting",
        ],
        default_target_path=default_target_path,
    )


@router.post("/runs", response_model=AgentRunResponse)
def run_agent(
    payload: AgentRunRequest,
    service: AgentService = Depends(get_agent_service),
) -> AgentRunResponse:
    try:
        return service.run(payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/runs/file", response_model=AgentRunResponse)
async def run_agent_with_uploaded_file(
    file: UploadFile | None = File(default=None),
    instructions: Annotated[str | None, Form()] = None,
    session_id: Annotated[str | None, Form()] = None,
    include_raw_analysis: Annotated[bool, Form()] = False,
    service: AgentService = Depends(get_agent_service),
) -> AgentRunResponse:
    if file is None or not file.filename:
        raise HTTPException(status_code=422, detail="파일을 첨부해주세요")

    try:
        content = await file.read()
        return service.run_uploaded_file(
            filename=file.filename,
            content=content,
            session_id=session_id,
            instructions=instructions or "",
            include_raw_analysis=include_raw_analysis,
        )
    except InvalidJavaFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AnalysisExecutionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/runs/archive", response_model=AgentRunResponse)
async def run_agent_with_uploaded_repository(
    file: UploadFile | None = File(default=None),
    instructions: Annotated[str | None, Form()] = None,
    session_id: Annotated[str | None, Form()] = None,
    include_raw_analysis: Annotated[bool, Form()] = False,
    service: AgentService = Depends(get_agent_service),
) -> AgentRunResponse:
    if file is None or not file.filename:
        raise HTTPException(status_code=422, detail="레포지토리 압축 파일을 첨부해주세요")

    try:
        content = await file.read()
        return service.run_uploaded_repository(
            filename=file.filename,
            content=content,
            session_id=session_id,
            instructions=instructions or "",
            include_raw_analysis=include_raw_analysis,
        )
    except InvalidRepositoryArchiveError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RepositoryArchiveExtractionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except AnalysisExecutionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/runs/repository", response_model=AgentRunResponse)
async def run_agent_with_github_repository(
    body: GitHubRunRequest,
    service: AgentService = Depends(get_agent_service),
) -> AgentRunResponse:
    try:
        return service.run_github_repository(
            url=body.url,
            session_id=body.session_id,
            instructions=body.instructions or "",
            include_raw_analysis=body.include_raw_analysis,
        )
    except (InvalidGitHubRepositoryError, InvalidRepositoryArchiveError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GitHubRepositoryCloneError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except AnalysisExecutionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
