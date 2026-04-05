from fastapi import APIRouter, Depends, HTTPException

from src.app.api.deps import get_agent_service
from src.app.core.config import get_settings
from src.app.schemas.agent import AgentProfileResponse, AgentRunRequest, AgentRunResponse
from src.app.services.agent_service import AgentService

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
