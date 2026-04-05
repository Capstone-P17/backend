from fastapi import APIRouter, Depends

from src.app.api.deps import get_agent_service
from src.app.core.config import get_settings
from src.app.schemas.agent import AgentProfileResponse, AgentRunRequest, AgentRunResponse
from src.app.services.agent_service import AgentService

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("/profile", response_model=AgentProfileResponse)
def get_agent_profile() -> AgentProfileResponse:
    settings = get_settings()
    return AgentProfileResponse(
        agent_name=settings.default_agent_name,
        environment=settings.environment,
        api_prefix=settings.api_prefix,
        capabilities=[
            "conversation-orchestration",
            "context-aware-request-shaping",
            "extensible-tool-execution-placeholder",
        ],
    )


@router.post("/runs", response_model=AgentRunResponse)
def run_agent(
    payload: AgentRunRequest,
    service: AgentService = Depends(get_agent_service),
) -> AgentRunResponse:
    return service.run(payload)
