from functools import lru_cache

from src.app.core.config import get_settings
from src.app.services.agent_service import AgentService


@lru_cache
def get_agent_service() -> AgentService:
    return AgentService(settings=get_settings())
