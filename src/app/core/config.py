from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AGENT_",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "AI Agent Backend"
    app_version: str = "0.1.0"
    environment: Literal["local", "dev", "prod"] = "local"
    api_prefix: str = "/api/v1"

    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False

    default_agent_name: str = "orchestrator"
    default_system_prompt: str = (
        "You are a helpful orchestration agent that summarizes intent and suggests next steps."
    )
    allowed_origins: list[str] = Field(default_factory=lambda: ["*"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
