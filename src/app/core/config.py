from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_ANALYSIS_TARGET = PROJECT_ROOT / "src" / "analyzer" / "test_samples"
DEFAULT_SYSTEM_PROMPT = (
    "You are a senior application security analyst. Use the provided static-analysis results "
    "to write a concise but actionable Korean report for developers."
)
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


class Settings(BaseSettings):
    """Application settings loaded from code configuration and environment variables."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(
        default="AI Security Audit Backend",
        validation_alias=AliasChoices("APP_NAME", "AGENT_APP_NAME"),
    )
    app_version: str = Field(
        default="1.0.0",
        validation_alias=AliasChoices("APP_VERSION", "AGENT_APP_VERSION"),
    )
    environment: Literal["local", "dev", "prod"] = Field(
        default="local",
        validation_alias=AliasChoices("ENVIRONMENT", "AGENT_ENVIRONMENT"),
    )
    api_prefix: str = Field(
        default="", validation_alias=AliasChoices("API_PREFIX", "AGENT_API_PREFIX")
    )

    host: str = Field(
        default="0.0.0.0", validation_alias=AliasChoices("HOST", "AGENT_HOST")
    )
    port: int = Field(default=8000, validation_alias=AliasChoices("PORT", "AGENT_PORT"))
    reload: bool = Field(
        default=False, validation_alias=AliasChoices("RELOAD", "AGENT_RELOAD")
    )

    workspace_root: Path = Field(
        default=PROJECT_ROOT,
        validation_alias=AliasChoices("WORKSPACE_ROOT", "AGENT_WORKSPACE_ROOT"),
    )
    analysis_default_target: Path = Field(
        default=DEFAULT_ANALYSIS_TARGET,
        validation_alias=AliasChoices(
            "ANALYSIS_DEFAULT_TARGET", "AGENT_ANALYSIS_DEFAULT_TARGET"
        ),
    )
    analysis_max_findings_in_prompt: int = Field(
        default=20,
        validation_alias=AliasChoices(
            "ANALYSIS_MAX_FINDINGS_IN_PROMPT",
            "AGENT_ANALYSIS_MAX_FINDINGS_IN_PROMPT",
        ),
    )

    default_agent_name: str = Field(
        default="security-audit-agent",
        validation_alias=AliasChoices("DEFAULT_AGENT_NAME", "AGENT_DEFAULT_AGENT_NAME"),
    )
    openai_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OPENAI_API_KEY", "AGENT_OPENAI_API_KEY"),
    )
    openai_model: str = Field(
        default=DEFAULT_OPENAI_MODEL,
        validation_alias=AliasChoices("OPENAI_MODEL", "AGENT_OPENAI_MODEL"),
    )
    openai_temperature: float = Field(
        default=0.1,
        validation_alias=AliasChoices("OPENAI_TEMPERATURE", "AGENT_OPENAI_TEMPERATURE"),
    )
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        validation_alias=AliasChoices("ALLOWED_ORIGINS", "AGENT_ALLOWED_ORIGINS"),
    )
    cors_allow_credentials: bool = Field(
        default=True,
        validation_alias=AliasChoices("CORS_ALLOW_CREDENTIALS", "AGENT_CORS_ALLOW_CREDENTIALS"),
    )
    database_url: str = Field(
        default=f"sqlite:///{(PROJECT_ROOT / 'app.db').as_posix()}",
        validation_alias=AliasChoices("DATABASE_URL", "AGENT_DATABASE_URL"),
    )
    jwt_secret_key: str = Field(
        default="change-this-secret-in-production",
        validation_alias=AliasChoices("JWT_SECRET_KEY", "AGENT_JWT_SECRET_KEY"),
    )
    jwt_algorithm: str = Field(
        default="HS256",
        validation_alias=AliasChoices("JWT_ALGORITHM", "AGENT_JWT_ALGORITHM"),
    )
    access_token_expire_minutes: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "AGENT_ACCESS_TOKEN_EXPIRE_MINUTES",
        ),
    )
    frontend_auth_callback_url: str = Field(
        default="http://localhost:3000/auth/callback",
        validation_alias=AliasChoices(
            "FRONTEND_AUTH_CALLBACK_URL",
            "AGENT_FRONTEND_AUTH_CALLBACK_URL",
        ),
    )
    auth_cookie_name: str = Field(
        default="access_token",
        validation_alias=AliasChoices("AUTH_COOKIE_NAME", "AGENT_AUTH_COOKIE_NAME"),
    )
    auth_cookie_secure: bool = Field(
        default=True,
        validation_alias=AliasChoices("AUTH_COOKIE_SECURE", "AGENT_AUTH_COOKIE_SECURE"),
    )
    auth_cookie_samesite: Literal["lax", "strict", "none"] = Field(
        default="lax",
        validation_alias=AliasChoices("AUTH_COOKIE_SAMESITE", "AGENT_AUTH_COOKIE_SAMESITE"),
    )
    oauth_state_cookie_name: str = Field(
        default="github_oauth_state",
        validation_alias=AliasChoices(
            "OAUTH_STATE_COOKIE_NAME",
            "AGENT_OAUTH_STATE_COOKIE_NAME",
        ),
    )
    oauth_state_cookie_max_age_seconds: int = Field(
        default=600,
        validation_alias=AliasChoices(
            "OAUTH_STATE_COOKIE_MAX_AGE_SECONDS",
            "AGENT_OAUTH_STATE_COOKIE_MAX_AGE_SECONDS",
        ),
    )
    github_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("GITHUB_CLIENT_ID", "AGENT_GITHUB_CLIENT_ID"),
    )
    github_client_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "GITHUB_CLIENT_SECRET",
            "AGENT_GITHUB_CLIENT_SECRET",
        ),
    )
    github_redirect_uri: str = Field(
        default="http://localhost:8000/auth/github/callback",
        validation_alias=AliasChoices(
            "GITHUB_REDIRECT_URI",
            "AGENT_GITHUB_REDIRECT_URI",
        ),
    )
    github_authorize_url: str = Field(
        default="https://github.com/login/oauth/authorize",
        validation_alias=AliasChoices(
            "GITHUB_AUTHORIZE_URL",
            "AGENT_GITHUB_AUTHORIZE_URL",
        ),
    )
    github_token_url: str = Field(
        default="https://github.com/login/oauth/access_token",
        validation_alias=AliasChoices("GITHUB_TOKEN_URL", "AGENT_GITHUB_TOKEN_URL"),
    )
    github_user_api_url: str = Field(
        default="https://api.github.com/user",
        validation_alias=AliasChoices("GITHUB_USER_API_URL", "AGENT_GITHUB_USER_API_URL"),
    )

    @property
    def default_system_prompt(self) -> str:
        return DEFAULT_SYSTEM_PROMPT

    @property
    def default_openai_model(self) -> str:
        return DEFAULT_OPENAI_MODEL


@lru_cache
def get_settings() -> Settings:
    return Settings()
