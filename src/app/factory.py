from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.app.api.router import api_router
from src.app.core.config import get_settings
from src.app.core.logging import configure_logging, log_request_middleware
from src.app.db.session import init_db


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="LangGraph-enabled FastAPI backend for AI-driven security audit workflows.",
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )
    app.middleware("http")(log_request_middleware)

    @app.on_event("startup")
    def on_startup() -> None:
        from loguru import logger

        logger.bind(component="app").info(
            "app_startup name={} version={} environment={}",
            settings.app_name,
            settings.app_version,
            settings.environment,
        )
        init_db()

    app.include_router(api_router)

    @app.get("/", tags=["meta"])
    def read_root() -> dict[str, str]:
        payload = {
            "message": f"{settings.app_name} is running",
            "api_prefix": settings.api_prefix,
        }
        if settings.docs_enabled:
            payload["docs"] = "/docs"
        return payload

    return app
