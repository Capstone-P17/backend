from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.app.api.router import api_router
from src.app.core.config import get_settings
from src.app.db.session import init_db


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="LangGraph-enabled FastAPI backend for AI-driven security audit workflows.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def on_startup() -> None:
        init_db()

    app.include_router(api_router)

    @app.get("/", tags=["meta"])
    def read_root() -> dict[str, str]:
        return {
            "message": f"{settings.app_name} is running",
            "docs": "/docs",
            "api_prefix": settings.api_prefix,
        }

    return app
