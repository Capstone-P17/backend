from fastapi import APIRouter

from src.app.api.routes import agents, analyze, auth, capabilities, health, report, result

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(capabilities.router)
api_router.include_router(auth.router)
api_router.include_router(analyze.router)
api_router.include_router(result.router)
api_router.include_router(result.results_router)
api_router.include_router(report.router)
api_router.include_router(agents.router)
