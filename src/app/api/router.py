from fastapi import APIRouter

from src.app.api.routes import agents, health

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(agents.router)
