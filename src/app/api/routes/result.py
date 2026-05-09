from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from src.app.api.deps import get_analysis_service, get_current_user
from src.app.schemas.analysis import AnalysisResponse, AnalysisResultListResponse
from src.app.services.analysis_service import AnalysisResultNotFoundError, AnalysisService

router = APIRouter(
    prefix="/result",
    tags=["result"],
    dependencies=[Depends(get_current_user)],
)

results_router = APIRouter(
    prefix="/results",
    tags=["result"],
    dependencies=[Depends(get_current_user)],
)


@router.get("", response_model=AnalysisResponse)
def get_latest_result(
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        return service.get_latest_result()
    except AnalysisResultNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})


@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_result_by_id(
    analysis_id: str,
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        return service.get_result(analysis_id)
    except AnalysisResultNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})


@results_router.get("", response_model=AnalysisResultListResponse)
def list_results(
    limit: int = Query(default=20, ge=0, le=100),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, list[dict[str, Any]]]:
    return {"results": service.list_results(limit=limit)}
