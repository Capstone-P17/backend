from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from src.app.api.deps import get_analysis_service
from src.app.services.analysis_service import AnalysisResultNotFoundError, AnalysisService

router = APIRouter(prefix="/result", tags=["result"])


@router.get("", response_model=None)
def get_latest_result(
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        return service.get_latest_result()
    except AnalysisResultNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})
