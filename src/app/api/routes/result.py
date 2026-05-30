from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from loguru import logger

from src.app.api.deps import get_analysis_service, get_current_user
from src.app.schemas.analysis import AnalysisResponse, AnalysisResultListResponse, FileAnalysisResponse, FindingDetailResponse
from src.app.schemas.auth import UserResponse
from src.app.services.analysis_service import AnalysisResultNotFoundError, AnalysisService, FindingReportNotReadyError

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
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        logger.bind(component="result.api", user_id=current_user.id).debug("latest_result_requested")
        return service.get_latest_result(current_user.id)
    except AnalysisResultNotFoundError as exc:
        logger.bind(component="result.api", user_id=current_user.id).warning("latest_result_not_found")
        return JSONResponse(status_code=404, content={"error": str(exc)})


@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_result_by_id(
    analysis_id: str,
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id).debug(
            "analysis_result_requested analysis_id={}",
            analysis_id,
        )
        return service.get_result(analysis_id, current_user.id)
    except AnalysisResultNotFoundError as exc:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id).warning(
            "analysis_result_not_found analysis_id={}",
            analysis_id,
        )
        return JSONResponse(status_code=404, content={"error": str(exc)})


@router.get("/{analysis_id}/findings/{finding_id}", response_model=FindingDetailResponse)
def get_finding_result_by_id(
    analysis_id: str,
    finding_id: str,
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id, finding_id=finding_id).debug(
            "finding_detail_requested analysis_id={} finding_id={}",
            analysis_id,
            finding_id,
        )
        return service.get_finding_detail(analysis_id, finding_id, current_user.id)
    except FindingReportNotReadyError as exc:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id, finding_id=finding_id).warning(
            "finding_detail_not_ready analysis_id={} finding_id={}",
            analysis_id,
            finding_id,
        )
        return JSONResponse(status_code=409, content={"error": str(exc)})
    except AnalysisResultNotFoundError as exc:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id, finding_id=finding_id).warning(
            "finding_detail_not_found analysis_id={} finding_id={}",
            analysis_id,
            finding_id,
        )
        return JSONResponse(status_code=404, content={"error": str(exc)})


@router.get("/{analysis_id}/files/{file_id}", response_model=FileAnalysisResponse)
def get_file_result_by_id(
    analysis_id: str,
    file_id: str,
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id, file_id=file_id).debug(
            "file_detail_requested analysis_id={} file_id={}",
            analysis_id,
            file_id,
        )
        return service.get_file_result(analysis_id, file_id, current_user.id)
    except AnalysisResultNotFoundError as exc:
        logger.bind(component="result.api", user_id=current_user.id, analysis_id=analysis_id, file_id=file_id).warning(
            "file_detail_not_found analysis_id={} file_id={}",
            analysis_id,
            file_id,
        )
        return JSONResponse(status_code=404, content={"error": str(exc)})


@results_router.get("", response_model=AnalysisResultListResponse)
def list_results(
    limit: int = Query(default=20, ge=0, le=100),
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, list[dict[str, Any]]]:
    logger.bind(component="result.api", user_id=current_user.id).debug(
        "analysis_results_list_requested limit={}",
        limit,
    )
    return {"results": service.list_results(user_id=current_user.id, limit=limit)}
