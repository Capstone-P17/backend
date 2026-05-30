from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, UploadFile, status
from fastapi.responses import JSONResponse
from loguru import logger

from src.app.api.deps import get_analysis_job_store, get_analysis_service, get_current_user
from src.app.api.upload import read_upload_with_limit
from src.app.core.config import get_settings
from src.app.schemas.analysis import AnalysisResponse
from src.app.schemas.auth import UserResponse
from src.app.schemas.jobs import AnalysisJobCreateResponse, AnalysisJobStatusResponse
from src.app.schemas.repository import GitHubCloneRequest
from src.app.services.analysis_service import (
    AnalysisExecutionError,
    AnalysisService,
    GitHubRepositoryCloneError,
    InvalidGitHubRepositoryError,
    InvalidJavaFileError,
    InvalidRepositoryArchiveError,
    RepositoryArchiveExtractionError,
    UploadTooLargeError,
)
from src.app.services.job_store import AnalysisJobStore

router = APIRouter(
    prefix="/analyze",
    tags=["analyze"],
    dependencies=[Depends(get_current_user)],
)


def _run_repository_analysis_job(
    *,
    job_id: str,
    url: str,
    user_id: int,
    service: AnalysisService,
    job_store: AnalysisJobStore,
) -> None:
    logger.bind(component="analysis.job", job_id=job_id, user_id=user_id).info(
        "repository_analysis_job_started url={}",
        url,
    )
    job_store.update(
        job_id,
        status="running",
        phase="cloning",
        message="GitHub 저장소를 내려받고 분석 준비를 시작했습니다.",
        progress={"percent": 3},
    )

    def update_progress(event: dict[str, Any]) -> None:
        progress = event.get("progress")
        job_store.update(
            job_id,
            status="running",
            phase=str(event.get("phase") or "running"),
            message=str(event.get("message") or "분석 작업을 진행 중입니다."),
            progress=progress if isinstance(progress, dict) else None,
        )

    try:
        response = service.analyze_github_repository(
            url=url,
            user_id=user_id,
            progress_callback=update_progress,
        )
        job_store.update(
            job_id,
            status="succeeded",
            phase="succeeded",
            analysis_id=str(response["analysis_id"]),
            message="분석과 finding별 리포트 생성이 완료되었습니다.",
            progress={"percent": 100},
        )
        logger.bind(component="analysis.job", job_id=job_id, user_id=user_id).info(
            "repository_analysis_job_succeeded analysis_id={}",
            response["analysis_id"],
        )
    except Exception as exc:  # noqa: BLE001 - background job must capture user-facing failure
        job_store.update(
            job_id,
            status="failed",
            phase="failed",
            error=str(exc) or "레포지토리 분석 작업에 실패했습니다",
            message="분석 작업이 실패했습니다.",
        )
        logger.bind(component="analysis.job", job_id=job_id, user_id=user_id).exception(
            "repository_analysis_job_failed error={}",
            str(exc) or type(exc).__name__,
        )


@router.post("/file", response_model=AnalysisResponse)
async def analyze_file(
    file: UploadFile | None = File(default=None),
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    if file is None or not file.filename:
        return JSONResponse(status_code=422, content={"error": "파일을 첨부해주세요"})

    try:
        content = await read_upload_with_limit(file, max_bytes=get_settings().max_upload_bytes)
        logger.bind(component="analysis.api", user_id=current_user.id).info(
            "file_analysis_requested filename={} bytes={}",
            file.filename,
            len(content),
        )
        return service.analyze_uploaded_file(filename=file.filename, content=content, user_id=current_user.id)
    except UploadTooLargeError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "file_analysis_rejected reason=upload_too_large filename={}",
            file.filename,
        )
        return JSONResponse(status_code=413, content={"error": str(exc)})
    except InvalidJavaFileError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "file_analysis_rejected reason=invalid_java filename={}",
            file.filename,
        )
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).exception(
            "file_analysis_failed filename={}",
            file.filename,
        )
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/archive", response_model=AnalysisResponse)
async def analyze_uploaded_archive(
    file: UploadFile | None = File(default=None),
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    if file is None or not file.filename:
        return JSONResponse(status_code=422, content={"error": "레포지토리 압축 파일을 첨부해주세요"})

    try:
        content = await read_upload_with_limit(file, max_bytes=get_settings().max_upload_bytes)
        logger.bind(component="analysis.api", user_id=current_user.id).info(
            "archive_analysis_requested filename={} bytes={}",
            file.filename,
            len(content),
        )
        return service.analyze_uploaded_repository(
            filename=file.filename,
            content=content,
            user_id=current_user.id,
        )
    except UploadTooLargeError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "archive_analysis_rejected reason=upload_too_large filename={}",
            file.filename,
        )
        return JSONResponse(status_code=413, content={"error": str(exc)})
    except InvalidRepositoryArchiveError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "archive_analysis_rejected reason=invalid_archive filename={}",
            file.filename,
        )
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except RepositoryArchiveExtractionError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).exception(
            "archive_analysis_extract_failed filename={}",
            file.filename,
        )
        return JSONResponse(status_code=500, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).exception(
            "archive_analysis_failed filename={}",
            file.filename,
        )
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/repository", response_model=AnalysisResponse)
async def analyze_github_repository(
    body: GitHubCloneRequest,
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        logger.bind(component="analysis.api", user_id=current_user.id).info(
            "github_analysis_requested url={}",
            body.url,
        )
        return service.analyze_github_repository(url=body.url, user_id=current_user.id)
    except UploadTooLargeError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "github_analysis_rejected reason=upload_too_large url={}",
            body.url,
        )
        return JSONResponse(status_code=413, content={"error": str(exc)})
    except (InvalidGitHubRepositoryError, InvalidRepositoryArchiveError) as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "github_analysis_rejected reason=invalid_repository url={}",
            body.url,
        )
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except GitHubRepositoryCloneError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).warning(
            "github_analysis_clone_failed url={}",
            body.url,
        )
        return JSONResponse(status_code=502, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        logger.bind(component="analysis.api", user_id=current_user.id).exception(
            "github_analysis_failed url={}",
            body.url,
        )
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post(
    "/repository/jobs",
    response_model=AnalysisJobCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_repository_analysis_job(
    body: GitHubCloneRequest,
    background_tasks: BackgroundTasks,
    current_user: UserResponse = Depends(get_current_user),
    service: AnalysisService = Depends(get_analysis_service),
    job_store: AnalysisJobStore = Depends(get_analysis_job_store),
) -> dict[str, str]:
    job = job_store.create()
    logger.bind(component="analysis.api", job_id=job["job_id"], user_id=current_user.id).info(
        "repository_analysis_job_created url={}",
        body.url,
    )
    background_tasks.add_task(
        _run_repository_analysis_job,
        job_id=job["job_id"],
        url=body.url,
        user_id=current_user.id,
        service=service,
        job_store=job_store,
    )
    return {"job_id": job["job_id"], "status": job["status"]}


@router.get("/jobs/{job_id}", response_model=AnalysisJobStatusResponse)
def get_repository_analysis_job(
    job_id: str,
    job_store: AnalysisJobStore = Depends(get_analysis_job_store),
) -> dict[str, Any] | JSONResponse:
    job = job_store.get(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"error": "분석 작업을 찾을 수 없습니다"})
    return job
