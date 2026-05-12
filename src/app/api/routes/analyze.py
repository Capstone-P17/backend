from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, UploadFile, status
from fastapi.responses import JSONResponse

from src.app.api.deps import get_analysis_job_store, get_analysis_service, get_current_user
from src.app.api.upload import read_upload_with_limit
from src.app.core.config import get_settings
from src.app.schemas.analysis import AnalysisResponse
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
    service: AnalysisService,
    job_store: AnalysisJobStore,
) -> None:
    job_store.update(job_id, status="running")
    try:
        response = service.analyze_github_repository(url=url)
        job_store.update(
            job_id,
            status="succeeded",
            analysis_id=str(response["analysis_id"]),
        )
    except Exception as exc:  # noqa: BLE001 - background job must capture user-facing failure
        job_store.update(job_id, status="failed", error=str(exc) or "레포지토리 분석 작업에 실패했습니다")


@router.post("/file", response_model=AnalysisResponse)
async def analyze_file(
    file: UploadFile | None = File(default=None),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    if file is None or not file.filename:
        return JSONResponse(status_code=422, content={"error": "파일을 첨부해주세요"})

    try:
        content = await read_upload_with_limit(file, max_bytes=get_settings().max_upload_bytes)
        return service.analyze_uploaded_file(filename=file.filename, content=content)
    except UploadTooLargeError as exc:
        return JSONResponse(status_code=413, content={"error": str(exc)})
    except InvalidJavaFileError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/archive", response_model=AnalysisResponse)
async def analyze_uploaded_archive(
    file: UploadFile | None = File(default=None),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    if file is None or not file.filename:
        return JSONResponse(status_code=422, content={"error": "레포지토리 압축 파일을 첨부해주세요"})

    try:
        content = await read_upload_with_limit(file, max_bytes=get_settings().max_upload_bytes)
        return service.analyze_uploaded_repository(filename=file.filename, content=content)
    except UploadTooLargeError as exc:
        return JSONResponse(status_code=413, content={"error": str(exc)})
    except InvalidRepositoryArchiveError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except RepositoryArchiveExtractionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/repository", response_model=AnalysisResponse)
async def analyze_github_repository(
    body: GitHubCloneRequest,
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        return service.analyze_github_repository(url=body.url)
    except UploadTooLargeError as exc:
        return JSONResponse(status_code=413, content={"error": str(exc)})
    except (InvalidGitHubRepositoryError, InvalidRepositoryArchiveError) as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except GitHubRepositoryCloneError as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post(
    "/repository/jobs",
    response_model=AnalysisJobCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_repository_analysis_job(
    body: GitHubCloneRequest,
    background_tasks: BackgroundTasks,
    service: AnalysisService = Depends(get_analysis_service),
    job_store: AnalysisJobStore = Depends(get_analysis_job_store),
) -> dict[str, str]:
    job = job_store.create()
    background_tasks.add_task(
        _run_repository_analysis_job,
        job_id=job["job_id"],
        url=body.url,
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
