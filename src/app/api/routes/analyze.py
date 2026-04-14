from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import JSONResponse

from src.app.api.deps import get_analysis_service
from src.app.schemas.repository import GitHubCloneRequest
from src.app.services.analysis_service import (
    AnalysisExecutionError,
    AnalysisService,
    GitHubRepositoryCloneError,
    InvalidGitHubRepositoryError,
    InvalidJavaFileError,
    InvalidRepositoryArchiveError,
    RepositoryArchiveExtractionError,
)

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("/file", response_model=None)
async def analyze_file(
    file: UploadFile | None = File(default=None),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    if file is None or not file.filename:
        return JSONResponse(status_code=422, content={"error": "파일을 첨부해주세요"})

    try:
        content = await file.read()
        return service.analyze_uploaded_file(filename=file.filename, content=content)
    except InvalidJavaFileError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/archive", response_model=None)
async def analyze_uploaded_archive(
    file: UploadFile | None = File(default=None),
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    if file is None or not file.filename:
        return JSONResponse(status_code=422, content={"error": "레포지토리 압축 파일을 첨부해주세요"})

    try:
        content = await file.read()
        return service.analyze_uploaded_repository(filename=file.filename, content=content)
    except InvalidRepositoryArchiveError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except RepositoryArchiveExtractionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/repository", response_model=None)
async def analyze_github_repository(
    body: GitHubCloneRequest,
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        return service.analyze_github_repository(url=body.url)
    except (InvalidGitHubRepositoryError, InvalidRepositoryArchiveError) as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except GitHubRepositoryCloneError as exc:
        return JSONResponse(status_code=502, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
