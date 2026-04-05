from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import JSONResponse

from src.app.api.deps import get_analysis_service
from src.app.schemas.analysis import AnalyzeRepositoryRequest
from src.app.services.analysis_service import (
    AnalysisExecutionError,
    AnalysisService,
    InvalidGithubUrlError,
    InvalidJavaFileError,
    RepositoryCloneError,
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


@router.post("/repo", response_model=None)
def analyze_repository(
    payload: AnalyzeRepositoryRequest,
    service: AnalysisService = Depends(get_analysis_service),
) -> dict[str, Any] | JSONResponse:
    try:
        return service.analyze_repository(payload.url)
    except InvalidGithubUrlError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except RepositoryCloneError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    except AnalysisExecutionError as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
