from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import JSONResponse

from src.app.api.deps import get_analysis_service
from src.app.services.analysis_service import (
    AnalysisExecutionError,
    AnalysisService,
    InvalidRepositoryArchiveError,
    RepositoryArchiveExtractionError,
)

router = APIRouter(prefix="/repository", tags=["repository"])


@router.post("/upload", response_model=None)
async def analyze_uploaded_repository(
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
