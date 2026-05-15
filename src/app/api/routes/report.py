from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response

from src.app.api.deps import get_report_service
from src.app.services.analysis_service import AnalysisResultNotFoundError
from src.app.services.report_service import ReportService

router = APIRouter(prefix="/report", tags=["report"])


@router.get("/{analysis_id}", response_model=None)
def download_report(
    analysis_id: str,
    service: ReportService = Depends(get_report_service),
) -> Response | JSONResponse:
    try:
        filename, pdf_bytes = service.build_pdf(analysis_id)
    except AnalysisResultNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
