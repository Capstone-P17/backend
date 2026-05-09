from __future__ import annotations

from fastapi import APIRouter

from src.app.core.config import get_settings
from src.app.schemas.capabilities import CapabilitiesResponse, DetectorCapability
from src.app.services.static_analysis.detectors.metadata import DETECTOR_METADATA

router = APIRouter(prefix="/capabilities", tags=["capabilities"])


@router.get("", response_model=CapabilitiesResponse)
def get_capabilities() -> CapabilitiesResponse:
    settings = get_settings()
    return CapabilitiesResponse(
        llm_report_available=bool(settings.openai_api_key),
        detectors=[
            DetectorCapability(
                type=vulnerability_type,
                cwe=metadata.cwe,
                severity=metadata.severity,
                description=metadata.description,
            )
            for vulnerability_type, metadata in DETECTOR_METADATA.items()
        ],
    )
