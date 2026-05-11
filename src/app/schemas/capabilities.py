from __future__ import annotations

from pydantic import BaseModel, Field


class DetectorCapability(BaseModel):
    type: str
    cwe: str
    severity: str
    description: str


class CapabilitiesResponse(BaseModel):
    service: str = "java-security-static-analysis"
    supported_languages: list[str] = Field(default_factory=lambda: ["java"])
    supported_file_extensions: list[str] = Field(default_factory=lambda: [".java"])
    supported_archive_formats: list[str] = Field(default_factory=lambda: [".zip"])
    supported_repository_sources: list[str] = Field(default_factory=lambda: ["github_public_archive"])
    analysis_mode: str = "rule_based_static_analysis"
    llm_detection_enabled: bool = False
    llm_used_for_detection: bool = False
    llm_provider: str = "openai"
    static_analysis_available: bool = True
    llm_report_available: bool
    detectors: list[DetectorCapability]
