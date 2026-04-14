from __future__ import annotations

from uuid import uuid4

from src.app.agents.security_audit_graph import SecurityAuditGraph
from src.app.core.config import Settings
from src.app.schemas.agent import (
    AgentRunRequest,
    AgentRunResponse,
    SecurityAnalysisSummary,
    VulnerabilityFinding,
)
from src.app.services.analysis_service import AnalysisService


class AgentService:
    """Application service for the LangGraph-based security audit agent."""

    def __init__(self, settings: Settings, analysis_service: AnalysisService) -> None:
        self.settings = settings
        self.analysis_service = analysis_service
        self.analyzer_service = analysis_service.analyzer_service
        self.security_audit_graph = SecurityAuditGraph(
            settings=settings,
            analyzer_service=self.analyzer_service,
        )

    def run(self, payload: AgentRunRequest) -> AgentRunResponse:
        session_id = payload.session_id or f"session-{uuid4().hex[:12]}"
        result = self.security_audit_graph.invoke(
            target_path=payload.target_path,
            repository=payload.repository or "",
            instructions=payload.instructions or "",
        )
        return self._build_response(
            result=result,
            session_id=session_id,
            display_target_path=payload.target_path,
            include_raw_analysis=payload.include_raw_analysis,
        )

    def run_uploaded_file(
        self,
        *,
        filename: str,
        content: bytes,
        session_id: str | None = None,
        instructions: str = "",
        include_raw_analysis: bool = False,
    ) -> AgentRunResponse:
        with self.analysis_service.prepare_uploaded_file(filename=filename, content=content) as prepared_target:
            result = self.security_audit_graph.invoke(
                target_path=prepared_target.target_path,
                repository=prepared_target.repository,
                instructions=instructions,
            )
        return self._build_response(
            result=result,
            session_id=session_id or f"session-{uuid4().hex[:12]}",
            display_target_path=prepared_target.display_target_path,
            include_raw_analysis=include_raw_analysis,
        )

    def run_uploaded_repository(
        self,
        *,
        filename: str,
        content: bytes,
        session_id: str | None = None,
        instructions: str = "",
        include_raw_analysis: bool = False,
    ) -> AgentRunResponse:
        with self.analysis_service.prepare_uploaded_repository(filename=filename, content=content) as prepared_target:
            result = self.security_audit_graph.invoke(
                target_path=prepared_target.target_path,
                repository=prepared_target.repository,
                instructions=instructions,
            )
        return self._build_response(
            result=result,
            session_id=session_id or f"session-{uuid4().hex[:12]}",
            display_target_path=prepared_target.display_target_path,
            include_raw_analysis=include_raw_analysis,
        )

    def run_github_repository(
        self,
        *,
        url: str,
        session_id: str | None = None,
        instructions: str = "",
        include_raw_analysis: bool = False,
    ) -> AgentRunResponse:
        with self.analysis_service.prepare_github_repository(url=url) as prepared_target:
            result = self.security_audit_graph.invoke(
                target_path=prepared_target.target_path,
                repository=prepared_target.repository,
                instructions=instructions,
            )
        return self._build_response(
            result=result,
            session_id=session_id or f"session-{uuid4().hex[:12]}",
            display_target_path=prepared_target.display_target_path,
            include_raw_analysis=include_raw_analysis,
        )

    def _build_response(
        self,
        *,
        result: dict[str, object],
        session_id: str,
        display_target_path: str,
        include_raw_analysis: bool,
    ) -> AgentRunResponse:
        analysis = result["analysis_result"]["analysis_result"]
        summary_model = SecurityAnalysisSummary.model_validate(analysis["summary"])
        findings = [
            VulnerabilityFinding.model_validate(vulnerability)
            for vulnerability in analysis.get("vulnerabilities", [])
        ]

        return AgentRunResponse(
            agent_name=self.settings.default_agent_name,
            session_id=session_id,
            target_path=display_target_path,
            summary=self._build_summary(summary_model),
            report=result["report"],
            trace=result["trace"],
            analysis_summary=summary_model,
            findings=findings,
            raw_analysis=result["analysis_result"] if include_raw_analysis else None,
        )

    @staticmethod
    def _build_summary(summary: SecurityAnalysisSummary) -> str:
        return (
            f"총 {summary.total_vulnerabilities}건의 취약점을 탐지했습니다. "
            f"HIGH {summary.by_severity.get('HIGH', 0)}건, "
            f"MEDIUM {summary.by_severity.get('MEDIUM', 0)}건, "
            f"LOW {summary.by_severity.get('LOW', 0)}건이며, "
            f"전체 보안 점수는 {summary.score.overall}점입니다."
        )
