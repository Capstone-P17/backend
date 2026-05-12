from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from src.app.core.config import Settings
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.llm_report_service import SecurityReportGenerator


class SecurityAuditState(TypedDict):
    target_path: str
    repository: str
    instructions: str
    analysis_result: dict[str, Any]
    report: str
    trace: list[str]


class SecurityAuditGraph:
    """LangGraph workflow that runs static analysis and asks an LLM for a report."""

    def __init__(self, settings: Settings, analyzer_service: AnalyzerService) -> None:
        self.settings = settings
        self.analyzer_service = analyzer_service
        self.report_generator = SecurityReportGenerator(settings)
        self.graph = self._build_graph()

    def invoke(
        self,
        *,
        target_path: str,
        repository: str = "",
        instructions: str = "",
    ) -> SecurityAuditState:
        return self.graph.invoke(
            {
                "target_path": target_path,
                "repository": repository,
                "instructions": instructions,
                "analysis_result": {},
                "report": "",
                "trace": ["graph:started"],
            }
        )

    def _build_graph(self):
        workflow = StateGraph(SecurityAuditState)
        workflow.add_node("run_static_analysis", self._run_static_analysis)
        workflow.add_node("generate_natural_language_report", self._generate_report)
        workflow.add_edge(START, "run_static_analysis")
        workflow.add_edge("run_static_analysis", "generate_natural_language_report")
        workflow.add_edge("generate_natural_language_report", END)
        return workflow.compile()

    def _run_static_analysis(self, state: SecurityAuditState) -> dict[str, Any]:
        analysis_result = self.analyzer_service.analyze(
            target_path=state["target_path"],
            repository=state["repository"],
        )
        return {
            "analysis_result": analysis_result,
            "trace": [*state["trace"], "graph:run_static_analysis", "analyzer:completed"],
        }

    def _generate_report(self, state: SecurityAuditState) -> dict[str, Any]:
        return {
            "report": self.report_generator.generate(
                result=state["analysis_result"],
                target_path=state["target_path"],
                repository=state["repository"],
                instructions=state["instructions"],
            ),
            "trace": [
                *state["trace"],
                f"llm:model:{self.settings.openai_model}",
                "graph:generate_natural_language_report",
            ],
        }
