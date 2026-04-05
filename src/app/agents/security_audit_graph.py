from __future__ import annotations

import json
from typing import Any, TypedDict

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from src.app.core.config import Settings
from src.app.services.analyzer_service import AnalyzerService


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
        llm = self._create_llm()
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    self.settings.default_system_prompt,
                ),
                (
                    "human",
                    """
대상 경로: {target_path}
저장소 이름: {repository}
추가 지시사항: {instructions}

아래는 정적 분석기가 추출한 보안 분석 요약 JSON이다.
{analysis_json}

위 결과를 바탕으로 한국어 보안 리포트를 작성하라.
반드시 다음 섹션을 포함하라:
1. 전체 요약
2. 주요 취약점 분석
3. 우선순위별 대응 방안
4. 다음 단계

각 취약점 설명에는 위험도, 악용 가능성, 개발자가 바로 적용할 수 있는 수정 방향을 포함하라.
""".strip(),
                ),
            ]
        )

        analysis_payload = self._build_llm_payload(state["analysis_result"])
        response = (prompt | llm).invoke(
            {
                "target_path": state["target_path"],
                "repository": state["repository"] or "(not provided)",
                "instructions": state["instructions"] or "(none)",
                "analysis_json": json.dumps(analysis_payload, indent=2, ensure_ascii=False),
            }
        )

        return {
            "report": self._coerce_content(response.content),
            "trace": [
                *state["trace"],
                f"llm:model:{self.settings.openai_model}",
                "graph:generate_natural_language_report",
            ],
        }

    def _create_llm(self) -> ChatOpenAI:
        if not self.settings.openai_api_key:
            raise RuntimeError("AGENT_OPENAI_API_KEY is not configured.")

        return ChatOpenAI(
            api_key=self.settings.openai_api_key,
            model=self.settings.openai_model,
            temperature=self.settings.openai_temperature,
        )

    def _build_llm_payload(self, result: dict[str, Any]) -> dict[str, Any]:
        analysis = result["analysis_result"]
        vulnerabilities = analysis.get("vulnerabilities", [])
        selected_vulnerabilities = vulnerabilities[: self.settings.analysis_max_findings_in_prompt]
        call_graph = analysis.get("call_graph", {})
        selected_call_graph = dict(list(call_graph.items())[:10])

        return {
            "repository": analysis.get("repository", ""),
            "target_path": analysis.get("target_path", ""),
            "language": analysis.get("language", "java"),
            "files_analyzed": analysis.get("files_analyzed", 0),
            "summary": analysis.get("summary", {}),
            "vulnerabilities": selected_vulnerabilities,
            "call_graph_excerpt": selected_call_graph,
        }

    @staticmethod
    def _coerce_content(content: Any) -> str:
        if isinstance(content, str):
            return content

        if isinstance(content, list):
            text_parts: list[str] = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text_parts.append(part.get("text", ""))
                else:
                    text_parts.append(str(part))
            return "\n".join(part for part in text_parts if part).strip()

        return str(content)
