from __future__ import annotations

import json
import re
from typing import Any

from src.app.core.config import Settings
from src.app.schemas.analysis import FindingLLMExplanation
from src.app.services.llm_grounding import verify_finding_explanation


class SecurityReportGenerator:
    """Generate a developer-facing LLM report from static analysis output."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def is_available(self) -> bool:
        return bool(self.settings.openai_api_key)

    def generate(
        self,
        *,
        result: dict[str, Any],
        target_path: str = "",
        repository: str = "",
        instructions: str = "",
    ) -> str:
        llm = self._create_llm()
        self._attach_finding_explanations(result, llm)
        from langchain_core.prompts import ChatPromptTemplate

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
취약점 존재 여부는 정적 분석 evidence를 기준으로 하며, 새로운 취약점 위치나 새로운 취약점을 추측하지 마라.
취약점 위치는 제공된 file, line, function만 사용하라.
설명 근거는 finding.evidence, finding.confidence_reason, finding.call_chain, finding.guideline_refs, verified llm_explanation만 사용하라.
출처는 guideline_refs.citations에 있는 source/version/page/section만 명시하라.
guideline_refs가 없는 finding은 가이드라인 출처가 있는 것처럼 설명하지 말고, 등록된 가이드라인 근거 없음 또는 검토 필요로 표시하라.
반드시 다음 섹션을 포함하라:
1. 전체 요약
2. 주요 취약점 분석
3. 우선순위별 대응 방안
4. 다음 단계

각 취약점 설명에는 위험도, 악용 가능성, 발견 위치, 개발자가 바로 적용할 수 있는 수정 방향을 포함하라.
수정 방향은 추상적인 권고에 그치지 말고, 해당 취약점 유형에 맞는 구체적인 개선 방법을 1~2문장으로 작성하라.
예를 들어 SQL 인젝션은 파라미터 바인딩 또는 PreparedStatement 사용, 하드코딩된 비밀값은 환경 변수나 시크릿 저장소 사용, 약한 해시는 더 안전한 해시 또는 비밀번호 전용 KDF 사용 방향을 우선 제시하라.
""".strip(),
                ),
            ]
        )

        response = (prompt | llm).invoke(
            {
                "target_path": target_path or "(not provided)",
                "repository": repository or "(not provided)",
                "instructions": instructions or "(none)",
                "analysis_json": json.dumps(self._build_payload(result), indent=2, ensure_ascii=False),
            }
        )
        return self._coerce_content(response.content)

    def _create_llm(self) -> Any:
        if not self.settings.openai_api_key:
            raise RuntimeError("LLM 리포트 생성을 위한 OPENAI_API_KEY가 설정되어 있지 않습니다.")

        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            api_key=self.settings.openai_api_key,
            model=self.settings.openai_model,
            temperature=self.settings.openai_temperature,
        )

    def _build_payload(self, result: dict[str, Any]) -> dict[str, Any]:
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
            "vulnerabilities": self._build_vulnerability_briefs(selected_vulnerabilities),
            "call_graph_excerpt": selected_call_graph,
        }

    @staticmethod
    def _build_vulnerability_briefs(vulnerabilities: list[Any]) -> list[dict[str, Any]]:
        briefs: list[dict[str, Any]] = []
        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            briefs.append(
                {
                    "type": finding.get("type"),
                    "severity": finding.get("severity"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "function": finding.get("function"),
                    "description": finding.get("description"),
                    "evidence": finding.get("evidence"),
                    "recommendation": finding.get("recommendation"),
                    "call_chain": finding.get("call_chain", []),
                    "confidence": finding.get("confidence"),
                    "confidence_reason": finding.get("confidence_reason"),
                    "guideline_grounding_status": finding.get("guideline_grounding_status"),
                    "analysis_status": finding.get("analysis_status"),
                    "llm_explanation_status": finding.get("llm_explanation_status"),
                    "llm_explanation": finding.get("llm_explanation"),
                    "llm_explanation_error": finding.get("llm_explanation_error"),
                    "guideline_refs": [
                        _build_guideline_brief(reference)
                        for reference in finding.get("guideline_refs", [])
                        if isinstance(reference, dict)
                    ],
                }
            )
        return briefs

    def _attach_finding_explanations(self, result: dict[str, Any], llm: Any) -> None:
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return
        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return

        for finding in vulnerabilities[: self.settings.analysis_max_findings_in_prompt]:
            if not isinstance(finding, dict):
                continue
            if not finding.get("guideline_refs"):
                finding["llm_explanation_status"] = "skipped"
                finding["llm_explanation"] = None
                finding["llm_explanation_error"] = "등록된 가이드라인 근거 없음"
                continue
            try:
                explanation = self._generate_finding_explanation(finding, llm)
                verification = verify_finding_explanation(finding=finding, explanation=explanation)
                if not verification.passed:
                    finding["llm_explanation_status"] = "failed"
                    finding["llm_explanation"] = None
                    finding["llm_explanation_error"] = "; ".join(verification.notes)
                    continue

                model = FindingLLMExplanation.model_validate(explanation)
                finding["llm_explanation_status"] = "generated"
                finding["llm_explanation"] = model.model_dump()
                finding["llm_explanation_error"] = None
            except Exception as exc:  # noqa: BLE001 - static findings must survive explanation failures
                finding["llm_explanation_status"] = "failed"
                finding["llm_explanation"] = None
                finding["llm_explanation_error"] = str(exc) or "finding 설명 생성에 실패했습니다."

    def _generate_finding_explanation(self, finding: dict[str, Any], llm: Any) -> dict[str, Any]:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are a security explanation generator. Return only valid JSON. "
                        "Use only the supplied static-analysis evidence and guideline references."
                    ),
                ),
                (
                    "human",
                    """
다음 정적 분석 finding에 대한 구조화된 한국어 설명 JSON만 생성하라.

제약:
- 취약점 존재 여부는 finding.evidence와 confidence_reason을 기준으로 한다.
- 취약점 위치는 제공된 file, line, function만 사용한다.
- 새로운 취약점, 파일, 라인, 함수, 출처를 추측하지 않는다.
- 가이드라인 출처는 guideline_refs[].citations에 있는 값만 사용한다.
- cited_guideline_ids에는 guideline_refs[].id에 존재하는 값만 넣는다.

필수 JSON 형식:
{{
  "why_vulnerable": "...",
  "how_to_fix": "...",
  "fix_steps": ["..."],
  "cited_guideline_ids": ["..."],
  "citations": [
    {{"source": "...", "version": "...", "page_start": 0, "page_end": 0, "section": "..."}}
  ],
  "grounding_notes": null
}}

finding JSON:
{finding_json}
""".strip(),
                ),
            ]
        )
        response = (prompt | llm).invoke(
            {
                "finding_json": json.dumps(
                    _build_finding_explanation_input(finding),
                    ensure_ascii=False,
                    indent=2,
                )
            }
        )
        return _parse_json_object(self._coerce_content(response.content))

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


def _build_guideline_brief(reference: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": reference.get("id"),
        "source": reference.get("source_title"),
        "version": reference.get("source_version"),
        "section": f"{reference.get('category')} - {reference.get('item')}",
        "pages": [reference.get("page_start"), reference.get("page_end")],
        "overview": _truncate(str(reference.get("overview") or ""), max_chars=1200),
        "security_measures": _truncate(str(reference.get("security_measures") or ""), max_chars=1200),
        "diagnosis": _truncate(str(reference.get("diagnosis") or ""), max_chars=1200),
        "citations": reference.get("citations", []),
    }


def _truncate(value: str, *, max_chars: int) -> str:
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    return f"{value[:max_chars].rstrip()}…"


def _build_finding_explanation_input(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": finding.get("id"),
        "type": finding.get("type"),
        "severity": finding.get("severity"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "function": finding.get("function"),
        "evidence": finding.get("evidence"),
        "confidence": finding.get("confidence"),
        "confidence_reason": finding.get("confidence_reason"),
        "call_chain": finding.get("call_chain", []),
        "guideline_refs": [
            _build_guideline_brief(reference)
            for reference in finding.get("guideline_refs", [])
            if isinstance(reference, dict)
        ],
    }


def _parse_json_object(value: str) -> dict[str, Any]:
    cleaned = value.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        cleaned = fenced.group(1).strip()
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("LLM explanation output must be a JSON object.")
    return parsed
