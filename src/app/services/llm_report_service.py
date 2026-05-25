from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any

from src.app.core.config import Settings
from src.app.schemas.analysis import FindingLLMExplanation
from src.app.services.llm_grounding import verify_finding_explanation


class ContextBudgetExceededError(RuntimeError):
    """Raised when an LLM prompt cannot be made small enough for the configured budget."""


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class SecurityReportGenerator:
    """Generate a developer-facing LLM report from static analysis output."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def is_available(self) -> bool:
        return bool(self.settings.openai_api_key)

    def attach_finding_explanations(self, result: dict[str, Any]) -> None:
        """Attach per-finding dynamic explanations when an LLM is configured.

        Static detector metadata remains in the finding as fallback text. This method only
        populates the optional llm_explanation fields used by clients that want a
        finding-specific explanation.
        """
        if not self.is_available:
            self._mark_finding_explanations_unavailable(result)
            return

        llm = self._create_llm()
        self._attach_finding_explanations(result, llm)

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
설명 근거는 finding.evidence, finding.confidence_reason, finding.call_chain, verified llm_explanation, guideline_catalog의 citation 메타데이터만 사용하라.
출처는 guideline_catalog.allowed_citations 또는 llm_explanation.citations에 있는 source/version/page/section만 명시하라.
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

        analysis_json = self._dump_payload_with_budget(self._build_payload(result))
        try:
            response = (prompt | llm).invoke(
                {
                    "target_path": target_path or "(not provided)",
                    "repository": repository or "(not provided)",
                    "instructions": instructions or "(none)",
                    "analysis_json": analysis_json,
                }
            )
        except Exception as exc:  # noqa: BLE001 - normalize provider context-limit errors
            if _is_context_limit_error(exc):
                raise ContextBudgetExceededError(str(exc) or "LLM context budget exceeded") from exc
            raise
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
        vulnerabilities = [
            finding for finding in analysis.get("vulnerabilities", []) if isinstance(finding, dict)
        ]
        detailed_vulnerabilities = self._select_detailed_vulnerabilities(vulnerabilities)
        call_graph = analysis.get("call_graph", {})
        selected_call_graph = dict(list(call_graph.items())[:10]) if isinstance(call_graph, dict) else {}

        return {
            "repository": analysis.get("repository", ""),
            "target_path": analysis.get("target_path", ""),
            "language": analysis.get("language", "java"),
            "files_analyzed": analysis.get("files_analyzed", 0),
            "summary": analysis.get("summary", {}),
            "finding_selection": {
                "total_static_findings": len(vulnerabilities),
                "detailed_findings_in_prompt": len(detailed_vulnerabilities),
                "selection_policy": (
                    "Static findings are never removed from the analysis result. "
                    "The LLM prompt carries detailed records only for the highest-priority findings "
                    "and grouped summaries for the rest."
                ),
            },
            "vulnerability_groups": self._build_vulnerability_groups(vulnerabilities),
            "guideline_catalog": self._build_guideline_catalog(vulnerabilities),
            "vulnerabilities": self._build_vulnerability_briefs(detailed_vulnerabilities),
            "call_graph_excerpt": selected_call_graph,
        }

    def _select_detailed_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        max_detailed = max(0, self.settings.llm_report_max_detailed_findings)
        if max_detailed == 0:
            return []

        indexed = list(enumerate(vulnerabilities))
        indexed.sort(
            key=lambda item: (
                _SEVERITY_RANK.get(str(item[1].get("severity", "LOW")), 4),
                item[0],
            )
        )

        selected_indexes: set[int] = set()
        for index, _finding in indexed[:max_detailed]:
            selected_indexes.add(index)

        if self.settings.llm_report_group_summary_enabled:
            seen_types: set[str] = set()
            for index, finding in enumerate(vulnerabilities):
                finding_type = str(finding.get("type") or "UNKNOWN")
                if finding_type in seen_types:
                    continue
                seen_types.add(finding_type)
                selected_indexes.add(index)
                if len(selected_indexes) >= max_detailed:
                    break

        return [finding for index, finding in enumerate(vulnerabilities) if index in selected_indexes][:max_detailed]

    def _build_vulnerability_briefs(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        briefs: list[dict[str, Any]] = []
        for finding in vulnerabilities:
            guideline_refs = [
                reference for reference in finding.get("guideline_refs", []) if isinstance(reference, dict)
            ]
            brief: dict[str, Any] = {
                "id": finding.get("id"),
                "type": finding.get("type"),
                "severity": finding.get("severity"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "function": finding.get("function"),
                "description": _truncate(str(finding.get("description") or ""), max_chars=600),
                "evidence": _truncate(
                    str(finding.get("evidence") or ""),
                    max_chars=self.settings.llm_finding_evidence_max_chars,
                ),
                "recommendation": _truncate(str(finding.get("recommendation") or ""), max_chars=600),
                "call_chain": _bounded_list(finding.get("call_chain", []), max_items=8),
                "confidence": finding.get("confidence"),
                "confidence_reason": _truncate(str(finding.get("confidence_reason") or ""), max_chars=600),
                "guideline_grounding_status": finding.get("guideline_grounding_status"),
                "analysis_status": finding.get("analysis_status"),
                "llm_explanation_status": finding.get("llm_explanation_status"),
                "llm_explanation": finding.get("llm_explanation"),
                "llm_explanation_error": finding.get("llm_explanation_error"),
                "guideline_ref_ids": [reference.get("id") for reference in guideline_refs if reference.get("id")],
                "citations": _collect_allowed_citations(guideline_refs),
            }
            briefs.append(brief)
        return briefs

    def _build_vulnerability_groups(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in vulnerabilities:
            grouped[str(finding.get("type") or "UNKNOWN")].append(finding)

        groups: list[dict[str, Any]] = []
        for finding_type, findings in sorted(grouped.items()):
            severity_counts = Counter(str(finding.get("severity") or "UNKNOWN") for finding in findings)
            grounding_counts = Counter(
                str(finding.get("guideline_grounding_status") or "unknown") for finding in findings
            )
            guideline_ref_ids = sorted(
                {
                    str(reference.get("id"))
                    for finding in findings
                    for reference in finding.get("guideline_refs", [])
                    if isinstance(reference, dict) and reference.get("id")
                }
            )
            groups.append(
                {
                    "type": finding_type,
                    "count": len(findings),
                    "severity_counts": dict(severity_counts),
                    "guideline_grounding_status_counts": dict(grounding_counts),
                    "representative_finding_ids": [
                        _finding_id(finding)
                        for finding in findings[: self.settings.llm_report_max_findings_per_group]
                    ],
                    "files": sorted(
                        {str(finding.get("file")) for finding in findings if finding.get("file")}
                    )[: self.settings.llm_report_max_findings_per_group],
                    "guideline_ref_ids": guideline_ref_ids,
                }
            )
        return groups

    def _build_guideline_catalog(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        catalog: dict[str, dict[str, Any]] = {}
        for finding in vulnerabilities:
            for reference in finding.get("guideline_refs", []):
                if not isinstance(reference, dict) or not reference.get("id"):
                    continue
                ref_id = str(reference["id"])
                entry = catalog.setdefault(
                    ref_id,
                    {
                        "id": ref_id,
                        "source": reference.get("source_title"),
                        "version": reference.get("source_version"),
                        "section": f"{reference.get('category')} - {reference.get('item')}",
                        "pages": [reference.get("page_start"), reference.get("page_end")],
                        "detector_types": reference.get("detector_types", []),
                        "cwe": reference.get("cwe", []),
                        "allowed_citations": [],
                    },
                )
                entry["allowed_citations"] = _dedupe_citations(
                    [
                        *entry.get("allowed_citations", []),
                        *reference.get("citations", []),
                    ]
                )
        return catalog

    def _mark_finding_explanations_unavailable(self, result: dict[str, Any]) -> None:
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return
        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return

        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            finding.setdefault("llm_explanation_status", "unavailable")
            finding.setdefault("llm_explanation", None)
            finding.setdefault("llm_explanation_error", None)

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
            if self._has_final_finding_explanation_state(finding):
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
            except ContextBudgetExceededError as exc:
                finding["llm_explanation_status"] = "skipped_context_budget_exceeded"
                finding["llm_explanation"] = None
                finding["llm_explanation_error"] = str(exc) or "finding 설명 입력이 context budget을 초과했습니다."
            except Exception as exc:  # noqa: BLE001 - static findings must survive explanation failures
                finding["llm_explanation_status"] = "failed"
                finding["llm_explanation"] = None
                finding["llm_explanation_error"] = str(exc) or "finding 설명 생성에 실패했습니다."

    @staticmethod
    def _has_final_finding_explanation_state(finding: dict[str, Any]) -> bool:
        status = finding.get("llm_explanation_status")
        if status in (None, "", "unavailable"):
            return False
        return True

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
        finding_json = self._dump_finding_explanation_input(finding)
        try:
            response = (prompt | llm).invoke({"finding_json": finding_json})
        except Exception as exc:  # noqa: BLE001 - normalize provider context-limit errors
            if _is_context_limit_error(exc):
                raise ContextBudgetExceededError(str(exc) or "Finding explanation context budget exceeded") from exc
            raise
        return _parse_json_object(self._coerce_content(response.content))

    def _build_finding_explanation_input(self, finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": finding.get("id"),
            "type": finding.get("type"),
            "severity": finding.get("severity"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "function": finding.get("function"),
            "evidence": _truncate(
                str(finding.get("evidence") or ""),
                max_chars=self.settings.llm_finding_evidence_max_chars,
            ),
            "confidence": finding.get("confidence"),
            "confidence_reason": _truncate(str(finding.get("confidence_reason") or ""), max_chars=800),
            "call_chain": _bounded_list(finding.get("call_chain", []), max_items=8),
            "guideline_refs": [
                self._build_guideline_explanation_brief(reference)
                for reference in finding.get("guideline_refs", [])
                if isinstance(reference, dict)
            ],
        }

    def _build_guideline_explanation_brief(self, reference: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": reference.get("id"),
            "source": reference.get("source_title"),
            "version": reference.get("source_version"),
            "section": f"{reference.get('category')} - {reference.get('item')}",
            "pages": [reference.get("page_start"), reference.get("page_end")],
            "why_vulnerable": _truncate(
                str(reference.get("overview") or ""),
                max_chars=self.settings.llm_guideline_overview_max_chars,
            ),
            "diagnosis_rules": _truncate(
                str(reference.get("diagnosis") or ""),
                max_chars=self.settings.llm_guideline_diagnosis_max_chars,
            ),
            "fix_rules": _truncate(
                str(reference.get("security_measures") or ""),
                max_chars=self.settings.llm_guideline_security_measures_max_chars,
            ),
            "citations": reference.get("citations", []),
        }

    def _dump_finding_explanation_input(self, finding: dict[str, Any]) -> str:
        payload = self._build_finding_explanation_input(finding)
        dumped = json.dumps(payload, ensure_ascii=False, indent=2)
        budget = self.settings.llm_finding_explanation_payload_max_chars
        if budget > 0 and len(dumped) > budget:
            raise ContextBudgetExceededError(
                f"Finding explanation payload is {len(dumped)} chars, budget is {budget} chars."
            )
        return dumped

    def _dump_payload_with_budget(self, payload: dict[str, Any]) -> str:
        dumped = json.dumps(payload, indent=2, ensure_ascii=False)
        budget = self.settings.llm_report_payload_max_chars
        if budget <= 0 or len(dumped) <= budget:
            return dumped

        compact_payload = self._compact_report_payload(payload)
        compact_dumped = json.dumps(compact_payload, indent=2, ensure_ascii=False)
        if len(compact_dumped) <= budget:
            return compact_dumped

        raise ContextBudgetExceededError(
            f"LLM report payload is {len(compact_dumped)} chars after compaction; budget is {budget} chars."
        )

    def _compact_report_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        compact = deepcopy(payload)
        compact["call_graph_excerpt"] = {}
        compact["budget_compaction"] = {
            "applied": True,
            "policy": "Removed call graph and long per-finding text from the LLM prompt only; static findings remain unchanged in stored analysis results.",
        }
        for finding in compact.get("vulnerabilities", []):
            if not isinstance(finding, dict):
                continue
            for field in ("description", "evidence", "recommendation", "confidence_reason"):
                if field in finding:
                    finding[field] = _truncate(str(finding.get(field) or ""), max_chars=240)
            if "call_chain" in finding:
                finding["call_chain"] = _bounded_list(finding.get("call_chain", []), max_items=3)
        return compact

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


def _collect_allowed_citations(guideline_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _dedupe_citations(
        [
            citation
            for reference in guideline_refs
            for citation in reference.get("citations", [])
            if isinstance(citation, dict)
        ]
    )


def _dedupe_citations(citations: list[Any]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int, str]] = set()
    for citation in citations:
        if not isinstance(citation, dict):
            continue
        key = (
            str(citation.get("source", "")),
            str(citation.get("version", "")),
            int(citation.get("page_start") or 0),
            int(citation.get("page_end") or 0),
            str(citation.get("section", "")),
        )
        if key not in seen:
            deduped.append(citation)
            seen.add(key)
    return deduped


def _bounded_list(value: Any, *, max_items: int) -> list[Any]:
    if not isinstance(value, list):
        return []
    return value[:max_items]


def _finding_id(finding: dict[str, Any]) -> str:
    return str(
        finding.get("id")
        or f"{finding.get('type', 'UNKNOWN')}:{finding.get('file', '')}:{finding.get('line', '')}"
    )


def _truncate(value: str, *, max_chars: int) -> str:
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    return f"{value[:max_chars].rstrip()}…"


def _parse_json_object(value: str) -> dict[str, Any]:
    cleaned = value.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        cleaned = fenced.group(1).strip()
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("LLM explanation output must be a JSON object.")
    return parsed


def _is_context_limit_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "context_length_exceeded",
            "maximum context length",
            "context length",
            "token limit",
            "too many tokens",
        )
    )
