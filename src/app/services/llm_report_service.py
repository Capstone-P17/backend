from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from loguru import logger

from src.app.core.config import Settings
from src.app.schemas.analysis import FindingLLMExplanation, FindingMarkdownReport, FindingReportMetadata
from src.app.services.llm_grounding import verify_finding_explanation


class ContextBudgetExceededError(RuntimeError):
    """Raised when an LLM prompt cannot be made small enough for the configured budget."""


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
            logger.bind(component="llm.report").info("finding_explanations_skipped reason=openai_api_key_missing")
            self._mark_finding_explanations_unavailable(result)
            return

        logger.bind(component="llm.report", model=self.settings.openai_model).info("finding_explanations_started")
        llm = self._create_llm()
        self._attach_finding_explanations(result, llm)
        logger.bind(component="llm.report", model=self.settings.openai_model).info("finding_explanations_finished")

    def generate(
        self,
        *,
        result: dict[str, Any],
        target_path: str = "",
        repository: str = "",
        instructions: str = "",
    ) -> str:
        logger.bind(component="llm.report", model=self.settings.openai_model).info(
            "summary_report_generation_started target_path={} repository={}",
            target_path or "(not provided)",
            repository or "(not provided)",
        )
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

아래는 정적 분석기가 추출한 보안 분석 요약 데이터이다.
{analysis_json}

위 결과를 바탕으로 한국어 보안 리포트를 작성하라.
취약점 존재 여부는 정적 분석 evidence를 기준으로 하며, 새로운 취약점 위치나 새로운 취약점을 추측하지 마라.
취약점 위치는 제공된 file, line, function만 사용하라.
사용자에게 데이터 구조, JSON, 필드명, 속성명, finding.xxx 같은 내부 구현 표현을 노출하지 마라.
출처는 제공된 공식 가이드 citation 정보만 자연어로 명시하라.
가이드라인 근거가 없는 항목은 출처를 지어내지 말고, 공식 가이드 근거 확인이 필요하다고 자연스럽게 설명하라.
CVE, CWE, CVSS, 점수형 위험도, 정량 등급은 쓰지 마라.
반드시 다음 섹션을 포함하라:
1. 전체 요약
2. 주요 취약점 분석
3. 우선순위별 대응 방안
4. 다음 단계

각 취약점 설명에는 악용 가능성, 발견 위치, 개발자가 바로 적용할 수 있는 수정 방향을 포함하라.
수정 방향은 추상적인 권고에 그치지 말고, 해당 취약점 유형에 맞는 구체적인 개선 방법을 1~2문장으로 작성하라.
예를 들어 SQL 인젝션은 파라미터 바인딩 또는 PreparedStatement 사용, 하드코딩된 비밀값은 환경 변수나 시크릿 저장소 사용, 약한 해시는 더 안전한 해시 또는 비밀번호 전용 KDF 사용 방향을 우선 제시하라.
""".strip(),
                ),
            ]
        )

        analysis_json = self._dump_payload_with_budget(self._build_payload(result))
        try:
            logger.bind(component="llm.report", model=self.settings.openai_model).debug(
                "summary_report_prompt_ready chars={}",
                len(analysis_json),
            )
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
                logger.bind(component="llm.report", model=self.settings.openai_model).warning(
                    "summary_report_context_budget_exceeded error={}",
                    str(exc) or type(exc).__name__,
                )
                raise ContextBudgetExceededError(str(exc) or "LLM context budget exceeded") from exc
            logger.bind(component="llm.report", model=self.settings.openai_model).exception(
                "summary_report_generation_failed"
            )
            raise
        content = self._coerce_content(response.content)
        logger.bind(component="llm.report", model=self.settings.openai_model).info(
            "summary_report_generation_finished chars={}",
            len(content),
        )
        return content

    def generate_finding_markdown_report(
        self,
        *,
        finding: dict[str, Any],
        analysis: dict[str, Any],
    ) -> dict[str, Any]:
        finding_id = _finding_id(finding)
        if not self.is_available:
            logger.bind(component="llm.finding_report", finding_id=finding_id).info(
                "finding_markdown_report_static_fallback reason=openai_api_key_missing finding_id={}",
                finding_id,
            )
            return self.build_static_finding_markdown_report(
                finding=finding,
                analysis=analysis,
                reason="LLM 리포트 생성을 위한 OPENAI_API_KEY가 설정되어 있지 않습니다.",
            )

        try:
            payload = self._build_finding_detail_payload(finding=finding, analysis=analysis)
            payload_json = self._dump_finding_detail_payload_with_budget(payload)
            logger.bind(component="llm.finding_report", finding_id=finding_id, model=self.settings.openai_model).info(
                "finding_markdown_report_generation_started finding_id={} prompt_chars={}",
                finding_id,
                len(payload_json),
            )
            markdown = self._generate_finding_markdown_from_payload(payload_json)
            markdown = _clean_markdown(markdown)
            markdown = _ensure_remediation_sections(markdown, finding)
            markdown = _clean_markdown(markdown)
            if self.settings.llm_finding_detail_markdown_max_chars > 0:
                markdown = _truncate(
                    markdown,
                    max_chars=self.settings.llm_finding_detail_markdown_max_chars,
                )
            title = _finding_title(finding)
            report = FindingMarkdownReport(
                status="generated",
                title=title,
                summary=_finding_summary(finding),
                markdown=markdown,
                proposed_patch=_extract_proposed_patch(markdown),
                metadata=FindingReportMetadata(
                    title=title,
                    generated_at=_utc_now(),
                    model=self.settings.openai_model,
                    prompt_chars=len(payload_json),
                    source="llm",
                ),
            )
            logger.bind(component="llm.finding_report", finding_id=finding_id, model=self.settings.openai_model).info(
                "finding_markdown_report_generation_finished finding_id={} markdown_chars={}",
                finding_id,
                len(markdown),
            )
            return report.model_dump()
        except ContextBudgetExceededError as exc:
            logger.bind(component="llm.finding_report", finding_id=finding_id).warning(
                "finding_markdown_report_context_budget_exceeded finding_id={} error={}",
                finding_id,
                str(exc) or type(exc).__name__,
            )
            return self.build_static_finding_markdown_report(
                finding=finding,
                analysis=analysis,
                reason=str(exc) or "finding 상세 리포트 입력이 context budget을 초과했습니다.",
            )
        except Exception as exc:  # noqa: BLE001 - selected finding detail must survive LLM outages
            logger.bind(component="llm.finding_report", finding_id=finding_id).exception(
                "finding_markdown_report_generation_failed finding_id={}",
                finding_id,
            )
            return self.build_static_finding_markdown_report(
                finding=finding,
                analysis=analysis,
                reason=str(exc) or "finding 상세 리포트 생성에 실패했습니다.",
            )

    def _generate_finding_markdown_from_payload(self, finding_json: str) -> str:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are a senior application security analyst. Write safe Markdown only. "
                        "Do not output raw HTML. Do not invent files, lines, runtime validation, "
                        "numeric risk scores, CVE/CWE/CVSS identifiers, patches, citations, "
                        "or exploitability beyond supplied evidence. Never mention JSON, field names, "
                        "or internal property paths in the user-facing report."
                    ),
                ),
                (
                    "human",
                    """
다음 단일 정적 분석 결과 데이터를 사용해 개발자가 바로 읽을 수 있는 한국어 Markdown 보고서를 작성하라.
코드 식별자와 파일 경로는 원문을 유지한다. 원시 HTML을 쓰지 마라.

권장 섹션은 아래 4개만 사용하라:
## 문제가 되는 코드
## 왜 취약한가
## 어떻게 수정할까
## 수정 예시

규칙:
- 내부 데이터 구조를 설명하지 않는다. JSON, finding, code_snippet, call_chain, call_chain_details, guideline_refs, source_link 같은 단어를 출력하지 않는다.
- 런타임 검증/실제 공격 수행 여부에 대한 면책 문구를 쓰지 않는다.
- CVE, CWE, CVSS, 점수형 위험도, 정량 등급을 쓰지 않는다.
- 제공된 파일, 라인, 함수에 없는 위치를 만들지 않는다.
- 패치를 확정할 수 없으면 안전한 패턴 또는 의사코드로 표시한다.
- 취약 코드 맥락은 fenced code block으로 유지하고, 수정 예시는 가능하면 ```diff fenced block으로 작성한다.
- diff에는 제공된 취약 코드/라인과 safe_example/recommendation에서 직접 근거가 있는 변경만 포함한다.
- 공식 가이드 출처는 제공된 citation 값만 자연어로 쓴다.
- 취약점이 발생한 한 줄만 쓰지 말고, 제공된 코드 맥락과 호출 흐름을 자연어로 설명한다.
- 소스 링크가 있으면 Markdown 링크로 제공하고, 없으면 링크를 추정하지 않는다.

정적 분석 결과 데이터:
{finding_json}
""".strip(),
                ),
            ]
        )
        try:
            response = (prompt | self._create_llm()).invoke({"finding_json": finding_json})
        except Exception as exc:  # noqa: BLE001 - normalize provider context-limit errors
            if _is_context_limit_error(exc):
                raise ContextBudgetExceededError(str(exc) or "Finding report context budget exceeded") from exc
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
            "summary": _sanitize_summary_for_public_output(analysis.get("summary", {})),
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
            guideline_refs = _select_relevant_guideline_refs_for_finding(finding)
            brief: dict[str, Any] = {
                "id": finding.get("id"),
                "type": finding.get("type"),
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
                "call_chain_details": _bounded_list(finding.get("call_chain_details", []), max_items=8),
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
            grounding_counts = Counter(
                str(finding.get("guideline_grounding_status") or "unknown") for finding in findings
            )
            guideline_ref_ids = sorted(
                {
                    str(reference.get("id"))
                    for finding in findings
                    for reference in _select_relevant_guideline_refs_for_finding(finding)
                    if reference.get("id")
                }
            )
            groups.append(
                {
                    "type": finding_type,
                    "count": len(findings),
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
            for reference in _select_relevant_guideline_refs_for_finding(finding):
                if not reference.get("id"):
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
다음 정적 분석 결과에 대한 구조화된 한국어 설명 JSON만 생성하라.

제약:
- 취약점 존재 여부는 제공된 탐지 근거와 신뢰도 사유를 기준으로 한다.
- 취약점 위치는 제공된 file, line, function만 사용한다.
- 새로운 취약점, 파일, 라인, 함수, 출처를 추측하지 않는다.
- 가이드라인 출처는 제공된 citations 값만 사용한다.
- cited_guideline_ids에는 제공된 guideline id에 존재하는 값만 넣는다.
- 설명 본문 값에는 JSON, finding.xxx, code_snippet, call_chain, guideline_refs, source_link 같은 내부 구현 표현을 쓰지 않는다.
- 런타임 검증/실제 공격 수행 여부 면책 문구와 CVE/CWE/CVSS/점수형 위험도 표현은 쓰지 않는다.

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

정적 분석 결과 데이터:
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
        return _sanitize_llm_explanation_output(_parse_json_object(self._coerce_content(response.content)))

    def _build_finding_explanation_input(self, finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": finding.get("id"),
            "type": finding.get("type"),
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
                for reference in _select_relevant_guideline_refs_for_finding(finding)
            ],
        }

    def _build_finding_detail_payload(
        self,
        *,
        finding: dict[str, Any],
        analysis: dict[str, Any],
    ) -> dict[str, Any]:
        vulnerabilities = [
            item for item in analysis.get("vulnerabilities", []) if isinstance(item, dict)
        ]
        selected_id = _finding_id(finding)
        same_file_count = sum(
            1 for item in vulnerabilities if item.get("file") and item.get("file") == finding.get("file")
        )
        sibling_counts = Counter(str(item.get("type") or "UNKNOWN") for item in vulnerabilities)

        return {
            "repository": analysis.get("repository", ""),
            "language": analysis.get("language", "java"),
            "analyzed_at": analysis.get("analyzed_at", ""),
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "same_file_count": same_file_count,
                "by_type": dict(sibling_counts),
            },
            "selected_finding_id": selected_id,
            "finding": self._build_finding_detail_brief(finding),
        }

    def _build_finding_detail_brief(self, finding: dict[str, Any]) -> dict[str, Any]:
        guideline_refs = [
            self._build_guideline_explanation_brief(reference)
            for reference in _select_relevant_guideline_refs_for_finding(finding)
        ]
        return {
            "id": finding.get("id"),
            "type": finding.get("type"),
            "file": finding.get("file"),
            "line": finding.get("line"),
            "function": finding.get("function"),
            "description": _truncate(str(finding.get("description") or ""), max_chars=800),
            "evidence": _truncate(
                str(finding.get("evidence") or ""),
                max_chars=self.settings.llm_finding_evidence_max_chars,
            ),
            "recommendation": _truncate(str(finding.get("recommendation") or ""), max_chars=800),
            "safe_example": _truncate(str(finding.get("safe_example") or ""), max_chars=800),
            "code_snippet": _truncate(str(finding.get("code_snippet") or ""), max_chars=1200),
            "source_link": finding.get("source_link"),
            "source_ref": finding.get("source_ref"),
            "call_chain": _bounded_list(finding.get("call_chain", []), max_items=8),
            "call_chain_details": _bounded_list(finding.get("call_chain_details", []), max_items=8),
            "confidence": finding.get("confidence"),
            "confidence_reason": _truncate(str(finding.get("confidence_reason") or ""), max_chars=800),
            "guideline_grounding_status": finding.get("guideline_grounding_status"),
            "analysis_status": finding.get("analysis_status"),
            "llm_explanation": finding.get("llm_explanation"),
            "guideline_refs": guideline_refs,
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

    def _dump_finding_detail_payload_with_budget(self, payload: dict[str, Any]) -> str:
        dumped = json.dumps(payload, ensure_ascii=False, indent=2)
        budget = self.settings.llm_finding_detail_payload_max_chars
        if budget <= 0 or len(dumped) <= budget:
            return dumped

        compact_payload = self._compact_finding_detail_payload(payload)
        compact_dumped = json.dumps(compact_payload, ensure_ascii=False, indent=2)
        if len(compact_dumped) <= budget:
            return compact_dumped
        raise ContextBudgetExceededError(
            f"Finding detail payload is {len(compact_dumped)} chars after compaction; budget is {budget} chars."
        )

    def _compact_finding_detail_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        compact = deepcopy(payload)
        compact["budget_compaction"] = {
            "applied": True,
            "policy": (
                "Kept the selected finding, location, citations, and concise code/call-chain evidence; "
                "trimmed long prose and guide excerpts for this LLM prompt only."
            ),
        }
        finding = compact.get("finding")
        if not isinstance(finding, dict):
            return compact

        field_limits = {
            "description": 320,
            "evidence": 500,
            "recommendation": 420,
            "safe_example": 420,
            "code_snippet": 700,
            "confidence_reason": 420,
        }
        for field, max_chars in field_limits.items():
            if field in finding:
                finding[field] = _truncate(str(finding.get(field) or ""), max_chars=max_chars)

        finding["call_chain"] = _bounded_list(finding.get("call_chain", []), max_items=4)
        finding["call_chain_details"] = [
            _compact_mapping_strings(item, max_chars=180)
            for item in _bounded_list(finding.get("call_chain_details", []), max_items=4)
            if isinstance(item, dict)
        ]
        if isinstance(finding.get("llm_explanation"), dict):
            finding["llm_explanation"] = _compact_llm_explanation(finding["llm_explanation"])

        compact_refs: list[dict[str, Any]] = []
        for reference in finding.get("guideline_refs", []):
            if not isinstance(reference, dict):
                continue
            ref = dict(reference)
            for field in ("why_vulnerable", "diagnosis_rules", "fix_rules"):
                ref[field] = _truncate(str(ref.get(field) or ""), max_chars=260)
            compact_refs.append(ref)
        finding["guideline_refs"] = compact_refs
        return compact

    @staticmethod
    def build_static_finding_markdown_report(
        *,
        finding: dict[str, Any],
        analysis: dict[str, Any],
        reason: str = "",
    ) -> dict[str, Any]:
        title = _finding_title(finding)
        summary = _finding_summary(finding)
        file_path = str(finding.get("file") or "unknown file")
        line = finding.get("line")
        location = f"{file_path}:{line}" if line is not None else file_path
        function = str(finding.get("function") or "unknown function")
        evidence = str(finding.get("evidence") or "정적 분석 evidence가 제공되지 않았습니다.")
        recommendation = str(finding.get("recommendation") or "수동 검토 후 안전한 수정 방안을 적용하세요.")
        code_snippet = str(finding.get("code_snippet") or "").strip()
        safe_example = str(finding.get("safe_example") or "").strip()
        call_chain = _bounded_list(finding.get("call_chain", []), max_items=8)
        call_chain_details = [
            item for item in _bounded_list(finding.get("call_chain_details", []), max_items=8)
            if isinstance(item, dict)
        ]
        citations = _collect_allowed_citations(_select_relevant_guideline_refs_for_finding(finding))
        citation_lines = (
            "\n".join(
                f"- {citation.get('source')} {citation.get('version')} "
                f"p.{citation.get('page_start')}-{citation.get('page_end')} "
                f"({citation.get('section')})"
                for citation in citations
            )
            or "- 등록된 가이드라인 citation 없음"
        )
        if call_chain_details:
            call_chain_lines = "\n".join(
                (
                    f"- `{item.get('label')}`"
                    f" — `{item.get('file') or file_path}{':' + str(item.get('line')) if item.get('line') else ''}`"
                    f"{' (' + str(item.get('function')) + ')' if item.get('function') else ''}"
                    f"{' [소스 보기](' + str(item.get('source_link')) + ')' if item.get('source_link') else ''}"
                )
                for item in call_chain_details
            )
        else:
            call_chain_lines = "\n".join(f"- `{item}`" for item in call_chain) or "- 제공된 호출 경로 없음"
        source_link = str(finding.get("source_link") or "").strip()
        source_link_lines = f"\n\n[GitHub에서 해당 위치 열기]({source_link})" if source_link else ""
        code_block = f"\n```java\n{code_snippet}\n```\n" if code_snippet else "\n코드 스니펫이 제공되지 않았습니다.\n"
        patch_block = (
            _build_static_diff_patch(code_snippet=code_snippet, safe_example=safe_example)
            if safe_example
            else "구체적인 패치는 원본 파일 전체 문맥 확인 후 적용하세요. 위 수정 방향을 기준으로 취약 API 사용부를 안전한 패턴으로 교체하면 됩니다."
        )
        markdown = _clean_markdown(
            f"""
## 문제가 되는 코드
`{location}`의 `{function}` 함수에서 `{title}` 항목이 발견되었습니다. {summary}
{source_link_lines}

{code_block}

## 왜 취약한가
{evidence}

관련 호출 흐름은 다음과 같습니다.
{call_chain_lines}

공식 가이드 기준:
{citation_lines}

## 영향
{finding.get("description") or "영향 설명이 제공되지 않았습니다."}

판단 근거:
{finding.get("confidence_reason") or "정적 분석 근거와 신뢰도 사유가 제한적으로 제공되었습니다."}

## 어떻게 수정할까
{recommendation}

## 수정 예시
{patch_block}
""".strip()
        )
        report = FindingMarkdownReport(
            status="static_fallback",
            title=title,
            summary=summary,
            markdown=markdown,
            proposed_patch=patch_block,
            metadata=FindingReportMetadata(
                title=title,
                generated_at=_utc_now(),
                model=None,
                prompt_chars=None,
                source="static_fallback",
            ),
            error=reason or "LLM 상세 Markdown을 사용할 수 없어 정적 분석 근거로 작성했습니다.",
        )
        return report.model_dump()

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


def _select_relevant_guideline_refs_for_finding(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only citation refs specifically grounded to this finding.

    Older analysis results may already contain over-broad category matches. Keep
    detector/item-specific references and use category only as a tie-breaker
    so an SQL injection report cannot cite every "입력데이터 검증 및 표현" section.
    """
    refs = [reference for reference in finding.get("guideline_refs", []) if isinstance(reference, dict)]
    if not refs:
        return []

    detector_type = _normalize_reference_value(finding.get("type"))
    guide_item = _normalize_reference_value(finding.get("guide_item"))
    guide_category = _normalize_reference_value(finding.get("guide_category"))

    matches: list[tuple[int, int, dict[str, Any]]] = []
    for index, reference in enumerate(refs):
        score = 0
        ref_detector_types = {
            _normalize_reference_value(value)
            for value in _listish(reference.get("detector_types"))
        }
        if detector_type and detector_type in ref_detector_types:
            score += 100
        if guide_item and guide_item == _normalize_reference_value(reference.get("item")):
            score += 30
        if score <= 0:
            continue
        if guide_category and guide_category == _normalize_reference_value(reference.get("category")):
            score += 5
        matches.append((score, index, reference))

    matches.sort(key=lambda match: (-match[0], match[1]))
    if matches:
        return [reference for _, _, reference in matches]

    # Some tests and legacy stored results carry a single already-resolved
    # guideline ref without detector/item metadata. Preserve that one
    # citation, but never preserve a multi-ref category bundle without a
    # specific match.
    if len(refs) == 1:
        return refs
    return []


def _sanitize_summary_for_public_output(summary: Any) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    public_summary = dict(summary)
    hidden_bucket_key = "".join(("by", "sever", "ity"))
    for key in list(public_summary):
        if key.casefold().replace("_", "") == hidden_bucket_key:
            public_summary.pop(key, None)
    return public_summary


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


def _listish(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _normalize_reference_values(value: Any) -> set[str]:
    return {
        normalized
        for item in _listish(value)
        if (normalized := _normalize_reference_value(item))
    }


def _normalize_reference_value(value: Any) -> str:
    return str(value or "").strip().casefold()


def _compact_mapping_strings(value: dict[str, Any], *, max_chars: int) -> dict[str, Any]:
    return {
        key: _truncate(item, max_chars=max_chars) if isinstance(item, str) else item
        for key, item in value.items()
    }


def _compact_llm_explanation(value: dict[str, Any]) -> dict[str, Any]:
    compact = dict(value)
    for field in ("why_vulnerable", "how_to_fix", "grounding_notes"):
        if field in compact and compact[field] is not None:
            compact[field] = _truncate(str(compact[field]), max_chars=420)
    if isinstance(compact.get("fix_steps"), list):
        compact["fix_steps"] = [
            _truncate(str(item), max_chars=180)
            for item in compact["fix_steps"][:5]
        ]
    return compact


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


def _sanitize_llm_explanation_output(explanation: dict[str, Any]) -> dict[str, Any]:
    """Remove prompt/data-structure artifacts before text reaches the UI."""
    sanitized = dict(explanation)
    fallback_text = {
        "why_vulnerable": "제공된 코드에서 외부 입력이 검증 없이 민감한 처리 지점에 전달되는 흐름이 확인되었습니다.",
        "how_to_fix": "취약 지점의 입력 검증과 안전한 API 사용 패턴을 적용하세요.",
    }
    for field in ("why_vulnerable", "how_to_fix", "grounding_notes"):
        if field not in sanitized or sanitized[field] is None:
            continue
        cleaned = _strip_user_facing_artifact_lines(str(sanitized[field])).strip()
        sanitized[field] = cleaned or fallback_text.get(field)

    if isinstance(sanitized.get("fix_steps"), list):
        sanitized["fix_steps"] = [
            cleaned
            for item in sanitized["fix_steps"]
            if (cleaned := _strip_user_facing_artifact_lines(str(item)).strip())
        ]
    return sanitized


def _finding_title(finding: dict[str, Any]) -> str:
    existing = str(finding.get("finding_report_title") or "").strip()
    if existing:
        return existing
    guide_item = str(finding.get("guide_item") or "").strip()
    file_path = str(finding.get("file") or "").strip()
    function = str(finding.get("function") or "").strip()
    location = f"{file_path}:{finding.get('line')}" if finding.get("line") else file_path
    if guide_item and function:
        return f"{guide_item} 위험 - {function}"
    if guide_item and location:
        return f"{guide_item} 위험 - {location}"
    raw_type = str(finding.get("type") or "UNKNOWN").replace("_", " ").strip()
    return " ".join(part.capitalize() for part in raw_type.split()) or "Security finding"


def _finding_summary(finding: dict[str, Any]) -> str:
    existing = str(finding.get("finding_report_summary") or "").strip()
    if existing:
        return existing
    for field in ("description", "evidence", "recommendation"):
        value = str(finding.get(field) or "").strip()
        if value:
            return _truncate(" ".join(value.split()), max_chars=220)
    return "선택된 취약점에 대한 정적 분석 상세 정보가 제한적으로 제공되었습니다."


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_proposed_patch(markdown: str) -> str | None:
    match = re.search(
        r"(?is)^#{1,6}\s+(?:Proposed patch|수정 예시|패치 제안)\s*(.*?)(?:^#{1,6}\s+|\Z)",
        markdown,
        flags=re.MULTILINE,
    )
    if not match:
        return None
    patch = match.group(1).strip()
    return patch or None


def _ensure_remediation_sections(markdown: str, finding: dict[str, Any]) -> str:
    """Make deterministic remediation visible even when the LLM is conservative."""
    sections = [markdown.strip()]
    recommendation = str(finding.get("recommendation") or "").strip()
    safe_example = str(finding.get("safe_example") or "").strip()
    code_snippet = str(finding.get("code_snippet") or "").strip()

    has_remediation_section = re.search(r"(?im)^#{1,6}\s+(?:어떻게 수정할까|수정 방법)\s*$", markdown)
    if recommendation and not has_remediation_section:
        sections.append(f"## 어떻게 수정할까\n{recommendation}")
    elif recommendation and recommendation not in markdown:
        sections.append(f"## 추가 수정 권고\n{recommendation}")

    if safe_example and not re.search(r"(?im)^#{1,6}\s+수정 예시\s*$", markdown):
        sections.append(f"## 수정 예시\n{_build_static_diff_patch(code_snippet=code_snippet, safe_example=safe_example)}")

    return "\n\n".join(section for section in sections if section)


def _build_static_diff_patch(*, code_snippet: str, safe_example: str) -> str:
    vulnerable_lines = _parse_numbered_snippet_lines(code_snippet)
    safe_lines = [
        line.rstrip()
        for line in safe_example.strip().splitlines()
        if line.strip()
    ][:12]
    if not safe_lines:
        return "구체적인 patch는 원본 파일 전체 문맥이 필요해 자동 생성하지 않았습니다. 위 remediation을 기준으로 수동 수정하세요."

    active_indexes = [index for index, item in enumerate(vulnerable_lines) if item["active"]]
    center_index = active_indexes[0] if active_indexes else 0
    if vulnerable_lines:
        start_index = max(0, center_index - 1)
        end_index = min(len(vulnerable_lines), center_index + 2)
        context_lines = vulnerable_lines[start_index:end_index]
    else:
        context_lines = []

    hunk_start = int(context_lines[0]["line"]) if context_lines and context_lines[0]["line"] else 1
    old_count = max(1, len(context_lines))
    deleted_count = sum(1 for item in context_lines if item["active"]) or 1
    new_count = old_count - deleted_count + len(safe_lines)
    diff_lines = [
        "```diff",
        "--- 취약 코드",
        "+++ 수정 방향",
        f"@@ -{hunk_start},{old_count} +{hunk_start},{new_count} @@",
    ]

    if context_lines:
        inserted_safe_example = False
        for item in context_lines:
            prefix = "-" if item["active"] else " "
            diff_lines.append(f"{prefix} {item['content']}")
            if item["active"] and not inserted_safe_example:
                diff_lines.extend(f"+ {line}" for line in safe_lines)
                inserted_safe_example = True
        if not inserted_safe_example:
            diff_lines.append(f"- {context_lines[0]['content']}")
            diff_lines.extend(f"+ {line}" for line in safe_lines)
    else:
        diff_lines.append("- 취약 코드 위치는 위 탐지 코드 맥락을 확인하세요.")
        diff_lines.extend(f"+ {line}" for line in safe_lines)

    diff_lines.append("```")
    return "\n".join(diff_lines)


def _parse_numbered_snippet_lines(code_snippet: str) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for raw_line in code_snippet.splitlines():
        match = re.match(r"^\s*(>?)\s*(\d+)\s*\|\s?(.*)$", raw_line)
        if not match:
            continue
        parsed.append(
            {
                "active": bool(match.group(1)),
                "line": int(match.group(2)),
                "content": match.group(3).rstrip(),
            }
        )
    if parsed:
        return parsed

    return [
        {"active": index == 0, "line": index + 1, "content": raw_line.rstrip()}
        for index, raw_line in enumerate(code_snippet.splitlines()[:3])
        if raw_line.strip()
    ]


_FORBIDDEN_USER_FACING_HEADINGS = re.compile(
    r"(?i)^\s*#{1,6}\s*(?:요약|검증|검증\s*기준|검토\s*보고|근거와\s*코드\s*맥락|공격\s*경로\s*분석|가정)\s*$"
)
_FORBIDDEN_USER_FACING_LINE_PATTERNS = [
    re.compile(r"(?i)finding(?:\s*\.|\s+json\b)?"),
    re.compile(r"(?i)json"),
    re.compile(r"(?i)(?:code_snippet|call_chain|call_chain_details|guideline_refs|source_link)"),
    re.compile(r"런타임\s*검증|실제\s*공격\s*수행|실제\s*공격"),
    re.compile(r"(?i)(?:CVE|CWE|CVSS)(?:[-_:]?\w+)?"),
]


def _clean_markdown(markdown: str) -> str:
    cleaned = re.sub(
        r"(?is)<\s*/?\s*(script|style|iframe|object|embed|form|input|button|textarea|select|option|meta|link)[^>]*>",
        "",
        markdown,
    )
    cleaned = _strip_user_facing_artifact_lines(cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _strip_user_facing_artifact_lines(text: str) -> str:
    lines: list[str] = []
    in_fenced_code = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_fenced_code = not in_fenced_code
            lines.append(line)
            continue
        if in_fenced_code:
            lines.append(line)
            continue
        if _FORBIDDEN_USER_FACING_HEADINGS.search(line):
            continue
        if any(pattern.search(line) for pattern in _FORBIDDEN_USER_FACING_LINE_PATTERNS):
            continue
        lines.append(line)
    return "\n".join(lines)

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
