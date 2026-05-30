from __future__ import annotations

from copy import deepcopy

from reportlab.platypus import PageBreakIfNotEmpty

from src.app.core.config import get_settings
from src.app.services.report_service import ReportService


class _FakeAnalysisService:
    def __init__(self, analysis_result: dict[str, object]) -> None:
        self.analysis_result = analysis_result

    def get_result(self, analysis_id: str, user_id: int) -> dict[str, object]:
        assert analysis_id == "analysis-1234"
        assert user_id == 1
        return {"analysis_result": self.analysis_result}


def _sample_analysis_result() -> dict[str, object]:
    return {
        "repository": "veracode/verademo",
        "analyzed_at": "2026-05-29T04:37:17.424539",
        "files_analyzed": 17,
        "llm_report_status": "generated",
        "llm_model": "gpt-4o",
        "llm_report": (
            "1. 전체 요약\n"
            "Verademo 프로젝트의 정적 분석 결과, 총 16개의 보안 취약점이 발견되었습니다.\n\n"
            "2. 주요 취약점 분석\n"
            "- SQL 인젝션은 execute 흐름에서 반복적으로 확인되었습니다.\n"
        ),
        "summary": {
            "total_vulnerabilities": 16,
            "by_type": {
                "SQL Injection": 12,
                "Dangerous File Upload": 1,
                "Weak Cryptographic Hash": 2,
                "Hardcoded Credentials": 1,
            },
            "by_guide_category": {
                "입력데이터 검증 및 표현": 13,
                "보안기능": 3,
            },
            "by_severity": {
                "CRITICAL": 12,
                "HIGH": 1,
                "MEDIUM": 3,
                "LOW": 0,
            },
            "score": {
                "overall": 84,
                "by_file": {},
            },
        },
        "vulnerabilities": [
            {
                "id": "VULN-001",
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "file": "app/src/main/java/com/veracode/verademo/commands/IgnoreCommand.java",
                "line": 37,
                "function": "execute",
                "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L"},
                "confidence": "HIGH",
                "guide_category": "입력데이터 검증 및 표현",
                "guide_item": "SQL 삽입",
                "finding_report_status": "generated",
                "finding_report_title": "execute에서 executeQuery로 이어지는 SQL 삽입",
                "finding_report_summary": "메서드 파라미터 값이 SQL 문자열에 결합된 뒤 executeQuery로 실행됩니다.",
                "evidence": "blabberUsername 값이 sqlQuery에 직접 결합된 뒤 sqlStatement.executeQuery로 실행됩니다.",
                "recommendation": "PreparedStatement와 바인딩 파라미터를 사용하고, SQL 문자열에 사용자 입력을 직접 연결하지 마세요.",
                "confidence_reason": "사용자 입력이 그대로 SQL 실행 sink로 이어지는 흐름이 확인되었습니다.",
                "guideline_refs": [
                    {
                        "source_title": "행정안전부 [소프트웨어 보안약점 진단가이드]",
                        "source_version": "2019.6 개정",
                        "category": "입력데이터 검증 및 표현",
                        "item": "SQL 삽입",
                        "page_start": 178,
                        "page_end": 191,
                    }
                ],
                "code_snippet": " 37 | sqlQuery += blabberUsername;\n 45 | sqlStatement.executeQuery(sqlQuery);",
                "source_ref": "main",
                "source_link": "https://github.com/example/repo/blob/main/IgnoreCommand.java#L37-L45",
            },
            {
                "id": "VULN-002",
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "file": "app/src/main/java/com/veracode/verademo/commands/IgnoreCommand.java",
                "line": 45,
                "function": "execute",
                "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L"},
                "confidence": "HIGH",
                "guide_category": "입력데이터 검증 및 표현",
                "guide_item": "SQL 삽입",
                "finding_report_status": "generated",
                "finding_report_title": "execute에서 sqlQuery로 이어지는 SQL 삽입",
                "finding_report_summary": "같은 파일에서 두 번째 SQL 인젝션 흐름이 확인되었습니다.",
                "evidence": "추가적인 쿼리 결합 흐름이 execute 내부에 남아 있습니다.",
                "recommendation": "PreparedStatement 바인딩으로 변경합니다.",
                "confidence_reason": "동일 메서드 내부에 복수의 sink가 존재합니다.",
                "guideline_refs": [],
                "code_snippet": " 45 | sqlStatement.executeQuery(sqlQuery);",
                "source_ref": "main",
                "source_link": "https://github.com/example/repo/blob/main/IgnoreCommand.java#L45",
            },
            {
                "id": "VULN-003",
                "type": "WEAK_HASH",
                "severity": "MEDIUM",
                "cwe": "CWE-328",
                "file": "app/src/main/java/com/veracode/verademo/utils/User.java",
                "line": 103,
                "function": "md5",
                "cvss": {"score": 5.9, "vector": "CVSS:3.1/AV:N/AC:H"},
                "confidence": "HIGH",
                "guide_category": "보안기능",
                "guide_item": "취약한 해시 알고리즘 사용",
                "finding_report_status": "generated",
                "finding_report_title": "md5의 취약한 해시 알고리즘 사용",
                "finding_report_summary": "MD5 해시 함수가 인증/무결성 맥락에서 사용될 수 있습니다.",
                "evidence": "User.java의 md5 함수가 직접 호출됩니다.",
                "recommendation": "SHA-256 이상 또는 bcrypt/scrypt/Argon2로 대체합니다.",
                "confidence_reason": "MD5 문자열이 명시적으로 코드에 포함되어 있습니다.",
                "guideline_refs": [
                    {
                        "source_title": "행정안전부 [소프트웨어 보안약점 진단가이드]",
                        "source_version": "2019.6 개정",
                        "category": "보안기능",
                        "item": "취약한 해시 알고리즘 사용",
                        "page_start": 301,
                        "page_end": 309,
                    }
                ],
                "code_snippet": "103 | MessageDigest.getInstance(\"MD5\");",
                "source_ref": "main",
                "source_link": "https://github.com/example/repo/blob/main/User.java#L103",
            },
        ],
    }


def test_report_service_builds_pdf_with_latest_analysis_shape() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    filename, pdf_bytes = service.build_pdf("analysis-1234", user_id=1)

    assert filename == "report-veracode-verademo-analysis.pdf"
    assert pdf_bytes.startswith(b"%PDF")


def test_report_service_overview_rows_format_timestamp_and_exclude_removed_fields() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    rows = service._build_overview_rows(_sample_analysis_result())

    assert ["영향 파일 수", "2"] in rows
    assert ["분석 시각", "2026-05-29 04:37:17"] in rows
    assert not any(label == "보안 점수" for label, _ in rows)
    assert not any(label == "리포트 상태" for label, _ in rows)


def test_report_service_file_summary_rows_aggregate_lines_and_severity() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    rows = service._build_file_summary_rows(_sample_analysis_result()["vulnerabilities"])

    assert rows == [
        [
            "verademo/commands/IgnoreCommand.java",
            "2",
            "37, 45",
            "치명적",
        ],
        [
            "verademo/utils/User.java",
            "1",
            "103",
            "경고",
        ],
    ]


def test_report_service_guideline_summary_limits_output_and_formats_plain_text() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    refs = [
        {
            "source_title": "행정안전부 [소프트웨어 보안약점 진단가이드]",
            "source_version": "2019.6 개정",
            "category": "입력데이터 검증 및 표현",
            "item": f"SQL 삽입 {index}",
            "page_start": 178 + index,
            "page_end": 191 + index,
        }
        for index in range(5)
    ]

    body = service._build_guideline_summary_text(refs)

    assert "<br/>" not in body
    assert "추가 근거 외 2건" in body
    assert "1. " in body
    assert "2. " in body
    assert "3. " in body


def test_report_service_finding_metadata_uses_report_focused_labels() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    analysis = _sample_analysis_result()
    finding = analysis["vulnerabilities"][0]
    rows = service._build_finding_metadata_rows(finding, analysis)

    assert any(
        label == "파일 / 라인" and "commands/IgnoreCommand.java" in value and "/ 37라인" in value
        for label, value in rows
    )
    assert not any(label == "저장소" for label, _ in rows)
    assert not any(label == "리포트 상태" for label, _ in rows)


def test_report_service_prefers_how_to_fix_and_falls_back_to_recommendation() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    analysis = _sample_analysis_result()
    finding = analysis["vulnerabilities"][0]
    finding["llm_explanation"] = {"how_to_fix": "PreparedStatement 바인딩을 적용합니다."}

    assert service._build_fix_method_text(finding) == "PreparedStatement 바인딩을 적용합니다."

    finding.pop("llm_explanation")
    assert (
        service._build_fix_method_text(finding)
        == "PreparedStatement와 바인딩 파라미터를 사용하고, SQL 문자열에 사용자 입력을 직접 연결하지 마세요."
    )


def test_report_service_renders_stored_finding_markdown_before_static_fallback_sections() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )
    analysis = deepcopy(_sample_analysis_result())
    finding = analysis["vulnerabilities"][0]
    finding["evidence"] = "STATIC_ONLY_EVIDENCE_SHOULD_NOT_RENDER"
    finding["finding_report"] = {
        "status": "generated",
        "markdown": (
            "# 요약\n"
            "생성된 finding markdown 본문입니다.\n"
            "# 수정 예시\n"
            "```diff\n"
            "- Statement 사용\n"
            "+ PreparedStatement 사용\n"
            "```\n"
        ),
    }
    story: list[object] = []

    service._append_finding_sections(story, analysis, [finding], service._build_styles())

    paragraph_text = "\n".join(
        flowable.getPlainText()
        for flowable in story
        if hasattr(flowable, "getPlainText")
    )
    assert "상세 Markdown 보고서" in paragraph_text
    assert "생성된 finding markdown 본문입니다." in paragraph_text
    assert "STATIC_ONLY_EVIDENCE_SHOULD_NOT_RENDER" not in paragraph_text


def test_report_service_sorts_findings_like_analysis_ui() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    findings = [
        {"id": "low-z", "severity": "LOW", "file": "b/File.java", "line": 5, "type": "WEAK_HASH"},
        {"id": "critical-b", "severity": "CRITICAL", "file": "b/File.java", "line": 40, "type": "SQL_INJECTION"},
        {"id": "critical-a", "severity": "CRITICAL", "file": "a/File.java", "line": 50, "type": "SQL_INJECTION"},
        {"id": "critical-a-early", "severity": "CRITICAL", "file": "a/File.java", "line": 10, "type": "SQL_INJECTION"},
        {"id": "high-a", "severity": "HIGH", "file": "a/File.java", "line": 10, "type": "XSS"},
    ]

    ordered = service._sort_findings_for_report(findings)

    assert [finding["id"] for finding in ordered] == [
        "critical-a-early",
        "critical-a",
        "critical-b",
        "high-a",
        "low-z",
    ]


def test_report_service_uses_non_empty_page_breaks_for_pdf_sections() -> None:
    service = ReportService(
        settings=get_settings(),
        analysis_service=_FakeAnalysisService(_sample_analysis_result()),  # type: ignore[arg-type]
    )

    story = service._build_story(_sample_analysis_result())
    page_breaks = [flowable for flowable in story if isinstance(flowable, PageBreakIfNotEmpty)]

    assert len(page_breaks) >= 2
