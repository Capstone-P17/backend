from __future__ import annotations

from html import escape
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.pdfmetrics import registerFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.app.core.config import Settings
from src.app.services.analysis_service import AnalysisResultNotFoundError, AnalysisService

_PDF_FONT_NAME = "HYGothic-Medium"
_SEVERITY_LABELS = {
    "CRITICAL": "치명적",
    "HIGH": "위험",
    "MEDIUM": "경고",
    "LOW": "보통",
}
_FINDING_STATUS_LABELS = {
    "generated": "생성됨",
    "static_fallback": "정적 대체",
    "failed": "생성 실패",
    "skipped_context_budget_exceeded": "생성 보류",
    "unavailable": "미생성",
}


class ReportService:
    """Generate downloadable PDF reports from stored analysis results."""

    def __init__(self, settings: Settings, analysis_service: AnalysisService) -> None:
        self.settings = settings
        self.analysis_service = analysis_service
        self._register_fonts()

    def build_pdf(self, analysis_id: str, user_id: int) -> tuple[str, bytes]:
        response = self.analysis_service.get_result(analysis_id, user_id)
        analysis = response.get("analysis_result", {})
        if not isinstance(analysis, dict):
            raise AnalysisResultNotFoundError("분석 결과를 찾을 수 없습니다")

        repository = str(analysis.get("repository") or "analysis")
        safe_repository = self._safe_filename(repository)
        filename = f"report-{safe_repository}-{analysis_id[:8]}.pdf"

        buffer = BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=f"{repository} security report",
        )
        story = self._build_story(analysis)
        document.build(story)
        return filename, buffer.getvalue()

    def _build_story(self, analysis: dict[str, Any]) -> list[Any]:
        summary = analysis.get("summary", {})
        findings = analysis.get("vulnerabilities", [])
        llm_report = str(analysis.get("llm_report") or "").strip()

        styles = self._build_styles()
        story: list[Any] = []

        story.append(Paragraph("보안 취약점 분석 리포트", styles["title"]))
        repository = str(analysis.get("repository") or "-")
        story.append(Paragraph(self._paragraphify(repository), styles["subtitle"]))
        story.append(Spacer(1, 6 * mm))

        story.append(Paragraph("1. 결과 요약", styles["heading"]))
        story.append(self._build_key_value_table(self._build_overview_rows(analysis)))
        story.append(Spacer(1, 5 * mm))

        story.append(Paragraph("2. 보안 리포트", styles["heading"]))
        if llm_report:
            self._append_markdownish_report(story, llm_report, styles)
        else:
            story.append(Paragraph("LLM 리포트가 아직 생성되지 않았습니다.", styles["body"]))
            story.append(Spacer(1, 2.5 * mm))

        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("3. 취약점 목록", styles["heading"]))
        self._append_finding_sections(story, analysis, findings, styles)

        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("4. 취약점 파일 목록", styles["heading"]))
        story.append(self._build_file_summary_table(findings, styles))

        return story

    @staticmethod
    def _register_fonts() -> None:
        try:
            registerFont(UnicodeCIDFont(_PDF_FONT_NAME))
        except KeyError:
            # Registering the same font more than once can raise in repeated test runs.
            pass

    @staticmethod
    def _safe_filename(value: str) -> str:
        sanitized = "".join(char if char.isalnum() or char in "-_." else "-" for char in value)
        return sanitized.strip("-") or "analysis"

    @staticmethod
    def _paragraphify(value: str) -> str:
        escaped = escape(value)
        return escaped.replace("\n", "<br/>")

    def _build_styles(self) -> dict[str, ParagraphStyle]:
        styles = getSampleStyleSheet()
        return {
            "title": ParagraphStyle(
                "ReportTitle",
                parent=styles["Title"],
                fontName=_PDF_FONT_NAME,
                fontSize=18,
                leading=24,
                alignment=TA_LEFT,
                textColor=colors.HexColor("#1F2937"),
            ),
            "subtitle": ParagraphStyle(
                "ReportSubtitle",
                parent=styles["Heading3"],
                fontName=_PDF_FONT_NAME,
                fontSize=11,
                leading=15,
                spaceAfter=2,
                textColor=colors.HexColor("#4B5563"),
            ),
            "heading": ParagraphStyle(
                "ReportHeading",
                parent=styles["Heading2"],
                fontName=_PDF_FONT_NAME,
                fontSize=13,
                leading=18,
                spaceAfter=6,
                textColor=colors.HexColor("#111827"),
            ),
            "subheading": ParagraphStyle(
                "ReportSubHeading",
                parent=styles["Heading3"],
                fontName=_PDF_FONT_NAME,
                fontSize=11,
                leading=15,
                spaceBefore=2,
                spaceAfter=4,
                textColor=colors.HexColor("#0F766E"),
            ),
            "body": ParagraphStyle(
                "ReportBody",
                parent=styles["BodyText"],
                fontName=_PDF_FONT_NAME,
                fontSize=10,
                leading=15,
                textColor=colors.HexColor("#374151"),
            ),
            "meta_label": ParagraphStyle(
                "ReportMetaLabel",
                parent=styles["BodyText"],
                fontName=_PDF_FONT_NAME,
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#4B5563"),
            ),
            "bullet": ParagraphStyle(
                "ReportBullet",
                parent=styles["BodyText"],
                fontName=_PDF_FONT_NAME,
                fontSize=10,
                leading=15,
                leftIndent=10,
                firstLineIndent=-6,
                textColor=colors.HexColor("#374151"),
            ),
            "table": ParagraphStyle(
                "ReportTable",
                parent=styles["BodyText"],
                fontName=_PDF_FONT_NAME,
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#111827"),
            ),
        }

    def _build_key_value_table(self, rows: list[list[str]]) -> Table:
        table = Table(rows, colWidths=[38 * mm, 125 * mm], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), _PDF_FONT_NAME),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEADING", (0, 0), (-1, -1), 12),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E5E7EB")),
                    ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#F9FAFB")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def _build_metadata_table(self, rows: list[list[str]]) -> Table:
        table = Table(rows, colWidths=[34 * mm, 129 * mm], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), _PDF_FONT_NAME),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEADING", (0, 0), (-1, -1), 12),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EFF6FF")),
                    ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#F9FAFB")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#BFDBFE")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DBEAFE")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def _build_callout_table(self, title: str, body: str) -> Table:
        rows = [
            [Paragraph(self._paragraphify(title), self._build_styles()["subheading"])],
            [Paragraph(self._paragraphify(body), self._build_styles()["body"])],
        ]
        table = Table(rows, colWidths=[163 * mm], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), _PDF_FONT_NAME),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ECFEFF")),
                    ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#22D3EE")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    def _build_overview_rows(self, analysis: dict[str, Any]) -> list[list[str]]:
        summary = analysis.get("summary", {})
        by_severity = summary.get("by_severity", {}) if isinstance(summary, dict) else {}
        by_guide_category = summary.get("by_guide_category", {}) if isinstance(summary, dict) else {}
        by_type = summary.get("by_type", {}) if isinstance(summary, dict) else {}
        score = summary.get("score", {}) if isinstance(summary, dict) else {}
        overall_score = score.get("overall") if isinstance(score, dict) else None
        findings = analysis.get("vulnerabilities", [])
        impacted_files = self._count_impacted_files(findings)
        llm_status = self._build_report_status(
            str(analysis.get("llm_report_status") or ""),
            str(analysis.get("llm_model") or ""),
        )

        return [
            ["저장소", str(analysis.get("repository") or "-")],
            ["분석 시각", str(analysis.get("analyzed_at") or "-")],
            ["분석 파일 수", str(analysis.get("files_analyzed", 0))],
            ["발견된 취약점", str(summary.get("total_vulnerabilities", 0) if isinstance(summary, dict) else 0)],
            ["영향 파일 수", str(impacted_files)],
            ["보안 점수", "-" if overall_score is None else f"{overall_score}/100"],
            ["리포트 상태", llm_status],
            ["심각도 분포", self._format_distribution(by_severity, _SEVERITY_LABELS)],
            ["가이드 대분류 분포", self._format_distribution(by_guide_category)],
            ["주요 취약점 유형", self._format_distribution(by_type)],
        ]

    @staticmethod
    def _count_impacted_files(findings: Any) -> int:
        if not isinstance(findings, list):
            return 0
        return len({str(finding.get("file") or "") for finding in findings if isinstance(finding, dict)})

    def _append_markdownish_report(
        self,
        story: list[Any],
        llm_report: str,
        styles: dict[str, ParagraphStyle],
    ) -> None:
        for raw_line in llm_report.splitlines():
            line = raw_line.strip()
            if not line:
                story.append(Spacer(1, 1.5 * mm))
                continue
            if line.startswith("### "):
                story.append(Paragraph(self._paragraphify(line[4:]), styles["subheading"]))
                continue
            if line.startswith("## "):
                story.append(Paragraph(self._paragraphify(line[3:]), styles["heading"]))
                continue
            if line.startswith("# "):
                story.append(Paragraph(self._paragraphify(line[2:]), styles["heading"]))
                continue
            if line[:2].isdigit() and line[1:3] == ". ":
                story.append(Paragraph(self._paragraphify(line), styles["subheading"]))
                continue
            if line.startswith(("- ", "* ")):
                story.append(Paragraph(self._paragraphify(f"• {line[2:]}"), styles["bullet"]))
                continue
            story.append(Paragraph(self._paragraphify(line), styles["body"]))

    def _append_finding_sections(
        self,
        story: list[Any],
        analysis: dict[str, Any],
        findings: Any,
        styles: dict[str, ParagraphStyle],
    ) -> None:
        if not isinstance(findings, list) or not findings:
            story.append(Paragraph("표시할 취약점이 없습니다.", styles["body"]))
            return

        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("finding_report_title") or finding.get("type") or "취약점")
            story.append(Paragraph(self._paragraphify(f"3.{index} {title}"), styles["subheading"]))

            summary_text = str(
                finding.get("finding_report_summary")
                or finding.get("description")
                or finding.get("evidence")
                or "상세 설명이 아직 생성되지 않았습니다."
            ).strip()
            story.append(Paragraph(self._paragraphify(summary_text), styles["body"]))
            story.append(Spacer(1, 2 * mm))

            story.append(self._build_metadata_table(self._build_finding_metadata_rows(finding, analysis)))
            story.append(Spacer(1, 2 * mm))

            guideline_box = self._build_guideline_box(finding)
            if guideline_box is not None:
                story.append(guideline_box)
                story.append(Spacer(1, 2 * mm))

            evidence = str(finding.get("evidence") or "").strip()
            if evidence:
                story.append(Paragraph("탐지 근거", styles["subheading"]))
                story.append(Paragraph(self._paragraphify(evidence), styles["body"]))
                story.append(Spacer(1, 1.5 * mm))

            confidence_reason = str(finding.get("confidence_reason") or "").strip()
            if confidence_reason:
                story.append(Paragraph("신뢰도 판단 기준", styles["subheading"]))
                story.append(Paragraph(self._paragraphify(confidence_reason), styles["body"]))
                story.append(Spacer(1, 1.5 * mm))

            code_snippet = str(finding.get("code_snippet") or "").strip()
            if code_snippet:
                story.append(Paragraph("탐지 코드 스니펫", styles["subheading"]))
                story.append(self._build_code_block(code_snippet))
                story.append(Spacer(1, 1.5 * mm))

            source_link = str(finding.get("source_link") or "").strip()
            source_ref = str(finding.get("source_ref") or "").strip()
            if source_link or source_ref:
                story.append(Paragraph("원본 코드 참조", styles["subheading"]))
                parts = []
                if source_ref:
                    parts.append(f"브랜치/태그: {source_ref}")
                if source_link:
                    parts.append(f"링크: {source_link}")
                story.append(Paragraph(self._paragraphify(" | ".join(parts)), styles["body"]))
                story.append(Spacer(1, 1.5 * mm))

            story.append(Spacer(1, 3 * mm))

    def _build_finding_metadata_rows(
        self,
        finding: dict[str, Any],
        analysis: dict[str, Any],
    ) -> list[list[str]]:
        cvss = finding.get("cvss")
        cvss_text = "-"
        if isinstance(cvss, dict):
            score = cvss.get("score")
            vector = str(cvss.get("vector") or "").strip()
            score_text = str(score) if score is not None else "-"
            cvss_text = score_text if not vector else f"{score_text} ({vector})"

        file_path = str(finding.get("file") or "-")
        line = finding.get("line")
        file_line = file_path if line in (None, "", "-") else f"{file_path}:{line}"
        confidence = str(finding.get("confidence") or "-")
        cwe = str(finding.get("cwe") or "-")

        return [
            ["심각도", self._severity_label(str(finding.get("severity") or ""))],
            ["파일 / 라인", file_line],
            ["함수", str(finding.get("function") or "-")],
            ["CWE / CVSS / 신뢰도", f"{cwe} / {cvss_text} / {confidence}"],
            ["저장소", str(analysis.get("repository") or "-")],
            ["리포트 상태", self._build_report_status(str(finding.get("finding_report_status") or ""), str(analysis.get("llm_model") or ""))],
            ["가이드 분류", self._build_guide_path(finding)],
        ]

    def _build_guideline_box(self, finding: dict[str, Any]) -> Table | None:
        refs = finding.get("guideline_refs")
        if not isinstance(refs, list) or not refs:
            return None

        lines: list[str] = []
        for reference in refs:
            if not isinstance(reference, dict):
                continue
            source_title = str(reference.get("source_title") or "소프트웨어 보안약점 진단가이드")
            source_version = str(reference.get("source_version") or "").strip()
            category = str(reference.get("category") or "").strip()
            item = str(reference.get("item") or "").strip()
            page_start = reference.get("page_start")
            page_end = reference.get("page_end")

            head = source_title if not source_version else f"{source_title}({source_version})"
            detail = self._join_non_empty([category, item], " > ")
            if page_start and page_end:
                detail = self._join_non_empty([detail, f"페이지 {page_start}-{page_end}"], " · ")
            elif page_start:
                detail = self._join_non_empty([detail, f"페이지 {page_start}"], " · ")
            lines.append(self._join_non_empty([head, detail], "<br/>"))

        if not lines:
            return None
        return self._build_callout_table("가이드라인 근거", "<br/><br/>".join(lines))

    def _build_code_block(self, code_snippet: str) -> Table:
        rows = [[Paragraph(self._paragraphify(code_snippet), self._build_styles()["table"])]]
        table = Table(rows, colWidths=[163 * mm], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), _PDF_FONT_NAME),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#111827")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.whitesmoke),
                    ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#1F2937")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    def _build_file_summary_table(self, findings: Any, styles: dict[str, ParagraphStyle]) -> Table:
        header = [
            Paragraph("파일명", styles["table"]),
            Paragraph("취약점", styles["table"]),
            Paragraph("탐지 라인", styles["table"]),
            Paragraph("위험도", styles["table"]),
        ]
        rows: list[list[Any]] = [header]

        file_rows = self._build_file_summary_rows(findings)
        if file_rows:
            for row in file_rows:
                rows.append([Paragraph(self._paragraphify(value), styles["table"]) for value in row])
        else:
            rows.append(
                [
                    Paragraph("취약점 없음", styles["table"]),
                    Paragraph("-", styles["table"]),
                    Paragraph("-", styles["table"]),
                    Paragraph("-", styles["table"]),
                ]
            )

        table = Table(
            rows,
            colWidths=[89 * mm, 18 * mm, 40 * mm, 16 * mm],
            repeatRows=1,
            hAlign="LEFT",
        )
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), _PDF_FONT_NAME),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def _build_file_summary_rows(self, findings: Any) -> list[list[str]]:
        if not isinstance(findings, list):
            return []

        aggregated: dict[str, dict[str, Any]] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            file_path = str(finding.get("file") or "-")
            bucket = aggregated.setdefault(
                file_path,
                {"count": 0, "lines": [], "severities": []},
            )
            bucket["count"] += 1
            line = finding.get("line")
            if isinstance(line, int):
                bucket["lines"].append(line)
            bucket["severities"].append(str(finding.get("severity") or ""))

        rows: list[list[str]] = []
        for file_path, values in aggregated.items():
            line_numbers = sorted({line for line in values["lines"] if isinstance(line, int)})
            line_preview = ", ".join(str(line) for line in line_numbers[:4])
            if len(line_numbers) > 4:
                line_preview = f"{line_preview} 외 {len(line_numbers) - 4}개"
            rows.append(
                [
                    file_path,
                    str(values["count"]),
                    line_preview or "-",
                    self._highest_severity_label(values["severities"]),
                ]
            )
        return rows

    def _format_distribution(self, raw_counts: Any, labels: dict[str, str] | None = None) -> str:
        if not isinstance(raw_counts, dict) or not raw_counts:
            return "-"
        formatted: list[str] = []
        for key, value in sorted(raw_counts.items(), key=lambda item: (-int(item[1]), str(item[0]))):
            label = labels.get(str(key), str(key)) if labels else str(key)
            formatted.append(f"{label} {value}")
        return " / ".join(formatted)

    @staticmethod
    def _join_non_empty(parts: list[str], separator: str) -> str:
        return separator.join(part for part in parts if part)

    def _build_report_status(self, status: str, model: str) -> str:
        label = _FINDING_STATUS_LABELS.get(status, status or "-")
        return label if not model else f"{label} · {model}"

    @staticmethod
    def _build_guide_path(finding: dict[str, Any]) -> str:
        category = str(finding.get("guide_category") or "").strip()
        item = str(finding.get("guide_item") or "").strip()
        return ReportService._join_non_empty([category, item], " > ") or "-"

    @staticmethod
    def _severity_label(severity: str) -> str:
        return _SEVERITY_LABELS.get(severity, severity or "-")

    def _highest_severity_label(self, severities: list[str]) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        best = min(severities, key=lambda severity: order.get(severity, 99), default="")
        return self._severity_label(best)
