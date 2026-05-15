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
        by_severity = summary.get("by_severity", {}) if isinstance(summary, dict) else {}
        score = summary.get("score", {}) if isinstance(summary, dict) else {}
        overall_score = score.get("overall") if isinstance(score, dict) else None
        findings = analysis.get("vulnerabilities", [])
        llm_report = str(analysis.get("llm_report") or "").strip()

        styles = self._build_styles()
        story: list[Any] = []

        story.append(Paragraph("보안 취약점 분석 리포트", styles["title"]))
        story.append(Spacer(1, 6 * mm))

        repository = str(analysis.get("repository") or "-")
        analyzed_at = str(analysis.get("analyzed_at") or "-")
        files_analyzed = analysis.get("files_analyzed", 0)
        total_vulnerabilities = summary.get("total_vulnerabilities", 0) if isinstance(summary, dict) else 0

        overview_data = [
            ["저장소", repository],
            ["분석 시각", analyzed_at],
            ["분석 파일 수", str(files_analyzed)],
            ["총 취약점 수", str(total_vulnerabilities)],
            ["보안 점수", "-" if overall_score is None else f"{overall_score}/100"],
            [
                "심각도 분포",
                f"위험 {by_severity.get('CRITICAL', 0)} / "
                f"경고 {by_severity.get('HIGH', 0) + by_severity.get('MEDIUM', 0)} / "
                f"보통 {by_severity.get('LOW', 0)}",
            ],
        ]
        story.append(Paragraph("1. 결과 요약", styles["heading"]))
        story.append(self._build_key_value_table(overview_data))
        story.append(Spacer(1, 5 * mm))

        story.append(Paragraph("2. 보안 리포트", styles["heading"]))
        if llm_report:
            for block in llm_report.split("\n\n"):
                cleaned = block.strip()
                if cleaned:
                    story.append(Paragraph(self._paragraphify(cleaned), styles["body"]))
                    story.append(Spacer(1, 2.5 * mm))
        else:
            story.append(Paragraph("LLM 리포트가 아직 생성되지 않았습니다.", styles["body"]))
            story.append(Spacer(1, 2.5 * mm))

        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("3. 취약점 요약 목록", styles["heading"]))
        story.append(self._build_findings_table(findings, styles))

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
            "heading": ParagraphStyle(
                "ReportHeading",
                parent=styles["Heading2"],
                fontName=_PDF_FONT_NAME,
                fontSize=13,
                leading=18,
                spaceAfter=6,
                textColor=colors.HexColor("#111827"),
            ),
            "body": ParagraphStyle(
                "ReportBody",
                parent=styles["BodyText"],
                fontName=_PDF_FONT_NAME,
                fontSize=10,
                leading=15,
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

    def _build_findings_table(self, findings: Any, styles: dict[str, ParagraphStyle]) -> Table:
        header = [
            Paragraph("유형", styles["table"]),
            Paragraph("심각도", styles["table"]),
            Paragraph("파일", styles["table"]),
            Paragraph("라인", styles["table"]),
        ]
        rows: list[list[Any]] = [header]

        if isinstance(findings, list) and findings:
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                rows.append(
                    [
                        Paragraph(self._paragraphify(str(finding.get("type", "-"))), styles["table"]),
                        Paragraph(self._paragraphify(str(finding.get("severity", "-"))), styles["table"]),
                        Paragraph(
                            self._paragraphify(Path(str(finding.get("file", "-"))).name),
                            styles["table"],
                        ),
                        Paragraph(self._paragraphify(str(finding.get("line", "-"))), styles["table"]),
                    ]
                )
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
            colWidths=[42 * mm, 24 * mm, 95 * mm, 16 * mm],
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
