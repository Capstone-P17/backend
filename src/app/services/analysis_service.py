from __future__ import annotations

import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile, ZipInfo

import httpx
from loguru import logger

from src.app.core.config import Settings
from src.app.services.llm_report_service import ContextBudgetExceededError
from src.app.services.result_store import AnalysisResultStore
from src.app.services.static_analysis.detectors.metadata import DETECTOR_METADATA

if TYPE_CHECKING:
    from src.app.services.analyzer_service import AnalyzerService
    from src.app.services.guidelines.repository import GuidelineRepository
    from src.app.services.llm_report_service import SecurityReportGenerator

_GITHUB_REPO_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?$"
)
_GITHUB_ARCHIVE_URL = "https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
_DEFAULT_BRANCHES = ("main", "master")
_CLONE_TIMEOUT_SECONDS = 60
ProgressCallback = Callable[[dict[str, Any]], None]


def _emit_progress(callback: ProgressCallback | None, *, phase: str, message: str, percent: int, **progress: object) -> None:
    if callback is None:
        return
    payload: dict[str, Any] = {
        "phase": phase,
        "message": message,
        "progress": {
            "percent": max(0, min(100, int(percent))),
            **progress,
        },
    }
    callback(payload)


def _emit_analysis_snapshot(
    callback: ProgressCallback | None,
    result: dict[str, object],
    *,
    phase: str,
    message: str,
    percent: int,
) -> None:
    analysis = result.get("analysis_result", {})
    if not isinstance(analysis, dict):
        _emit_progress(callback, phase=phase, message=message, percent=percent)
        return
    vulnerabilities = analysis.get("vulnerabilities", [])
    findings_total = len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    files_analyzed = _safe_int(analysis.get("files_analyzed"))
    _emit_progress(
        callback,
        phase=phase,
        message=message,
        percent=percent,
        files_analyzed=files_analyzed,
        files_total=files_analyzed,
        findings_total=findings_total,
        finding_reports_total=findings_total,
    )


def _report_progress_percent(completed: int, total: int) -> int:
    if total <= 0:
        return 92
    return 72 + round((max(0, min(completed, total)) / total) * 20)


def _safe_int(value: object) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


class InvalidJavaFileError(ValueError):
    pass


class InvalidRepositoryArchiveError(ValueError):
    pass


class RepositoryArchiveExtractionError(RuntimeError):
    pass


class InvalidGitHubRepositoryError(ValueError):
    pass


class GitHubRepositoryCloneError(RuntimeError):
    pass


class AnalysisExecutionError(RuntimeError):
    pass


class UploadTooLargeError(ValueError):
    pass


class AnalysisResultNotFoundError(LookupError):
    pass


class FindingReportNotReadyError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedAnalysisTarget:
    target_path: str
    display_target_path: str
    repository: str = ""
    source_url: str = ""
    source_ref: str = ""


class AnalysisService:
    """Application service that matches the public analysis API contract."""

    def __init__(
        self,
        settings: Settings,
        analyzer_service: AnalyzerService,
        result_store: AnalysisResultStore,
        report_generator: SecurityReportGenerator | None = None,
        guideline_repository: GuidelineRepository | None = None,
    ) -> None:
        self.settings = settings
        self.analyzer_service = analyzer_service
        self.result_store = result_store
        if report_generator is None:
            from src.app.services.llm_report_service import SecurityReportGenerator

            report_generator = SecurityReportGenerator(settings)
        self.report_generator = report_generator
        if guideline_repository is None:
            from src.app.services.guidelines.repository import get_guideline_repository

            guideline_repository = get_guideline_repository()
        self.guideline_repository = guideline_repository

    def analyze_uploaded_file(self, filename: str, content: bytes, user_id: int) -> dict[str, object]:
        started = time.perf_counter()
        bound = logger.bind(component="analysis.service", user_id=user_id, source="file")
        bound.info("analysis_started filename={} bytes={}", filename, len(content))
        try:
            with self.prepare_uploaded_file(filename=filename, content=content) as prepared_target:
                result = self.analyzer_service.analyze(prepared_target.target_path)
        except InvalidJavaFileError:
            raise
        except UploadTooLargeError:
            raise
        except Exception as exc:
            bound.exception("analysis_failed filename={}", filename)
            raise AnalysisExecutionError("파일 분석 중 오류 발생") from exc

        self._attach_source_metadata(result, prepared_target)
        response = self._save_public_result(result, user_id)
        bound.info(
            "analysis_finished filename={} analysis_id={} duration_ms={:.2f}",
            filename,
            response["analysis_id"],
            (time.perf_counter() - started) * 1000,
        )
        return response

    @contextmanager
    def prepare_uploaded_file(self, filename: str, content: bytes) -> Iterator[PreparedAnalysisTarget]:
        self._validate_upload_size(len(content))
        normalized_name = Path(filename).name
        if Path(normalized_name).suffix.lower() != ".java":
            raise InvalidJavaFileError("Java 파일만 분석 가능합니다")

        with TemporaryDirectory(dir=self.settings.workspace_root) as temp_dir:
            target_path = Path(temp_dir) / normalized_name
            target_path.write_bytes(content)
            yield PreparedAnalysisTarget(
                target_path=str(target_path),
                display_target_path=normalized_name,
            )

    def analyze_uploaded_repository(self, filename: str, content: bytes, user_id: int) -> dict[str, object]:
        started = time.perf_counter()
        bound = logger.bind(component="analysis.service", user_id=user_id, source="archive")
        bound.info("analysis_started filename={} bytes={}", filename, len(content))
        try:
            with self.prepare_uploaded_repository(filename=filename, content=content) as prepared_target:
                result = self.analyzer_service.analyze(
                    prepared_target.target_path,
                    repository=prepared_target.repository,
                )
        except InvalidRepositoryArchiveError:
            raise
        except RepositoryArchiveExtractionError:
            raise
        except UploadTooLargeError:
            raise
        except Exception as exc:
            bound.exception("analysis_failed filename={}", filename)
            raise AnalysisExecutionError("업로드한 레포지토리 분석 중 오류 발생") from exc

        self._attach_source_metadata(result, prepared_target)
        response = self._save_public_result(result, user_id)
        bound.info(
            "analysis_finished filename={} analysis_id={} duration_ms={:.2f}",
            filename,
            response["analysis_id"],
            (time.perf_counter() - started) * 1000,
        )
        return response

    @contextmanager
    def prepare_uploaded_repository(self, filename: str, content: bytes) -> Iterator[PreparedAnalysisTarget]:
        self._validate_upload_size(len(content))
        archive_name = Path(filename).name
        if not archive_name:
            raise InvalidRepositoryArchiveError("레포지토리 압축 파일을 첨부해주세요")

        self._validate_repository_archive_filename(archive_name)

        with TemporaryDirectory(dir=self.settings.workspace_root) as temp_dir:
            archive_path = Path(temp_dir) / archive_name
            extract_root = Path(temp_dir) / "repo_upload"
            archive_path.write_bytes(content)
            extract_root.mkdir()
            self._extract_repository_archive(archive_path, extract_root)
            analysis_root = self._resolve_repository_analysis_root(extract_root)
            yield PreparedAnalysisTarget(
                target_path=str(analysis_root),
                display_target_path=archive_name,
                repository=Path(archive_name).stem,
            )

    def analyze_github_repository(
        self,
        url: str,
        user_id: int,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, object]:
        started = time.perf_counter()
        bound = logger.bind(component="analysis.service", user_id=user_id, source="github")
        bound.info("analysis_started url={}", url)
        try:
            _emit_progress(
                progress_callback,
                phase="cloning",
                message="GitHub 저장소를 내려받고 분석 대상을 준비하고 있습니다.",
                percent=5,
            )
            with self.prepare_github_repository(url=url) as prepared_target:
                _emit_progress(
                    progress_callback,
                    phase="indexing",
                    message="Java 파일과 호출 그래프 후보를 수집하고 있습니다.",
                    percent=20,
                )
                result = self.analyzer_service.analyze(
                    prepared_target.target_path,
                    repository=prepared_target.repository,
                )
                _emit_analysis_snapshot(
                    progress_callback,
                    result,
                    phase="static_analysis",
                    message="정적 분석을 완료하고 발견된 취약점 후보를 정리하고 있습니다.",
                    percent=50,
                )
        except (
            InvalidGitHubRepositoryError,
            GitHubRepositoryCloneError,
            InvalidRepositoryArchiveError,
            UploadTooLargeError,
        ):
            raise
        except Exception as exc:
            bound.exception("analysis_failed url={}", url)
            raise AnalysisExecutionError("GitHub 레포지토리 분석 중 오류 발생") from exc

        self._attach_source_metadata(result, prepared_target)
        _emit_analysis_snapshot(
            progress_callback,
            result,
            phase="finding_validation",
            message="보안 가이드와 탐지 근거를 매핑하고 finding 제목과 설명을 정리하고 있습니다.",
            percent=58,
        )
        response = self._save_public_result(result, user_id, progress_callback=progress_callback)
        bound.info(
            "analysis_finished url={} analysis_id={} duration_ms={:.2f}",
            url,
            response["analysis_id"],
            (time.perf_counter() - started) * 1000,
        )
        return response

    @contextmanager
    def prepare_github_repository(self, url: str) -> Iterator[PreparedAnalysisTarget]:
        url = url.strip().rstrip("/")
        match = _GITHUB_REPO_URL_RE.match(url)
        if not match:
            raise InvalidGitHubRepositoryError(
                "유효한 GitHub 레포지토리 URL이 아닙니다. "
                "https://github.com/owner/repo 형식으로 입력해주세요."
            )

        owner = match.group("owner")
        repo = match.group("repo")

        with TemporaryDirectory(dir=self.settings.workspace_root) as temp_dir:
            archive_content, branch = self._download_github_archive(owner, repo)
            archive_name = f"{repo}-{branch}.zip"
            archive_path = Path(temp_dir) / archive_name
            extract_root = Path(temp_dir) / "repo_clone"
            archive_path.write_bytes(archive_content)
            extract_root.mkdir()
            self._extract_repository_archive(archive_path, extract_root)
            analysis_root = self._resolve_repository_analysis_root(extract_root)
            yield PreparedAnalysisTarget(
                target_path=str(analysis_root),
                display_target_path=f"github.com/{owner}/{repo}",
                repository=f"{owner}/{repo}",
                source_url=f"https://github.com/{owner}/{repo}",
                source_ref=branch,
            )

    def _download_github_archive(self, owner: str, repo: str) -> tuple[bytes, str]:
        """GitHub archive zip을 다운로드합니다. main 브랜치를 먼저 시도하고 실패 시 master를 시도합니다."""
        last_exc: Exception | None = None
        for branch in _DEFAULT_BRANCHES:
            archive_url = _GITHUB_ARCHIVE_URL.format(owner=owner, repo=repo, branch=branch)
            try:
                logger.bind(component="analysis.github", repository=f"{owner}/{repo}", branch=branch).info(
                    "github_archive_download_started url={}",
                    archive_url,
                )
                with httpx.Client(follow_redirects=True, timeout=_CLONE_TIMEOUT_SECONDS) as client:
                    response = client.get(archive_url)
                if response.status_code == 200:
                    self._validate_upload_size(len(response.content))
                    logger.bind(component="analysis.github", repository=f"{owner}/{repo}", branch=branch).info(
                        "github_archive_download_succeeded bytes={}",
                        len(response.content),
                    )
                    return response.content, branch
                if response.status_code == 404:
                    logger.bind(component="analysis.github", repository=f"{owner}/{repo}", branch=branch).debug(
                        "github_archive_branch_not_found"
                    )
                    continue
                logger.bind(component="analysis.github", repository=f"{owner}/{repo}", branch=branch).warning(
                    "github_archive_download_failed status={}",
                    response.status_code,
                )
                raise GitHubRepositoryCloneError(
                    f"GitHub 레포지토리 다운로드 실패 (HTTP {response.status_code})"
                )
            except httpx.TimeoutException as exc:
                logger.bind(component="analysis.github", repository=f"{owner}/{repo}", branch=branch).warning(
                    "github_archive_download_timeout"
                )
                raise GitHubRepositoryCloneError(
                    "GitHub 레포지토리 다운로드 시간이 초과되었습니다"
                ) from exc
            except httpx.RequestError as exc:
                logger.bind(component="analysis.github", repository=f"{owner}/{repo}", branch=branch).warning(
                    "github_archive_request_error error={}",
                    str(exc) or type(exc).__name__,
                )
                last_exc = exc

        if last_exc:
            raise GitHubRepositoryCloneError(
                "GitHub 레포지토리에 연결할 수 없습니다"
            ) from last_exc
        raise InvalidGitHubRepositoryError(
            f"레포지토리를 찾을 수 없습니다: github.com/{owner}/{repo}"
        )

    def get_latest_result(self, user_id: int) -> dict[str, object]:
        logger.bind(component="analysis.service", user_id=user_id).debug("latest_result_lookup_started")
        latest_result = self.result_store.get_latest(user_id)
        if latest_result is None:
            logger.bind(component="analysis.service", user_id=user_id).warning("latest_result_lookup_miss")
            raise AnalysisResultNotFoundError("분석 결과가 없습니다")
        analysis_id, result = latest_result
        logger.bind(component="analysis.service", user_id=user_id, analysis_id=analysis_id).debug(
            "latest_result_lookup_hit analysis_id={}",
            analysis_id,
        )
        return self._build_analysis_response(analysis_id, result)

    def get_result(self, analysis_id: str, user_id: int) -> dict[str, object]:
        logger.bind(component="analysis.service", user_id=user_id, analysis_id=analysis_id).debug(
            "analysis_result_lookup_started analysis_id={}",
            analysis_id,
        )
        result = self.result_store.get(analysis_id, user_id)
        if result is None:
            logger.bind(component="analysis.service", user_id=user_id, analysis_id=analysis_id).warning(
                "analysis_result_lookup_miss analysis_id={}",
                analysis_id,
            )
            raise AnalysisResultNotFoundError("분석 결과를 찾을 수 없습니다")
        return self._build_analysis_response(analysis_id, result)

    def get_report_result(self, analysis_id: str, user_id: int) -> dict[str, object]:
        """Return the full stored result for PDF generation.

        The public result endpoint intentionally compacts finding_report.markdown
        into previews. PDF generation needs the same full finding payload that
        the finding-detail endpoint renders in the UI.
        """
        result = self.result_store.get(analysis_id, user_id)
        if result is None:
            raise AnalysisResultNotFoundError("분석 결과를 찾을 수 없습니다")
        analysis = result.get("analysis_result", {}) if isinstance(result, dict) else {}
        return {
            "analysis_id": analysis_id,
            "analysis_result": analysis,
        }

    def get_finding_detail(self, analysis_id: str, finding_id: str, user_id: int) -> dict[str, object]:
        result = self.result_store.get(analysis_id, user_id)
        if result is None:
            raise AnalysisResultNotFoundError("분석 결과를 찾을 수 없습니다")

        analysis = result.get("analysis_result", {}) if isinstance(result, dict) else {}
        if not isinstance(analysis, dict):
            raise AnalysisResultNotFoundError("취약점 상세 결과를 찾을 수 없습니다")

        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise AnalysisResultNotFoundError("취약점 상세 결과를 찾을 수 없습니다")

        selected = next(
            (
                finding
                for finding in vulnerabilities
                if isinstance(finding, dict) and self._finding_identifier(finding) == finding_id
            ),
            None,
        )
        if selected is None:
            raise AnalysisResultNotFoundError("취약점 상세 결과를 찾을 수 없습니다")

        report = selected.get("finding_report")
        if not self._has_full_finding_markdown(report):
            raise FindingReportNotReadyError("취약점 상세 리포트가 아직 생성되지 않았습니다")

        return {
            "analysis_id": analysis_id,
            "repository": analysis.get("repository", "") if isinstance(analysis, dict) else "",
            "analyzed_at": analysis.get("analyzed_at", "") if isinstance(analysis, dict) else "",
            "finding": selected,
        }

    def get_file_result(self, analysis_id: str, file_id: str, user_id: int) -> dict[str, object]:
        response = self.get_result(analysis_id, user_id)
        analysis = response.get("analysis_result", {})
        if not isinstance(analysis, dict):
            raise AnalysisResultNotFoundError("파일 상세 결과를 찾을 수 없습니다")

        findings = analysis.get("vulnerabilities", [])
        if not isinstance(findings, list):
            raise AnalysisResultNotFoundError("파일 상세 결과를 찾을 수 없습니다")

        summary = analysis.get("summary", {})

        exact_matches = [
            finding for finding in findings
            if isinstance(finding, dict) and str(finding.get("file", "")) == file_id
        ]

        matched_findings = exact_matches
        if not matched_findings:
            matched_findings = [
                finding for finding in findings
                if isinstance(finding, dict) and Path(str(finding.get("file", ""))).name == file_id
            ]

        if not matched_findings:
            raise AnalysisResultNotFoundError("파일 상세 결과를 찾을 수 없습니다")

        file_score = None
        file_path = str(matched_findings[0].get("file", file_id))
        if isinstance(summary, dict):
            score = summary.get("score", {})
            if isinstance(score, dict):
                by_file = score.get("by_file", {})
                if isinstance(by_file, dict):
                    raw_score = by_file.get(file_path)
                    if not isinstance(raw_score, int):
                        raw_score = by_file.get(Path(file_path).name)
                    if isinstance(raw_score, int):
                        file_score = raw_score

        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in matched_findings:
            finding_type = str(finding.get("type", "UNKNOWN"))
            finding_severity = str(finding.get("severity", "UNKNOWN"))
            by_type[finding_type] = by_type.get(finding_type, 0) + 1
            by_severity[finding_severity] = by_severity.get(finding_severity, 0) + 1

        return {
            "analysis_id": analysis_id,
            "file_id": file_id,
            "file_path": file_path,
            "repository": analysis.get("repository", "") if isinstance(analysis, dict) else "",
            "analyzed_at": analysis.get("analyzed_at", "") if isinstance(analysis, dict) else "",
            "findings": matched_findings,
            "summary": {
                "total_vulnerabilities": len(matched_findings),
                "by_type": by_type,
                "by_severity": by_severity,
                "score": file_score,
            },
        }

    def list_results(self, user_id: int, limit: int = 20) -> list[dict[str, object]]:
        return self.result_store.list_results(user_id=user_id, limit=limit)

    @staticmethod
    def _validate_repository_archive_filename(filename: str) -> None:
        allowed_suffixes = (".zip",)
        if not filename.lower().endswith(allowed_suffixes):
            raise InvalidRepositoryArchiveError("ZIP 형식의 레포지토리 압축 파일만 업로드 가능합니다")

    def _validate_upload_size(self, size_bytes: int) -> None:
        if size_bytes > self.settings.max_upload_bytes:
            raise UploadTooLargeError(
                f"업로드 크기는 최대 {self.settings.max_upload_bytes // (1024 * 1024)}MB까지 허용됩니다"
            )

    def _extract_repository_archive(self, archive_path: Path, extract_root: Path) -> None:
        logger.bind(component="analysis.archive").debug(
            "archive_extract_started archive={} target={}",
            archive_path.name,
            str(extract_root),
        )
        try:
            with ZipFile(archive_path) as archive_file:
                members = archive_file.infolist()
                if not members:
                    raise InvalidRepositoryArchiveError("압축 파일이 비어 있습니다")
                self._validate_archive_limits(members)
                for member in members:
                    self._validate_archive_member_path(member.filename)
                archive_file.extractall(extract_root)
                logger.bind(component="analysis.archive").info(
                    "archive_extract_finished archive={} members={}",
                    archive_path.name,
                    len(members),
                )
        except BadZipFile as exc:
            raise InvalidRepositoryArchiveError("유효한 ZIP 파일이 아닙니다") from exc
        except InvalidRepositoryArchiveError:
            raise
        except OSError as exc:
            raise RepositoryArchiveExtractionError("레포지토리 압축 해제 실패") from exc

    def _validate_archive_limits(self, members: list[ZipInfo]) -> None:
        file_members = [member for member in members if not member.is_dir()]
        if len(file_members) > self.settings.max_archive_members:
            raise InvalidRepositoryArchiveError(
                f"압축 파일 내부 파일 수는 최대 {self.settings.max_archive_members}개까지 허용됩니다"
            )

        total_uncompressed_bytes = sum(member.file_size for member in file_members)
        if total_uncompressed_bytes > self.settings.max_upload_bytes:
            raise InvalidRepositoryArchiveError(
                f"압축 해제 후 크기는 최대 {self.settings.max_upload_bytes // (1024 * 1024)}MB까지 허용됩니다"
            )

    @staticmethod
    def _validate_archive_member_path(member_name: str) -> None:
        target_path = Path(member_name)
        if target_path.is_absolute() or ".." in target_path.parts:
            raise InvalidRepositoryArchiveError("압축 파일 경로가 올바르지 않습니다")

    def _resolve_repository_analysis_root(self, extract_root: Path) -> Path:
        java_files = sorted(extract_root.rglob("*.java"))
        if not java_files:
            raise InvalidRepositoryArchiveError("분석할 Java 파일이 없습니다")

        top_level_directories = sorted(
            path for path in extract_root.iterdir() if path.is_dir() and not path.name.startswith("__MACOSX")
        )
        top_level_files = [path for path in extract_root.iterdir() if path.is_file()]
        if len(top_level_directories) == 1 and not top_level_files:
            nested_root = top_level_directories[0]
            if any(nested_root.rglob("*.java")):
                return nested_root
        return extract_root

    @staticmethod
    def _attach_source_metadata(result: dict[str, object], prepared_target: PreparedAnalysisTarget) -> None:
        if not prepared_target.source_url:
            return
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return

        analysis["source_url"] = prepared_target.source_url
        analysis["source_ref"] = prepared_target.source_ref
        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return

        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            finding["source_url"] = prepared_target.source_url
            finding["source_ref"] = prepared_target.source_ref
            link = AnalysisService._build_source_link(
                source_url=prepared_target.source_url,
                source_ref=prepared_target.source_ref,
                file_path=str(finding.get("file") or ""),
                line=finding.get("line"),
                code_snippet=str(finding.get("code_snippet") or ""),
            )
            if link:
                finding["source_link"] = link
            call_details = finding.get("call_chain_details", [])
            if not isinstance(call_details, list):
                continue
            for detail in call_details:
                if not isinstance(detail, dict):
                    continue
                detail["source_url"] = prepared_target.source_url
                detail["source_ref"] = prepared_target.source_ref
                detail_link = AnalysisService._build_source_link(
                    source_url=prepared_target.source_url,
                    source_ref=prepared_target.source_ref,
                    file_path=str(detail.get("file") or finding.get("file") or ""),
                    line=detail.get("line"),
                )
                if detail_link:
                    detail["source_link"] = detail_link

    @staticmethod
    def _build_source_link(
        *,
        source_url: str,
        source_ref: str,
        file_path: str,
        line: object,
        code_snippet: str = "",
    ) -> str:
        if not source_url.startswith("https://github.com/") or not source_ref or not file_path:
            return ""
        try:
            line_number = int(line) if line is not None else 0
        except (TypeError, ValueError):
            line_number = 0
        if line_number <= 0:
            return ""

        start_line, end_line = AnalysisService._snippet_line_range(code_snippet)
        if start_line <= 0:
            start_line = line_number
        if end_line < start_line:
            end_line = start_line

        encoded_ref = quote(source_ref, safe="")
        encoded_path = quote(file_path.lstrip("/"), safe="/")
        if start_line <= line_number <= end_line and start_line != end_line:
            anchor = f"#L{start_line}-L{end_line}"
        else:
            anchor = f"#L{line_number}"
        return f"{source_url.rstrip('/')}/blob/{encoded_ref}/{encoded_path}{anchor}"

    @staticmethod
    def _snippet_line_range(code_snippet: str) -> tuple[int, int]:
        line_numbers: list[int] = []
        for raw_line in code_snippet.splitlines():
            match = re.match(r"^\s*>?\s*(\d+)\s*\|", raw_line)
            if match:
                line_numbers.append(int(match.group(1)))
        if not line_numbers:
            return 0, 0
        return min(line_numbers), max(line_numbers)

    def _save_public_result(
        self,
        result: dict[str, object],
        user_id: int,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, object]:
        started = time.perf_counter()
        logger.bind(component="analysis.pipeline", user_id=user_id).debug("result_sanitize_started")
        sanitized_result = self._sanitize_public_result(result)
        analysis = sanitized_result.get("analysis_result", {})
        vulnerabilities = analysis.get("vulnerabilities", []) if isinstance(analysis, dict) else []
        logger.bind(component="analysis.pipeline", user_id=user_id).info(
            "result_processing_started files={} findings={}",
            analysis.get("files_analyzed", 0) if isinstance(analysis, dict) else 0,
            len(vulnerabilities) if isinstance(vulnerabilities, list) else 0,
        )
        _emit_analysis_snapshot(
            progress_callback,
            sanitized_result,
            phase="finding_validation",
            message="탐지 결과를 검증 가능한 finding 정보로 정리하고 있습니다.",
            percent=60,
        )
        self._attach_guideline_references(sanitized_result)
        logger.bind(component="analysis.pipeline", user_id=user_id).debug("guideline_references_attached")
        self._attach_compact_finding_titles(sanitized_result)
        logger.bind(component="analysis.pipeline", user_id=user_id).debug("compact_finding_titles_attached")
        self._attach_finding_explanations(sanitized_result)
        logger.bind(component="analysis.pipeline", user_id=user_id).debug("finding_explanations_attached")
        self._attach_finding_markdown_reports(sanitized_result, progress_callback=progress_callback)
        logger.bind(component="analysis.pipeline", user_id=user_id).debug("finding_markdown_reports_attached")
        _emit_analysis_snapshot(
            progress_callback,
            sanitized_result,
            phase="summary_generation",
            message="전체 요약 리포트를 생성하고 저장 준비를 하고 있습니다.",
            percent=94,
        )
        self._attach_llm_report(sanitized_result)
        logger.bind(component="analysis.pipeline", user_id=user_id).debug("llm_summary_report_attached")
        _emit_analysis_snapshot(
            progress_callback,
            sanitized_result,
            phase="saving",
            message="분석 결과를 저장하고 있습니다.",
            percent=98,
        )
        analysis_id = self.result_store.save(sanitized_result, user_id)
        logger.bind(component="analysis.pipeline", user_id=user_id, analysis_id=analysis_id).info(
            "result_saved analysis_id={} duration_ms={:.2f}",
            analysis_id,
            (time.perf_counter() - started) * 1000,
        )
        return self._build_analysis_response(analysis_id, sanitized_result)


    @staticmethod
    def _finding_identifier(finding: dict[str, object]) -> str:
        return str(
            finding.get("id")
            or f"{finding.get('type', 'UNKNOWN')}:{finding.get('file', '')}:{finding.get('line', '')}"
        )

    @staticmethod
    def _has_full_finding_markdown(report: object) -> bool:
        return isinstance(report, dict) and bool(str(report.get("markdown") or "").strip())

    def _generate_finding_markdown_report(self, *, finding: dict[str, object], analysis: dict[str, object]) -> dict[str, object]:
        generate = getattr(self.report_generator, "generate_finding_markdown_report", None)
        if callable(generate):
            return generate(finding=deepcopy(finding), analysis=deepcopy(analysis))

        from src.app.services.llm_report_service import SecurityReportGenerator

        return SecurityReportGenerator.build_static_finding_markdown_report(
            finding=deepcopy(finding),
            analysis=deepcopy(analysis),
            reason="Finding 상세 Markdown 생성기가 설정되어 있지 않아 정적 fallback을 사용했습니다.",
        )

    def _attach_finding_markdown_reports(
        self,
        result: dict[str, object],
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return

        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return
        total = len([finding for finding in vulnerabilities if isinstance(finding, dict)])
        completed = 0
        _emit_progress(
            progress_callback,
            phase="report_generation",
            message=f"finding별 상세 리포트를 생성하고 있습니다. (0/{total})",
            percent=72,
            finding_reports_completed=0,
            finding_reports_total=total,
            findings_total=total,
            files_analyzed=_safe_int(analysis.get("files_analyzed")),
            files_total=_safe_int(analysis.get("files_analyzed")),
        )

        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            if self._has_full_finding_markdown(finding.get("finding_report")):
                logger.bind(component="analysis.finding_report", finding_id=self._finding_identifier(finding)).debug(
                    "finding_report_already_present finding_id={}",
                    self._finding_identifier(finding),
                )
                completed += 1
                _emit_progress(
                    progress_callback,
                    phase="report_generation",
                    message=f"finding별 상세 리포트를 생성하고 있습니다. ({completed}/{total})",
                    percent=_report_progress_percent(completed, total),
                    finding_reports_completed=completed,
                    finding_reports_total=total,
                    findings_total=total,
                    files_analyzed=_safe_int(analysis.get("files_analyzed")),
                    files_total=_safe_int(analysis.get("files_analyzed")),
                )
                continue
            finding_id = self._finding_identifier(finding)
            report_started = time.perf_counter()
            logger.bind(component="analysis.finding_report", finding_id=finding_id).debug(
                "finding_report_generation_started finding_id={} type={} severity={}",
                finding_id,
                finding.get("type", "UNKNOWN"),
                finding.get("severity", "UNKNOWN"),
            )
            finding["finding_report"] = self._generate_finding_markdown_report(
                finding=finding,
                analysis=analysis,
            )
            completed += 1
            report = finding.get("finding_report")
            report_status = report.get("status", "unknown") if isinstance(report, dict) else "unknown"
            logger.bind(component="analysis.finding_report", finding_id=finding_id).info(
                "finding_report_generation_finished finding_id={} status={} duration_ms={:.2f}",
                finding_id,
                report_status,
                (time.perf_counter() - report_started) * 1000,
            )
            _emit_progress(
                progress_callback,
                phase="report_generation",
                message=f"finding별 상세 리포트를 생성하고 있습니다. ({completed}/{total})",
                percent=_report_progress_percent(completed, total),
                finding_reports_completed=completed,
                finding_reports_total=total,
                findings_total=total,
                files_analyzed=_safe_int(analysis.get("files_analyzed")),
                files_total=_safe_int(analysis.get("files_analyzed")),
            )

    @staticmethod
    def _compact_finding_report(report: object) -> dict[str, object] | None:
        if not isinstance(report, dict):
            return None
        compact: dict[str, object] = {
            "status": report.get("status", "unavailable"),
            "title": report.get("title", ""),
            "summary": report.get("summary", ""),
            "metadata": report.get("metadata"),
            "error": report.get("error"),
        }
        markdown = str(report.get("markdown") or "").strip()
        if markdown:
            compact["markdown_preview"] = markdown[:220].rstrip() + ("…" if len(markdown) > 220 else "")
        return compact

    @classmethod
    def _compact_result_for_list_response(cls, result: dict[str, object]) -> dict[str, object]:
        compact = deepcopy(result)
        analysis = compact.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return compact
        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return compact
        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            compact_report = cls._compact_finding_report(finding.get("finding_report"))
            if compact_report is not None:
                finding["finding_report_status"] = compact_report.get("status", "unavailable")
                finding["finding_report_title"] = compact_report.get("title", "")
                finding["finding_report_summary"] = compact_report.get("summary", "")
                finding["finding_report_markdown_preview"] = compact_report.get("markdown_preview", "")
                finding.pop("finding_report", None)
        return compact

    @classmethod
    def _attach_compact_finding_titles(cls, result: dict[str, object]) -> None:
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return

        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return

        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            cls._attach_contextual_finding_description(finding)

            existing_title = str(finding.get("finding_report_title") or "").strip()
            if not existing_title or cls._is_generic_finding_title(existing_title, finding):
                finding["finding_report_title"] = cls._build_compact_finding_title(finding)

            existing_summary = str(finding.get("finding_report_summary") or "").strip()
            if not existing_summary:
                finding["finding_report_summary"] = cls._build_compact_finding_summary(finding)

    @classmethod
    def _attach_contextual_finding_description(cls, finding: dict[str, object]) -> None:
        current = re.sub(r"\s+", " ", str(finding.get("description") or "")).strip()
        metadata = DETECTOR_METADATA.get(str(finding.get("type") or ""))
        static_description = re.sub(r"\s+", " ", metadata.description).strip() if metadata else ""
        if current and current != static_description:
            return

        finding["description"] = cls._build_contextual_finding_description(finding)

    @classmethod
    def _build_contextual_finding_description(cls, finding: dict[str, object]) -> str:
        finding_type = str(finding.get("type") or "").upper()
        function = cls._compact_identifier(str(finding.get("function") or ""))
        sink = cls._call_chain_sink(finding)
        location = cls._compact_location(finding)
        evidence = cls._clean_inline_text(str(finding.get("evidence") or ""))

        subject = function or location
        if finding_type == "SQL_INJECTION":
            if function and sink:
                return f"{function}에서 구성한 SQL이 {sink} 호출로 실행되어 입력값이 쿼리 구조에 영향을 줄 수 있습니다."
            return f"{subject}에서 사용자 입력이 SQL 실행 흐름에 포함될 수 있습니다."

        if finding_type == "XSS":
            if function and sink:
                return f"{function}에서 받은 입력이 {sink} 출력 흐름으로 이어져 브라우저에서 스크립트가 실행될 수 있습니다."
            return f"{subject}에서 검증되지 않은 입력이 응답 출력에 포함될 수 있습니다."

        if finding_type == "COMMAND_INJECTION":
            if function and sink:
                return f"{function}에서 사용자 입력이 {sink} 명령 실행 흐름으로 전달될 수 있습니다."
            return f"{subject}에서 외부 입력이 OS 명령 실행에 영향을 줄 수 있습니다."

        if finding_type == "PATH_TRAVERSAL":
            return f"{subject}에서 외부 입력이 파일 경로 생성이나 파일 접근에 사용될 수 있습니다."

        if finding_type == "HARDCODED_SECRET":
            secret_name = cls._secret_identifier(finding)
            if secret_name:
                return f"{secret_name} 값이 코드에 직접 포함되어 저장소나 배포 산출물을 통해 노출될 수 있습니다."
            return f"{subject}에 인증정보나 비밀값으로 추정되는 문자열이 코드에 직접 포함되어 있습니다."

        if finding_type == "DANGEROUS_FILE_UPLOAD":
            return f"{subject}에서 업로드 파일이 충분한 형식·크기·저장경로 검증 없이 저장될 수 있습니다."

        if finding_type == "INSECURE_RANDOM":
            return f"{subject}에서 보안 값 생성에 예측 가능한 난수 생성기가 사용될 수 있습니다."

        if finding_type == "WEAK_HASH":
            return f"{subject}에서 보안 목적에 부적합한 약한 해시 알고리즘이 사용될 수 있습니다."

        if evidence:
            return evidence[:137].rstrip() + ("…" if len(evidence) > 137 else "")
        return f"{subject}에서 검토가 필요한 취약 코드 후보가 확인되었습니다."

    @staticmethod
    def _is_generic_finding_title(title: str, finding: dict[str, object]) -> bool:
        normalized_title = re.sub(r"[^a-z0-9]", "", title.casefold())
        raw_type = str(finding.get("type") or "")
        normalized_type = re.sub(r"[^a-z0-9]", "", raw_type.casefold())
        return bool(normalized_title and normalized_title == normalized_type)

    @classmethod
    def _build_compact_finding_title(cls, finding: dict[str, object]) -> str:
        finding_type = str(finding.get("type") or "").upper()
        guide_item = cls._short_guide_item(finding)
        function = cls._compact_identifier(str(finding.get("function") or ""))
        sink = cls._call_chain_sink(finding)
        location = cls._compact_location(finding)

        if finding_type == "HARDCODED_SECRET":
            secret_name = cls._secret_identifier(finding)
            if secret_name:
                return f"{secret_name} 하드코딩된 인증정보"
            if function:
                return f"{function}의 하드코딩된 인증정보"

        if finding_type == "DANGEROUS_FILE_UPLOAD":
            if function:
                return f"{function}의 파일 업로드 검증 누락"
            return f"{location}의 파일 업로드 검증 누락"

        if finding_type == "PATH_TRAVERSAL":
            if function:
                return f"{function}의 경로 조작 가능성"
            return f"{location}의 경로 조작 가능성"

        if finding_type == "COMMAND_INJECTION":
            if function and sink:
                return f"{function}에서 {sink}로 이어지는 OS 명령어 삽입"
            if function:
                return f"{function}의 OS 명령어 삽입"

        if finding_type == "SQL_INJECTION":
            if function and sink:
                return f"{function}에서 {sink}로 이어지는 SQL 삽입"
            if function:
                return f"{function}의 SQL 삽입"

        if finding_type == "XSS":
            if function and sink:
                return f"{function}에서 {sink}로 이어지는 XSS"
            if function:
                return f"{function}의 XSS"

        if finding_type == "INSECURE_RANDOM":
            if function:
                return f"{function}의 예측 가능한 난수 사용"

        if finding_type == "WEAK_HASH":
            if function:
                return f"{function}의 취약한 해시 알고리즘 사용"

        if function and sink:
            return f"{function}에서 {sink}로 이어지는 {guide_item}"
        if function:
            return f"{function}의 {guide_item}"
        return f"{location}의 {guide_item}"

    @staticmethod
    def _build_compact_finding_summary(finding: dict[str, object]) -> str:
        for field in ("evidence", "description", "recommendation", "confidence_reason"):
            value = AnalysisService._clean_inline_text(str(finding.get(field) or ""))
            if value:
                return value[:137].rstrip() + ("…" if len(value) > 137 else "")
        return "정적 분석에서 검토가 필요한 취약 코드 후보를 확인했습니다."

    @staticmethod
    def _clean_inline_text(value: str) -> str:
        return re.sub(r"\s+", " ", value.replace("`", "")).strip()

    @staticmethod
    def _short_guide_item(finding: dict[str, object]) -> str:
        guide_item = str(finding.get("guide_item") or "").strip()
        finding_type = str(finding.get("type") or "").upper()
        replacements = {
            "HARDCODED_SECRET": "하드코드된 인증정보",
            "PATH_TRAVERSAL": "경로 조작",
            "COMMAND_INJECTION": "OS 명령어 삽입",
            "XSS": "XSS",
            "INSECURE_RANDOM": "예측 가능한 난수 사용",
            "WEAK_HASH": "취약한 해시 알고리즘 사용",
            "DANGEROUS_FILE_UPLOAD": "위험한 파일 업로드",
            "SQL_INJECTION": "SQL 삽입",
        }
        if finding_type in replacements:
            return replacements[finding_type]
        if guide_item:
            return guide_item.split("/")[0].strip()
        return str(finding.get("type") or "취약점").replace("_", " ").title()

    @staticmethod
    def _compact_location(finding: dict[str, object]) -> str:
        file_path = str(finding.get("file") or "").strip()
        line = finding.get("line")
        if file_path and line:
            return f"{Path(file_path).name}:{line}"
        if file_path:
            return Path(file_path).name
        return "분석 대상"

    @staticmethod
    def _compact_identifier(value: str) -> str:
        value = value.strip()
        if not value:
            return ""
        return value.split(".")[-1]

    @classmethod
    def _call_chain_sink(cls, finding: dict[str, object]) -> str:
        call_chain = finding.get("call_chain")
        if not isinstance(call_chain, list):
            return ""
        function = cls._compact_identifier(str(finding.get("function") or ""))
        for raw_step in reversed(call_chain):
            raw_text = str(raw_step or "")
            invocation_matches = re.findall(
                r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(",
                raw_text,
            )
            step = (
                invocation_matches[-1].split(".")[-1]
                if invocation_matches
                else cls._compact_identifier(raw_text)
            )
            if not step or step == function:
                continue
            match = re.search(r"([A-Za-z_$][\w$]*)\s*(?:\(|$)", step)
            return match.group(1) if match else step
        return ""

    @staticmethod
    def _secret_identifier(finding: dict[str, object]) -> str:
        searchable = "\n".join(
            str(finding.get(field) or "")
            for field in ("evidence", "code_snippet", "description")
        )
        backtick_match = re.search(r"`([A-Za-z_$][\w$]{2,})`", searchable)
        if backtick_match:
            return backtick_match.group(1)
        assignment_match = re.search(
            r"\b(?:String|char\[\]|byte\[\]|var)\s+([A-Za-z_$][\w$]*(?:password|passwd|secret|token|key|apiKey)[\w$]*)\s*=",
            searchable,
            flags=re.IGNORECASE,
        )
        if assignment_match:
            return assignment_match.group(1)
        return ""

    @staticmethod
    def _build_analysis_response(analysis_id: str, result: dict[str, object]) -> dict[str, object]:
        compact_result = AnalysisService._compact_result_for_list_response(result)
        analysis = compact_result.get("analysis_result", {}) if isinstance(compact_result, dict) else {}
        return {
            "analysis_id": analysis_id,
            "analysis_result": analysis,
        }

    @staticmethod
    def _sanitize_public_result(result: dict[str, object]) -> dict[str, object]:
        sanitized = deepcopy(result)
        analysis = sanitized.get("analysis_result", {})
        if isinstance(analysis, dict):
            analysis.setdefault("target_path", None)
        return sanitized

    def _attach_finding_explanations(self, result: dict[str, object]) -> None:
        attach = getattr(self.report_generator, "attach_finding_explanations", None)
        if not callable(attach):
            return
        attach(result)

    def _attach_llm_report(self, result: dict[str, object]) -> None:
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return

        llm_available = self.report_generator.is_available
        analysis["llm_report_available"] = llm_available
        analysis["llm_model"] = self.settings.openai_model if llm_available else None
        analysis.setdefault("llm_report", None)
        analysis.setdefault("llm_report_error", None)

        if not llm_available:
            analysis["llm_report_status"] = "unavailable"
            return

        try:
            analysis["llm_report"] = self.report_generator.generate(
                result=result,
                target_path=str(analysis.get("target_path") or ""),
                repository=str(analysis.get("repository") or ""),
            )
            analysis["llm_report_status"] = "generated"
            analysis["llm_report_error"] = None
        except ContextBudgetExceededError as exc:
            analysis["llm_report"] = None
            analysis["llm_report_status"] = "skipped_context_budget_exceeded"
            analysis["llm_report_error"] = str(exc) or "LLM 리포트 입력이 context budget을 초과했습니다."
        except Exception as exc:  # noqa: BLE001 - static results should survive LLM outages
            analysis["llm_report"] = None
            analysis["llm_report_status"] = "failed"
            analysis["llm_report_error"] = str(exc) or "LLM 리포트 생성에 실패했습니다."

    def _attach_guideline_references(self, result: dict[str, object]) -> None:
        analysis = result.get("analysis_result", {})
        if not isinstance(analysis, dict):
            return

        vulnerabilities = analysis.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return

        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                continue
            references = self.guideline_repository.find_for_finding(finding)
            finding["guideline_refs"] = [reference.to_finding_payload() for reference in references]
            if references:
                finding["guideline_grounding_status"] = "matched"
                finding["analysis_status"] = "confirmed"
            else:
                finding["guideline_grounding_status"] = "missing"
                finding["analysis_status"] = "needs_review"
            finding.setdefault("llm_explanation_status", "unavailable")
            finding.setdefault("llm_explanation", None)
