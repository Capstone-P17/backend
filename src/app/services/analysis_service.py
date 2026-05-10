from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

import httpx

from src.app.core.config import Settings
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.result_store import AnalysisResultStore

_GITHUB_REPO_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?$"
)
_GITHUB_ARCHIVE_URL = "https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
_DEFAULT_BRANCHES = ("main", "master")
_CLONE_TIMEOUT_SECONDS = 60


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


class AnalysisResultNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class PreparedAnalysisTarget:
    target_path: str
    display_target_path: str
    repository: str = ""


class AnalysisService:
    """Application service that matches the public analysis API contract."""

    def __init__(
        self,
        settings: Settings,
        analyzer_service: AnalyzerService,
        result_store: AnalysisResultStore,
    ) -> None:
        self.settings = settings
        self.analyzer_service = analyzer_service
        self.result_store = result_store

    def analyze_uploaded_file(self, filename: str, content: bytes) -> dict[str, object]:
        try:
            with self.prepare_uploaded_file(filename=filename, content=content) as prepared_target:
                result = self.analyzer_service.analyze(prepared_target.target_path)
        except InvalidJavaFileError:
            raise
        except Exception as exc:
            raise AnalysisExecutionError("파일 분석 중 오류 발생") from exc

        return self._save_public_result(result)

    @contextmanager
    def prepare_uploaded_file(self, filename: str, content: bytes) -> Iterator[PreparedAnalysisTarget]:
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

    def analyze_uploaded_repository(self, filename: str, content: bytes) -> dict[str, object]:
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
        except Exception as exc:
            raise AnalysisExecutionError("업로드한 레포지토리 분석 중 오류 발생") from exc

        return self._save_public_result(result)

    @contextmanager
    def prepare_uploaded_repository(self, filename: str, content: bytes) -> Iterator[PreparedAnalysisTarget]:
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

    def analyze_github_repository(self, url: str) -> dict[str, object]:
        try:
            with self.prepare_github_repository(url=url) as prepared_target:
                result = self.analyzer_service.analyze(
                    prepared_target.target_path,
                    repository=prepared_target.repository,
                )
        except (InvalidGitHubRepositoryError, GitHubRepositoryCloneError, InvalidRepositoryArchiveError):
            raise
        except Exception as exc:
            raise AnalysisExecutionError("GitHub 레포지토리 분석 중 오류 발생") from exc

        return self._save_public_result(result)

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
                repository=repo,
            )

    def _download_github_archive(self, owner: str, repo: str) -> tuple[bytes, str]:
        """GitHub archive zip을 다운로드합니다. main 브랜치를 먼저 시도하고 실패 시 master를 시도합니다."""
        last_exc: Exception | None = None
        for branch in _DEFAULT_BRANCHES:
            archive_url = _GITHUB_ARCHIVE_URL.format(owner=owner, repo=repo, branch=branch)
            try:
                with httpx.Client(follow_redirects=True, timeout=_CLONE_TIMEOUT_SECONDS) as client:
                    response = client.get(archive_url)
                if response.status_code == 200:
                    return response.content, branch
                if response.status_code == 404:
                    continue
                raise GitHubRepositoryCloneError(
                    f"GitHub 레포지토리 다운로드 실패 (HTTP {response.status_code})"
                )
            except httpx.TimeoutException as exc:
                raise GitHubRepositoryCloneError(
                    "GitHub 레포지토리 다운로드 시간이 초과되었습니다"
                ) from exc
            except httpx.RequestError as exc:
                last_exc = exc

        if last_exc:
            raise GitHubRepositoryCloneError(
                "GitHub 레포지토리에 연결할 수 없습니다"
            ) from last_exc
        raise InvalidGitHubRepositoryError(
            f"레포지토리를 찾을 수 없습니다: github.com/{owner}/{repo}"
        )

    def get_latest_result(self) -> dict[str, object]:
        latest_result = self.result_store.get_latest()
        if latest_result is None:
            raise AnalysisResultNotFoundError("분석 결과가 없습니다")
        analysis_id, result = latest_result
        return self._build_analysis_response(analysis_id, result)

    def get_result(self, analysis_id: str) -> dict[str, object]:
        result = self.result_store.get(analysis_id)
        if result is None:
            raise AnalysisResultNotFoundError("분석 결과를 찾을 수 없습니다")
        return self._build_analysis_response(analysis_id, result)

    def get_file_result(self, analysis_id: str, file_id: str) -> dict[str, object]:
        response = self.get_result(analysis_id)
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

    def list_results(self, limit: int = 20) -> list[dict[str, object]]:
        return self.result_store.list_results(limit=limit)

    @staticmethod
    def _validate_repository_archive_filename(filename: str) -> None:
        allowed_suffixes = (".zip",)
        if not filename.lower().endswith(allowed_suffixes):
            raise InvalidRepositoryArchiveError("ZIP 형식의 레포지토리 압축 파일만 업로드 가능합니다")

    def _extract_repository_archive(self, archive_path: Path, extract_root: Path) -> None:
        try:
            with ZipFile(archive_path) as archive_file:
                members = archive_file.infolist()
                if not members:
                    raise InvalidRepositoryArchiveError("압축 파일이 비어 있습니다")
                for member in members:
                    self._validate_archive_member_path(member.filename)
                archive_file.extractall(extract_root)
        except BadZipFile as exc:
            raise InvalidRepositoryArchiveError("유효한 ZIP 파일이 아닙니다") from exc
        except InvalidRepositoryArchiveError:
            raise
        except OSError as exc:
            raise RepositoryArchiveExtractionError("레포지토리 압축 해제 실패") from exc

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

    def _save_public_result(self, result: dict[str, object]) -> dict[str, object]:
        sanitized_result = self._sanitize_public_result(result)
        analysis_id = self.result_store.save(sanitized_result)
        return self._build_analysis_response(analysis_id, sanitized_result)

    @staticmethod
    def _build_analysis_response(analysis_id: str, result: dict[str, object]) -> dict[str, object]:
        analysis = result.get("analysis_result", {}) if isinstance(result, dict) else {}
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
