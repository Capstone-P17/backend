from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from src.app.core.config import Settings
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.result_store import AnalysisResultStore


class InvalidJavaFileError(ValueError):
    pass


class InvalidGithubUrlError(ValueError):
    pass


class RepositoryCloneError(RuntimeError):
    pass


class AnalysisExecutionError(RuntimeError):
    pass


class AnalysisResultNotFoundError(LookupError):
    pass


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
        if Path(filename).suffix.lower() != ".java":
            raise InvalidJavaFileError("Java 파일만 분석 가능합니다")

        try:
            with TemporaryDirectory(dir=self.settings.workspace_root) as temp_dir:
                target_path = Path(temp_dir) / Path(filename).name
                target_path.write_bytes(content)
                result = self.analyzer_service.analyze(str(target_path))
        except InvalidJavaFileError:
            raise
        except Exception as exc:
            raise AnalysisExecutionError("파일 분석 중 오류 발생") from exc

        sanitized_result = self._sanitize_public_result(result)
        self.result_store.save(sanitized_result)
        return sanitized_result

    def analyze_repository(self, url: str | None) -> dict[str, object]:
        normalized_url = self._validate_github_url(url)

        with TemporaryDirectory(dir=self.settings.workspace_root) as temp_dir:
            repo_dir = Path(temp_dir) / "repo"
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", normalized_url, str(repo_dir)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as exc:
                raise RepositoryCloneError("레포지토리 클론 실패") from exc

            try:
                result = self.analyzer_service.analyze(
                    str(repo_dir),
                    repository=normalized_url,
                )
            except Exception as exc:
                raise AnalysisExecutionError("분석 중 오류 발생") from exc

        sanitized_result = self._sanitize_public_result(result)
        self.result_store.save(sanitized_result)
        return sanitized_result

    def get_latest_result(self) -> dict[str, object]:
        latest_result = self.result_store.get_latest()
        if latest_result is None:
            raise AnalysisResultNotFoundError("분석 결과가 없습니다")
        return latest_result

    @staticmethod
    def _validate_github_url(url: str | None) -> str:
        if url is None or not url.strip():
            raise InvalidGithubUrlError("GitHub URL을 입력해주세요")

        normalized = url.strip()
        parsed = urlparse(normalized)
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.scheme not in {"http", "https"} or parsed.netloc != "github.com" or len(path_parts) < 2:
            raise InvalidGithubUrlError("유효한 GitHub URL이 아닙니다")

        return normalized

    @staticmethod
    def _sanitize_public_result(result: dict[str, object]) -> dict[str, object]:
        sanitized = deepcopy(result)
        analysis = sanitized.get("analysis_result", {})
        if isinstance(analysis, dict):
            analysis.pop("target_path", None)
        return sanitized
