from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

from src.app.core.config import Settings
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.result_store import AnalysisResultStore


class InvalidJavaFileError(ValueError):
    pass


class InvalidRepositoryArchiveError(ValueError):
    pass


class RepositoryArchiveExtractionError(RuntimeError):
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

        sanitized_result = self._sanitize_public_result(result)
        self.result_store.save(sanitized_result)
        return sanitized_result

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

        sanitized_result = self._sanitize_public_result(result)
        self.result_store.save(sanitized_result)
        return sanitized_result

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

    def get_latest_result(self) -> dict[str, object]:
        latest_result = self.result_store.get_latest()
        if latest_result is None:
            raise AnalysisResultNotFoundError("분석 결과가 없습니다")
        return latest_result

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

    @staticmethod
    def _sanitize_public_result(result: dict[str, object]) -> dict[str, object]:
        sanitized = deepcopy(result)
        analysis = sanitized.get("analysis_result", {})
        if isinstance(analysis, dict):
            analysis.pop("target_path", None)
        return sanitized
