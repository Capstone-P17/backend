from __future__ import annotations

from pathlib import Path
from typing import Any

from src.analyzer.analyzer import analyze_directory, analyze_file


class AnalyzerService:
    """Adapter around the existing static analyzer module."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def analyze(self, target_path: str, repository: str = "") -> dict[str, Any]:
        resolved_target = self.resolve_target(target_path)

        if resolved_target.is_file():
            result = analyze_file(str(resolved_target))
        else:
            result = analyze_directory(str(resolved_target), repository=repository)

        return self._normalize_result(
            result=result,
            resolved_target=resolved_target,
            repository=repository,
        )

    def resolve_target(self, target_path: str) -> Path:
        candidate = Path(target_path)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate

        resolved = candidate.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Analysis target does not exist: {target_path}")

        if resolved != self.workspace_root and self.workspace_root not in resolved.parents:
            raise ValueError("Analysis target must stay inside the project workspace.")

        return resolved

    def _normalize_result(
        self,
        result: dict[str, Any],
        resolved_target: Path,
        repository: str,
    ) -> dict[str, Any]:
        analysis = result["analysis_result"]
        analysis["repository"] = repository or analysis.get("repository", "")
        analysis["target_path"] = self._display_path(resolved_target)

        for vulnerability in analysis.get("vulnerabilities", []):
            file_path = Path(vulnerability["file"])
            vulnerability["file"] = self._display_vulnerability_path(
                vulnerability_path=file_path,
                target_root=resolved_target,
            )

        return result

    def _display_path(self, path: Path) -> str:
        resolved = path.resolve()
        try:
            return str(resolved.relative_to(self.workspace_root))
        except ValueError:
            return str(resolved)

    @staticmethod
    def _display_vulnerability_path(vulnerability_path: Path, target_root: Path) -> str:
        resolved_vulnerability = vulnerability_path.resolve()
        resolved_target = target_root.resolve()

        if resolved_target.is_file():
            return resolved_vulnerability.name

        try:
            return str(resolved_vulnerability.relative_to(resolved_target))
        except ValueError:
            return resolved_vulnerability.name
