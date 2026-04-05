from __future__ import annotations

from typing import Any


class AnalysisResultStore:
    """In-memory store for the most recent analysis result."""

    def __init__(self) -> None:
        self._latest_result: dict[str, Any] | None = None

    def save(self, result: dict[str, Any]) -> None:
        self._latest_result = self._clone(result)

    def get_latest(self) -> dict[str, Any] | None:
        if self._latest_result is None:
            return None
        return self._clone(self._latest_result)

    @staticmethod
    def _clone(result: dict[str, Any]) -> dict[str, Any]:
        analysis = result.get("analysis_result", {})
        return {
            "analysis_result": {
                **analysis,
                "vulnerabilities": [dict(item) for item in analysis.get("vulnerabilities", [])],
                "call_graph": {
                    key: list(value)
                    for key, value in analysis.get("call_graph", {}).items()
                },
                "summary": dict(analysis.get("summary", {})),
            }
        }
