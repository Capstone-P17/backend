from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from src.app.services.static_analysis.runner import analyze_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK_ROOT = PROJECT_ROOT.parent / "security-benchmarks"
BENCHMARK_ROOT = Path(os.environ.get("P17_BENCHMARK_ROOT", DEFAULT_BENCHMARK_ROOT))
CASES_FILE = PROJECT_ROOT / "tests" / "benchmark_cases" / "official_cases.json"


def _load_cases() -> list[dict]:
    return json.loads(CASES_FILE.read_text(encoding="utf-8"))


def _case_ids() -> list[str]:
    return [case["id"] for case in _load_cases()]


@pytest.mark.parametrize("case", _load_cases(), ids=_case_ids())
def test_official_benchmark_case_current_detector_behavior(case: dict) -> None:
    sample_path = BENCHMARK_ROOT / case["relative_path"]
    if not sample_path.exists():
        pytest.skip(
            f"Official benchmark sample is not available. "
            f"Set P17_BENCHMARK_ROOT or prepare {BENCHMARK_ROOT}."
        )

    result = analyze_file(str(sample_path))
    findings = result["analysis_result"]["vulnerabilities"]
    detected = any(finding["type"] == case["vulnerability_type"] for finding in findings)

    assert detected is case["expected_detected"], (
        f"{case['id']} expected {case['vulnerability_type']} detected="
        f"{case['expected_detected']}, got {detected}. notes={case['notes']}"
    )


def test_official_benchmark_manifest_tracks_detection_outcomes() -> None:
    cases = _load_cases()
    outcomes = {
        "true_positive": [
            case for case in cases if case["ground_truth_vulnerable"] and case["expected_detected"]
        ],
        "true_negative": [
            case
            for case in cases
            if not case["ground_truth_vulnerable"] and not case["expected_detected"]
        ],
        "known_false_negative": [
            case
            for case in cases
            if case["ground_truth_vulnerable"] and not case["expected_detected"]
        ],
        "expected_false_positive": [
            case
            for case in cases
            if not case["ground_truth_vulnerable"] and case["expected_detected"]
        ],
    }

    assert outcomes["true_positive"]
    assert outcomes["true_negative"]
    assert not outcomes["expected_false_positive"]
