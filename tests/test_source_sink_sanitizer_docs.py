from __future__ import annotations

from pathlib import Path

from src.app.services.static_analysis.detectors.metadata import DETECTOR_METADATA
from src.app.services.static_analysis import rules


DOC_PATH = Path(__file__).resolve().parents[1] / "docs" / "source-sink-sanitizer-model.md"


DETECTOR_DOC_LABELS = {
    "SQL_INJECTION": "SQL Injection",
    "XSS": "XSS",
    "HARDCODED_SECRET": "Hardcoded Secret",
    "PATH_TRAVERSAL": "Path Traversal",
    "COMMAND_INJECTION": "Command Injection",
    "INSECURE_RANDOM": "Insecure Random",
    "WEAK_HASH": "Weak Hash",
    "DANGEROUS_FILE_UPLOAD": "Dangerous File Upload",
}


def test_source_sink_sanitizer_doc_lists_all_detector_types() -> None:
    doc = DOC_PATH.read_text(encoding="utf-8")

    assert set(DETECTOR_DOC_LABELS) == set(DETECTOR_METADATA)
    for label in DETECTOR_DOC_LABELS.values():
        assert label in doc


def test_source_sink_sanitizer_doc_mentions_representative_rule_constants() -> None:
    doc = DOC_PATH.read_text(encoding="utf-8")

    representative_terms = [
        rules.HTTP_REQUEST_SOURCE_METHODS[0],
        rules.SPRING_MVC_SOURCE_ANNOTATIONS[0],
        rules.SQL_EXEC_METHODS[0],
        rules.SQL_TEMPLATE_METHODS[0],
        rules.XSS_SANITIZER_METHODS[0],
        rules.PATH_NORMALIZATION_METHODS[0],
        rules.COMMAND_ALLOWLIST_METHODS[0],
        rules.UPLOAD_STORAGE_SINKS[0],
        rules.WEAK_HASH_ALGORITHMS[0],
        rules.SECRET_KEYWORDS[0],
        rules.SECURITY_RANDOM_CONTEXT_KEYWORDS[0],
    ]

    for term in representative_terms:
        assert term in doc
