from __future__ import annotations

import os
import re
from datetime import datetime

from loguru import logger

from src.app.services.static_analysis.call_graph import build_call_graph
from src.app.services.static_analysis.detectors.command_injection import detect_command_injection
from src.app.services.static_analysis.detectors.file_upload import detect_dangerous_file_upload
from src.app.services.static_analysis.detectors.insecure_random import detect_insecure_random
from src.app.services.static_analysis.detectors.mybatis_xml import (
    detect_mybatis_xml_sql_injection,
    is_mybatis_mapper_xml,
)
from src.app.services.static_analysis.detectors.path_traversal import detect_path_traversal
from src.app.services.static_analysis.detectors.secrets import detect_hardcoded_secrets
from src.app.services.static_analysis.detectors.sql_injection import detect_sql_injection
from src.app.services.static_analysis.detectors.weak_hash import detect_weak_hash
from src.app.services.static_analysis.detectors.xss import detect_xss
from src.app.services.static_analysis.parser import parse_file
from src.app.services.static_analysis.project_index import build_project_index
from src.app.services.static_analysis.scoring import build_summary

_CONTEXT_RADIUS = 3
_MAX_CONTEXT_LINES = (_CONTEXT_RADIUS * 2) + 1


def analyze_file(filepath):
    logger.bind(component="static.runner", file=filepath).info("file_analysis_started file={}", filepath)
    if filepath.lower().endswith(".xml"):
        return _analyze_xml_file(filepath)

    tree, code = parse_file(filepath)
    vuln_counter = [0]

    vulnerabilities = []
    vulnerabilities += detect_hardcoded_secrets(filepath, tree, vuln_counter)
    vulnerabilities += detect_sql_injection(filepath, tree, vuln_counter)
    vulnerabilities += detect_xss(filepath, tree, vuln_counter)
    vulnerabilities += detect_path_traversal(filepath, tree, vuln_counter)
    vulnerabilities += detect_command_injection(filepath, tree, vuln_counter)
    vulnerabilities += detect_insecure_random(filepath, tree, vuln_counter)
    vulnerabilities += detect_weak_hash(filepath, tree, vuln_counter)
    vulnerabilities += detect_dangerous_file_upload(filepath, tree, vuln_counter)
    _attach_code_context(vulnerabilities, code)
    logger.bind(component="static.runner", file=filepath).info(
        "file_analysis_finished file={} findings={}",
        filepath,
        len(vulnerabilities),
    )

    return {
        "analysis_result": {
            "repository": "",
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": 1,
            "vulnerabilities": vulnerabilities,
            "call_graph": build_call_graph(tree),
            "summary": build_summary(vulnerabilities, [filepath]),
        }
    }


def analyze_directory(directory, repository=""):
    logger.bind(component="static.runner", repository=repository or "-", directory=directory).info(
        "directory_analysis_started directory={} repository={}",
        directory,
        repository,
    )
    all_vulnerabilities = []
    all_call_graph = {}
    analyzed_files = []
    parsed_files = []
    xml_files = []
    vuln_counter = [0]

    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            lowered_filename = filename.lower()
            if lowered_filename.endswith(".java"):
                analyzed_files.append(filepath)
                parsed_files.append((filepath, *parse_file(filepath)))
                continue
            if lowered_filename.endswith(".xml"):
                try:
                    xml_code = _read_text_file(filepath)
                except UnicodeDecodeError:
                    logger.bind(component="static.runner", file=filepath).debug(
                        "xml_file_skipped_non_utf8 file={}",
                        filepath,
                    )
                    continue
                if is_mybatis_mapper_xml(xml_code):
                    analyzed_files.append(filepath)
                    xml_files.append((filepath, xml_code))

    project_index = build_project_index(parsed_files)

    for filepath, tree, code in parsed_files:
        logger.bind(component="static.runner", file=filepath).debug("java_file_analysis_started file={}", filepath)
        file_vulnerabilities = []
        file_vulnerabilities += detect_hardcoded_secrets(filepath, tree, vuln_counter)
        file_vulnerabilities += detect_sql_injection(filepath, tree, vuln_counter, project_index=project_index)
        file_vulnerabilities += detect_xss(filepath, tree, vuln_counter, project_index=project_index)
        file_vulnerabilities += detect_path_traversal(filepath, tree, vuln_counter, project_index=project_index)
        file_vulnerabilities += detect_command_injection(filepath, tree, vuln_counter, project_index=project_index)
        file_vulnerabilities += detect_insecure_random(filepath, tree, vuln_counter)
        file_vulnerabilities += detect_weak_hash(filepath, tree, vuln_counter)
        file_vulnerabilities += detect_dangerous_file_upload(filepath, tree, vuln_counter, project_index=project_index)
        _attach_code_context(file_vulnerabilities, code)
        all_vulnerabilities += file_vulnerabilities
        all_call_graph.update(build_call_graph(tree))
        logger.bind(component="static.runner", file=filepath).debug(
            "java_file_analysis_finished file={} findings={}",
            filepath,
            len(file_vulnerabilities),
        )

    for filepath, code in xml_files:
        logger.bind(component="static.runner", file=filepath).debug("xml_file_analysis_started file={}", filepath)
        file_vulnerabilities = detect_mybatis_xml_sql_injection(filepath, code, vuln_counter)
        _attach_code_context(file_vulnerabilities, code)
        all_vulnerabilities += file_vulnerabilities
        logger.bind(component="static.runner", file=filepath).debug(
            "xml_file_analysis_finished file={} findings={}",
            filepath,
            len(file_vulnerabilities),
        )

    logger.bind(component="static.runner", repository=repository or "-", directory=directory).info(
        "directory_analysis_finished directory={} files={} findings={}",
        directory,
        len(analyzed_files),
        len(all_vulnerabilities),
    )
    return {
        "analysis_result": {
            "repository": repository,
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": len(analyzed_files),
            "vulnerabilities": all_vulnerabilities,
            "call_graph": all_call_graph,
            "summary": build_summary(all_vulnerabilities, analyzed_files),
        }
    }


def _attach_code_context(vulnerabilities, source_code: str) -> None:
    for vulnerability in vulnerabilities:
        line = vulnerability.get("line")
        if not isinstance(line, int):
            continue
        context = _build_line_context(
            source_code,
            target_line=line,
            has_function=bool(vulnerability.get("function")),
        )
        if context:
            vulnerability["code_snippet"] = context
        _attach_call_chain_details(vulnerability, source_code)


def _analyze_xml_file(filepath: str) -> dict:
    code = _read_text_file(filepath)
    vuln_counter = [0]
    vulnerabilities = detect_mybatis_xml_sql_injection(filepath, code, vuln_counter)
    _attach_code_context(vulnerabilities, code)
    logger.bind(component="static.runner", file=filepath).info(
        "file_analysis_finished file={} findings={}",
        filepath,
        len(vulnerabilities),
    )
    return {
        "analysis_result": {
            "repository": "",
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": 1 if is_mybatis_mapper_xml(code) else 0,
            "vulnerabilities": vulnerabilities,
            "call_graph": {},
            "summary": build_summary(vulnerabilities, [filepath] if is_mybatis_mapper_xml(code) else []),
        }
    }


def _read_text_file(filepath: str) -> str:
    with open(filepath, encoding="utf-8") as source_file:
        return source_file.read()


def _attach_call_chain_details(vulnerability, source_code: str) -> None:
    call_chain = vulnerability.get("call_chain")
    if not isinstance(call_chain, list) or not call_chain:
        vulnerability.setdefault("call_chain_details", [])
        return

    details = []
    source_lines = source_code.splitlines()
    file_path = vulnerability.get("file")
    function = vulnerability.get("function")
    finding_line = vulnerability.get("line")
    for index, raw_label in enumerate(call_chain):
        label = str(raw_label).strip()
        if not label:
            continue
        kind = _infer_call_chain_kind(index=index, total=len(call_chain), label=label, function=function)
        line = _find_call_chain_line(
            source_lines=source_lines,
            label=label,
            kind=kind,
            function=function,
            fallback_line=finding_line if index == len(call_chain) - 1 else None,
        )
        details.append(
            {
                "label": label,
                "kind": kind,
                "file": file_path,
                "line": line,
                "function": function,
            }
        )
    vulnerability["call_chain_details"] = details


def _infer_call_chain_kind(*, index: int, total: int, label: str, function: object) -> str:
    compact_function = str(function or "").strip()
    if index == 0 and compact_function and label.endswith(f".{compact_function}"):
        return "function"
    if index == total - 1:
        return "sink"
    lowered = label.lower()
    if any(token in lowered for token in ("검증", "확인", "미확인", "control", "validation", "limit")):
        return "control"
    return "data"


def _find_call_chain_line(
    *,
    source_lines: list[str],
    label: str,
    kind: str,
    function: object,
    fallback_line: object = None,
) -> int | None:
    search_terms = _call_chain_search_terms(label, kind=kind, function=function)
    for term in search_terms:
        pattern = re.compile(rf"(?<![\w$]){re.escape(term)}\s*(?:\(|=|;|,|\\.|$)")
        for line_no, line_text in enumerate(source_lines, start=1):
            if pattern.search(line_text):
                return line_no

    if isinstance(fallback_line, int):
        return fallback_line
    return None


def _call_chain_search_terms(label: str, *, kind: str, function: object) -> list[str]:
    terms = []
    compact_function = str(function or "").strip()
    if kind == "function" and compact_function:
        terms.append(compact_function)
    if "." in label:
        terms.append(label.rsplit(".", 1)[-1])
    terms.append(label)
    return [term for index, term in enumerate(terms) if term and term not in terms[:index]]


def _build_line_context(source_code: str, *, target_line: int, has_function: bool) -> str:
    lines = source_code.splitlines()
    if target_line < 1 or target_line > len(lines):
        return ""

    if has_function:
        start = max(1, target_line - _CONTEXT_RADIUS)
        end = min(len(lines), target_line + _CONTEXT_RADIUS)
    else:
        # Field-level findings can sit next to unrelated secrets. Keep structural
        # context before the declaration, but do not pull in following fields that
        # were not part of this finding.
        start = max(1, target_line - 1)
        end = target_line

    if end - start + 1 > _MAX_CONTEXT_LINES:
        end = start + _MAX_CONTEXT_LINES - 1

    width = len(str(end))
    rendered = []
    for line_no in range(start, end + 1):
        marker = ">" if line_no == target_line else " "
        rendered.append(f"{marker} {line_no:>{width}} | {lines[line_no - 1]}")
    return "\n".join(rendered)
