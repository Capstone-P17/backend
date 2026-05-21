from __future__ import annotations

import re

from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

UPLOAD_TYPES = ("MultipartFile", "Part", "FileItem")
FILENAME_METHODS = ("getOriginalFilename", "getSubmittedFileName")


def detect_dangerous_file_upload(filepath, tree, vuln_counter):
    """Detect uploads stored without an allowlist validation step.

    CWE-434 is only meaningful when an uploaded file reaches a persistence API.
    This detector therefore looks for upload objects flowing into common Java
    storage sinks and suppresses findings when extension or content-type
    allowlist validation is visible before the sink.
    """

    vulnerabilities = []

    def text(node):
        return node.text.decode()

    def iter_methods(node):
        if node.type == "method_declaration":
            yield node
            return
        for child in node.children:
            yield from iter_methods(child)

    def collect_upload_vars(method_node):
        method_text = text(method_node)
        pattern = r"\b(?:" + "|".join(UPLOAD_TYPES) + r")\s+(?:\[\]\s*)?([A-Za-z_][A-Za-z0-9_]*)"
        return set(re.findall(pattern, method_text))

    def find_upload_sinks(method_node, upload_vars):
        sinks = []
        for node in iterate_all(method_node):
            if node.type != "method_invocation":
                continue

            name_node = node.child_by_field_name("name")
            if not name_node:
                continue

            method_name = text(name_node)
            object_node = node.child_by_field_name("object")
            object_name = text(object_node) if object_node else ""
            node_text = text(node)
            args_node = node.child_by_field_name("arguments")
            args_text = text(args_node) if args_node else ""

            if method_name == "transferTo" and (object_name in upload_vars or _mentions_upload_var(node_text, upload_vars)):
                sinks.append((node, "MultipartFile.transferTo(...)"))
                continue

            if method_name == "write" and object_name in upload_vars:
                sinks.append((node, "Part.write(...)"))
                continue

            if method_name == "copy" and object_name == "Files" and _mentions_upload_stream(args_text, upload_vars):
                sinks.append((node, "Files.copy(...)"))
                continue

            if method_name in {"copyInputStreamToFile", "copyToFile"} and _mentions_upload_var(node_text, upload_vars):
                sinks.append((node, f"{method_name}(...)"))

        return sinks

    def _mentions_upload_var(value, upload_vars):
        return any(re.search(rf"\b{re.escape(var_name)}\b", value) for var_name in upload_vars)

    def _mentions_upload_stream(value, upload_vars):
        return any(
            re.search(rf"\b{re.escape(var_name)}\s*\.\s*getInputStream\s*\(", value)
            or re.search(rf"\b{re.escape(var_name)}\b", value)
            for var_name in upload_vars
        )

    def has_validation_before(method_node, sink_node, upload_vars):
        sink_offset = max(0, sink_node.start_byte - method_node.start_byte)
        prefix = method_node.text[:sink_offset].decode()
        if not prefix.strip():
            return False

        return (
            _has_extension_allowlist(prefix)
            or _has_content_type_allowlist(prefix)
            or _has_upload_validator_call(prefix, upload_vars)
        )

    def _has_extension_allowlist(prefix):
        lower = prefix.lower()
        has_filename_context = any(method.lower() in lower for method in FILENAME_METHODS) or any(
            token in lower for token in ("extension", "filenameutils.getextension", "fileextension")
        )
        has_ext_var = re.search(r"\bext\b", lower) is not None
        if not (has_filename_context or has_ext_var):
            return False

        if re.search(r"\.endswith\s*\(\s*\"\\?.", lower) or re.search(r"\.matches\s*\(", lower):
            return True

        return re.search(
            r"\b(?:allowed|allowlist|allow_list|whitelist|white_list|permitted|valid)[a-z0-9_]*\s*\.contains\s*\(",
            lower,
        ) is not None

    def _has_content_type_allowlist(prefix):
        lower = prefix.lower()
        if not any(token in lower for token in ("getcontenttype", "probecontenttype", "contenttype")):
            return False

        if re.search(r"\bcontenttype\s*\.startswith\s*\(\s*\"(?:image/|application/pdf|text/plain)", lower):
            return True
        if re.search(r"\bcontenttype\s*\.equals(?:ignorecase)?\s*\(", lower):
            return True
        return re.search(
            r"\b(?:allowed|allowlist|allow_list|whitelist|white_list|permitted|valid)[a-z0-9_]*\s*\.contains\s*\(\s*contenttype",
            lower,
        ) is not None

    def _has_upload_validator_call(prefix, upload_vars):
        validator_pattern = re.compile(
            r"\b(?:validate|verify|check|ensure|isAllowed|isValid)[A-Za-z0-9_]*(?:File|Upload|Extension|ContentType|Type)\s*\(",
        )
        if not validator_pattern.search(prefix):
            return False

        lower = prefix.lower()
        if any(var_name.lower() in lower for var_name in upload_vars):
            return True
        return any(token in lower for token in ("filename", "extension", "contenttype", "upload"))

    def build_evidence(upload_vars, sink_desc):
        upload_names = ", ".join(f"`{var_name}`" for var_name in sorted(upload_vars))
        return (
            f"{upload_names} 업로드 파일이 `{sink_desc}` 저장 API로 전달되지만, "
            "저장 전에 확장자 또는 Content-Type 허용목록 검증이 확인되지 않았습니다."
        )

    def build_call_chain(node, upload_vars, sink_desc):
        chain = []
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        chain.append(f"{', '.join(sorted(upload_vars))} → {sink_desc}")
        chain.append("검증 없음: 확장자/Content-Type allowlist 미확인")
        return chain

    for method_node in iter_methods(tree.root_node):
        upload_vars = collect_upload_vars(method_node)
        if not upload_vars:
            continue

        for sink_node, sink_desc in find_upload_sinks(method_node, upload_vars):
            if has_validation_before(method_node, sink_node, upload_vars):
                continue

            vuln_counter[0] += 1
            method_name = find_parent_method(sink_node)
            vulnerabilities.append(
                {
                    "id": f"VULN-{vuln_counter[0]:03d}",
                    "type": "DANGEROUS_FILE_UPLOAD",
                    "severity": "HIGH",
                    "cvss": get_cvss("DANGEROUS_FILE_UPLOAD", "HIGH"),
                    "file": filepath,
                    "line": sink_node.start_point[0] + 1,
                    "function": method_name,
                    "code_snippet": text(sink_node).strip(),
                    "call_chain": build_call_chain(sink_node, upload_vars, sink_desc),
                    "evidence": build_evidence(upload_vars, sink_desc),
                    "description": "",
                }
            )

    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
