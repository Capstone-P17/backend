from __future__ import annotations

import re

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all
from src.app.services.static_analysis.rules import (
    UPLOAD_FILENAME_METHODS,
    UPLOAD_STORAGE_SINKS,
    UPLOAD_TYPES,
    UPLOAD_WEB_ROOT_TOKENS,
)
from src.app.services.static_analysis.taint_summary import (
    argument_expressions as _argument_expressions,
    initialize_summary_cache,
)

FILENAME_METHODS = UPLOAD_FILENAME_METHODS
STORAGE_SINKS = UPLOAD_STORAGE_SINKS
WEB_ROOT_TOKENS = UPLOAD_WEB_ROOT_TOKENS


def detect_dangerous_file_upload(filepath, tree, vuln_counter, project_index=None):
    """Detect uploads stored without sufficient server-side validation.

    This detector therefore looks for upload objects flowing into common Java
    storage sinks and suppresses findings only when enough controls are visible:
    extension allowlist, file signature validation, size limit, regenerated file
    name, and a non-web-root storage path.
    """

    vulnerabilities = []

    def text(node):
        return node.text.decode()

    def iter_methods(node):
        for child in iterate_all(node):
            if child.type == "method_declaration":
                yield child

    def method_declaration_name(method_node):
        name_node = method_node.child_by_field_name("name")
        return text(name_node) if name_node else None

    def parameter_names(method_node):
        params = []
        for node in iterate_all(method_node):
            if node.type != "formal_parameter":
                continue
            name_node = node.child_by_field_name("name")
            if name_node and text(name_node) not in params:
                params.append(text(name_node))
        return params

    def method_label(method_node):
        class_name = find_parent_class(method_node)
        name = method_declaration_name(method_node)
        return f"{class_name}.{name}" if class_name and name else name

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

            if "Files.copy" in STORAGE_SINKS and method_name == "copy" and object_name == "Files" and _mentions_upload_stream(args_text, upload_vars):
                sinks.append((node, "Files.copy(...)"))
                continue

            if method_name in STORAGE_SINKS and _mentions_upload_var(node_text, upload_vars):
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

    def has_sufficient_validation_before(method_node, sink_node, upload_vars):
        sink_offset = max(0, sink_node.start_byte - method_node.start_byte)
        prefix = method_node.text[:sink_offset].decode()
        if not prefix.strip():
            return False

        controls = analyze_controls(prefix, text(sink_node), upload_vars, text(method_node))
        return (
            controls["extension"]["ok"]
            and controls["signature"]["ok"]
            and controls["size"]["ok"]
            and controls["count"]["ok"]
            and controls["filename"]["ok"]
            and controls["permission"]["ok"]
            and not controls["path"]["risky"]
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

    def _has_weak_extension_check(prefix):
        lower = prefix.lower()
        return bool(
            re.search(r"\.endswith\s*\(", lower)
            or re.search(r"\.split\s*\(", lower)
            or re.search(r"\.matches\s*\(", lower)
        )

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

    def _has_signature_validation(prefix):
        lower = prefix.lower()
        return any(
            token in lower
            for token in (
                "tika.detect",
                "imageio.read",
                "magicbyte",
                "magic_byte",
                "magic bytes",
                "signature",
                "files.probecontenttype",
                "readnbytes",
                ".getinputstream().read",
            )
        )

    def _has_size_limit(prefix, upload_vars):
        lower = prefix.lower()
        if any(re.search(rf"\b{re.escape(var_name.lower())}\s*\.\s*getsize\s*\(", lower) for var_name in upload_vars):
            return True
        return any(
            token in lower
            for token in (
                "max_upload",
                "maxupload",
                "max_file",
                "maxfile",
                "maxsize",
                "max_size",
                "setmaxuploadsize",
                "setfilemax",
                "sizelimit",
                "size_limit",
            )
        )

    def _count_limit_status(prefix, upload_vars):
        lower = prefix.lower()
        handles_multi_upload = bool(
            re.search(r"\bmultipartfile\s*\[\]", lower)
            or re.search(r"\b(?:list|collection|arraylist)\s*<\s*multipartfile\s*>", lower)
            or any(var_name.lower().endswith("s") for var_name in upload_vars)
        )
        has_count_limit = any(
            token in lower
            for token in (
                "max_file_count",
                "maxfilecount",
                "max_files",
                "maxfiles",
                "file_count_limit",
                "filecountlimit",
                "maxuploadcount",
                "max_upload_count",
            )
        ) or bool(re.search(r"\.(?:length|size)\s*\(\s*\)\s*[<>=!]+", lower))

        if has_count_limit:
            return {"ok": True, "text": "파일 개수 제한: 확인됨", "chain": "파일 개수 제한 확인"}
        if not handles_multi_upload and len(upload_vars) == 1:
            return {
                "ok": True,
                "text": "파일 개수 제한: 단일 파일 업로드 파라미터로 제한된 형태입니다.",
                "chain": "파일 개수 제한: 단일 업로드",
            }
        return {"ok": False, "text": "파일 개수 제한: 미확인", "chain": "파일 개수 제한 미확인"}

    def _has_regenerated_filename(prefix, sink_text):
        lower = f"{prefix}\n{sink_text}".lower()
        return any(
            token in lower
            for token in (
                "uuid.randomuuid",
                "createtempfile",
                "secure random",
                "securerandom",
                "randomuuid",
                "savedname",
                "storedname",
                "storagefilename",
            )
        )

    def _uses_original_filename(prefix, sink_text):
        lower = f"{prefix}\n{sink_text}".lower()
        return any(method.lower() in lower for method in FILENAME_METHODS) or any(
            token in lower for token in ("originalname", "original_name", "filename")
        )

    def _permission_status(method_text):
        lower = method_text.lower()
        if any(
            token in lower
            for token in (
                "setexecutable(false",
                "setposixfilepermissions",
                "posixfilepermission",
                "owner_read",
                "owner_write",
                "noexec",
                "chmod",
                "umask",
            )
        ):
            return {"ok": True, "text": "실행권한 제거: 확인됨", "chain": "실행권한 제거 확인"}
        return {"ok": False, "text": "실행권한 제거: 미확인", "chain": "실행권한 제거 미확인"}

    def _download_validation_status(method_text):
        lower = method_text.lower()
        if "download" not in lower:
            return {
                "ok": False,
                "text": "다운로드 검증: 업로드 저장 코드에서는 확인되지 않았습니다. 다운로드 기능에서 요청 파일명 검증, 권한 확인, 경로조작 문자 차단을 별도로 확인해야 합니다.",
                "chain": "다운로드 검증 별도 확인 필요",
            }
        has_path_check = any(token in lower for token in ("normalize", "startswith", "../", "..\\\\", "canonicalpath"))
        has_auth_check = any(token in lower for token in ("authorize", "permission", "owner", "principal", "userid", "user_id"))
        if has_path_check and has_auth_check:
            return {"ok": True, "text": "다운로드 검증: 요청 파일명 경로 검증과 권한 확인이 함께 확인되었습니다.", "chain": "다운로드 검증 확인"}
        return {
            "ok": False,
            "text": "다운로드 검증: 다운로드 관련 코드가 있으나 요청 파일명 경로 검증 또는 권한 확인이 충분히 확인되지 않았습니다.",
            "chain": "다운로드 검증 부족",
        }

    def _path_status(sink_text):
        lower = sink_text.lower()
        string_literals = re.findall(r'"([^"]+)"', lower)
        path_text = "\n".join(string_literals)
        if any(token in path_text for token in WEB_ROOT_TOKENS):
            return {
                "ok": False,
                "risky": True,
                "text": "저장 경로: 웹 루트 의심 경로가 사용되었습니다.",
                "chain": "저장 경로 위험: 웹 루트 의심",
            }
        if "uploads" in path_text or "upload" in path_text:
            return {
                "ok": False,
                "risky": False,
                "text": "저장 경로: 업로드 디렉터리 사용이 확인되지만 외부 직접 접근 가능 여부는 정적 분석만으로 확정할 수 없습니다.",
                "chain": "저장 경로 불명확: 외부 접근 여부 미확정",
            }
        return {
            "ok": True,
            "risky": False,
            "text": "저장 경로: 웹 루트 의심 경로는 확인되지 않았습니다.",
            "chain": "저장 경로: 웹 루트 의심 없음",
        }

    def analyze_controls(prefix, sink_text, upload_vars, method_text):
        has_ext_allowlist = _has_extension_allowlist(prefix)
        has_weak_ext = _has_weak_extension_check(prefix)
        has_content_type = _has_content_type_allowlist(prefix)
        has_signature = _has_signature_validation(prefix)
        has_size = _has_size_limit(prefix, upload_vars)
        count = _count_limit_status(prefix, upload_vars)
        has_regenerated_name = _has_regenerated_filename(prefix, sink_text)
        uses_original_name = _uses_original_filename(prefix, sink_text)

        if has_ext_allowlist:
            extension = {"ok": True, "text": "확장자 검증: 허용목록 기반 검증이 확인되었습니다.", "chain": "확장자 allowlist 확인"}
        elif has_weak_ext:
            extension = {
                "ok": False,
                "text": "확장자 검증: endsWith/split/matches 기반 약한 검증이 확인되어 우회 가능성이 있습니다.",
                "chain": "확장자 검증 약함",
            }
        else:
            extension = {"ok": False, "text": "확장자 검증: 미확인", "chain": "확장자 검증 미확인"}

        content_type = (
            {
                "ok": False,
                "text": "Content-Type 검증: 확인됨. 다만 클라이언트 제공값은 위변조가 쉬워 단독 방어로는 부족합니다.",
                "chain": "Content-Type 검증 확인: 단독 방어 부족",
            }
            if has_content_type
            else {"ok": False, "text": "Content-Type 검증: 미확인", "chain": "Content-Type 검증 미확인"}
        )
        signature = (
            {"ok": True, "text": "파일 시그니쳐/Magic byte 검증: 확인됨", "chain": "파일 시그니쳐 검증 확인"}
            if has_signature
            else {"ok": False, "text": "파일 시그니쳐/Magic byte 검증: 미확인", "chain": "파일 시그니쳐 검증 미확인"}
        )
        size = (
            {"ok": True, "text": "파일 크기 제한: 확인됨", "chain": "파일 크기 제한 확인"}
            if has_size
            else {"ok": False, "text": "파일 크기 제한: 미확인", "chain": "파일 크기 제한 미확인"}
        )

        if has_regenerated_name:
            filename = {"ok": True, "text": "파일명 재생성: UUID/임시파일명 등 서버 생성 파일명이 확인되었습니다.", "chain": "파일명 재생성 확인"}
        elif uses_original_name:
            filename = {
                "ok": False,
                "text": "파일명 재생성: 미확인. 원본 파일명 사용 가능성이 있어 외부에서 저장 파일명을 추측할 수 있습니다.",
                "chain": "파일명 재생성 미확인",
            }
        else:
            filename = {"ok": False, "text": "파일명 재생성: 미확인", "chain": "파일명 재생성 미확인"}

        path = _path_status(f"{prefix}\n{sink_text}")
        return {
            "extension": extension,
            "content_type": content_type,
            "signature": signature,
            "size": size,
            "count": count,
            "filename": filename,
            "path": path,
            "permission": _permission_status(method_text),
            "download": _download_validation_status(method_text),
        }

    def build_evidence(upload_vars, sink_desc, controls):
        upload_names = ", ".join(f"`{var_name}`" for var_name in sorted(upload_vars))
        control_lines = "\n".join(
            f"- {controls[key]['text']}"
            for key in (
                "extension",
                "content_type",
                "signature",
                "size",
                "count",
                "filename",
                "path",
                "permission",
                "download",
            )
        )
        return (
            f"{upload_names} 업로드 파일이 `{sink_desc}` 저장 API로 전달되었습니다.\n"
            "행정안전부 소프트웨어 보안약점 진단가이드(2019.6)는 업로드 파일의 타입, 크기, 개수, 실행권한 제한과 "
            "외부에서 식별되지 않는 저장 경로/파일명 사용, 다운로드 요청 파일명 검증을 요구합니다.\n"
            f"{control_lines}"
        )

    def build_call_chain(node, upload_vars, sink_desc, controls):
        chain = []
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        chain.append(f"{', '.join(sorted(upload_vars))} → {sink_desc}")
        chain.extend(
            controls[key]["chain"]
            for key in (
                "extension",
                "content_type",
                "signature",
                "size",
                "count",
                "filename",
                "path",
                "permission",
                "download",
            )
            if not controls[key]["ok"]
        )
        return chain

    def summary_key(summary):
        return (
            summary["method_key"],
            tuple(summary["source_params"]),
            summary["sink"],
            summary["sink_line"],
            tuple(summary["missing_controls"]),
        )

    def collect_upload_summaries_for_method(method_info):
        method_node = method_info.node
        upload_vars = collect_upload_vars(method_node)
        if not upload_vars:
            return []

        summaries = []
        for sink_node, sink_desc in find_upload_sinks(method_node, upload_vars):
            sink_offset = max(0, sink_node.start_byte - method_node.start_byte)
            prefix = method_node.text[:sink_offset].decode()
            controls = analyze_controls(prefix, text(sink_node), upload_vars, text(method_node))
            if has_sufficient_validation_before(method_node, sink_node, upload_vars):
                continue
            source_params = sorted(var_name for var_name in upload_vars if var_name in method_info.parameters)
            if not source_params:
                continue
            summaries.append(
                {
                    "method_node": method_node,
                    "method_key": method_info.signature_key,
                    "method_name": method_info.method_name,
                    "method_label": method_info.key,
                    "filepath": method_info.filepath,
                    "parameters": method_info.parameters,
                    "source_params": source_params,
                    "sink": sink_desc,
                    "sink_line": sink_node.start_point[0] + 1,
                    "controls": controls,
                    "missing_controls": [
                        controls[key]["chain"]
                        for key in (
                            "extension",
                            "content_type",
                            "signature",
                            "size",
                            "count",
                            "filename",
                            "path",
                            "permission",
                            "download",
                        )
                        if not controls[key]["ok"]
                    ],
                    "chain": [method_info.key, f"{', '.join(source_params)} → {sink_desc}"],
                }
            )
        return summaries

    def get_project_upload_summaries():
        return initialize_summary_cache(
            project_index,
            cache_attr="upload_summaries_by_key",
            collect_fn=lambda method, _summaries_by_key: collect_upload_summaries_for_method(method),
            key_fn=summary_key,
            max_rounds=1,
        )

    project_summaries_by_key = get_project_upload_summaries() if project_index else None
    interprocedural_reported = set()

    def report_interprocedural_uploads(caller_method):
        if not project_index or project_summaries_by_key is None:
            return
        caller_info = project_index.resolve_method(method_label(caller_method), arity=len(parameter_names(caller_method)))
        if not caller_info:
            return
        local_types = project_index.variable_types_for(caller_info)
        upload_vars = collect_upload_vars(caller_method)
        if not upload_vars:
            return

        for node in iterate_all(caller_method):
            if node.type != "method_invocation":
                continue
            callee = project_index.resolve_invocation(caller_info, node, local_types)
            if not callee or callee.signature_key == caller_info.signature_key:
                continue
            summaries = project_summaries_by_key.get(callee.signature_key, [])
            if not summaries:
                continue
            args = _argument_expressions(node.child_by_field_name("arguments"))
            for summary in summaries:
                matched = []
                for param_name in summary["source_params"]:
                    try:
                        param_index = summary["parameters"].index(param_name)
                    except ValueError:
                        continue
                    if param_index >= len(args):
                        continue
                    arg_text = text(args[param_index])
                    matched_vars = sorted(var_name for var_name in upload_vars if re.search(rf"\b{re.escape(var_name)}\b", arg_text))
                    for var_name in matched_vars:
                        matched.append((param_name, var_name))
                if not matched:
                    continue

                report_key = (
                    caller_info.signature_key,
                    node.start_point[0],
                    callee.signature_key,
                    tuple(matched),
                )
                if report_key in interprocedural_reported:
                    continue
                interprocedural_reported.add(report_key)

                source_desc = ", ".join(f"`{var}` → `{param}`" for param, var in matched)
                controls = summary["controls"]
                boundary_desc = "클래스/파일 경계를 넘는" if summary.get("filepath") != filepath else "같은 파일 내"
                vuln_counter[0] += 1
                vulnerabilities.append(
                    {
                        "id": f"VULN-{vuln_counter[0]:03d}",
                        "type": "DANGEROUS_FILE_UPLOAD",
                        "file": filepath,
                        "line": node.start_point[0] + 1,
                        "function": find_parent_method(node),
                        "code_snippet": text(node).strip(),
                        "call_chain": [
                            method_label(caller_method),
                            f"{source_desc} → {callee.method_name}(...)",
                            *summary.get("chain", []),
                            *summary["missing_controls"],
                        ],
                        "evidence": (
                            f"업로드 파일 {source_desc}가 line {node.start_point[0] + 1}의 `{callee.method_name}(...)` 호출을 통해 "
                            f"`{summary['method_label']}`로 전달되고, line {summary['sink_line']}의 `{summary['sink']}` 저장 API까지 도달합니다.\n"
                            f"{boundary_desc} 메서드 흐름에서 다음 업로드 보안 통제가 충분히 확인되지 않았습니다.\n"
                            + "\n".join(f"- {controls[key]['text']}" for key in (
                                "extension",
                                "content_type",
                                "signature",
                                "size",
                                "count",
                                "filename",
                                "path",
                                "permission",
                                "download",
                            ))
                        ),
                        "description": "",
                    }
                )

    for method_node in iter_methods(tree.root_node):
        upload_vars = collect_upload_vars(method_node)
        if not upload_vars:
            continue

        for sink_node, sink_desc in find_upload_sinks(method_node, upload_vars):
            sink_offset = max(0, sink_node.start_byte - method_node.start_byte)
            prefix = method_node.text[:sink_offset].decode()
            controls = analyze_controls(prefix, text(sink_node), upload_vars, text(method_node))
            if has_sufficient_validation_before(method_node, sink_node, upload_vars):
                continue

            vuln_counter[0] += 1
            method_name = find_parent_method(sink_node)
            vulnerabilities.append(
                {
                    "id": f"VULN-{vuln_counter[0]:03d}",
                    "type": "DANGEROUS_FILE_UPLOAD",
                    "file": filepath,
                    "line": sink_node.start_point[0] + 1,
                    "function": method_name,
                    "code_snippet": text(sink_node).strip(),
                    "call_chain": build_call_chain(sink_node, upload_vars, sink_desc, controls),
                    "evidence": build_evidence(upload_vars, sink_desc, controls),
                    "description": "",
                }
            )
        report_interprocedural_uploads(method_node)

    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
