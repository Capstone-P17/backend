from __future__ import annotations

import re

from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

UPLOAD_TYPES = ("MultipartFile", "Part", "FileItem")
FILENAME_METHODS = ("getOriginalFilename", "getSubmittedFileName")
WEB_ROOT_TOKENS = (
    "src/main/resources/static",
    "resources/static",
    "webapp",
    "public",
    "wwwroot",
    "htdocs",
)


def detect_dangerous_file_upload(filepath, tree, vuln_counter):
    """Detect uploads stored without sufficient server-side validation.

    CWE-434 is only meaningful when an uploaded file reaches a persistence API.
    This detector therefore looks for upload objects flowing into common Java
    storage sinks and suppresses findings only when enough controls are visible:
    extension allowlist, file signature validation, size limit, regenerated file
    name, and a non-web-root storage path.
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

    def has_sufficient_validation_before(method_node, sink_node, upload_vars):
        sink_offset = max(0, sink_node.start_byte - method_node.start_byte)
        prefix = method_node.text[:sink_offset].decode()
        if not prefix.strip():
            return False

        controls = analyze_controls(prefix, text(sink_node), upload_vars)
        return (
            controls["extension"]["ok"]
            and controls["signature"]["ok"]
            and controls["size"]["ok"]
            and controls["filename"]["ok"]
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

    def analyze_controls(prefix, sink_text, upload_vars):
        has_ext_allowlist = _has_extension_allowlist(prefix)
        has_weak_ext = _has_weak_extension_check(prefix)
        has_content_type = _has_content_type_allowlist(prefix)
        has_signature = _has_signature_validation(prefix)
        has_size = _has_size_limit(prefix, upload_vars)
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
            "filename": filename,
            "path": path,
        }

    def build_evidence(upload_vars, sink_desc, controls):
        upload_names = ", ".join(f"`{var_name}`" for var_name in sorted(upload_vars))
        control_lines = "\n".join(
            f"- {controls[key]['text']}"
            for key in ("extension", "content_type", "signature", "size", "filename", "path")
        )
        return (
            f"{upload_names} 업로드 파일이 `{sink_desc}` 저장 API로 전달되었습니다.\n"
            "행정안전부 소프트웨어 보안약점 진단가이드(2019.6)는 업로드 파일의 타입, 크기, 실행권한 제한과 "
            "외부에서 식별되지 않는 저장 경로/파일명 사용을 요구합니다.\n"
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
            for key in ("extension", "content_type", "signature", "size", "filename", "path")
            if not controls[key]["ok"]
        )
        return chain

    for method_node in iter_methods(tree.root_node):
        upload_vars = collect_upload_vars(method_node)
        if not upload_vars:
            continue

        for sink_node, sink_desc in find_upload_sinks(method_node, upload_vars):
            sink_offset = max(0, sink_node.start_byte - method_node.start_byte)
            prefix = method_node.text[:sink_offset].decode()
            controls = analyze_controls(prefix, text(sink_node), upload_vars)
            if has_sufficient_validation_before(method_node, sink_node, upload_vars):
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
                    "call_chain": build_call_chain(sink_node, upload_vars, sink_desc, controls),
                    "evidence": build_evidence(upload_vars, sink_desc, controls),
                    "description": "",
                }
            )

    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
