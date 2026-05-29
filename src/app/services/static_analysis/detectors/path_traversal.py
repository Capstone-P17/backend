from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI", "getPathInfo"]
FILE_TYPES = ["File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"]


def detect_path_traversal(filepath, tree, vuln_counter):
    vulnerabilities = []
    tainted_vars = {}

    def contains_input_method(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in INPUT_METHODS:
                return True
        for child in node.children:
            if contains_input_method(child):
                return True
        return False

    def collect_tainted_vars(node):
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node and contains_input_method(value_node):
                        tainted_vars[name_node.text.decode()] = {
                            "line": name_node.start_point[0] + 1,
                            "code": node.text.decode().strip(),
                        }
        for child in node.children:
            collect_tainted_vars(child)

    def build_evidence(tainted_var, sink_desc):
        source = tainted_vars.get(tainted_var, {})
        source_line = source.get("line")
        source_code = source.get("code")
        source_desc = f"line {source_line}에서 사용자 입력이 `{tainted_var}` 변수에 저장되었습니다"
        if source_code:
            source_desc += f": `{source_code}`"
        return (
            f"{source_desc}. 이후 `{tainted_var}` 값이 `{sink_desc}` 경로 생성/파일 접근 API에 전달되었습니다. "
            "정규화(normalize) 후 기준 디렉터리 내부 여부(startsWith)를 확인하는 방어 로직은 탐지되지 않았습니다."
        )

    def build_confidence_reason(tainted_var, sink_desc):
        source = tainted_vars.get(tainted_var, {})
        source_line = source.get("line")
        return (
            f"line {source_line}의 요청 입력 변수 `{tainted_var}` 값이 파일 경로 API `{sink_desc}`까지 전달되는 흐름이 확인되어 HIGH로 판단했습니다. "
            "분석 범위에서 `normalize()`, `toRealPath()`, `startsWith(baseDir)` 같은 기준 디렉터리 검증은 확인되지 않았습니다."
        )

    def report(node, tainted_var, sink_desc):
        vuln_counter[0] += 1
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        chain = []
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        chain.append(f"req → {tainted_var} → {sink_desc}")
        vulnerabilities.append(
            {
                "id": f"VULN-{vuln_counter[0]:03d}",
                "type": "PATH_TRAVERSAL",
                "severity": "HIGH",
                "cvss": get_cvss("PATH_TRAVERSAL", "HIGH"),
                "file": filepath,
                "line": node.start_point[0] + 1,
                "function": method_name,
                "code_snippet": node.text.decode().strip(),
                "call_chain": chain,
                "description": "",
                "evidence": build_evidence(tainted_var, sink_desc),
                "confidence_reason": build_confidence_reason(tainted_var, sink_desc),
            }
        )

    def find_path_traversal(node):
        # new File(tainted), new FileInputStream(tainted) 등
        if node.type == "object_creation_expression":
            text = node.text.decode()
            for file_type in FILE_TYPES:
                if f"new {file_type}(" in text:
                    for var in tainted_vars:
                        if var in text:
                            report(node, var, f"new {file_type}(...)")
                            return  # 같은 노드에서 중복 탐지 방지

        # Paths.get(tainted) 또는 Path.of(tainted)
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            obj_node = node.child_by_field_name("object")
            args_node = node.child_by_field_name("arguments")
            if name_node and obj_node and args_node:
                method = name_node.text.decode()
                obj = obj_node.text.decode()
                if method in ("get", "of") and obj in ("Paths", "Path"):
                    args_text = args_node.text.decode()
                    for var in tainted_vars:
                        if var in args_text:
                            report(node, var, f"{obj}.{method}(...)")
                            return

        for child in node.children:
            find_path_traversal(child)

    collect_tainted_vars(tree.root_node)
    find_path_traversal(tree.root_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
