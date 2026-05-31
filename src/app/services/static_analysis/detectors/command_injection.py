from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]


def detect_command_injection(filepath, tree, vuln_counter):
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
            f"{source_desc}. 이후 `{tainted_var}` 값이 `{sink_desc}` 운영체제 명령 실행 지점에 전달되었습니다. "
            "명령 allowlist, 고정 명령어 사용, 또는 인자 분리 기반 검증 로직은 탐지되지 않았습니다."
        )

    def build_confidence_reason(tainted_var, sink_desc):
        source = tainted_vars.get(tainted_var, {})
        source_line = source.get("line")
        return (
            f"line {source_line}의 요청 입력 변수 `{tainted_var}` 값이 운영체제 명령 실행 API `{sink_desc}`까지 전달되는 흐름이 확인되어 HIGH로 판단했습니다. "
            "정적 분석 범위에서 허용 명령 목록, 고정 명령어, 인자 분리 또는 쉘 메타문자 검증은 확인되지 않았습니다."
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
                "type": "COMMAND_INJECTION",
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

    def find_command_injection(node):
        text = node.text.decode()

        # Runtime.getRuntime().exec(tainted) 또는 Runtime.exec(tainted)
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            args_node = node.child_by_field_name("arguments")
            if name_node and name_node.text.decode() == "exec" and args_node:
                if "Runtime" in text:
                    args_text = args_node.text.decode()
                    for var in tainted_vars:
                        if var in args_text:
                            report(node, var, "Runtime.exec(...)")
                            return

        # new ProcessBuilder(tainted) 또는 new ProcessBuilder(Arrays.asList(tainted, ...))
        if node.type == "object_creation_expression":
            if "ProcessBuilder" in text:
                for var in tainted_vars:
                    if var in text:
                        report(node, var, "new ProcessBuilder(...)")
                        return

        for child in node.children:
            find_command_injection(child)

    collect_tainted_vars(tree.root_node)
    find_command_injection(tree.root_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
