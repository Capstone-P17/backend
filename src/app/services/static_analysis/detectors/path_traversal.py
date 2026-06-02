from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI", "getPathInfo"]
FILE_TYPES = ["File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"]


def detect_path_traversal(filepath, tree, vuln_counter):
    vulnerabilities = []
    tainted_vars = {}
    reported_sinks = set()

    def node_text(node):
        return node.text.decode() if node else ""

    def identifiers_in(node):
        if node is None:
            return set()
        return {child.text.decode() for child in iterate_all(node) if child.type == "identifier"}

    def type_name(node):
        if node is None:
            return ""
        return node_text(node).split(".")[-1]

    def contains_input_method(node):
        for child in iterate_all(node):
            if child.type != "method_invocation":
                continue
            name_node = child.child_by_field_name("name")
            if name_node and name_node.text.decode() in INPUT_METHODS:
                return True
        return False

    def tainted_identifier_in(node):
        for name in identifiers_in(node):
            if name in tainted_vars:
                return name
        return None

    def source_root_var(var_name):
        current = var_name
        visited = set()
        while current and current not in visited:
            visited.add(current)
            source_var = tainted_vars.get(current, {}).get("source_var")
            if not source_var or source_var == current:
                break
            current = source_var
        return current or var_name

    def source_info_for(var_name):
        root_var = source_root_var(var_name)
        return tainted_vars.get(root_var, tainted_vars.get(var_name, {}))

    def cookie_value_source_in(node):
        for child in iterate_all(node):
            if child.type != "method_invocation":
                continue
            name_node = child.child_by_field_name("name")
            object_node = child.child_by_field_name("object")
            if not name_node or not object_node:
                continue
            if name_node.text.decode() != "getValue":
                continue
            object_name = object_node.text.decode()
            if object_name in tainted_vars and tainted_vars[object_name].get("source_kind") == "cookie":
                return object_name
        return None

    def is_file_object_creation(node):
        if node is None or node.type != "object_creation_expression":
            return False
        return type_name(node.child_by_field_name("type")) in FILE_TYPES

    def mark_tainted_var(name_node, source_node, statement_node, source_kind="request"):
        if not name_node or not source_node:
            return False
        if is_file_object_creation(source_node):
            return False

        source_var = tainted_identifier_in(source_node)
        cookie_source = cookie_value_source_in(source_node)
        if not contains_input_method(source_node) and not source_var and not cookie_source:
            return False

        name = name_node.text.decode()
        root_source = source_root_var(source_var) if source_var and not cookie_source else name
        tainted_vars[name] = {
            "line": name_node.start_point[0] + 1,
            "code": statement_node.text.decode().strip(),
            "source_var": root_source,
            "previous_var": source_var or cookie_source,
            "source_kind": source_kind,
        }
        return True

    def mark_enhanced_for_cookie_var(node):
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if not name_node or not value_node:
            return
        collection_name = value_node.text.decode()
        if collection_name not in tainted_vars:
            return
        if tainted_vars[collection_name].get("source_kind") != "cookie_collection":
            return
        name = name_node.text.decode()
        tainted_vars[name] = {
            "line": name_node.start_point[0] + 1,
            "code": node.text.decode().strip(),
            "source_var": collection_name,
            "previous_var": collection_name,
            "source_kind": "cookie",
        }

    def collect_taint_state(root):
        for node in iterate_all(root):
            if node.type == "enhanced_for_statement":
                mark_enhanced_for_cookie_var(node)
                continue

            if node.type in ("local_variable_declaration", "field_declaration"):
                for child in node.children:
                    if child.type != "variable_declarator":
                        continue
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    source_kind = "cookie_collection" if value_node and "getCookies" in value_node.text.decode() else "request"
                    marked = mark_tainted_var(name_node, value_node, node, source_kind)
                    if not marked and name_node and value_node:
                        tainted_vars.pop(name_node.text.decode(), None)
                continue

            if node.type == "assignment_expression":
                left_node = node.child_by_field_name("left")
                right_node = node.child_by_field_name("right")
                if left_node and left_node.type == "identifier":
                    marked = mark_tainted_var(left_node, right_node, node)
                    if not marked and right_node:
                        tainted_vars.pop(left_node.text.decode(), None)

    def build_evidence(tainted_var, sink_desc):
        source = source_info_for(tainted_var)
        current = tainted_vars.get(tainted_var, {})
        source_line = source.get("line")
        source_code = source.get("code")
        root_var = source_root_var(tainted_var)
        source_desc = f"line {source_line}에서 사용자 입력이 `{root_var}` 변수에 저장되었습니다"
        if source_code:
            source_desc += f": `{source_code}`"
        if root_var != tainted_var:
            current_line = current.get("line")
            current_code = current.get("code")
            source_desc += f" 이후 line {current_line}에서 `{root_var}` 값이 `{tainted_var}` 경로 변수에 결합되었습니다"
            if current_code:
                source_desc += f": `{current_code}`"
        return (
            f"{source_desc}. 이후 `{tainted_var}` 값이 `{sink_desc}` 경로 생성/파일 접근 API에 전달되었습니다. "
            "정규화(normalize) 후 기준 디렉터리 내부 여부(startsWith)를 확인하는 방어 로직은 탐지되지 않았습니다."
        )

    def build_confidence_reason(tainted_var, sink_desc):
        source = source_info_for(tainted_var)
        source_line = source.get("line")
        root_var = source_root_var(tainted_var)
        flow_desc = f"line {source_line}의 요청 입력 변수 `{root_var}` 값이"
        if root_var != tainted_var:
            flow_desc += f" `{tainted_var}` 경로 변수로 전달된 뒤"
        return (
            f"{flow_desc} 파일 경로 API `{sink_desc}`까지 전달되는 흐름이 확인되어 HIGH로 판단했습니다. "
            "분석 범위에서 `normalize()`, `toRealPath()`, `startsWith(baseDir)` 같은 기준 디렉터리 검증은 확인되지 않았습니다."
        )

    def report(node, tainted_var, sink_desc):
        report_key = (node.start_point[0], tainted_var, sink_desc)
        if report_key in reported_sinks:
            return
        reported_sinks.add(report_key)

        vuln_counter[0] += 1
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        chain = []
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        root_var = source_root_var(tainted_var)
        if root_var != tainted_var:
            chain.append(f"req → {root_var} → {tainted_var} → {sink_desc}")
        else:
            chain.append(f"req → {tainted_var} → {sink_desc}")
        vulnerabilities.append(
            {
                "id": f"VULN-{vuln_counter[0]:03d}",
                "type": "PATH_TRAVERSAL",
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

    def parent_file_sink_type(node):
        current = node.parent
        while current:
            if current.type == "object_creation_expression":
                parent_type = type_name(current.child_by_field_name("type"))
                if parent_type in FILE_TYPES and parent_type != "File":
                    return parent_type
            current = current.parent
        return None

    def find_path_traversal(root):
        for node in iterate_all(root):
            if node.type == "object_creation_expression":
                file_type = type_name(node.child_by_field_name("type"))
                args_node = node.child_by_field_name("arguments")
                if file_type in FILE_TYPES and args_node:
                    if file_type == "File" and parent_file_sink_type(node):
                        continue
                    tainted_var = tainted_identifier_in(args_node)
                    if tainted_var:
                        report(node, tainted_var, f"new {file_type}(...)")

            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                obj_node = node.child_by_field_name("object")
                args_node = node.child_by_field_name("arguments")
                if not name_node or not obj_node or not args_node:
                    continue
                method = name_node.text.decode()
                obj = obj_node.text.decode()
                if method in ("get", "of") and obj in ("Paths", "Path"):
                    tainted_var = tainted_identifier_in(args_node)
                    if tainted_var:
                        report(node, tainted_var, f"{obj}.{method}(...)")

    methods = [node for node in iterate_all(tree.root_node) if node.type == "method_declaration"]
    scopes = methods or [tree.root_node]
    for scope in scopes:
        tainted_vars.clear()
        collect_taint_state(scope)
        find_path_traversal(scope)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
