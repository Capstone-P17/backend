from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]


def detect_command_injection(filepath, tree, vuln_counter):
    vulnerabilities = []
    tainted_vars = {}
    tainted_collections = {}
    process_builder_vars = set()
    reported_sinks = set()

    def identifiers_in(node):
        if node is None:
            return set()
        return {child.text.decode() for child in iterate_all(node) if child.type == "identifier"}

    def contains_input_method(node):
        for child in iterate_all(node):
            if child.type == "method_invocation":
                name_node = child.child_by_field_name("name")
                if name_node and name_node.text.decode() in INPUT_METHODS:
                    return True
        return False

    def tainted_identifier_in(node):
        for name in identifiers_in(node):
            if name in tainted_vars:
                return name
        return None

    def mark_tainted_var(name_node, source_node, declaration_node):
        if not name_node or not source_node:
            return
        tainted_source = tainted_identifier_in(source_node)
        if not contains_input_method(source_node) and not tainted_source:
            return
        name = name_node.text.decode()
        tainted_vars[name] = {
            "line": name_node.start_point[0] + 1,
            "code": declaration_node.text.decode().strip(),
            "source_var": tainted_source or name,
        }

    def mark_process_builder_var(name_node, declaration_node):
        if not name_node:
            return
        declaration_text = declaration_node.text.decode()
        if "ProcessBuilder" in declaration_text:
            process_builder_vars.add(name_node.text.decode())

    def mark_tainted_collection(collection_name, source_var, node):
        source = tainted_vars.get(source_var, {})
        tainted_collections[collection_name] = {
            "line": node.start_point[0] + 1,
            "code": node.text.decode().strip(),
            "source_var": source_var,
            "source_line": source.get("line"),
            "source_code": source.get("code"),
            "function": find_parent_method(node),
        }

    def collect_taint_state(root):
        for node in iterate_all(root):
            if node.type in ("local_variable_declaration", "field_declaration"):
                for child in node.children:
                    if child.type != "variable_declarator":
                        continue
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    mark_tainted_var(name_node, value_node, node)
                    mark_process_builder_var(name_node, node)
                continue

            if node.type == "assignment_expression":
                left_node = node.child_by_field_name("left")
                right_node = node.child_by_field_name("right")
                if left_node and left_node.type == "identifier":
                    mark_tainted_var(left_node, right_node, node)
                continue

            if node.type != "method_invocation":
                continue

            name_node = node.child_by_field_name("name")
            object_node = node.child_by_field_name("object")
            args_node = node.child_by_field_name("arguments")
            if not name_node or not object_node or not args_node:
                continue
            method_name = name_node.text.decode()
            object_name = object_node.text.decode()
            if method_name in {"add", "addAll"}:
                source_var = tainted_identifier_in(args_node)
                if source_var:
                    mark_tainted_collection(object_name, source_var, node)

    def build_evidence(tainted_var, sink_desc, collection_var=None):
        source = tainted_vars.get(tainted_var, {})
        source_line = source.get("line")
        source_code = source.get("code")
        source_desc = f"line {source_line}에서 사용자 입력이 `{tainted_var}` 변수에 저장되었습니다"
        if source_code:
            source_desc += f": `{source_code}`"
        if collection_var:
            collection = tainted_collections.get(collection_var, {})
            collection_line = collection.get("line")
            collection_code = collection.get("code")
            collection_desc = (
                f" 이후 line {collection_line}에서 `{tainted_var}` 값이 `{collection_var}` 명령 인자 컬렉션에 추가되었습니다"
            )
            if collection_code:
                collection_desc += f": `{collection_code}`"
            source_desc += collection_desc
        return (
            f"{source_desc}. 이후 `{tainted_var}` 값이 `{sink_desc}` 운영체제 명령 실행 지점에 전달되었습니다. "
            "명령 allowlist, 고정 명령어 사용, 또는 인자 분리 기반 검증 로직은 탐지되지 않았습니다."
        )

    def build_confidence_reason(tainted_var, sink_desc, collection_var=None):
        source = tainted_vars.get(tainted_var, {})
        source_line = source.get("line")
        flow_desc = f"line {source_line}의 요청 입력 변수 `{tainted_var}` 값이"
        if collection_var:
            flow_desc += f" `{collection_var}` 컬렉션에 추가된 뒤"
        return (
            f"{flow_desc} 운영체제 명령 실행 API `{sink_desc}`까지 전달되는 흐름이 확인되어 HIGH로 판단했습니다. "
            "정적 분석 범위에서 허용 명령 목록, 고정 명령어, 인자 분리 또는 쉘 메타문자 검증은 확인되지 않았습니다."
        )

    def report(node, tainted_var, sink_desc, collection_var=None):
        report_key = (node.start_point[0], tainted_var, sink_desc, collection_var or "")
        if report_key in reported_sinks:
            return
        reported_sinks.add(report_key)
        vuln_counter[0] += 1
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        chain = []
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        if collection_var:
            chain.append(f"req → {tainted_var} → {collection_var} → {sink_desc}")
        else:
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
                "evidence": build_evidence(tainted_var, sink_desc, collection_var),
                "confidence_reason": build_confidence_reason(tainted_var, sink_desc, collection_var),
            }
        )

    def report_if_tainted_collection(node, args_node, sink_desc):
        sink_function = find_parent_method(node)
        for collection_var in identifiers_in(args_node):
            collection = tainted_collections.get(collection_var)
            if not collection:
                continue
            if collection.get("function") != sink_function:
                continue
            report(node, collection["source_var"], sink_desc, collection_var)
            return True
        return False

    def find_command_injection(root):
        for node in iterate_all(root):
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
                                break

            # new ProcessBuilder(tainted) 또는 new ProcessBuilder(Arrays.asList(tainted, ...))
            if node.type == "object_creation_expression":
                if "ProcessBuilder" in text:
                    args_node = node.child_by_field_name("arguments")
                    if args_node and report_if_tainted_collection(node, args_node, "new ProcessBuilder(...)"):
                        continue
                    for var in tainted_vars:
                        if var in text:
                            report(node, var, "new ProcessBuilder(...)")
                            break

            # ProcessBuilder pb = new ProcessBuilder(); pb.command(taintedCollection)
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                object_node = node.child_by_field_name("object")
                args_node = node.child_by_field_name("arguments")
                if (
                    name_node
                    and object_node
                    and args_node
                    and name_node.text.decode() == "command"
                    and object_node.text.decode() in process_builder_vars
                ):
                    report_if_tainted_collection(node, args_node, "ProcessBuilder.command(...)")

    collect_taint_state(tree.root_node)
    find_command_injection(tree.root_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
