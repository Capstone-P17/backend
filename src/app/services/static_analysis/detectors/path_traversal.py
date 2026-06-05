from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI", "getPathInfo"]
FILE_TYPES = ["File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile"]


def _node_text(node):
    return node.text.decode() if node else ""


def _argument_expressions(arguments_node):
    if not arguments_node:
        return []
    return [child for child in arguments_node.children if child.is_named]


def _identifiers(node):
    if node is None:
        return set()
    return {_node_text(child) for child in iterate_all(node) if child.type == "identifier"}


def _referenced_vars(node, var_names):
    seen = set()
    refs = []
    for child in iterate_all(node):
        if child.type != "identifier":
            continue
        name = _node_text(child)
        if name in var_names and name not in seen:
            seen.add(name)
            refs.append(name)
    return refs


def _method_invocation_name(node):
    if node.type != "method_invocation":
        return None
    name_node = node.child_by_field_name("name")
    return _node_text(name_node) if name_node else None


def _type_name(node):
    if node is None:
        return ""
    return _node_text(node).split(".")[-1]


def _file_sink_desc(node):
    if node.type == "object_creation_expression":
        file_type = _type_name(node.child_by_field_name("type"))
        if file_type in FILE_TYPES:
            return f"new {file_type}(...)"
    if node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if name_node and obj_node:
            method = _node_text(name_node)
            obj = _node_text(obj_node)
            if method in ("get", "of") and obj in ("Paths", "Path"):
                return f"{obj}.{method}(...)"
    return None


def _sink_arguments(node):
    if node.type == "object_creation_expression":
        return node.child_by_field_name("arguments")
    if node.type == "method_invocation":
        return node.child_by_field_name("arguments")
    return None


def _get_project_path_summaries(project_index):
    if project_index is None:
        return {}
    if project_index.path_summaries_by_key is not None:
        return project_index.path_summaries_by_key

    summaries_by_key = {method.signature_key: [] for method in project_index.methods}
    for method in project_index.methods:
        summaries_by_key[method.signature_key].extend(
            _collect_path_summaries_for_method(method, project_index, summaries_by_key)
        )

    for _ in range(4):
        changed = False
        for method in project_index.methods:
            current = summaries_by_key.setdefault(method.signature_key, [])
            existing = {_summary_key(summary) for summary in current}
            for summary in _collect_path_summaries_for_method(method, project_index, summaries_by_key):
                key = _summary_key(summary)
                if key in existing:
                    continue
                current.append(summary)
                existing.add(key)
                changed = True
        if not changed:
            break

    project_index.path_summaries_by_key = summaries_by_key
    return summaries_by_key


def _collect_path_summaries_for_method(method, project_index, summaries_by_key):
    tainted_vars = set(method.parameters)
    param_sources = {param: {param} for param in method.parameters}
    summaries = []
    local_types = project_index.variable_types_for(method)

    def expression_source_params(node):
        refs = _referenced_vars(node, tainted_vars)
        sources = set()
        for ref in refs:
            sources.update(param_sources.get(ref, set()))
        return sources

    def update_variable(var_name, value_node):
        source_params = expression_source_params(value_node)
        if source_params:
            tainted_vars.add(var_name)
            param_sources[var_name] = set(source_params)
            return
        tainted_vars.discard(var_name)
        param_sources.pop(var_name, None)

    def add_summary(*, source_params, sink_node, path_var=None, callee_summary=None):
        if not source_params:
            return
        sink = callee_summary["sink"] if callee_summary else _file_sink_desc(sink_node)
        if not sink:
            return
        sink_line = callee_summary["sink_line"] if callee_summary else sink_node.start_point[0] + 1
        path_line = callee_summary["path_line"] if callee_summary else sink_line
        summary = {
            "method_node": method.node,
            "method_key": method.signature_key,
            "method_name": method.method_name,
            "method_label": method.key,
            "filepath": method.filepath,
            "parameters": method.parameters,
            "source_params": sorted(source_params),
            "sink": sink,
            "sink_line": sink_line,
            "path_line": path_line,
            "path_var": path_var if path_var is not None else (callee_summary or {}).get("path_var"),
            "chain": [method.key],
        }
        if callee_summary:
            summary["chain"].extend(callee_summary.get("chain") or [callee_summary["method_label"]])
        else:
            if path_var:
                summary["chain"].append(f"경로 변수 `{path_var}`")
            summary["chain"].append(sink)
        summaries.append(summary)

    def inspect_path_sink(node):
        sink = _file_sink_desc(node)
        if not sink:
            return
        args_node = _sink_arguments(node)
        if not args_node:
            return
        refs = _referenced_vars(args_node, tainted_vars)
        if not refs:
            return
        source_params = set()
        for ref in refs:
            source_params.update(param_sources.get(ref, set()))
        add_summary(source_params=source_params, sink_node=node, path_var=refs[0])

    def inspect_summary_call(node):
        callee = project_index.resolve_invocation(method, node, local_types)
        if not callee or callee.signature_key == method.signature_key:
            return
        args = _argument_expressions(node.child_by_field_name("arguments"))
        for callee_summary in summaries_by_key.get(callee.signature_key, []):
            source_params = set()
            for callee_param in callee_summary["source_params"]:
                try:
                    index = callee_summary["parameters"].index(callee_param)
                except ValueError:
                    continue
                if index >= len(args):
                    continue
                source_params.update(expression_source_params(args[index]))
            add_summary(source_params=source_params, sink_node=node, callee_summary=callee_summary)

    stack = [method.node]
    while stack:
        node = stack.pop()
        if node.type == "method_declaration" and node is not method.node:
            continue

        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type != "variable_declarator":
                    continue
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                if name_node and value_node:
                    update_variable(_node_text(name_node), value_node)

        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right and left.type == "identifier":
                update_variable(_node_text(left), right)

        if node.type == "object_creation_expression":
            inspect_path_sink(node)

        if node.type == "method_invocation":
            inspect_path_sink(node)
            inspect_summary_call(node)

        stack.extend(reversed(node.children))

    unique = {}
    for summary in summaries:
        unique.setdefault(_summary_key(summary), summary)
    return list(unique.values())


def _summary_key(summary):
    return (
        summary["method_key"],
        tuple(summary["source_params"]),
        tuple(summary.get("chain") or []),
        summary["sink"],
        summary["path_line"],
    )


def detect_path_traversal(filepath, tree, vuln_counter, project_index=None):
    vulnerabilities = []
    tainted_vars = {}
    reported_sinks = set()
    interprocedural_reported = set()
    project_summaries_by_key = _get_project_path_summaries(project_index) if project_index else None

    def node_text(node):
        return _node_text(node)

    def identifiers_in(node):
        return _identifiers(node)

    def type_name(node):
        return _type_name(node)

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

    def method_declaration_name(method_node):
        name_node = method_node.child_by_field_name("name")
        return node_text(name_node) if name_node else None

    def parameter_names(method_node):
        params = []
        for node in iterate_all(method_node):
            if node.type != "formal_parameter":
                continue
            name_node = node.child_by_field_name("name")
            if name_node and node_text(name_node) not in params:
                params.append(node_text(name_node))
        return params

    def method_label(method_node):
        class_name = find_parent_class(method_node)
        name = method_declaration_name(method_node)
        return f"{class_name}.{name}" if class_name and name else name

    def detect_interprocedural_calls(caller_method):
        if not project_index or project_summaries_by_key is None:
            return

        caller_name = method_declaration_name(caller_method)
        if not caller_name:
            return

        caller_info = project_index.resolve_method(
            method_label(caller_method),
            arity=len(parameter_names(caller_method)),
        )
        if not caller_info:
            return
        local_types = project_index.variable_types_for(caller_info)
        caller_tainted_vars = set(caller_info.source_parameters)
        caller_taint_sources = {
            var_name: {
                "label": f"Spring MVC source parameter `{var_name}`",
                "line": caller_method.start_point[0] + 1,
            }
            for var_name in caller_tainted_vars
        }

        def expression_source(node):
            input_call = None
            for child in iterate_all(node):
                if child.type != "method_invocation":
                    continue
                name_node = child.child_by_field_name("name")
                if name_node and node_text(name_node) in INPUT_METHODS:
                    input_call = child
                    break
            if input_call:
                return {
                    "label": f"`{node_text(input_call)}`",
                    "line": input_call.start_point[0] + 1,
                }
            refs = _referenced_vars(node, caller_tainted_vars)
            if refs:
                first_var = refs[0]
                return caller_taint_sources.get(
                    first_var,
                    {"label": f"`{first_var}`", "line": node.start_point[0] + 1},
                )
            return None

        def update_caller_taint(var_name, value_node):
            source = expression_source(value_node)
            if source:
                caller_tainted_vars.add(var_name)
                caller_taint_sources[var_name] = source
                return
            caller_tainted_vars.discard(var_name)
            caller_taint_sources.pop(var_name, None)

        def argument_source(argument_node):
            source = expression_source(argument_node)
            if source:
                return source
            refs = _referenced_vars(argument_node, caller_tainted_vars)
            if refs:
                return caller_taint_sources.get(
                    refs[0],
                    {"label": f"`{refs[0]}`", "line": argument_node.start_point[0] + 1},
                )
            return None

        def maybe_report_interprocedural_call(node):
            callee = project_index.resolve_invocation(caller_info, node, local_types)
            if not callee or callee.signature_key == caller_info.signature_key:
                return
            summaries = project_summaries_by_key.get(callee.signature_key, [])
            if not summaries:
                return

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
                    source = argument_source(args[param_index])
                    if source:
                        matched.append((param_name, args[param_index], source))

                if not matched:
                    continue

                report_key = (
                    caller_info.signature_key,
                    node.start_point[0],
                    callee.signature_key,
                    tuple(param for param, _, _ in matched),
                )
                if report_key in interprocedural_reported:
                    continue
                interprocedural_reported.add(report_key)

                source_label = ", ".join(source["label"] for _, _, source in matched)
                source_lines = sorted({source["line"] for _, _, source in matched if source.get("line")})
                source_line_desc = f"line {source_lines[0]}에서 " if source_lines else ""
                param_desc = ", ".join(f"`{node_text(arg)}` → `{param}`" for param, arg, _ in matched)
                callee_label = summary["method_label"] or callee.key
                sink = summary["sink"]
                path_step = f"경로 변수 `{summary['path_var']}`" if summary.get("path_var") else "파일 경로 값"
                summary_chain = summary.get("chain") or [callee_label, path_step, sink]
                boundary_desc = "클래스/파일 경계를 넘는" if summary.get("filepath") != filepath else "같은 파일 내"
                call_chain = [method_label(caller_method), f"{source_label} → {param_desc}", *summary_chain]

                vuln_counter[0] += 1
                vulnerabilities.append(
                    {
                        "id": f"VULN-{vuln_counter[0]:03d}",
                        "type": "PATH_TRAVERSAL",
                        "file": filepath,
                        "line": node.start_point[0] + 1,
                        "function": find_parent_method(node),
                        "code_snippet": node.text.decode().strip(),
                        "call_chain": call_chain,
                        "evidence": (
                            f"{source_line_desc}{source_label}에서 온 입력이 line {node.start_point[0] + 1}의 "
                            f"`{callee.method_name}(...)` 호출을 통해 {param_desc} 형태로 전달되었습니다. "
                            f"이후 `{callee_label}` 내부 line {summary['path_line']}에서 {path_step}로 사용되고 "
                            f"line {summary['sink_line']}의 `{sink}` 경로 생성/파일 접근 API까지 도달합니다. "
                            f"{boundary_desc} 메서드 흐름에서 `normalize()`, `toRealPath()`, `startsWith(baseDir)` 같은 "
                            "기준 디렉터리 검증은 확인되지 않았습니다."
                        ),
                        "confidence_reason": (
                            f"caller `{caller_name}`의 오염된 인자가 callee `{callee.method_name}`의 경로 파라미터로 전달되고, "
                            f"callee 내부에서 `{sink}` 파일 접근 API까지 이어지는 {boundary_desc} inter-procedural 흐름을 확인했기 때문에 HIGH로 판단했습니다."
                        ),
                        "description": "",
                    }
                )

        stack = [caller_method]
        while stack:
            node = stack.pop()
            if node.type == "method_declaration" and node is not caller_method:
                continue

            if node.type in ("local_variable_declaration", "field_declaration"):
                for child in node.children:
                    if child.type != "variable_declarator":
                        continue
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node:
                        update_caller_taint(node_text(name_node), value_node)

            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and left.type == "identifier":
                    update_caller_taint(node_text(left), right)

            if node.type == "method_invocation":
                maybe_report_interprocedural_call(node)

            stack.extend(reversed(node.children))

    methods = [node for node in iterate_all(tree.root_node) if node.type == "method_declaration"]
    scopes = methods or [tree.root_node]
    for scope in scopes:
        tainted_vars.clear()
        if project_index and scope.type == "method_declaration":
            method_info = project_index.resolve_method(method_label(scope), arity=len(parameter_names(scope)))
            if method_info:
                for source_param in method_info.source_parameters:
                    tainted_vars[source_param] = {
                        "line": scope.start_point[0] + 1,
                        "code": f"Spring MVC source parameter `{source_param}`",
                        "source_var": source_param,
                        "previous_var": None,
                        "source_kind": "spring_mvc",
                    }
        collect_taint_state(scope)
        find_path_traversal(scope)
    for method in methods:
        detect_interprocedural_calls(method)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
