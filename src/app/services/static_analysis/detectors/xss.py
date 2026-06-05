from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all
from src.app.services.static_analysis.rules import (
    HTTP_REQUEST_SOURCE_METHODS,
    XSS_HTML_FRAGMENTS,
    XSS_OUTPUT_METHODS,
    XSS_SANITIZER_METHODS,
)
from src.app.services.static_analysis.taint_summary import (
    argument_expressions as _argument_expressions,
    identifiers as _identifiers,
    initialize_summary_cache,
    node_text as _node_text,
    referenced_vars as _referenced_vars,
    source_member_label,
    unique_summaries,
)

INPUT_METHODS = HTTP_REQUEST_SOURCE_METHODS
OUTPUT_METHODS = XSS_OUTPUT_METHODS
HTML_FRAGMENTS = XSS_HTML_FRAGMENTS
SANITIZER_METHODS = XSS_SANITIZER_METHODS


def _method_invocation_name(node):
    if node.type != "method_invocation":
        return None
    name_node = node.child_by_field_name("name")
    return _node_text(name_node) if name_node else None


def _contains_sanitizer(node):
    for child in iterate_all(node):
        if child.type == "method_invocation" and _method_invocation_name(child) in SANITIZER_METHODS:
            return True
    return False


def _contains_html_fragment(node):
    node_text = _node_text(node)
    return any(fragment in node_text for fragment in HTML_FRAGMENTS)


def _contains_binary_expression(node):
    return any(child.type == "binary_expression" for child in iterate_all(node))


def _return_expression(node):
    if node.type != "return_statement":
        return None
    value_node = node.child_by_field_name("value")
    if value_node:
        return value_node
    named_children = [child for child in node.children if child.is_named]
    return named_children[0] if named_children else None


def _get_project_xss_summaries(project_index):
    return initialize_summary_cache(
        project_index,
        cache_attr="xss_summaries_by_key",
        collect_fn=lambda method, summaries_by_key: _collect_xss_summaries_for_method(
            method, project_index, summaries_by_key
        ),
        key_fn=_summary_key,
    )


def _collect_xss_summaries_for_method(method, project_index, summaries_by_key):
    tainted_vars = set(method.parameters)
    param_sources = {param: {param} for param in method.parameters}
    unsafe_html_vars = {}
    summaries = []
    local_types = project_index.variable_types_for(method)

    def expression_source_params(node):
        refs = _referenced_vars(node, tainted_vars)
        sources = set()
        for ref in refs:
            sources.update(param_sources.get(ref, set()))
        return sources

    def update_variable(var_name, value_node, statement_node):
        if _contains_sanitizer(value_node):
            tainted_vars.discard(var_name)
            param_sources.pop(var_name, None)
            unsafe_html_vars.pop(var_name, None)
            return

        callee_summary = summary_for_call(value_node)
        if callee_summary:
            source_params = source_params_for_call(value_node, callee_summary)
            if source_params:
                tainted_vars.add(var_name)
                param_sources[var_name] = set(source_params)
                unsafe_html_vars[var_name] = {
                    "source_params": set(source_params),
                    "line": statement_node.start_point[0] + 1,
                    "callee_summary": callee_summary,
                }
                return

        source_params = expression_source_params(value_node)
        if source_params:
            tainted_vars.add(var_name)
            param_sources[var_name] = set(source_params)
            if _contains_html_fragment(value_node) and _contains_binary_expression(value_node):
                unsafe_html_vars[var_name] = {
                    "source_params": set(source_params),
                    "line": statement_node.start_point[0] + 1,
                }
            else:
                unsafe_html_vars.pop(var_name, None)
            return

        tainted_vars.discard(var_name)
        param_sources.pop(var_name, None)
        unsafe_html_vars.pop(var_name, None)

    def source_params_for_call(node, summary):
        args = _argument_expressions(node.child_by_field_name("arguments"))
        source_params = set()
        for callee_param in summary["source_params"]:
            try:
                index = summary["parameters"].index(callee_param)
            except ValueError:
                continue
            if index >= len(args):
                continue
            source_params.update(expression_source_params(args[index]))
        return source_params

    def summary_for_call(node):
        if node.type != "method_invocation":
            return None
        callee = project_index.resolve_invocation(method, node, local_types)
        if not callee or callee.signature_key == method.signature_key:
            return None
        summaries = summaries_by_key.get(callee.signature_key, [])
        return summaries[0] if len(summaries) == 1 else None

    def add_summary(*, source_params, return_node, html_line, html_var=None, callee_summary=None):
        if not source_params:
            return
        sink = "return unsafe HTML"
        summary = {
            "method_node": method.node,
            "method_key": method.signature_key,
            "method_name": method.method_name,
            "method_label": method.key,
            "filepath": method.filepath,
            "parameters": method.parameters,
            "source_params": sorted(source_params),
            "sink": sink,
            "sink_line": return_node.start_point[0] + 1,
            "html_line": html_line,
            "html_var": html_var if html_var is not None else (callee_summary or {}).get("html_var"),
            "chain": [method.key],
        }
        if callee_summary:
            summary["chain"].extend(callee_summary.get("chain") or [callee_summary["method_label"]])
        else:
            if html_var:
                summary["chain"].append(f"HTML 변수 `{html_var}`")
            summary["chain"].append(sink)
        summaries.append(summary)

    def inspect_return(node):
        value_node = _return_expression(node)
        if not value_node or _contains_sanitizer(value_node):
            return

        callee_summary = summary_for_call(value_node)
        if callee_summary:
            source_params = source_params_for_call(value_node, callee_summary)
            add_summary(
                source_params=source_params,
                return_node=node,
                html_line=callee_summary["html_line"],
                callee_summary=callee_summary,
            )
            return

        refs = _referenced_vars(value_node, tainted_vars)
        unsafe_html_ref = next((ref for ref in refs if ref in unsafe_html_vars), None)
        if unsafe_html_ref:
            html_info = unsafe_html_vars[unsafe_html_ref]
            add_summary(
                source_params=html_info["source_params"],
                return_node=node,
                html_line=html_info["line"],
                html_var=unsafe_html_ref,
            )
            return

        source_params = expression_source_params(value_node)
        if (
            source_params
            and _contains_html_fragment(value_node)
            and _contains_binary_expression(value_node)
        ):
            add_summary(
                source_params=source_params,
                return_node=node,
                html_line=node.start_point[0] + 1,
            )

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
                    update_variable(_node_text(name_node), value_node, node)

        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right and left.type == "identifier":
                update_variable(_node_text(left), right, node)

        if node.type == "return_statement":
            inspect_return(node)

        stack.extend(reversed(node.children))

    return unique_summaries(summaries, _summary_key)


def _summary_key(summary):
    return (
        summary["method_key"],
        tuple(summary["source_params"]),
        tuple(summary.get("chain") or []),
        summary["sink"],
        summary["html_line"],
    )


def detect_xss(filepath, tree, vuln_counter, project_index=None):
    vulnerabilities = []
    project_summaries_by_key = _get_project_xss_summaries(project_index) if project_index else None

    def text(node):
        return _node_text(node)

    def iter_methods(node):
        for child in iterate_all(node):
            if child.type == "method_declaration":
                yield child

    def contains_input_method(node):
        return find_input_call(node) is not None

    def contains_sanitizer(node):
        return _contains_sanitizer(node)

    def find_input_call(node):
        for child in iterate_all(node):
            if child.type == "method_invocation":
                name_node = child.child_by_field_name("name")
                if name_node and text(name_node) in INPUT_METHODS:
                    return child
        return None

    def identifiers(node):
        return _identifiers(node)

    def analyze_method(method_node):
        user_input_vars = {}
        tainted_vars = set()
        sanitized_vars = set()
        unsafe_html_vars = {}
        html_response_seen = False
        caller_info = None
        local_types = {}

        def remember_taint(var_name, source_node, source_var=None):
            tainted_vars.add(var_name)
            sanitized_vars.discard(var_name)
            source = user_input_vars.get(source_var) if source_var else None
            user_input_vars[var_name] = source or {
                "line": source_node.start_point[0] + 1,
                "code": source_node.text.decode().strip(),
                "input_call": text(find_input_call(source_node)) if find_input_call(source_node) else None,
            }

        def remember_interprocedural_html(var_name, source_node, source, summary):
            remember_taint(var_name, source_node)
            user_input_vars[var_name] = {
                "line": source.get("line") or source_node.start_point[0] + 1,
                "code": source.get("label") or source_node.text.decode().strip(),
                "input_call": source.get("label"),
                "interprocedural_summary": summary,
                "call_line": source_node.start_point[0] + 1,
            }
            unsafe_html_vars[var_name] = {
                "source": source,
                "summary": summary,
                "line": source_node.start_point[0] + 1,
            }

        def remember_sanitized(var_name):
            sanitized_vars.add(var_name)
            tainted_vars.discard(var_name)
            unsafe_html_vars.pop(var_name, None)

        def clear_tracking(var_name):
            tainted_vars.discard(var_name)
            sanitized_vars.discard(var_name)
            user_input_vars.pop(var_name, None)
            unsafe_html_vars.pop(var_name, None)

        def update_variable(var_name, value_node, statement_node):
            refs = identifiers(value_node)
            source_var = next((name for name in refs if name in tainted_vars), None)
            sanitized_source_var = next((name for name in refs if name in sanitized_vars), None)
            interprocedural = interprocedural_html_source(value_node)

            if contains_sanitizer(value_node):
                remember_sanitized(var_name)
            elif interprocedural:
                remember_interprocedural_html(
                    var_name,
                    statement_node,
                    interprocedural["source"],
                    interprocedural["summary"],
                )
            elif contains_input_method(value_node):
                remember_taint(var_name, statement_node)
            elif source_var:
                remember_taint(var_name, statement_node, source_var)
                member_label = source_member_label(
                    value_node,
                    {source_var},
                    source_labels={name: info.get("input_call", f"`{name}`") for name, info in user_input_vars.items()},
                )
                if member_label:
                    user_input_vars[var_name]["input_call"] = member_label
                    user_input_vars[var_name]["code"] = member_label
                if source_var in unsafe_html_vars:
                    unsafe_html_vars[var_name] = dict(unsafe_html_vars[source_var])
            elif sanitized_source_var:
                remember_sanitized(var_name)
            elif value_node.type == "null_literal":
                return
            else:
                clear_tracking(var_name)

        def collect_parameter_names(method_node):
            params = []
            for node in iterate_all(method_node):
                if node.type != "formal_parameter":
                    continue
                name_node = node.child_by_field_name("name")
                if name_node and text(name_node) not in params:
                    params.append(text(name_node))
            return params

        def method_declaration_name(method_node):
            name_node = method_node.child_by_field_name("name")
            return text(name_node) if name_node else None

        def method_label(method_node):
            class_name = find_parent_class(method_node)
            name = method_declaration_name(method_node)
            return f"{class_name}.{name}" if class_name and name else name

        def expression_source(node):
            input_call = find_input_call(node)
            if input_call:
                return {
                    "label": f"`{text(input_call)}`",
                    "line": input_call.start_point[0] + 1,
                }
            refs = _referenced_vars(node, tainted_vars)
            if refs:
                first_var = refs[0]
                info = user_input_vars.get(first_var, {})
                member_label = source_member_label(
                    node,
                    refs,
                    source_labels={name: source.get("input_call", f"`{name}`") for name, source in user_input_vars.items()},
                )
                return {
                    "label": member_label or info.get("input_call") or f"`{first_var}`",
                    "line": info.get("line") or node.start_point[0] + 1,
                }
            return None

        def interprocedural_html_source(node):
            if not caller_info or project_summaries_by_key is None or node.type != "method_invocation":
                return None
            callee = project_index.resolve_invocation(caller_info, node, local_types)
            if not callee or callee.signature_key == caller_info.signature_key:
                return None
            summaries = project_summaries_by_key.get(callee.signature_key, [])
            if not summaries:
                return None
            args = _argument_expressions(node.child_by_field_name("arguments"))
            for summary in summaries:
                for param_name in summary["source_params"]:
                    try:
                        param_index = summary["parameters"].index(param_name)
                    except ValueError:
                        continue
                    if param_index >= len(args):
                        continue
                    source = expression_source(args[param_index])
                    if source:
                        return {
                            "callee": callee,
                            "summary": summary,
                            "source": source,
                            "argument": args[param_index],
                            "param": param_name,
                        }
            return None

        if project_index:
            caller_info = project_index.resolve_method(
                method_label(method_node),
                arity=len(collect_parameter_names(method_node)),
            )
            if caller_info:
                local_types = project_index.variable_types_for(caller_info)
                for source_param in caller_info.source_parameters:
                    tainted_vars.add(source_param)
                    sanitized_vars.discard(source_param)
                    user_input_vars[source_param] = {
                        "line": method_node.start_point[0] + 1,
                        "code": f"Spring MVC source parameter `{source_param}`",
                        "input_call": f"Spring MVC source parameter `{source_param}`",
                    }

        def visit_method_nodes():
            nonlocal html_response_seen
            stack = [method_node]
            while stack:
                node = stack.pop()
                if node.type == "method_declaration" and node is not method_node:
                    continue

                if node.type in ("local_variable_declaration", "field_declaration"):
                    for child in node.children:
                        if child.type == "variable_declarator":
                            name_node = child.child_by_field_name("name")
                            value_node = child.child_by_field_name("value")
                            if name_node and value_node:
                                update_variable(text(name_node), value_node, node)
                    continue

                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left and right and left.type == "identifier":
                        update_variable(text(left), right, node)
                    continue

                if node.type == "method_invocation":
                    if is_html_content_type_call(node):
                        html_response_seen = True
                    update_from_enumeration_next(node)
                    inspect_output(node)

                stack.extend(reversed(node.children))

        def is_html_content_type_call(node):
            name_node = node.child_by_field_name("name")
            args_node = node.child_by_field_name("arguments")
            return bool(
                name_node
                and args_node
                and text(name_node) == "setContentType"
                and "text/html" in args_node.text.decode().lower()
            )

        def update_from_enumeration_next(node):
            name_node = node.child_by_field_name("name")
            object_node = node.child_by_field_name("object")
            if not name_node or not object_node or text(name_node) != "nextElement":
                return
            object_name = text(object_node)
            if object_name not in tainted_vars:
                return
            parent = node.parent
            while parent and parent.type not in {"assignment_expression", "variable_declarator", "method_declaration"}:
                parent = parent.parent
            if not parent or parent.type == "method_declaration":
                return
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                if left and left.type == "identifier":
                    remember_taint(text(left), parent, object_name)
            if parent.type == "variable_declarator":
                name = parent.child_by_field_name("name")
                if name:
                    remember_taint(text(name), parent, object_name)

        def inspect_output(node):
            name_node = node.child_by_field_name("name")
            if not name_node or text(name_node) not in OUTPUT_METHODS:
                return

            arguments = node.child_by_field_name("arguments")
            if not arguments:
                return

            args_text = arguments.text.decode()
            argument_identifiers = identifiers(arguments)
            unsafe_vars = [
                var_name
                for var_name in tainted_vars
                if var_name in argument_identifiers and var_name not in sanitized_vars
            ]
            direct_input = contains_input_method(arguments)
            has_user_input = bool(unsafe_vars) or direct_input
            has_html = any(fragment in args_text for fragment in HTML_FRAGMENTS)
            has_concat = contains_binary_expression(arguments)
            is_sanitized = contains_sanitizer(arguments)
            is_format_output = text(name_node) == "format"
            has_unsafe_html_output = has_html and has_concat
            has_unsafe_format_output = is_format_output and html_response_seen and has_user_input
            has_unsafe_interprocedural_html = any(var_name in unsafe_html_vars for var_name in unsafe_vars)

            if (
                has_user_input
                and (has_unsafe_html_output or has_unsafe_format_output or has_unsafe_interprocedural_html)
                and not is_sanitized
            ):
                used_var = unsafe_vars[0] if unsafe_vars else None
                vuln_counter[0] += 1
                vulnerabilities.append(
                    {
                        "id": f"VULN-{vuln_counter[0]:03d}",
                        "type": "XSS",
                        "file": filepath,
                        "line": node.start_point[0] + 1,
                        "function": find_parent_method(node),
                        "code_snippet": node.text.decode().strip(),
                        "call_chain": build_xss_chain(node, used_var, user_input_vars),
                        "evidence": build_xss_evidence(
                            node,
                            used_var,
                            user_input_vars,
                            text(find_input_call(arguments)) if find_input_call(arguments) else None,
                        ),
                        "confidence_reason": build_xss_confidence_reason(
                            node,
                            used_var,
                            user_input_vars,
                            text(find_input_call(arguments)) if find_input_call(arguments) else None,
                        ),
                        "description": "",
                    }
                )

        visit_method_nodes()

    def contains_binary_expression(node):
        for child in iterate_all(node):
            if child.type == "binary_expression":
                return True
        return False

    def build_xss_chain(node, used_var, user_input_vars):
        chain = []
        if used_var and used_var in user_input_vars:
            summary = user_input_vars[used_var].get("interprocedural_summary")
            source_code = user_input_vars[used_var]["code"]
            if "getHeaders" in source_code:
                chain.append(f"req.getHeaders → {used_var}")
            elif "getHeader" in source_code:
                chain.append(f"req.getHeader → {used_var}")
            elif "getQueryString" in source_code:
                chain.append(f"req.getQueryString → {used_var}")
            elif "getCookies" in source_code:
                chain.append(f"req.getCookies → {used_var}")
            else:
                chain.append(f"req.getParameter → {used_var}")
            if summary:
                chain.extend(summary.get("chain") or [summary["method_label"]])
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        name_node = node.child_by_field_name("name")
        if name_node:
            chain.append(f"resp.getWriter().{name_node.text.decode()}")
        return chain

    def build_xss_evidence(node, used_var, user_input_vars, direct_input_call):
        sink = build_output_name(node)
        if used_var and used_var in user_input_vars:
            info = user_input_vars[used_var]
            summary = info.get("interprocedural_summary")
            source = user_input_vars[used_var].get("input_call") or user_input_vars[used_var]["code"]
            if summary:
                boundary_desc = "클래스/파일 경계를 넘는" if summary.get("filepath") != filepath else "같은 파일 내"
                return (
                    f"{source}에서 온 입력이 line {info.get('call_line')}의 중간 메서드 호출 결과 `{used_var}`로 저장되었습니다. "
                    f"이후 `{summary['method_label']}` 내부 line {summary['html_line']}에서 사용자 입력이 HTML 문자열로 조합되고 "
                    f"line {summary['sink_line']}의 반환값이 `{sink}`로 출력됩니다. "
                    f"{boundary_desc} 메서드 흐름에서 HTML 이스케이프 처리는 확인되지 않았습니다."
                )
            if is_format_output(node):
                return (
                    f"`{source}`에서 온 `{used_var}` 값이 HTML 응답의 `{sink}` 출력 포맷 문자열/인자로 전달되며, "
                    "HTML 이스케이프 처리가 확인되지 않았습니다."
                )
            return (
                f"`{source}`에서 온 `{used_var}` 값이 HTML 문자열과 결합되어 "
                f"`{sink}`로 출력되며, HTML 이스케이프 처리가 확인되지 않았습니다."
            )
        if direct_input_call:
            if is_format_output(node):
                return (
                    f"`{direct_input_call}` 입력이 HTML 응답의 `{sink}` 출력 포맷 문자열/인자로 직접 전달되며, "
                    "HTML 이스케이프 처리가 확인되지 않았습니다."
                )
            return (
                f"`{direct_input_call}` 입력이 HTML 문자열과 직접 결합되어 "
                f"`{sink}`로 출력되며, HTML 이스케이프 처리가 확인되지 않았습니다."
            )
        return f"외부 입력 값이 HTML 문자열과 결합되어 `{sink}`로 출력되며, HTML 이스케이프 처리가 확인되지 않았습니다."

    def build_xss_confidence_reason(node, used_var, user_input_vars, direct_input_call):
        sink = build_output_name(node)
        if used_var and used_var in user_input_vars:
            info = user_input_vars[used_var]
            summary = info.get("interprocedural_summary")
            source = info.get("input_call") or info["code"]
            if summary:
                boundary_desc = "클래스/파일 경계를 넘는" if summary.get("filepath") != filepath else "같은 파일 내"
                return (
                    f"`{source}` 입력 출처가 `{summary['method_label']}`의 HTML 생성 파라미터로 전달되고, "
                    f"반환된 HTML 문자열 `{used_var}`가 `{sink}` 응답 출력 API까지 이어지는 {boundary_desc} "
                    "inter-procedural 흐름을 확인했기 때문에 HIGH로 판단했습니다."
                )
            source_desc = f"`{source}` 입력 출처와 `{used_var}` 변수 흐름"
        elif direct_input_call:
            source_desc = f"`{direct_input_call}` 직접 입력 출처"
        else:
            source_desc = "외부 입력으로 추정되는 값"
        if is_format_output(node):
            return (
                f"{source_desc}, HTML 응답 문맥, `{sink}` 출력 API가 같은 흐름에서 확인되어 HIGH로 판단했습니다. "
                "탐지 가능한 HTML 이스케이프 또는 sanitizer 호출은 출력 직전까지 확인되지 않았습니다."
            )
        return (
            f"{source_desc}, HTML 조각과의 문자열 결합, `{sink}` 응답 출력 API가 같은 흐름에서 확인되어 HIGH로 판단했습니다. "
            "탐지 가능한 HTML 이스케이프 또는 sanitizer 호출은 출력 직전까지 확인되지 않았습니다."
        )

    def is_format_output(node):
        name_node = node.child_by_field_name("name")
        return bool(name_node and name_node.text.decode() == "format")

    def build_output_name(node):
        name_node = node.child_by_field_name("name")
        object_node = node.child_by_field_name("object")
        if object_node and name_node:
            return f"{object_node.text.decode()}.{name_node.text.decode()}"
        if name_node:
            return name_node.text.decode()
        return node.text.decode().strip()

    for method_node in iter_methods(tree.root_node):
        analyze_method(method_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
