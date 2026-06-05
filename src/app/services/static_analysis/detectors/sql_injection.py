from __future__ import annotations

import re

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import (
    find_parent_class,
    find_parent_method,
    iterate_all,
)
from src.app.services.static_analysis.rules import (
    HTTP_REQUEST_SOURCE_METHODS,
    SQL_BUILDER_METHODS,
    SQL_EXEC_METHODS,
    SQL_KEYWORDS,
    SQL_PREPARE_METHODS,
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

SQL_SINK_METHODS = SQL_EXEC_METHODS + SQL_PREPARE_METHODS
SQL_KEYWORD_PATTERN = re.compile(r"\b(?:" + "|".join(SQL_KEYWORDS) + r")\b", re.IGNORECASE)
INPUT_METHODS = HTTP_REQUEST_SOURCE_METHODS
SQL_LITERAL_NODE_TYPES = {"string_literal", "text_block"}


def _method_invocation_name(node):
    if node.type != "method_invocation":
        return None
    name_node = node.child_by_field_name("name")
    return _node_text(name_node) if name_node else None


def _find_input_call(node):
    for child in iterate_all(node):
        if child.type != "method_invocation":
            continue
        name_node = child.child_by_field_name("name")
        if name_node and _node_text(name_node) in INPUT_METHODS:
            return child
    return None


def _contains_sql_keyword(node):
    return any(
        SQL_KEYWORD_PATTERN.search(_node_text(child))
        for child in iterate_all(node)
        if child.type in SQL_LITERAL_NODE_TYPES
    )


def _contains_sql_builder(node):
    for child in iterate_all(node):
        if child.type == "binary_expression" and "+" in _node_text(child):
            return True
        if child.type == "method_invocation" and _method_invocation_name(child) in SQL_BUILDER_METHODS:
            return True
    return False


def _build_sink_name(node):
    name_node = node.child_by_field_name("name")
    object_node = node.child_by_field_name("object")
    if object_node and name_node:
        return f"{_node_text(object_node)}.{_node_text(name_node)}"
    if name_node:
        return _node_text(name_node)
    return _node_text(node).strip()


def _get_project_sql_summaries(project_index):
    return initialize_summary_cache(
        project_index,
        cache_attr="sql_summaries_by_key",
        collect_fn=lambda method, summaries_by_key: _collect_sql_summaries_for_method(
            method, project_index, summaries_by_key
        ),
        key_fn=_summary_key,
    )


def _collect_sql_summaries_for_method(method, project_index, summaries_by_key):
    tainted_vars = set(method.parameters)
    param_sources = {param: {param} for param in method.parameters}
    sql_vars = {}
    summaries = []
    local_types = project_index.variable_types_for(method)

    def expression_source_params(node):
        refs = _referenced_vars(node, tainted_vars)
        sources = set()
        for ref in refs:
            sources.update(param_sources.get(ref, set()))
        return sources

    def expression_has_taint(node):
        return _find_input_call(node) is not None or bool(expression_source_params(node))

    def is_unsafe_sql_expression(node):
        return _contains_sql_keyword(node) and _contains_sql_builder(node) and expression_has_taint(node)

    def update_variable(var_name, value_node, statement_node):
        source_params = expression_source_params(value_node)
        if is_unsafe_sql_expression(value_node):
            sql_vars[var_name] = {
                "line": statement_node.start_point[0] + 1,
                "source_params": source_params,
            }
            if source_params:
                tainted_vars.add(var_name)
                param_sources[var_name] = set(source_params)
            return

        if source_params:
            tainted_vars.add(var_name)
            param_sources[var_name] = set(source_params)
        else:
            tainted_vars.discard(var_name)
            param_sources.pop(var_name, None)
        sql_vars.pop(var_name, None)

    def add_summary(*, source_params, sink_node, sql_line, sql_var=None, callee_summary=None):
        if not source_params:
            return
        sink = callee_summary["sink"] if callee_summary else _build_sink_name(sink_node)
        sink_line = callee_summary["sink_line"] if callee_summary else sink_node.start_point[0] + 1
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
            "sql_line": sql_line,
            "sql_var": sql_var if sql_var is not None else (callee_summary or {}).get("sql_var"),
            "chain": [method.key],
        }
        if callee_summary:
            summary["chain"].extend(callee_summary.get("chain") or [callee_summary["method_label"]])
        else:
            if sql_var:
                summary["chain"].append(f"SQL 변수 `{sql_var}`")
            summary["chain"].append(sink)
        summaries.append(summary)

    def inspect_sql_sink(node):
        name = _method_invocation_name(node)
        if name not in SQL_SINK_METHODS:
            return
        arguments = node.child_by_field_name("arguments")
        if not arguments:
            return
        argument_vars = _identifiers(arguments)
        matched_sql_var = next((var_name for var_name in argument_vars if var_name in sql_vars), None)
        if matched_sql_var:
            sql_info = sql_vars[matched_sql_var]
            add_summary(
                source_params=sql_info.get("source_params") or set(),
                sink_node=node,
                sql_line=sql_info["line"],
                sql_var=matched_sql_var,
            )
            return
        if is_unsafe_sql_expression(arguments):
            add_summary(
                source_params=expression_source_params(arguments),
                sink_node=node,
                sql_line=node.start_point[0] + 1,
            )

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
            add_summary(
                source_params=source_params,
                sink_node=node,
                sql_line=callee_summary["sql_line"],
                sql_var=callee_summary.get("sql_var"),
                callee_summary=callee_summary,
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

        if node.type == "method_invocation":
            inspect_sql_sink(node)
            inspect_summary_call(node)

        stack.extend(reversed(node.children))

    return unique_summaries(summaries, _summary_key)


def _summary_key(summary):
    return (
        summary["method_key"],
        tuple(summary["source_params"]),
        tuple(summary.get("chain") or []),
        summary["sink"],
        summary["sql_line"],
    )


def detect_sql_injection(filepath, tree, vuln_counter, project_index=None):
    vulnerabilities = []

    def text(node):
        return node.text.decode()

    def iter_methods(node):
        for child in iterate_all(node):
            if child.type == "method_declaration":
                yield child

    method_nodes = list(iter_methods(tree.root_node))
    method_summaries = {}
    interprocedural_reported = set()
    project_summaries_by_key = _get_project_sql_summaries(project_index) if project_index else None

    def identifiers(node):
        return {text(child) for child in iterate_all(node) if child.type == "identifier"}

    def referenced_tainted_vars(node, tainted_vars):
        seen = set()
        refs = []
        for child in iterate_all(node):
            if child.type != "identifier":
                continue
            name = text(child)
            if name in tainted_vars and name not in seen:
                seen.add(name)
                refs.append(name)
        return refs

    def method_name(node):
        if node.type != "method_invocation":
            return None
        name_node = node.child_by_field_name("name")
        return text(name_node) if name_node else None

    def find_input_call(node):
        for child in iterate_all(node):
            if child.type == "method_invocation":
                name_node = child.child_by_field_name("name")
                if name_node and text(name_node) in INPUT_METHODS:
                    return child
        return None

    def string_literals(node):
        return [text(child) for child in iterate_all(node) if child.type in SQL_LITERAL_NODE_TYPES]

    def contains_sql_keyword(node):
        return any(SQL_KEYWORD_PATTERN.search(literal) for literal in string_literals(node))

    def contains_input_method(node):
        return find_input_call(node) is not None

    def contains_sql_builder(node):
        for child in iterate_all(node):
            if child.type == "binary_expression" and "+" in text(child):
                return True
            if child.type == "method_invocation":
                name = method_name(child)
                if name in SQL_BUILDER_METHODS:
                    return True
        return False

    def collect_parameter_names(method_node):
        params = []
        for node in iterate_all(method_node):
            if node.type == "formal_parameter":
                name_node = node.child_by_field_name("name")
                if name_node and text(name_node) not in params:
                    params.append(text(name_node))
        return params

    def method_declaration_name(method_node):
        name_node = method_node.child_by_field_name("name")
        return text(name_node) if name_node else None

    def argument_expressions(arguments_node):
        if not arguments_node:
            return []
        return [child for child in arguments_node.children if child.is_named]

    def method_label(method_node):
        class_name = find_parent_class(method_node)
        name = method_declaration_name(method_node)
        return f"{class_name}.{name}" if class_name and name else name

    def analyze_method(method_node):
        parameter_names = collect_parameter_names(method_node)
        tainted_vars = set(parameter_names)
        taint_sources = {var_name: f"메서드 파라미터 `{var_name}`" for var_name in tainted_vars}
        sql_vars = {}
        summaries = []

        def expression_has_taint(node):
            refs = identifiers(node)
            return contains_input_method(node) or bool(refs & tainted_vars)

        def is_unsafe_sql_expression(node):
            return contains_sql_keyword(node) and contains_sql_builder(node) and expression_has_taint(node)

        def update_variable(var_name, value_node, statement_node):
            source_vars = referenced_tainted_vars(value_node, tainted_vars)
            input_call = find_input_call(value_node)
            if is_unsafe_sql_expression(value_node):
                sql_vars[var_name] = {
                    "line": statement_node.start_point[0] + 1,
                    "code": statement_node.text.decode().strip(),
                    "source_vars": source_vars,
                    "input_call": text(input_call) if input_call else None,
                }
                tainted_vars.add(var_name)
                taint_sources[var_name] = build_taint_source(value_node, source_vars, input_call)
                return

            if input_call:
                tainted_vars.add(var_name)
                taint_sources[var_name] = f"`{text(input_call)}`에서 온 `{var_name}`"
            elif source_vars:
                tainted_vars.add(var_name)
                taint_sources[var_name] = (
                    source_member_label(value_node, source_vars, source_labels=taint_sources)
                    or taint_sources.get(source_vars[0], f"`{source_vars[0]}`")
                )
            elif expression_has_taint(value_node):
                tainted_vars.add(var_name)
                taint_sources[var_name] = f"`{var_name}`"
            else:
                tainted_vars.discard(var_name)
                taint_sources.pop(var_name, None)

            sql_vars.pop(var_name, None)

        def build_taint_source(node, source_vars, input_call):
            if input_call:
                return f"`{text(input_call)}`"
            if source_vars:
                member_label = source_member_label(node, source_vars, source_labels=taint_sources)
                if member_label:
                    return member_label
                return ", ".join(taint_sources.get(var_name, f"`{var_name}`") for var_name in source_vars)
            return "외부 입력 값"

        def visit_method_nodes():
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

                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left and right and left.type == "identifier":
                        update_variable(text(left), right, node)

                if node.type == "method_invocation":
                    inspect_sql_sink(node)

                stack.extend(reversed(node.children))

        def inspect_sql_sink(node):
            name = method_name(node)
            if name not in SQL_SINK_METHODS:
                return

            arguments = node.child_by_field_name("arguments")
            if not arguments:
                return

            argument_vars = identifiers(arguments)
            matched_sql_var = next((var_name for var_name in argument_vars if var_name in sql_vars), None)
            if matched_sql_var:
                var = sql_vars[matched_sql_var]
                add_finding(
                    node=node,
                    line=var["line"],
                    code=var["code"],
                    call_chain=build_call_chain(node, matched_sql_var),
                    evidence=build_sql_evidence(node, matched_sql_var, var),
                    confidence_reason=build_sql_confidence_reason(node, matched_sql_var, var),
                    source_vars=var.get("source_vars") or [],
                    sql_var=matched_sql_var,
                )
                return

            if is_unsafe_sql_expression(arguments):
                sql_info = {
                    "source_vars": referenced_tainted_vars(arguments, tainted_vars),
                    "input_call": text(find_input_call(arguments)) if find_input_call(arguments) else None,
                }
                add_finding(
                    node=node,
                    line=node.start_point[0] + 1,
                    code=node.text.decode().strip(),
                    call_chain=build_call_chain(node),
                    evidence=build_sql_evidence(node, None, sql_info),
                    confidence_reason=build_sql_confidence_reason(node, None, sql_info),
                    source_vars=sql_info.get("source_vars") or [],
                    sql_var=None,
                )

        def build_sql_evidence(node, sql_var, sql_info):
            sink = build_sink_name(node)
            source_vars = sql_info.get("source_vars") or []
            input_call = sql_info.get("input_call")
            source = f"`{input_call}`에서 온 입력이" if input_call else ""
            if not source and source_vars:
                source_parts = [taint_sources.get(var_name, f"`{var_name}`") for var_name in source_vars]
                source = f"{', '.join(source_parts)} 값이"
            if not source:
                source = "외부 입력으로 추정되는 값이"

            if sql_var:
                return (
                    f"{source} SQL 문자열 `{sql_var}`에 결합된 뒤 `{sink}`로 실행됩니다. "
                    "PreparedStatement 바인딩 또는 파라미터화된 쿼리 사용은 해당 흐름에서 확인되지 않았습니다."
                )
            return (
                f"{source} SQL 문자열에 직접 결합된 뒤 `{sink}`로 실행됩니다. "
                "PreparedStatement 바인딩 또는 파라미터화된 쿼리 사용은 해당 흐름에서 확인되지 않았습니다."
            )

        def build_sql_confidence_reason(node, sql_var, sql_info):
            sink = build_sink_name(node)
            source_vars = sql_info.get("source_vars") or []
            input_call = sql_info.get("input_call")
            if input_call:
                source = f"`{input_call}` 입력 출처"
            elif source_vars:
                source = f"오염 변수 `{', '.join(source_vars)}`"
            else:
                source = "메서드 파라미터 또는 외부 입력으로 추정되는 값"
            sql_step = f"SQL 변수 `{sql_var}` 생성" if sql_var else "SQL 문자열 직접 생성"
            return (
                f"{source}, {sql_step}, `{sink}` 실행 API가 같은 메서드 흐름에서 확인되었습니다. "
                "정적 분석 범위에서 PreparedStatement 바인딩으로 분리되는 방어 흐름은 확인되지 않았습니다."
            )

        def add_finding(node, line, code, call_chain, evidence, confidence_reason, source_vars, sql_var):
            vuln_counter[0] += 1
            finding = {
                "id": f"VULN-{vuln_counter[0]:03d}",
                "type": "SQL_INJECTION",
                "file": filepath,
                "line": line,
                "function": find_parent_method(node),
                "code_snippet": code,
                "call_chain": call_chain,
                "evidence": evidence,
                "confidence_reason": confidence_reason,
                "description": "",
            }
            vulnerabilities.append(finding)

            source_params = [name for name in source_vars if name in parameter_names]
            if source_params:
                summaries.append(
                    {
                        "method_node": method_node,
                        "method_name": method_declaration_name(method_node),
                        "method_label": method_label(method_node),
                        "parameters": parameter_names,
                        "source_params": source_params,
                        "sink": build_sink_name(node),
                        "sink_line": node.start_point[0] + 1,
                        "sql_line": line,
                        "sql_var": sql_var,
                    }
                )

        visit_method_nodes()
        current_method_name = method_declaration_name(method_node)
        if current_method_name and summaries:
            method_summaries.setdefault(current_method_name, []).extend(summaries)

    def detect_interprocedural_calls(caller_method):
        caller_name = method_declaration_name(caller_method)
        if not caller_name:
            return

        caller_info = None
        local_types = {}
        if project_index:
            caller_info = project_index.resolve_method(
                method_label(caller_method),
                arity=len(collect_parameter_names(caller_method)),
            )
            if caller_info:
                local_types = project_index.variable_types_for(caller_info)

        caller_tainted_vars = set(caller_info.source_parameters if caller_info else set())
        caller_taint_sources = {
            var_name: {
                "label": f"Spring MVC source parameter `{var_name}`",
                "line": caller_method.start_point[0] + 1,
            }
            for var_name in caller_tainted_vars
        }

        def expression_source(node):
            input_call = find_input_call(node)
            if input_call:
                return {
                    "label": f"`{text(input_call)}`",
                    "line": input_call.start_point[0] + 1,
                }
            source_vars = referenced_tainted_vars(node, caller_tainted_vars)
            if source_vars:
                first_var = source_vars[0]
                member_label = source_member_label(
                    node,
                    source_vars,
                    source_labels={name: info.get("label", f"`{name}`") for name, info in caller_taint_sources.items()},
                )
                if member_label:
                    return {
                        "label": member_label,
                        "line": node.start_point[0] + 1,
                    }
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
            else:
                caller_tainted_vars.discard(var_name)
                caller_taint_sources.pop(var_name, None)

        def argument_is_tainted(argument_node):
            source = expression_source(argument_node)
            if source:
                return source
            refs = referenced_tainted_vars(argument_node, caller_tainted_vars)
            if refs:
                return caller_taint_sources.get(refs[0], {"label": f"`{refs[0]}`", "line": argument_node.start_point[0] + 1})
            return None

        def maybe_report_interprocedural_call(node):
            callee_name = method_name(node)
            if not callee_name or callee_name == caller_name:
                return

            summaries = []
            resolved_callee_key = callee_name
            if caller_info and project_summaries_by_key is not None:
                callee_info = project_index.resolve_invocation(caller_info, node, local_types)
                if not callee_info or callee_info.signature_key == caller_info.signature_key:
                    return
                summaries = project_summaries_by_key.get(callee_info.signature_key, [])
                resolved_callee_key = callee_info.signature_key
                callee_name = callee_info.method_name
            else:
                summaries = method_summaries.get(callee_name, [])
            if not summaries:
                return

            args = argument_expressions(node.child_by_field_name("arguments"))
            for summary in summaries:
                if summary["method_node"] is caller_method:
                    continue

                matched = []
                for param_name in summary["source_params"]:
                    try:
                        param_index = summary["parameters"].index(param_name)
                    except ValueError:
                        continue
                    if param_index >= len(args):
                        continue
                    source = argument_is_tainted(args[param_index])
                    if source:
                        matched.append((param_name, args[param_index], source))

                if not matched:
                    continue

                report_key = (caller_name, node.start_point[0], resolved_callee_key, tuple(param for param, _, _ in matched))
                if report_key in interprocedural_reported:
                    continue
                interprocedural_reported.add(report_key)

                source_label = ", ".join(source["label"] for _, _, source in matched)
                source_lines = sorted({source["line"] for _, _, source in matched if source.get("line")})
                source_line_desc = f"line {source_lines[0]}에서 " if source_lines else ""
                param_desc = ", ".join(f"`{text(arg)}` → `{param}`" for param, arg, _ in matched)
                callee_label = summary["method_label"] or callee_name
                sink = summary["sink"]
                sql_step = f"SQL 변수 `{summary['sql_var']}`" if summary.get("sql_var") else "SQL 문자열"
                summary_chain = summary.get("chain") or [callee_label, sql_step, sink]
                boundary_desc = "클래스/파일 경계를 넘는" if summary.get("filepath") != filepath else "같은 파일 내"
                call_chain = [method_label(caller_method), f"{source_label} → {param_desc}", *summary_chain]

                vuln_counter[0] += 1
                vulnerabilities.append(
                    {
                        "id": f"VULN-{vuln_counter[0]:03d}",
                        "type": "SQL_INJECTION",
                        "file": filepath,
                        "line": node.start_point[0] + 1,
                        "function": find_parent_method(node),
                        "code_snippet": node.text.decode().strip(),
                        "call_chain": call_chain,
                        "evidence": (
                            f"{source_line_desc}{source_label}에서 온 입력이 line {node.start_point[0] + 1}의 "
                            f"`{callee_name}(...)` 호출을 통해 {param_desc} 형태로 전달되었습니다. "
                            f"이후 `{callee_label}` 내부 line {summary['sql_line']}에서 {sql_step}에 결합되고 "
                            f"line {summary['sink_line']}의 `{sink}` 실행 API까지 도달합니다. "
                            f"{boundary_desc} 메서드 흐름에서 PreparedStatement 바인딩 또는 파라미터화된 쿼리 사용은 확인되지 않았습니다."
                        ),
                        "confidence_reason": (
                            f"caller `{caller_name}`의 오염된 인자가 callee `{callee_name}`의 SQL 생성 파라미터로 전달되고, "
                            f"callee 내부에서 `{sink}` 실행 API까지 이어지는 {boundary_desc} inter-procedural 흐름을 확인했기 때문에 HIGH로 판단했습니다."
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
                    if child.type == "variable_declarator":
                        name_node = child.child_by_field_name("name")
                        value_node = child.child_by_field_name("value")
                        if name_node and value_node:
                            update_caller_taint(text(name_node), value_node)

            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and left.type == "identifier":
                    update_caller_taint(text(left), right)

            if node.type == "method_invocation":
                maybe_report_interprocedural_call(node)

            stack.extend(reversed(node.children))

    def build_call_chain(node, sql_var=None):
        chain = []
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        if sql_var:
            chain.append(sql_var)
        name_node = node.child_by_field_name("name")
        object_node = node.child_by_field_name("object")
        if object_node and name_node:
            chain.append(f"{object_node.text.decode()}.{name_node.text.decode()}")
        return chain

    def build_sink_name(node):
        name_node = node.child_by_field_name("name")
        object_node = node.child_by_field_name("object")
        if object_node and name_node:
            return f"{object_node.text.decode()}.{name_node.text.decode()}"
        if name_node:
            return name_node.text.decode()
        return node.text.decode().strip()

    for method_node in method_nodes:
        analyze_method(method_node)
    for method_node in method_nodes:
        detect_interprocedural_calls(method_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
