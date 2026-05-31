from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import (
    find_parent_class,
    find_parent_method,
    iterate_all,
)

SQL_EXEC_METHODS = ["executeQuery", "executeUpdate", "execute"]
SQL_PREPARE_METHODS = ["prepareStatement"]
SQL_SINK_METHODS = SQL_EXEC_METHODS + SQL_PREPARE_METHODS
SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"]
INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]
SQL_BUILDER_METHODS = ["format", "formatted", "concat"]

def detect_sql_injection(filepath, tree, vuln_counter):
    vulnerabilities = []

    def text(node):
        return node.text.decode()

    def iter_methods(node):
        if node.type == "method_declaration":
            yield node
            return
        for child in node.children:
            yield from iter_methods(child)

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
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and text(name_node) in INPUT_METHODS:
                return node
        for child in node.children:
            found = find_input_call(child)
            if found:
                return found
        return None

    def contains_sql_keyword(node):
        return any(keyword in text(node).upper() for keyword in SQL_KEYWORDS)

    def contains_input_method(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and text(name_node) in INPUT_METHODS:
                return True
        return any(contains_input_method(child) for child in node.children)

    def contains_sql_builder(node):
        if node.type == "binary_expression" and "+" in text(node):
            return True
        if node.type == "method_invocation":
            name = method_name(node)
            if name in SQL_BUILDER_METHODS:
                return True
        return any(contains_sql_builder(child) for child in node.children)

    def collect_parameter_names(method_node):
        params = set()
        for node in iterate_all(method_node):
            if node.type == "formal_parameter":
                name_node = node.child_by_field_name("name")
                if name_node:
                    params.add(text(name_node))
        return params

    def analyze_method(method_node):
        tainted_vars = set(collect_parameter_names(method_node))
        taint_sources = {var_name: f"메서드 파라미터 `{var_name}`" for var_name in tainted_vars}
        sql_vars = {}

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
                taint_sources[var_name] = taint_sources.get(source_vars[0], f"`{source_vars[0]}`")
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
                return ", ".join(taint_sources.get(var_name, f"`{var_name}`") for var_name in source_vars)
            return "외부 입력 값"

        def visit(node):
            if node.type == "method_declaration" and node is not method_node:
                return

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

            for child in node.children:
                visit(child)

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

        def add_finding(node, line, code, call_chain, evidence, confidence_reason):
            vuln_counter[0] += 1
            vulnerabilities.append(
                {
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
            )

        visit(method_node)

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

    for method_node in iter_methods(tree.root_node):
        analyze_method(method_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
