from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
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

# 인증 우회 가능성 → CRITICAL
AUTH_KEYWORDS = ["USERNAME", "PASSWORD", "PASSWD", "LOGIN", "AUTH"]
# 데이터 파괴 가능성 → CRITICAL
DESTRUCTIVE_KEYWORDS = ["DELETE", "DROP", "UPDATE"]


def _determine_severity(code_text: str) -> str:
    """쿼리 코드 컨텍스트로 severity 결정."""
    upper = code_text.upper()
    if any(kw in upper for kw in AUTH_KEYWORDS):
        return "CRITICAL"
    if any(kw in upper for kw in DESTRUCTIVE_KEYWORDS):
        return "CRITICAL"
    return "HIGH"


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

    def method_name(node):
        if node.type != "method_invocation":
            return None
        name_node = node.child_by_field_name("name")
        return text(name_node) if name_node else None

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
        sql_vars = {}

        def expression_has_taint(node):
            refs = identifiers(node)
            return contains_input_method(node) or bool(refs & tainted_vars)

        def is_unsafe_sql_expression(node):
            return contains_sql_keyword(node) and contains_sql_builder(node) and expression_has_taint(node)

        def update_variable(var_name, value_node, statement_node):
            if is_unsafe_sql_expression(value_node):
                sql_vars[var_name] = {
                    "line": statement_node.start_point[0] + 1,
                    "code": statement_node.text.decode().strip(),
                }
                tainted_vars.add(var_name)
                return

            if expression_has_taint(value_node):
                tainted_vars.add(var_name)
            else:
                tainted_vars.discard(var_name)

            sql_vars.pop(var_name, None)

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
                )
                return

            if is_unsafe_sql_expression(arguments):
                add_finding(
                    node=node,
                    line=node.start_point[0] + 1,
                    code=node.text.decode().strip(),
                    call_chain=build_call_chain(node),
                )

        def add_finding(node, line, code, call_chain):
            severity = _determine_severity(code)
            vuln_counter[0] += 1
            vulnerabilities.append(
                {
                    "id": f"VULN-{vuln_counter[0]:03d}",
                    "type": "SQL_INJECTION",
                    "severity": severity,
                    "cvss": get_cvss("SQL_INJECTION", severity),
                    "file": filepath,
                    "line": line,
                    "function": find_parent_method(node),
                    "code_snippet": code,
                    "call_chain": call_chain,
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

    for method_node in iter_methods(tree.root_node):
        analyze_method(method_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
