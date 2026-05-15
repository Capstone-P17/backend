from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

SECRET_KEYWORDS = ["password", "passwd", "secret", "api_key", "apikey", "token", "credential"]
SECRET_USAGE_METHODS = {
    "connect",
    "getConnection",
    "login",
    "authenticate",
    "authorize",
    "sign",
    "verify",
    "setPassword",
    "setToken",
    "setApiKey",
    "setSecret",
}


def _text(node):
    return node.text.decode()


def _nearest_usage_context(node):
    current = node.parent
    while current:
        if current.type in {
            "method_invocation",
            "object_creation_expression",
            "assignment_expression",
            "return_statement",
        }:
            return current
        current = current.parent
    return None


def _usage_method_name(node):
    context = _nearest_usage_context(node)
    if not context or context.type != "method_invocation":
        return None
    name_node = context.child_by_field_name("name")
    return _text(name_node) if name_node else None


def _is_relevant_secret_usage(node):
    method_name = _usage_method_name(node)
    if method_name and method_name in SECRET_USAGE_METHODS:
        return True
    context = _nearest_usage_context(node)
    return context is not None and context.type in {"object_creation_expression", "assignment_expression", "return_statement"}


def _build_secret_chain(declaration_node, usage_node):
    chain = []
    class_name = find_parent_class(usage_node)
    method_name = find_parent_method(usage_node)
    if class_name and method_name:
        chain.append(f"{class_name}.{method_name}")
    elif method_name:
        chain.append(method_name)

    usage_method = _usage_method_name(usage_node)
    if usage_method:
        chain.append(usage_method)
    else:
        context = _nearest_usage_context(usage_node)
        if context:
            chain.append(context.type)

    chain.append(f"선언 line {declaration_node.start_point[0] + 1}")
    chain.append(f"사용 line {usage_node.start_point[0] + 1}")
    return chain


def detect_hardcoded_secrets(filepath, tree, vuln_counter):
    vulnerabilities = []
    candidates = {}

    def visit(node):
        if node.type in ("field_declaration", "local_variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node:
                        var_name = name_node.text.decode().lower()
                        has_keyword = any(keyword in var_name for keyword in SECRET_KEYWORDS)
                        is_string = value_node.type == "string_literal"
                        if has_keyword and is_string:
                            candidates[name_node.text.decode()] = {
                                "declaration": node,
                                "name": name_node,
                            }
        for child in node.children:
            visit(child)

    visit(tree.root_node)

    reported = set()
    for node in iterate_all(tree.root_node):
        if node.type != "identifier":
            continue
        var_name = _text(node)
        candidate = candidates.get(var_name)
        if not candidate or var_name in reported:
            continue
        if node.start_byte == candidate["name"].start_byte and node.end_byte == candidate["name"].end_byte:
            continue
        if not _is_relevant_secret_usage(node):
            continue

        declaration = candidate["declaration"]
        vuln_counter[0] += 1
        reported.add(var_name)
        vulnerabilities.append(
            {
                "id": f"VULN-{vuln_counter[0]:03d}",
                "type": "HARDCODED_SECRET",
                "severity": "MEDIUM",
                "cvss": get_cvss("HARDCODED_SECRET", "MEDIUM"),
                "file": filepath,
                "line": candidate["name"].start_point[0] + 1,
                "function": find_parent_method(declaration),
                "code_snippet": declaration.text.decode().strip(),
                "call_chain": _build_secret_chain(declaration, node),
                "description": "",
            }
        )

    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
