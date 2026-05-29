from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]
OUTPUT_METHODS = ["println", "print", "write", "append"]
HTML_FRAGMENTS = ["<", ">", "</", "/>", "<h1", "<div", "<span", "<p", "<script", "<img", "<a "]
SANITIZER_METHODS = [
    "escapeHtml",
    "escapeHtml4",
    "escapeHtml3",
    "htmlEscape",
    "htmlEscapeDecimal",
    "htmlEscapeHex",
    "encodeForHTML",
    "encodeForHtml",
    "encodeForHTMLAttribute",
    "encodeForHtmlAttribute",
    "forHtml",
    "forHtmlContent",
    "forHtmlAttribute",
    "clean",
    "sanitize",
]


def detect_xss(filepath, tree, vuln_counter):
    vulnerabilities = []

    def text(node):
        return node.text.decode()

    def iter_methods(node):
        if node.type == "method_declaration":
            yield node
            return
        for child in node.children:
            yield from iter_methods(child)

    def contains_input_method(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and text(name_node) in INPUT_METHODS:
                return True
        for child in node.children:
            if contains_input_method(child):
                return True
        return False

    def contains_sanitizer(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and text(name_node) in SANITIZER_METHODS:
                return True
        for child in node.children:
            if contains_sanitizer(child):
                return True
        return False

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

    def identifiers(node):
        return {text(child) for child in iterate_all(node) if child.type == "identifier"}

    def analyze_method(method_node):
        user_input_vars = {}
        tainted_vars = set()
        sanitized_vars = set()

        def remember_taint(var_name, source_node, source_var=None):
            tainted_vars.add(var_name)
            sanitized_vars.discard(var_name)
            source = user_input_vars.get(source_var) if source_var else None
            user_input_vars[var_name] = source or {
                "line": source_node.start_point[0] + 1,
                "code": source_node.text.decode().strip(),
                "input_call": text(find_input_call(source_node)) if find_input_call(source_node) else None,
            }

        def remember_sanitized(var_name):
            sanitized_vars.add(var_name)
            tainted_vars.discard(var_name)

        def clear_tracking(var_name):
            tainted_vars.discard(var_name)
            sanitized_vars.discard(var_name)
            user_input_vars.pop(var_name, None)

        def update_variable(var_name, value_node, statement_node):
            refs = identifiers(value_node)
            source_var = next((name for name in refs if name in tainted_vars), None)
            sanitized_source_var = next((name for name in refs if name in sanitized_vars), None)

            if contains_sanitizer(value_node):
                remember_sanitized(var_name)
            elif contains_input_method(value_node):
                remember_taint(var_name, statement_node)
            elif source_var:
                remember_taint(var_name, statement_node, source_var)
            elif sanitized_source_var:
                remember_sanitized(var_name)
            else:
                clear_tracking(var_name)

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
                return

            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and left.type == "identifier":
                    update_variable(text(left), right, node)
                return

            if node.type == "method_invocation":
                inspect_output(node)

            for child in node.children:
                visit(child)

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

            if has_user_input and has_html and has_concat and not is_sanitized:
                used_var = unsafe_vars[0] if unsafe_vars else None
                vuln_counter[0] += 1
                vulnerabilities.append(
                    {
                        "id": f"VULN-{vuln_counter[0]:03d}",
                        "type": "XSS",
                        "severity": "HIGH",
                        "cvss": get_cvss("XSS", "HIGH"),
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

        visit(method_node)

    def contains_binary_expression(node):
        if node.type == "binary_expression":
            return True
        for child in node.children:
            if contains_binary_expression(child):
                return True
        return False

    def build_xss_chain(node, used_var, user_input_vars):
        chain = []
        if used_var and used_var in user_input_vars:
            source_code = user_input_vars[used_var]["code"]
            if "getHeader" in source_code:
                chain.append(f"req.getHeader → {used_var}")
            elif "getQueryString" in source_code:
                chain.append(f"req.getQueryString → {used_var}")
            elif "getCookies" in source_code:
                chain.append(f"req.getCookies → {used_var}")
            else:
                chain.append(f"req.getParameter → {used_var}")
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
            source = user_input_vars[used_var].get("input_call") or user_input_vars[used_var]["code"]
            return (
                f"`{source}`에서 온 `{used_var}` 값이 HTML 문자열과 결합되어 "
                f"`{sink}`로 출력되며, HTML 이스케이프 처리가 확인되지 않았습니다."
            )
        if direct_input_call:
            return (
                f"`{direct_input_call}` 입력이 HTML 문자열과 직접 결합되어 "
                f"`{sink}`로 출력되며, HTML 이스케이프 처리가 확인되지 않았습니다."
            )
        return f"외부 입력 값이 HTML 문자열과 결합되어 `{sink}`로 출력되며, HTML 이스케이프 처리가 확인되지 않았습니다."

    def build_xss_confidence_reason(node, used_var, user_input_vars, direct_input_call):
        sink = build_output_name(node)
        if used_var and used_var in user_input_vars:
            source = user_input_vars[used_var].get("input_call") or user_input_vars[used_var]["code"]
            source_desc = f"`{source}` 입력 출처와 `{used_var}` 변수 흐름"
        elif direct_input_call:
            source_desc = f"`{direct_input_call}` 직접 입력 출처"
        else:
            source_desc = "외부 입력으로 추정되는 값"
        return (
            f"{source_desc}, HTML 조각과의 문자열 결합, `{sink}` 응답 출력 API가 같은 흐름에서 확인되어 HIGH로 판단했습니다. "
            "탐지 가능한 HTML 이스케이프 또는 sanitizer 호출은 출력 직전까지 확인되지 않았습니다."
        )

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
