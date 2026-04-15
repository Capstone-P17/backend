from __future__ import annotations

from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method

INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]
OUTPUT_METHODS = ["println", "print", "write", "append"]
HTML_FRAGMENTS = ["<", ">", "</", "/>", "<h1", "<div", "<span", "<p", "<script", "<img", "<a "]


def detect_xss(filepath, tree, vuln_counter):
    vulnerabilities = []
    user_input_vars = {}

    def collect_user_inputs(node):
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node and contains_input_method(value_node):
                        user_input_vars[name_node.text.decode()] = {
                            "line": name_node.start_point[0] + 1,
                            "code": node.text.decode().strip(),
                        }
        for child in node.children:
            collect_user_inputs(child)

    def contains_input_method(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in INPUT_METHODS:
                return True
        for child in node.children:
            if contains_input_method(child):
                return True
        return False

    def find_xss(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in OUTPUT_METHODS:
                arguments = node.child_by_field_name("arguments")
                if arguments:
                    args_text = arguments.text.decode()
                    has_user_input = any(var in args_text for var in user_input_vars)
                    has_html = any(fragment in args_text for fragment in HTML_FRAGMENTS)
                    has_concat = contains_binary_expression(arguments)
                    if has_user_input and has_html and has_concat:
                        used_var = next((var for var in user_input_vars if var in args_text), None)
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
                                "call_chain": build_xss_chain(node, used_var),
                                "description": "",
                            }
                        )
        for child in node.children:
            find_xss(child)

    def contains_binary_expression(node):
        if node.type == "binary_expression":
            return True
        for child in node.children:
            if contains_binary_expression(child):
                return True
        return False

    def build_xss_chain(node, used_var):
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

    collect_user_inputs(tree.root_node)
    find_xss(tree.root_node)
    return vulnerabilities
