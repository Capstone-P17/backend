from __future__ import annotations

from src.app.services.static_analysis.parser import find_parent_method

SECRET_KEYWORDS = ["password", "passwd", "secret", "api_key", "apikey", "token", "credential"]


def detect_hardcoded_secrets(filepath, tree, vuln_counter):
    vulnerabilities = []

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
                            vuln_counter[0] += 1
                            vulnerabilities.append(
                                {
                                    "id": f"VULN-{vuln_counter[0]:03d}",
                                    "type": "HARDCODED_SECRET",
                                    "severity": "MEDIUM",
                                    "file": filepath,
                                    "line": name_node.start_point[0] + 1,
                                    "function": find_parent_method(node),
                                    "code_snippet": node.text.decode().strip(),
                                    "call_chain": [],
                                    "description": "",
                                }
                            )
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return vulnerabilities
