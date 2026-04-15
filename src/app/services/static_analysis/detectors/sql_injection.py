from __future__ import annotations

from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import (
    find_parent_class,
    find_parent_method,
    iterate_all,
)

SQL_EXEC_METHODS = ["executeQuery", "executeUpdate", "execute"]
SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"]

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
    tainted_vars = {}

    def collect_tainted_vars(node):
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node and has_string_concat_with_sql(value_node):
                        key = f"{name_node.text.decode()}_{name_node.start_point[0]}"
                        tainted_vars[key] = {
                            "var_name": name_node.text.decode(),
                            "line": name_node.start_point[0] + 1,
                            "code": node.text.decode().strip(),
                            "method": find_parent_method(node),
                        }
        for child in node.children:
            collect_tainted_vars(child)

    def has_string_concat_with_sql(node):
        if node.type == "binary_expression":
            text = node.text.decode()
            has_plus = "+" in text
            has_sql = any(keyword in text.upper() for keyword in SQL_KEYWORDS)
            has_identifier = any(child.type == "identifier" for child in iterate_all(node))
            return has_plus and has_sql and has_identifier
        return False

    def find_sqli(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in SQL_EXEC_METHODS:
                arguments = node.child_by_field_name("arguments")
                if arguments:
                    for arg in arguments.children:
                        if arg.type == "identifier":
                            arg_name = arg.text.decode()
                            current_method = find_parent_method(node)
                            matched = [
                                key
                                for key, value in tainted_vars.items()
                                if value["var_name"] == arg_name and value["method"] == current_method
                            ]
                            if matched:
                                closest = min(
                                    matched,
                                    key=lambda key: abs(
                                        tainted_vars[key]["line"] - (arg.start_point[0] + 1)
                                    ),
                                )
                                var = tainted_vars[closest]
                                severity = _determine_severity(var["code"])
                                vuln_counter[0] += 1
                                vulnerabilities.append(
                                    {
                                        "id": f"VULN-{vuln_counter[0]:03d}",
                                        "type": "SQL_INJECTION",
                                        "severity": severity,
                                        "cvss": get_cvss("SQL_INJECTION", severity),
                                        "file": filepath,
                                        "line": var["line"],
                                        "function": current_method,
                                        "code_snippet": var["code"],
                                        "call_chain": build_call_chain(node),
                                        "description": "",
                                    }
                                )
                        if arg.type == "binary_expression" and has_string_concat_with_sql(arg):
                            severity = _determine_severity(node.text.decode())
                            vuln_counter[0] += 1
                            vulnerabilities.append(
                                {
                                    "id": f"VULN-{vuln_counter[0]:03d}",
                                    "type": "SQL_INJECTION",
                                    "severity": severity,
                                    "cvss": get_cvss("SQL_INJECTION", severity),
                                    "file": filepath,
                                    "line": node.start_point[0] + 1,
                                    "function": find_parent_method(node),
                                    "code_snippet": node.text.decode().strip(),
                                    "call_chain": build_call_chain(node),
                                    "description": "",
                                }
                            )
        for child in node.children:
            find_sqli(child)

    def build_call_chain(node):
        chain = []
        class_name = find_parent_class(node)
        method_name = find_parent_method(node)
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        name_node = node.child_by_field_name("name")
        object_node = node.child_by_field_name("object")
        if object_node and name_node:
            chain.append(f"{object_node.text.decode()}.{name_node.text.decode()}")
        return chain

    collect_tainted_vars(tree.root_node)
    find_sqli(tree.root_node)
    return vulnerabilities
