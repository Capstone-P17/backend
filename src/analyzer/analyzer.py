import os
import json
from datetime import datetime
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))

# ============================================================
# 설정값
# ============================================================

SECRET_KEYWORDS = ["password", "passwd", "secret", "api_key", "apikey", "token", "credential"]
SQL_EXEC_METHODS = ["executeQuery", "executeUpdate", "execute"]
SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"]
INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]
OUTPUT_METHODS = ["println", "print", "write", "append"]
HTML_FRAGMENTS = ["<", ">", "</", "/>", "<h1", "<div", "<span", "<p", "<script", "<img", "<a "]


# ============================================================
# 공통 유틸리티
# ============================================================

def find_parent_method(node):
    current = node.parent
    while current:
        if current.type == "method_declaration":
            name_node = current.child_by_field_name("name")
            if name_node:
                return name_node.text.decode()
        current = current.parent
    return None

def find_parent_class(node):
    current = node.parent
    while current:
        if current.type == "class_declaration":
            name_node = current.child_by_field_name("name")
            if name_node:
                return name_node.text.decode()
        current = current.parent
    return None

def iterate_all(node):
    yield node
    for child in node.children:
        yield from iterate_all(child)

def parse_file(filepath):
    with open(filepath, "r") as f:
        code = f.read()
    tree = parser.parse(bytes(code, "utf-8"))
    return tree, code


# ============================================================
# 1. Hardcoded Secret 탐지
# ============================================================

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
                        has_keyword = any(kw in var_name for kw in SECRET_KEYWORDS)
                        is_string = value_node.type == "string_literal"
                        if has_keyword and is_string:
                            vuln_counter[0] += 1
                            vulnerabilities.append({
                                "id": f"VULN-{vuln_counter[0]:03d}",
                                "type": "HARDCODED_SECRET",
                                "severity": "MEDIUM",
                                "file": filepath,
                                "line": name_node.start_point[0] + 1,
                                "function": find_parent_method(node),
                                "code_snippet": node.text.decode().strip(),
                                "call_chain": [],
                                "description": ""
                            })
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return vulnerabilities


# ============================================================
# 2. SQL Injection 탐지
# ============================================================

def detect_sql_injection(filepath, tree, vuln_counter):
    vulnerabilities = []
    tainted_vars = {}

    def collect_tainted_vars(node):
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node:
                        if has_string_concat_with_sql(value_node):
                            tainted_vars[name_node.text.decode()] = {
                                "line": name_node.start_point[0] + 1,
                                "code": node.text.decode().strip()
                            }
        for child in node.children:
            collect_tainted_vars(child)

    def has_string_concat_with_sql(node):
        if node.type == "binary_expression":
            text = node.text.decode()
            has_plus = "+" in text
            has_sql = any(kw in text.upper() for kw in SQL_KEYWORDS)
            has_identifier = any(child.type == "identifier" for child in iterate_all(node))
            return has_plus and has_sql and has_identifier
        return False

    def find_sqli(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in SQL_EXEC_METHODS:
                args = node.child_by_field_name("arguments")
                if args:
                    for arg in args.children:
                        if arg.type == "identifier" and arg.text.decode() in tainted_vars:
                            var_name = arg.text.decode()
                            tainted = tainted_vars[var_name]
                            vuln_counter[0] += 1
                            vulnerabilities.append({
                                "id": f"VULN-{vuln_counter[0]:03d}",
                                "type": "SQL_INJECTION",
                                "severity": "HIGH",
                                "file": filepath,
                                "line": tainted["line"],
                                "function": find_parent_method(node),
                                "code_snippet": tainted["code"],
                                "call_chain": build_call_chain(node),
                                "description": ""
                            })
                        if arg.type == "binary_expression" and has_string_concat_with_sql(arg):
                            vuln_counter[0] += 1
                            vulnerabilities.append({
                                "id": f"VULN-{vuln_counter[0]:03d}",
                                "type": "SQL_INJECTION",
                                "severity": "HIGH",
                                "file": filepath,
                                "line": node.start_point[0] + 1,
                                "function": find_parent_method(node),
                                "code_snippet": node.text.decode().strip(),
                                "call_chain": build_call_chain(node),
                                "description": ""
                            })
        for child in node.children:
            find_sqli(child)

    def build_call_chain(node):
        chain = []
        cls = find_parent_class(node)
        method = find_parent_method(node)
        if cls and method:
            chain.append(f"{cls}.{method}")
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if obj_node and name_node:
            chain.append(f"{obj_node.text.decode()}.{name_node.text.decode()}")
        return chain

    collect_tainted_vars(tree.root_node)
    find_sqli(tree.root_node)
    return vulnerabilities


# ============================================================
# 3. XSS 탐지
# ============================================================

def detect_xss(filepath, tree, vuln_counter):
    vulnerabilities = []
    user_input_vars = {}

    def collect_user_inputs(node):
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node:
                        if contains_input_method(value_node):
                            user_input_vars[name_node.text.decode()] = {
                                "line": name_node.start_point[0] + 1,
                                "code": node.text.decode().strip()
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
                args = node.child_by_field_name("arguments")
                if args:
                    args_text = args.text.decode()
                    has_user_input = any(var in args_text for var in user_input_vars)
                    has_html = any(frag in args_text for frag in HTML_FRAGMENTS)
                    has_concat = contains_binary_expression(args)
                    if has_user_input and has_html and has_concat:
                        used_var = None
                        for var in user_input_vars:
                            if var in args_text:
                                used_var = var
                                break
                        vuln_counter[0] += 1
                        vulnerabilities.append({
                            "id": f"VULN-{vuln_counter[0]:03d}",
                            "type": "XSS",
                            "severity": "HIGH",
                            "file": filepath,
                            "line": node.start_point[0] + 1,
                            "function": find_parent_method(node),
                            "code_snippet": node.text.decode().strip(),
                            "call_chain": build_xss_chain(node, used_var),
                            "description": ""
                        })
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
        cls = find_parent_class(node)
        method = find_parent_method(node)
        if cls and method:
            chain.append(f"{cls}.{method}")
        name_node = node.child_by_field_name("name")
        if name_node:
            chain.append(f"resp.getWriter().{name_node.text.decode()}")
        return chain

    collect_user_inputs(tree.root_node)
    find_xss(tree.root_node)
    return vulnerabilities


# ============================================================
# 4. Call Graph 생성
# ============================================================

def build_call_graph(tree):
    call_graph = {}

    def visit(node):
        if node.type == "method_declaration":
            cls = find_parent_class(node)
            name_node = node.child_by_field_name("name")
            if name_node:
                method_name = name_node.text.decode()
                key = f"{cls}.{method_name}" if cls else method_name
                calls = []
                collect_calls(node, calls)
                if calls:
                    call_graph[key] = calls
        for child in node.children:
            visit(child)

    def collect_calls(node, calls):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            obj_node = node.child_by_field_name("object")
            if name_node:
                if obj_node:
                    call_name = f"{obj_node.text.decode()}.{name_node.text.decode()}"
                else:
                    call_name = name_node.text.decode()
                if call_name not in calls:
                    calls.append(call_name)
        for child in node.children:
            collect_calls(child, calls)

    visit(tree.root_node)
    return call_graph


# ============================================================
# 5. 통합 분석 실행
# ============================================================

def analyze_file(filepath):
    tree, code = parse_file(filepath)
    vuln_counter = [0]  # 리스트로 감싸서 내부 함수에서 공유

    vulns = []
    vulns += detect_hardcoded_secrets(filepath, tree, vuln_counter)
    vulns += detect_sql_injection(filepath, tree, vuln_counter)
    vulns += detect_xss(filepath, tree, vuln_counter)

    call_graph = build_call_graph(tree)

    summary = {
        "total_vulnerabilities": len(vulns),
        "by_severity": {
            "HIGH": sum(1 for v in vulns if v["severity"] == "HIGH"),
            "MEDIUM": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "LOW": sum(1 for v in vulns if v["severity"] == "LOW")
        },
        "by_type": {
            "SQL_INJECTION": sum(1 for v in vulns if v["type"] == "SQL_INJECTION"),
            "XSS": sum(1 for v in vulns if v["type"] == "XSS"),
            "HARDCODED_SECRET": sum(1 for v in vulns if v["type"] == "HARDCODED_SECRET")
        }
    }

    return {
        "analysis_result": {
            "repository": "",
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": 1,
            "vulnerabilities": vulns,
            "call_graph": call_graph,
            "summary": summary
        }
    }


def analyze_directory(directory, repository=""):
    """디렉토리 내 모든 .java 파일을 분석"""
    all_vulns = []
    all_call_graph = {}
    vuln_counter = [0]
    file_count = 0

    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".java"):
                filepath = os.path.join(root, filename)
                file_count += 1
                tree, code = parse_file(filepath)

                all_vulns += detect_hardcoded_secrets(filepath, tree, vuln_counter)
                all_vulns += detect_sql_injection(filepath, tree, vuln_counter)
                all_vulns += detect_xss(filepath, tree, vuln_counter)

                file_call_graph = build_call_graph(tree)
                all_call_graph.update(file_call_graph)

    summary = {
        "total_vulnerabilities": len(all_vulns),
        "by_severity": {
            "HIGH": sum(1 for v in all_vulns if v["severity"] == "HIGH"),
            "MEDIUM": sum(1 for v in all_vulns if v["severity"] == "MEDIUM"),
            "LOW": sum(1 for v in all_vulns if v["severity"] == "LOW")
        },
        "by_type": {
            "SQL_INJECTION": sum(1 for v in all_vulns if v["type"] == "SQL_INJECTION"),
            "XSS": sum(1 for v in all_vulns if v["type"] == "XSS"),
            "HARDCODED_SECRET": sum(1 for v in all_vulns if v["type"] == "HARDCODED_SECRET")
        }
    }

    return {
        "analysis_result": {
            "repository": repository,
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": file_count,
            "vulnerabilities": all_vulns,
            "call_graph": all_call_graph,
            "summary": summary
        }
    }


# ============================================================
# 실행
# ============================================================

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "test_samples"

    if os.path.isfile(target):
        result = analyze_file(target)
    else:
        result = analyze_directory(target)

    # 콘솔 요약 출력
    summary = result["analysis_result"]["summary"]
    vulns = result["analysis_result"]["vulnerabilities"]
    call_graph = result["analysis_result"]["call_graph"]

    print("=" * 60)
    print("  소스코드 보안취약점 분석 결과")
    print("=" * 60)
    print(f"\n  분석 파일 수: {result['analysis_result']['files_analyzed']}")
    print(f"  총 취약점: {summary['total_vulnerabilities']}건")
    print(f"  HIGH: {summary['by_severity']['HIGH']} | MEDIUM: {summary['by_severity']['MEDIUM']} | LOW: {summary['by_severity']['LOW']}")
    print()

    for v in vulns:
        print(f"  [{v['severity']}] {v['type']}")
        print(f"    위치: {v['file']}:{v['line']}")
        print(f"    함수: {v['function'] or '(클래스 필드)'}")
        print(f"    코드: {v['code_snippet']}")
        if v['call_chain']:
            print(f"    경로: {' → '.join(v['call_chain'])}")
        print()

    print("=" * 60)
    print("  Call Graph")
    print("=" * 60)
    for method, calls in call_graph.items():
        print(f"\n  {method}")
        for call in calls:
            print(f"    → {call}")

    # JSON 파일 저장
    output_path = "analysis_result.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n\n결과 JSON 저장: {output_path}")
