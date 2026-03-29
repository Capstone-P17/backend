import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))

# SQL 실행 메서드 이름
SQL_EXEC_METHODS = ["executeQuery", "executeUpdate", "execute"]

# SQL 키워드 (문자열 안에 이게 있으면 SQL 쿼리로 판단)
SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"]


def detect_sql_injection(filepath):
    with open(filepath, "r") as f:
        code = f.read()
    
    tree = parser.parse(bytes(code, "utf-8"))
    lines = code.split("\n")
    vulnerabilities = []

    # 1단계: 문자열 연결로 만들어진 변수를 수집
    tainted_vars = {}  # { 변수명: (라인, 코드) }

    def collect_tainted_vars(node):
        """문자열 + 변수 연결로 만들어진 변수를 찾는다"""
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")

                    if name_node and value_node:
                        if has_string_concat_with_sql(value_node):
                            var_name = name_node.text.decode()
                            tainted_vars[var_name] = {
                                "line": name_node.start_point[0] + 1,
                                "code": node.text.decode().strip()
                            }

        for child in node.children:
            collect_tainted_vars(child)

    def has_string_concat_with_sql(node):
        """binary_expression(+) 안에 SQL 키워드가 포함된 문자열이 있는지"""
        if node.type == "binary_expression":
            text = node.text.decode()
            has_plus = "+" in text
            has_sql = any(kw in text.upper() for kw in SQL_KEYWORDS)
            has_identifier = any(
                child.type == "identifier" 
                for child in iterate_all(node)
            )
            return has_plus and has_sql and has_identifier
        return False

    def iterate_all(node):
        """노드의 모든 하위 노드를 순회"""
        yield node
        for child in node.children:
            yield from iterate_all(child)

    # 2단계: SQL 실행 메서드 호출에서 tainted 변수가 사용되는지 확인
    def find_sqli(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in SQL_EXEC_METHODS:
                args = node.child_by_field_name("arguments")
                if args:
                    for arg in args.children:
                        # 케이스 1: executeQuery(query) — tainted 변수가 인자로
                        if arg.type == "identifier" and arg.text.decode() in tainted_vars:
                            var_name = arg.text.decode()
                            tainted = tainted_vars[var_name]
                            vulnerabilities.append({
                                "id": f"VULN-{len(vulnerabilities)+1:03d}",
                                "type": "SQL_INJECTION",
                                "severity": "HIGH",
                                "file": filepath,
                                "line": tainted["line"],
                                "function": find_parent_method(node),
                                "code_snippet": tainted["code"],
                                "call_chain": build_call_context(node),
                                "description": ""
                            })
                        
                        # 케이스 2: executeQuery("SELECT..." + var) — 직접 연결
                        if arg.type == "binary_expression" and has_string_concat_with_sql(arg):
                            vulnerabilities.append({
                                "id": f"VULN-{len(vulnerabilities)+1:03d}",
                                "type": "SQL_INJECTION",
                                "severity": "HIGH",
                                "file": filepath,
                                "line": node.start_point[0] + 1,
                                "function": find_parent_method(node),
                                "code_snippet": node.text.decode().strip(),
                                "call_chain": build_call_context(node),
                                "description": ""
                            })

        for child in node.children:
            find_sqli(child)

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

    def build_call_context(node):
        """간단한 호출 컨텍스트 생성"""
        chain = []
        cls = find_parent_class(node)
        method = find_parent_method(node)
        if cls and method:
            chain.append(f"{cls}.{method}")
        
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if obj_node and name_node:
            chain.append(f"{obj_node.text.decode()}.{name_node.text.decode()}")
        elif name_node:
            chain.append(name_node.text.decode())
        
        return chain

    # 실행
    collect_tainted_vars(tree.root_node)
    find_sqli(tree.root_node)
    return vulnerabilities


if __name__ == "__main__":
    import json
    results = detect_sql_injection("test_samples/UserDAO.java")

    print(f"탐지된 SQL Injection: {len(results)}건\n")
    for v in results:
        print(f"[{v['severity']}] {v['type']}")
        print(f"  파일: {v['file']}:{v['line']}")
        print(f"  함수: {v['function']}")
        print(f"  코드: {v['code_snippet']}")
        print(f"  경로: {' → '.join(v['call_chain'])}")
        print()

    print("=== JSON 출력 ===\n")
    print(json.dumps(results, indent=2, ensure_ascii=False))
