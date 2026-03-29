import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))

# 비밀번호로 의심되는 변수명 키워드
SECRET_KEYWORDS = ["password", "passwd", "secret", "api_key", "apikey", "token", "credential"]

def detect_hardcoded_secrets(filepath):
    with open(filepath, "r") as f:
        code = f.read()
    
    tree = parser.parse(bytes(code, "utf-8"))
    vulnerabilities = []

    def visit(node):
        # field_declaration (클래스 필드) 또는 local_variable_declaration (로컬 변수)
        if node.type in ("field_declaration", "local_variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")

                    if name_node and value_node:
                        var_name = name_node.text.decode().lower()
                        
                        # 변수명에 비밀번호 관련 키워드가 포함되어 있는지
                        has_keyword = any(kw in var_name for kw in SECRET_KEYWORDS)
                        
                        # 값이 문자열 리터럴인지
                        is_string = value_node.type == "string_literal"

                        if has_keyword and is_string:
                            vulnerabilities.append({
                                "id": f"VULN-{len(vulnerabilities)+1:03d}",
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

    def find_parent_method(node):
        """현재 노드가 속한 메서드 이름을 찾는다"""
        current = node.parent
        while current:
            if current.type == "method_declaration":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return name_node.text.decode()
            current = current.parent
        return None  # 메서드 밖 (클래스 필드)

    visit(tree.root_node)
    return vulnerabilities


if __name__ == "__main__":
    import json
    results = detect_hardcoded_secrets("test_samples/UserDAO.java")
    
    print(f"탐지된 취약점: {len(results)}건\n")
    for v in results:
        print(f"[{v['severity']}] {v['type']}")
        print(f"  파일: {v['file']}:{v['line']}")
        print(f"  함수: {v['function'] or '(클래스 필드)'}")
        print(f"  코드: {v['code_snippet']}")
        print()
    
    print("=== JSON 출력 ===\n")
    print(json.dumps(results, indent=2, ensure_ascii=False))
