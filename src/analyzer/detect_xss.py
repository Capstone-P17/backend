import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))

# 사용자 입력을 가져오는 메서드
INPUT_METHODS = ["getParameter", "getHeader", "getCookies", "getQueryString", "getRequestURI"]

# 응답에 쓰는 메서드
OUTPUT_METHODS = ["println", "print", "write", "append"]

# HTML 태그 패턴
HTML_FRAGMENTS = ["<", ">", "</", "/>", "<h1", "<div", "<span", "<p", "<script", "<img", "<a "]


def detect_xss(filepath):
    with open(filepath, "r") as f:
        code = f.read()

    tree = parser.parse(bytes(code, "utf-8"))
    vulnerabilities = []

    # 1단계: getParameter() 등으로 받은 변수 수집
    user_input_vars = {}  # { 변수명: (라인, 코드) }

    def collect_user_inputs(node):
        if node.type in ("local_variable_declaration", "field_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")

                    if name_node and value_node:
                        if contains_input_method(value_node):
                            var_name = name_node.text.decode()
                            user_input_vars[var_name] = {
                                "line": name_node.start_point[0] + 1,
                                "code": node.text.decode().strip()
                            }

        for child in node.children:
            collect_user_inputs(child)

    def contains_input_method(node):
        """노드 안에 getParameter() 등의 호출이 있는지"""
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in INPUT_METHODS:
                return True
        for child in node.children:
            if contains_input_method(child):
                return True
        return False

    # 2단계: 출력 메서드에서 user_input 변수 + HTML이 함께 쓰이는지 확인
    def find_xss(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            if name_node and name_node.text.decode() in OUTPUT_METHODS:
                args = node.child_by_field_name("arguments")
                if args:
                    args_text = args.text.decode()

                    # 인자에 user_input 변수가 포함되어 있는지
                    has_user_input = any(
                        var in args_text for var in user_input_vars
                    )

                    # 인자에 HTML 태그가 포함되어 있는지
                    has_html = any(
                        frag in args_text for frag in HTML_FRAGMENTS
                    )

                    # 문자열 연결(+)이 있는지
                    has_concat = contains_binary_expression(args)

                    if has_user_input and has_html and has_concat:
                        # 어떤 user_input 변수가 사용됐는지 찾기
                        used_var = None
                        for var in user_input_vars:
                            if var in args_text:
                                used_var = var
                                break

                        vulnerabilities.append({
                            "id": f"VULN-{len(vulnerabilities)+1:03d}",
                            "type": "XSS",
                            "severity": "HIGH",
                            "file": filepath,
                            "line": node.start_point[0] + 1,
                            "function": find_parent_method(node),
                            "code_snippet": node.text.decode().strip(),
                            "call_chain": build_call_context(node, used_var),
                            "description": ""
                        })

        for child in node.children:
            find_xss(child)

    def contains_binary_expression(node):
        """노드 안에 + 연결이 있는지"""
        if node.type == "binary_expression":
            return True
        for child in node.children:
            if contains_binary_expression(child):
                return True
        return False

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

    def build_call_context(node, used_var):
        chain = []
        cls = find_parent_class(node)
        method = find_parent_method(node)
        if cls and method:
            chain.append(f"{cls}.{method}")

        # 입력 소스 추가
        if used_var and used_var in user_input_vars:
            chain.insert(0, f"req.getParameter → {used_var}")

        # 출력 싱크 추가
        name_node = node.child_by_field_name("name")
        obj_node = node.child_by_field_name("object")
        if obj_node and name_node:
            chain.append(f"resp.getWriter().{name_node.text.decode()}")
        
        return chain

    # 실행
    collect_user_inputs(tree.root_node)
    find_xss(tree.root_node)
    return vulnerabilities


if __name__ == "__main__":
    import json
    results = detect_xss("test_samples/UserDAO.java")

    print(f"탐지된 XSS: {len(results)}건\n")
    for v in results:
        print(f"[{v['severity']}] {v['type']}")
        print(f"  파일: {v['file']}:{v['line']}")
        print(f"  함수: {v['function']}")
        print(f"  코드: {v['code_snippet']}")
        print(f"  경로: {' → '.join(v['call_chain'])}")
        print()

    print("=== JSON 출력 ===\n")
    print(json.dumps(results, indent=2, ensure_ascii=False))
