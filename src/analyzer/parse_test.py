import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

# 파서 초기화
parser = Parser(Language(tsjava.language()))

# Java 파일 읽기
with open("test_samples/UserDAO.java", "r") as f:
    code = f.read()

tree = parser.parse(bytes(code, "utf-8"))
root = tree.root_node

# AST 트리 출력
def print_tree(node, indent=0):
    text_preview = ""
    if node.child_count == 0:
        text_preview = f' → "{node.text.decode()[:50]}"'
    print(f"{' ' * indent}{node.type} [L{node.start_point[0]+1}:{node.start_point[1]}]{text_preview}")
    for child in node.children:
        print_tree(child, indent + 2)

print("=== AST 전체 구조 ===\n")
print_tree(root)

# 메서드 정의 추출
print("\n=== 메서드 정의 ===\n")
def find_methods(node):
    if node.type == "method_declaration":
        name_node = node.child_by_field_name("name")
        if name_node:
            print(f"  메서드: {name_node.text.decode()} (L{node.start_point[0]+1})")
    for child in node.children:
        find_methods(child)

find_methods(root)

# 메서드 호출 추출
print("\n=== 메서드 호출 ===\n")
def find_calls(node):
    if node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node:
            print(f"  호출: {name_node.text.decode()} (L{node.start_point[0]+1})")
    for child in node.children:
        find_calls(child)

find_calls(root)
