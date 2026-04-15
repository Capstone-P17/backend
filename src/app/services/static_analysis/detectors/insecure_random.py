from __future__ import annotations

from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method

# 보안 컨텍스트로 판단할 변수명 키워드
SECURITY_KEYWORDS = ["token", "session", "key", "nonce", "salt", "password", "passwd", "secret", "auth", "otp", "pin", "csrf", "random"]


def detect_insecure_random(filepath, tree, vuln_counter):
    """java.util.Random을 보안 컨텍스트에서 사용하는 경우 탐지.

    SecureRandom이 아닌 Random을 사용하면 예측 가능한 난수가 생성되어
    토큰/세션/키 등 보안 요소에 취약점이 발생합니다.
    """
    vulnerabilities = []

    def is_security_context(var_name: str) -> bool:
        name_lower = var_name.lower()
        return any(kw in name_lower for kw in SECURITY_KEYWORDS)

    def find_insecure_random(node):
        # new Random() 탐지 (SecureRandom 제외)
        if node.type == "object_creation_expression":
            text = node.text.decode()
            # new Random() 이지만 SecureRandom은 제외
            if "new Random(" in text and "SecureRandom" not in text:
                # 대입되는 변수명으로 보안 컨텍스트 판단
                var_name = _find_assigned_var_name(node)
                if var_name and is_security_context(var_name):
                    vuln_counter[0] += 1
                    class_name = find_parent_class(node)
                    method_name = find_parent_method(node)
                    chain = []
                    if class_name and method_name:
                        chain.append(f"{class_name}.{method_name}")
                    chain.append("new Random() → 예측 가능한 난수")
                    vulnerabilities.append(
                        {
                            "id": f"VULN-{vuln_counter[0]:03d}",
                            "type": "INSECURE_RANDOM",
                            "severity": "MEDIUM",
                            "cvss": get_cvss("INSECURE_RANDOM", "MEDIUM"),
                            "file": filepath,
                            "line": node.start_point[0] + 1,
                            "function": method_name,
                            "code_snippet": _get_declaration_snippet(node),
                            "call_chain": chain,
                            "description": "",
                        }
                    )

        for child in node.children:
            find_insecure_random(child)

    def _find_assigned_var_name(node):
        """object_creation_expression의 부모 variable_declarator에서 변수명 추출."""
        current = node.parent
        while current:
            if current.type == "variable_declarator":
                name_node = current.child_by_field_name("name")
                if name_node:
                    return name_node.text.decode()
            if current.type in ("local_variable_declaration", "field_declaration"):
                break
            current = current.parent
        return None

    def _get_declaration_snippet(node):
        """변수 선언 전체 코드를 코드 스니펫으로 반환."""
        current = node.parent
        while current:
            if current.type in ("local_variable_declaration", "field_declaration"):
                return current.text.decode().strip()
            current = current.parent
        return node.text.decode().strip()

    find_insecure_random(tree.root_node)
    return vulnerabilities
