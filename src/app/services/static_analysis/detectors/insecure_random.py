from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method

# 보안 컨텍스트로 판단할 변수명 키워드
SECURITY_KEYWORDS = ["token", "session", "key", "nonce", "salt", "password", "passwd", "secret", "auth", "otp", "pin", "csrf"]
NON_SECURITY_CONTEXT_KEYWORDS = ["dice", "roll", "page", "game", "shuffle", "simulation", "sample", "pager"]


def detect_insecure_random(filepath, tree, vuln_counter):
    """java.util.Random을 보안 컨텍스트에서 사용하는 경우 탐지.

    SecureRandom이 아닌 Random을 사용하면 예측 가능한 난수가 생성되어
    토큰/세션/키 등 보안 요소에 취약점이 발생합니다.
    """
    vulnerabilities = []

    def is_security_context(var_name: str) -> bool:
        name_lower = var_name.lower()
        return any(kw in name_lower for kw in SECURITY_KEYWORDS)

    def is_obvious_non_security_context(value: str) -> bool:
        lowered = value.lower()
        return any(keyword in lowered for keyword in NON_SECURITY_CONTEXT_KEYWORDS)

    def find_method_node(node):
        current = node.parent
        while current:
            if current.type == "method_declaration":
                return current
            current = current.parent
        return None

    def method_context_reason(node):
        method_node = find_method_node(node)
        if not method_node:
            return None
        name_node = method_node.child_by_field_name("name")
        method_name = name_node.text.decode() if name_node else ""
        if is_security_context(method_name):
            return f"메서드명 `{method_name}`의 보안값 생성 문맥"
        return None

    def method_name_for(node):
        method_node = find_method_node(node)
        if not method_node:
            return ""
        name_node = method_node.child_by_field_name("name")
        return name_node.text.decode() if name_node else ""

    def usage_context_reason(node, var_name):
        method_node = find_method_node(node)
        if not method_node or not var_name:
            return None
        for child in method_node.children:
            reason = _find_security_usage(child, var_name)
            if reason:
                return reason
        return None

    def _find_security_usage(node, var_name):
        node_text = node.text.decode()
        if var_name not in node_text:
            return None

        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node and value_node and var_name in value_node.text.decode() and is_security_context(name_node.text.decode()):
                return f"`{var_name}`에서 생성한 난수가 `{name_node.text.decode()}` 보안 변수에 저장되는 사용처"

        if node.type == "return_statement":
            method_reason = method_context_reason(node)
            if method_reason:
                return f"`{var_name}`에서 생성한 난수가 보안값 생성 메서드의 반환값으로 사용되는 흐름"

        for child in node.children:
            reason = _find_security_usage(child, var_name)
            if reason:
                return reason
        return None

    def find_insecure_random(node):
        # new Random() 탐지 (SecureRandom 제외)
        if node.type == "object_creation_expression":
            text = node.text.decode()
            # new Random() 이지만 SecureRandom은 제외
            if "new Random(" in text and "SecureRandom" not in text:
                # 대입되는 변수명으로 보안 컨텍스트 판단
                var_name = _find_assigned_var_name(node)
                context_reason = ""
                if var_name and is_security_context(var_name):
                    context_reason = f"변수명 `{var_name}`의 보안값 생성 문맥"
                if not context_reason:
                    context_reason = method_context_reason(node) or ""
                if not context_reason and var_name:
                    context_reason = usage_context_reason(node, var_name) or ""
                if not context_reason and is_obvious_non_security_context(f"{method_name_for(node)} {var_name}"):
                    return
                if not context_reason:
                    context_reason = "보안 사용 여부가 불명확한 `java.util.Random` 약한 PRNG 사용"

                if var_name and context_reason:
                    vuln_counter[0] += 1
                    class_name = find_parent_class(node)
                    method_name = find_parent_method(node)
                    chain = []
                    if class_name and method_name:
                        chain.append(f"{class_name}.{method_name}")
                    chain.append("new Random() → 예측 가능한 난수")
                    has_explicit_security_context = (
                        context_reason.startswith("메서드명")
                        or context_reason.startswith("변수명")
                        or "보안 변수" in context_reason
                        or "보안값 생성 메서드" in context_reason
                    )
                    confidence = "MEDIUM" if has_explicit_security_context else "LOW"
                    if has_explicit_security_context:
                        evidence = (
                            f"{context_reason}이 확인되었습니다. 해당 흐름에서 `{var_name}`에 예측 가능한 `new Random()` 생성기가 사용되었습니다. "
                            "토큰, 세션 ID, 키, nonce 등 보안 값에는 `java.util.Random` 대신 "
                            "`java.security.SecureRandom`을 사용해야 합니다."
                        )
                        confidence_reason = (
                            f"`new Random()` 생성 지점과 {context_reason}이 같은 메서드 범위에서 확인되어 MEDIUM으로 판단했습니다. "
                            "난수값이 외부로 전달되는 전체 경로까지는 추적하지 못하므로 HIGH가 아닌 MEDIUM으로 유지합니다."
                        )
                    else:
                        evidence = (
                            f"`{var_name}`에 예측 가능한 `new Random()` 생성기가 사용되었습니다. "
                            "명시적인 토큰/세션/키 변수명은 확인되지 않았지만, `java.util.Random`은 암호학적 보안 난수로 부적절하므로 "
                            "보안 목적 사용 여부를 검토해야 합니다."
                        )
                        confidence_reason = (
                            "`new Random()` 사용은 확인했지만 토큰, 세션, 키 등 명확한 보안 문맥은 확인되지 않아 LOW로 판단했습니다. "
                            "게임, 페이지 번호, 셔플 등 명백한 비보안 문맥은 제외했습니다."
                        )
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
                            "evidence": evidence,
                            "confidence": confidence,
                            "confidence_reason": confidence_reason,
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
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
