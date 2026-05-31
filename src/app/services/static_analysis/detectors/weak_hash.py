from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

WEAK_ALGORITHMS = {"MD5", "MD4", "MD2", "SHA-1", "SHA1"}
PASSWORD_CONTEXT_TERMS = (
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "secret",
    "token",
    "auth",
)
NON_PASSWORD_CONTEXT_TERMS = (
    "checksum",
    "etag",
    "fingerprint",
    "file",
    "bytes",
    "integrity",
)
KDF_OR_PASSWORD_HASH_TERMS = (
    "PBKDF2",
    "SecretKeyFactory",
    "PBEKeySpec",
    "BCrypt",
    "SCrypt",
    "Argon2",
)
SALT_TERMS = ("salt", "gensalt")


def _node_text(node) -> str:
    return node.text.decode(errors="ignore") if node else ""


def _normalized_algorithm(algorithm: str) -> str:
    return algorithm.upper().replace("_", "-")


def _string_literal_arguments(args_node) -> list[str]:
    literals = []
    for child in iterate_all(args_node):
        if child.type == "string_literal":
            literals.append(_node_text(child).strip('"').strip("'"))
    return literals


def _first_argument_text(args_node) -> str:
    if not args_node:
        return ""
    for child in args_node.children:
        if child.type not in {"(", ")", ","}:
            return _node_text(child)
    return ""


def _contains_any(value: str, terms: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(term.lower() in lowered for term in terms)


def _method_declaration_for(node):
    current = node.parent
    while current:
        if current.type == "method_declaration":
            return current
        current = current.parent
    return None


def _digest_variable_for_get_instance(node) -> str | None:
    current = node.parent
    while current:
        if current.type == "variable_declarator":
            name_node = current.child_by_field_name("name")
            return _node_text(name_node) if name_node else None
        if current.type == "assignment_expression":
            left_node = current.child_by_field_name("left")
            return _node_text(left_node).split(".")[-1] if left_node else None
        if current.type in {"method_declaration", "class_declaration"}:
            return None
        current = current.parent
    return None


def _has_salt_or_kdf(method_text: str) -> bool:
    return _contains_any(method_text, KDF_OR_PASSWORD_HASH_TERMS) or _contains_any(method_text, SALT_TERMS)


def _is_digest_call(node, digest_variables: set[str]) -> bool:
    if node.type != "method_invocation":
        return False
    name_node = node.child_by_field_name("name")
    if not name_node or _node_text(name_node) != "digest":
        return False
    object_node = node.child_by_field_name("object")
    if object_node is None:
        return True
    return _node_text(object_node) in digest_variables


def _password_digest_argument(method_node, digest_variables: set[str]) -> str:
    for node in iterate_all(method_node):
        if not _is_digest_call(node, digest_variables):
            continue
        args_node = node.child_by_field_name("arguments")
        argument_text = _first_argument_text(args_node)
        if _contains_any(argument_text, PASSWORD_CONTEXT_TERMS):
            return argument_text
    return ""


def detect_weak_hash(filepath, tree, vuln_counter):
    """취약한 해시 알고리즘 사용 탐지.

    MD5, SHA-1 등 충돌 취약 알고리즘 사용과, 비밀번호/토큰 문맥에서 salt 또는
    KDF 없이 일반 해시 함수를 사용하는 패턴을 구분해 탐지합니다.
    """
    vulnerabilities = []
    seen_locations: set[tuple[int, str]] = set()

    for node in iterate_all(tree.root_node):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        args_node = node.child_by_field_name("arguments")
        if not name_node or _node_text(name_node) != "getInstance" or not args_node:
            continue

        algorithms = _string_literal_arguments(args_node)
        if not algorithms:
            continue

        for algorithm in algorithms:
            normalized_algorithm = _normalized_algorithm(algorithm)
            method_node = _method_declaration_for(node)
            method_text = _node_text(method_node)
            method_signature = method_text.split("{", 1)[0]
            digest_variable = _digest_variable_for_get_instance(node)
            digest_variables = {digest_variable} if digest_variable else set()
            class_name = find_parent_class(node)
            method_name = find_parent_method(node)
            chain = []
            if class_name and method_name:
                chain.append(f"{class_name}.{method_name}")
            chain.append(f'MessageDigest.getInstance("{algorithm}")')

            is_weak_algorithm = normalized_algorithm in {_normalized_algorithm(value) for value in WEAK_ALGORITHMS}
            password_argument = _password_digest_argument(method_node, digest_variables) if method_node else ""
            has_password_context = _contains_any(method_signature, PASSWORD_CONTEXT_TERMS)
            has_non_password_context = _contains_any(method_signature, NON_PASSWORD_CONTEXT_TERMS)
            has_salt_or_kdf = _has_salt_or_kdf(method_text)
            is_unsalted_password_hash = (
                not is_weak_algorithm
                and has_password_context
                and password_argument
                and not has_salt_or_kdf
                and not has_non_password_context
            )

            if not is_weak_algorithm and not is_unsalted_password_hash:
                continue

            key = (node.start_point[0], normalized_algorithm)
            if key in seen_locations:
                continue
            seen_locations.add(key)

            vuln_counter[0] += 1
            if is_weak_algorithm:
                chain.append("취약 알고리즘")
                evidence_parts = [
                    f'`MessageDigest.getInstance("{algorithm}")` 호출이 확인되었습니다.',
                    "MD5/SHA-1/MD2 계열 해시는 충돌 공격에 취약해 보안 목적의 해시로 사용하기에 부적절합니다.",
                ]
                confidence = "HIGH"
                confidence_reason = (
                    f"`{algorithm}` 알고리즘 이름이 코드에 직접 지정되어 있고, "
                    "알려진 취약 해시 알고리즘 목록과 일치하므로 HIGH로 판단했습니다."
                )
                if has_password_context:
                    evidence_parts.append("또한 메서드/인자명에서 비밀번호·토큰 등 민감값 문맥이 확인되었습니다.")
            else:
                chain.append("salt/KDF 없는 비밀번호 해시")
                evidence_parts = [
                    f'`MessageDigest.getInstance("{algorithm}")` 자체는 약한 알고리즘은 아니지만,',
                    f"`{password_argument}` 값을 일반 해시 `digest()`에 전달하는 흐름이 확인되었습니다.",
                    "비밀번호/토큰 저장에는 salt와 반복 비용을 갖는 PBKDF2, bcrypt, scrypt, Argon2 같은 전용 KDF가 필요합니다.",
                    "현재 메서드 범위에서 salt 또는 KDF 사용은 확인되지 않았습니다.",
                ]
                confidence = "MEDIUM"
                confidence_reason = (
                    "메서드명/인자명과 digest 호출 인자에서 비밀번호 또는 인증값 문맥이 확인되었지만, "
                    "파일 간 데이터 흐름 전체까지 검증하지는 못하므로 MEDIUM으로 판단했습니다."
                )

            vulnerabilities.append(
                {
                    "id": f"VULN-{vuln_counter[0]:03d}",
                    "type": "WEAK_HASH",
                    "file": filepath,
                    "line": node.start_point[0] + 1,
                    "function": method_name,
                    "code_snippet": _node_text(node).strip(),
                    "call_chain": chain,
                    "description": "",
                    "evidence": " ".join(evidence_parts),
                    "recommendation": (
                        "MD5/SHA-1/MD2는 사용하지 말고, 일반 무결성 해시는 SHA-256 이상을 사용하세요. "
                        "비밀번호 저장은 MessageDigest 직접 사용 대신 PBKDF2, bcrypt, scrypt, Argon2처럼 salt와 반복 비용을 갖는 KDF를 사용하세요."
                    ),
                    "safe_example": (
                        'byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);\n'
                        "PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 256);\n"
                        'SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\n'
                        "byte[] hash = factory.generateSecret(spec).getEncoded();"
                    ),
                    "confidence": confidence,
                    "confidence_reason": confidence_reason,
                }
            )
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
