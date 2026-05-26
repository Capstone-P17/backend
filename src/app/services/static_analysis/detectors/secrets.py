from __future__ import annotations

import math
import re

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method, iterate_all

SECRET_KEYWORDS = ["password", "passwd", "secret", "api_key", "apikey", "token", "credential", "key"]
PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "change_me",
    "example",
    "sample",
    "placeholder",
    "dummy",
    "todo",
    "fixme",
    "test",
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "your-secret-here",
    "your-api-key",
}
VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
SECRET_USAGE_METHODS = {
    "connect",
    "getConnection",
    "login",
    "authenticate",
    "authorize",
    "sign",
    "verify",
    "setPassword",
    "setToken",
    "setApiKey",
    "setSecret",
}
SECRET_USAGE_CLASS_NAMES = {
    "PasswordAuthentication",
    "UsernamePasswordAuthenticationToken",
}


def _text(node):
    return node.text.decode()


def _string_literal_value(node):
    raw = _text(node).strip()
    if len(raw) >= 2 and raw[0] in {"'", '"'} and raw[-1] == raw[0]:
        return raw[1:-1]
    return raw


def _is_config_placeholder(value):
    stripped = value.strip()
    return bool(re.fullmatch(r"\$\{[^}]+\}", stripped) or re.fullmatch(r"%[^%]+%", stripped))


def _looks_like_placeholder(value):
    normalized = value.strip().lower()
    return normalized in PLACEHOLDER_VALUES or normalized.startswith("your-") or normalized.startswith("<")


def _matches_secret_value_pattern(value):
    return any(pattern.search(value) for pattern in VALUE_PATTERNS)


def _string_entropy(value):
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _classify_secret_confidence(value, has_keyword, has_value_pattern, has_sensitive_usage):
    if has_sensitive_usage or has_value_pattern:
        return "HIGH", "민감 호출 사용 흐름 또는 실제 비밀값 형식(API key/token/key pattern)이 확인되어 HIGH로 판단했습니다."
    if _looks_like_placeholder(value) or len(value.strip()) < 8 or _string_entropy(value) < 2.5:
        return "LOW", "민감 변수명에 문자열이 하드코딩되어 있으나 placeholder 또는 낮은 복잡도 값일 가능성이 있어 LOW로 판단했습니다."
    if has_keyword:
        return "MEDIUM", "민감 키워드 변수에 문자열 리터럴이 하드코딩되어 있어 사용처와 무관하게 노출 위험이 있으므로 MEDIUM으로 판단했습니다."
    return "LOW", "값 자체가 비밀값 형식과 유사하지만 변수명 또는 사용처 맥락이 제한적이므로 LOW로 판단했습니다."


def _nearest_sensitive_call(node):
    current = node.parent
    while current:
        if current.type == "method_declaration":
            return None
        if current.type == "method_invocation":
            return current
        if current.type == "object_creation_expression":
            return current
        current = current.parent
    return None


def _usage_method_name(node):
    context = _nearest_sensitive_call(node)
    if not context or context.type != "method_invocation":
        return None
    name_node = context.child_by_field_name("name")
    return _text(name_node) if name_node else None


def _object_creation_class_name(node):
    context = _nearest_sensitive_call(node)
    if not context or context.type != "object_creation_expression":
        return None
    type_node = context.child_by_field_name("type")
    return _text(type_node).split(".")[-1] if type_node else None


def _is_relevant_secret_usage(node):
    method_name = _usage_method_name(node)
    if method_name and method_name in SECRET_USAGE_METHODS:
        return True

    class_name = _object_creation_class_name(node)
    return class_name in SECRET_USAGE_CLASS_NAMES


def _build_secret_chain(declaration_node, usage_node):
    chain = []
    if usage_node is not None:
        class_name = find_parent_class(usage_node)
        method_name = find_parent_method(usage_node)
        if class_name and method_name:
            chain.append(f"{class_name}.{method_name}")
        elif method_name:
            chain.append(method_name)

        usage_method = _usage_method_name(usage_node)
        if usage_method:
            chain.append(usage_method)
        else:
            class_name = _object_creation_class_name(usage_node)
            if class_name:
                chain.append(class_name)

    chain.append(f"선언 line {declaration_node.start_point[0] + 1}")
    if usage_node is not None:
        chain.append(f"사용 line {usage_node.start_point[0] + 1}")
    else:
        chain.append("사용처 확인 안 됨")
    return chain


def _build_secret_evidence(var_name, declaration_node, usage_node, value, confidence):
    base = f"`{var_name}`가 line {declaration_node.start_point[0] + 1}에서 문자열 리터럴로 하드코딩되어 선언되었습니다."
    if usage_node is not None:
        usage_method = _usage_method_name(usage_node)
        usage_name = usage_method or _object_creation_class_name(usage_node) or "민감 API"
        return (
            f"{base} line {usage_node.start_point[0] + 1}의 `{usage_name}` 호출에서 인증/연결 정보로 사용됩니다. "
            "하드코딩된 비밀값은 저장소 이력에 남을 수 있으므로 환경 변수나 시크릿 매니저로 분리해야 합니다."
        )
    if confidence == "LOW":
        return (
            f"{base} 현재 분석 범위에서 민감 호출 사용처는 확인되지 않았습니다. "
            f"값 `{value}`는 placeholder 또는 테스트 값일 가능성이 있어 낮은 신뢰도로 분류했지만, 실제 비밀값이라면 저장소 노출 위험이 있습니다."
        )
    return (
        f"{base} 현재 분석 범위에서 민감 호출 사용처는 확인되지 않았습니다. "
        "다만 비밀번호, 토큰, 키 등은 사용 여부와 무관하게 소스코드와 Git 이력에 노출될 수 있으므로 외부 설정으로 분리해야 합니다."
    )


def detect_hardcoded_secrets(filepath, tree, vuln_counter):
    vulnerabilities = []
    candidates = {}

    def visit(node):
        if node.type in ("field_declaration", "local_variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node:
                        var_name = name_node.text.decode()
                        var_name_lower = var_name.lower()
                        has_keyword = any(keyword in var_name_lower for keyword in SECRET_KEYWORDS)
                        is_string = value_node.type == "string_literal"
                        if not is_string:
                            continue
                        value = _string_literal_value(value_node)
                        has_value_pattern = _matches_secret_value_pattern(value)
                        if _is_config_placeholder(value):
                            continue
                        if has_keyword or has_value_pattern:
                            candidates[var_name] = {
                                "declaration": node,
                                "name": name_node,
                                "value": value,
                                "has_keyword": has_keyword,
                                "has_value_pattern": has_value_pattern,
                            }
        for child in node.children:
            visit(child)

    visit(tree.root_node)

    usages = {}
    for node in iterate_all(tree.root_node):
        if node.type != "identifier":
            continue
        var_name = _text(node)
        candidate = candidates.get(var_name)
        if not candidate or var_name in usages:
            continue
        if node.start_byte == candidate["name"].start_byte and node.end_byte == candidate["name"].end_byte:
            continue
        if not _is_relevant_secret_usage(node):
            continue
        usages[var_name] = node

    for var_name, candidate in candidates.items():
        declaration = candidate["declaration"]
        usage_node = usages.get(var_name)
        has_sensitive_usage = usage_node is not None
        confidence, confidence_reason = _classify_secret_confidence(
            candidate["value"],
            candidate["has_keyword"],
            candidate["has_value_pattern"],
            has_sensitive_usage,
        )
        vuln_counter[0] += 1
        vulnerabilities.append(
            {
                "id": f"VULN-{vuln_counter[0]:03d}",
                "type": "HARDCODED_SECRET",
                "severity": "MEDIUM",
                "cvss": get_cvss("HARDCODED_SECRET", "MEDIUM"),
                "file": filepath,
                "line": candidate["name"].start_point[0] + 1,
                "function": find_parent_method(declaration),
                "code_snippet": declaration.text.decode().strip(),
                "call_chain": _build_secret_chain(declaration, usage_node),
                "evidence": _build_secret_evidence(var_name, declaration, usage_node, candidate["value"], confidence),
                "confidence": confidence,
                "confidence_reason": confidence_reason,
                "description": "",
            }
        )

    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
