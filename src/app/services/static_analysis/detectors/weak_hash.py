from __future__ import annotations

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.detectors.cvss import get_cvss
from src.app.services.static_analysis.parser import find_parent_class, find_parent_method

WEAK_ALGORITHMS = {"MD5", "MD4", "MD2", "SHA-1", "SHA1"}


def detect_weak_hash(filepath, tree, vuln_counter):
    """취약한 해시 알고리즘 사용 탐지.

    MD5, SHA-1 등은 충돌 취약점이 알려져 있어 보안 목적(비밀번호 해싱 등)으로
    사용하면 위험합니다. SHA-256 이상을 사용해야 합니다.
    """
    vulnerabilities = []

    def find_weak_hash(node):
        # MessageDigest.getInstance("MD5") 패턴 탐지
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            args_node = node.child_by_field_name("arguments")
            if name_node and name_node.text.decode() == "getInstance" and args_node:
                # 인수에서 문자열 리터럴 찾기
                for child in args_node.children:
                    if child.type == "string_literal":
                        algo = child.text.decode().strip('"').strip("'")
                        if algo.upper() in {a.upper() for a in WEAK_ALGORITHMS}:
                            vuln_counter[0] += 1
                            class_name = find_parent_class(node)
                            method_name = find_parent_method(node)
                            chain = []
                            if class_name and method_name:
                                chain.append(f"{class_name}.{method_name}")
                            chain.append(f'MessageDigest.getInstance("{algo}") → 취약한 해시')
                            evidence = (
                                f'`MessageDigest.getInstance("{algo}")` 호출이 확인되었습니다. '
                                "MD5/SHA-1 계열 해시는 충돌 공격에 취약하여 비밀번호 저장, 서명, 무결성 검증 등 "
                                "보안 목적의 해시로 사용하기에 부적절합니다."
                            )
                            vulnerabilities.append(
                                {
                                    "id": f"VULN-{vuln_counter[0]:03d}",
                                    "type": "WEAK_HASH",
                                    "severity": "MEDIUM",
                                    "cvss": get_cvss("WEAK_HASH", "MEDIUM"),
                                    "file": filepath,
                                    "line": node.start_point[0] + 1,
                                    "function": method_name,
                                    "code_snippet": node.text.decode().strip(),
                                    "call_chain": chain,
                                    "description": "",
                                    "evidence": evidence,
                                }
                            )

        for child in node.children:
            find_weak_hash(child)

    find_weak_hash(tree.root_node)
    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]
