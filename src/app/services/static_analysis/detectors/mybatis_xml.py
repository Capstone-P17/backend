from __future__ import annotations

import re

from src.app.services.static_analysis.detectors.metadata import enrich_finding
from src.app.services.static_analysis.rules import SQL_KEYWORDS

MAPPER_ROOT_PATTERN = re.compile(r"<\s*(?:mapper|sqlMap)\b", re.IGNORECASE)
STATEMENT_PATTERN = re.compile(
    r"<\s*(select|insert|update|delete)\b(?P<attrs>[^>]*)>(?P<body>.*?)</\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
ID_PATTERN = re.compile(r'\bid\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
UNSAFE_MYBATIS_SUBSTITUTION_PATTERN = re.compile(
    r"\$\{\s*([A-Za-z_][A-Za-z0-9_.$]*)\s*\}|\$([A-Za-z_][A-Za-z0-9_.$]*)\$"
)
SQL_KEYWORD_PATTERN = re.compile(r"\b(?:" + "|".join(SQL_KEYWORDS) + r")\b", re.IGNORECASE)


def is_mybatis_mapper_xml(source_code: str) -> bool:
    return bool(MAPPER_ROOT_PATTERN.search(source_code))


def detect_mybatis_xml_sql_injection(filepath: str, source_code: str, vuln_counter: list[int]) -> list[dict]:
    if not is_mybatis_mapper_xml(source_code):
        return []

    vulnerabilities = []
    comment_ranges = [(match.start(), match.end()) for match in COMMENT_PATTERN.finditer(source_code)]

    for statement in STATEMENT_PATTERN.finditer(source_code):
        if _inside_comment(statement.start(), comment_ranges):
            continue

        full_statement = statement.group(0)
        if not SQL_KEYWORD_PATTERN.search(full_statement):
            continue

        substitutions = list(UNSAFE_MYBATIS_SUBSTITUTION_PATTERN.finditer(full_statement))
        if not substitutions:
            continue

        statement_id = _statement_id(statement.group("attrs")) or "<unknown>"
        statement_type = statement.group(1).lower()
        line = source_code.count("\n", 0, statement.start()) + 1
        substitution_values = [_substitution_text(match) for match in substitutions]
        substitution_desc = ", ".join(f"`{value}`" for value in substitution_values)

        vuln_counter[0] += 1
        vulnerabilities.append(
            {
                "id": f"VULN-{vuln_counter[0]:03d}",
                "type": "SQL_INJECTION",
                "file": filepath,
                "line": line,
                "function": statement_id,
                "code_snippet": _compact_statement(full_statement),
                "call_chain": [
                    f"MyBatis XML mapper `{statement_id}`",
                    f"{statement_type} statement",
                    f"문자열 치환 {substitution_desc}",
                ],
                "evidence": (
                    f"MyBatis XML mapper `{statement_id}`의 `{statement_type}` 구문에서 "
                    f"{substitution_desc} 문자열 치환이 확인되었습니다. "
                    "`#{...}` 바인딩이 아니라 `${...}` 또는 `$name$` 치환을 사용하면 외부 입력이 SQL 문자열에 직접 삽입되어 "
                    "쿼리 구조가 변경될 수 있습니다."
                ),
                "confidence": "HIGH",
                "confidence_reason": (
                    "MyBatis XML SQL statement 내부에서 SQL 키워드와 문자열 치환 문법이 함께 확인되었습니다. "
                    "해당 치환 방식은 PreparedStatement 파라미터 바인딩이 아니라 문자열 결합으로 처리되므로 HIGH로 판단했습니다."
                ),
                "description": "",
            }
        )

    return [enrich_finding(vulnerability) for vulnerability in vulnerabilities]


def _inside_comment(offset: int, comment_ranges: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in comment_ranges)


def _statement_id(attrs: str) -> str | None:
    match = ID_PATTERN.search(attrs or "")
    return match.group(1) if match else None


def _substitution_text(match: re.Match[str]) -> str:
    return match.group(0)


def _compact_statement(statement: str) -> str:
    lines = [line.strip() for line in statement.strip().splitlines() if line.strip()]
    return "\n".join(lines[:8])
