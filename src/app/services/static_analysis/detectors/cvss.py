"""CVSS 3.1 preset vectors for each vulnerability type.

감점 기준과 동일하게 CVSS 3.1 심각도 등급에 기반합니다.
Reference: https://www.first.org/cvss/v3.1/specification-document
"""
from __future__ import annotations

CVSS_PRESETS: dict[str, dict[str, dict]] = {
    "SQL_INJECTION": {
        # 인증 우회(username/password 포함) 또는 DELETE/DROP/UPDATE → CRITICAL
        "CRITICAL": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        # 일반 SELECT 쿼리 → HIGH
        "HIGH": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    },
    "XSS": {
        "HIGH": {
            "score": 6.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        },
    },
    "HARDCODED_SECRET": {
        "MEDIUM": {
            "score": 5.5,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        },
    },
    "PATH_TRAVERSAL": {
        "HIGH": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    },
    "COMMAND_INJECTION": {
        "CRITICAL": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
    },
    "INSECURE_RANDOM": {
        "MEDIUM": {
            "score": 5.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        },
    },
    "WEAK_HASH": {
        "MEDIUM": {
            "score": 5.9,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
    },
}


def get_cvss(vuln_type: str, severity: str) -> dict:
    return CVSS_PRESETS.get(vuln_type, {}).get(severity, {"score": 0.0, "vector": "N/A"})
