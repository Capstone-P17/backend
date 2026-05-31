from __future__ import annotations

import os

DEFAULT_FINDING_PENALTY = 10

GUIDE_CATEGORIES = (
    "입력데이터 검증 및 표현",
    "보안기능",
    "시간 및 상태",
    "에러처리",
    "코드오류",
    "캡슐화",
    "API 오용",
)


def count_by_guide_category(vulnerabilities):
    counts = {category: 0 for category in GUIDE_CATEGORIES}
    for vulnerability in vulnerabilities:
        category = vulnerability.get("guide_category")
        if not category:
            continue
        counts.setdefault(str(category), 0)
        counts[str(category)] += 1
    return counts


def calculate_scores(vulnerabilities, files):
    file_vulnerabilities = {file_path: [v for v in vulnerabilities if v["file"] == file_path] for file_path in files}

    by_file = {}
    for file_path, current_vulnerabilities in file_vulnerabilities.items():
        score = 100
        for _vulnerability in current_vulnerabilities:
            score -= DEFAULT_FINDING_PENALTY
        by_file[os.path.basename(file_path)] = max(0, score)

    overall = round(sum(by_file.values()) / len(by_file)) if by_file else 100
    return {"overall": overall, "by_file": by_file}


def build_summary(vulnerabilities, files):
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "by_type": {
            "SQL_INJECTION": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "SQL_INJECTION"),
            "XSS": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "XSS"),
            "HARDCODED_SECRET": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "HARDCODED_SECRET"),
            "PATH_TRAVERSAL": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "PATH_TRAVERSAL"),
            "COMMAND_INJECTION": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "COMMAND_INJECTION"),
            "INSECURE_RANDOM": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "INSECURE_RANDOM"),
            "WEAK_HASH": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "WEAK_HASH"),
            "DANGEROUS_FILE_UPLOAD": sum(
                1 for vulnerability in vulnerabilities if vulnerability["type"] == "DANGEROUS_FILE_UPLOAD"
            ),
        },
        "by_guide_category": count_by_guide_category(vulnerabilities),
        "score": calculate_scores(vulnerabilities, files),
    }
