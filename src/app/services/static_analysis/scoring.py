from __future__ import annotations

import os

SEVERITY_PENALTY = {
    "HIGH": 15,
    "MEDIUM": 5,
    "LOW": 2,
}


def calculate_scores(vulnerabilities, files):
    file_vulnerabilities = {file_path: [v for v in vulnerabilities if v["file"] == file_path] for file_path in files}

    by_file = {}
    for file_path, current_vulnerabilities in file_vulnerabilities.items():
        score = 100
        for vulnerability in current_vulnerabilities:
            score -= SEVERITY_PENALTY.get(vulnerability["severity"], 0)
        by_file[os.path.basename(file_path)] = max(0, score)

    overall = round(sum(by_file.values()) / len(by_file)) if by_file else 100
    return {"overall": overall, "by_file": by_file}


def build_summary(vulnerabilities, files):
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "by_severity": {
            "HIGH": sum(1 for vulnerability in vulnerabilities if vulnerability["severity"] == "HIGH"),
            "MEDIUM": sum(1 for vulnerability in vulnerabilities if vulnerability["severity"] == "MEDIUM"),
            "LOW": sum(1 for vulnerability in vulnerabilities if vulnerability["severity"] == "LOW"),
        },
        "by_type": {
            "SQL_INJECTION": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "SQL_INJECTION"),
            "XSS": sum(1 for vulnerability in vulnerabilities if vulnerability["type"] == "XSS"),
            "HARDCODED_SECRET": sum(
                1 for vulnerability in vulnerabilities if vulnerability["type"] == "HARDCODED_SECRET"
            ),
        },
        "score": calculate_scores(vulnerabilities, files),
    }
