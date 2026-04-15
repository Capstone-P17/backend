from __future__ import annotations

import os
from datetime import datetime

from src.app.services.static_analysis.call_graph import build_call_graph
from src.app.services.static_analysis.detectors.command_injection import detect_command_injection
from src.app.services.static_analysis.detectors.insecure_random import detect_insecure_random
from src.app.services.static_analysis.detectors.path_traversal import detect_path_traversal
from src.app.services.static_analysis.detectors.secrets import detect_hardcoded_secrets
from src.app.services.static_analysis.detectors.sql_injection import detect_sql_injection
from src.app.services.static_analysis.detectors.weak_hash import detect_weak_hash
from src.app.services.static_analysis.detectors.xss import detect_xss
from src.app.services.static_analysis.parser import parse_file
from src.app.services.static_analysis.scoring import build_summary


def analyze_file(filepath):
    tree, _ = parse_file(filepath)
    vuln_counter = [0]

    vulnerabilities = []
    vulnerabilities += detect_hardcoded_secrets(filepath, tree, vuln_counter)
    vulnerabilities += detect_sql_injection(filepath, tree, vuln_counter)
    vulnerabilities += detect_xss(filepath, tree, vuln_counter)
    vulnerabilities += detect_path_traversal(filepath, tree, vuln_counter)
    vulnerabilities += detect_command_injection(filepath, tree, vuln_counter)
    vulnerabilities += detect_insecure_random(filepath, tree, vuln_counter)
    vulnerabilities += detect_weak_hash(filepath, tree, vuln_counter)

    return {
        "analysis_result": {
            "repository": "",
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": 1,
            "vulnerabilities": vulnerabilities,
            "call_graph": build_call_graph(tree),
            "summary": build_summary(vulnerabilities, [filepath]),
        }
    }


def analyze_directory(directory, repository=""):
    all_vulnerabilities = []
    all_call_graph = {}
    analyzed_files = []
    vuln_counter = [0]

    for root, _, files in os.walk(directory):
        for filename in files:
            if not filename.endswith(".java"):
                continue

            filepath = os.path.join(root, filename)
            analyzed_files.append(filepath)
            tree, _ = parse_file(filepath)
            all_vulnerabilities += detect_hardcoded_secrets(filepath, tree, vuln_counter)
            all_vulnerabilities += detect_sql_injection(filepath, tree, vuln_counter)
            all_vulnerabilities += detect_xss(filepath, tree, vuln_counter)
            all_vulnerabilities += detect_path_traversal(filepath, tree, vuln_counter)
            all_vulnerabilities += detect_command_injection(filepath, tree, vuln_counter)
            all_vulnerabilities += detect_insecure_random(filepath, tree, vuln_counter)
            all_vulnerabilities += detect_weak_hash(filepath, tree, vuln_counter)
            all_call_graph.update(build_call_graph(tree))

    return {
        "analysis_result": {
            "repository": repository,
            "analyzed_at": datetime.now().isoformat(),
            "language": "java",
            "files_analyzed": len(analyzed_files),
            "vulnerabilities": all_vulnerabilities,
            "call_graph": all_call_graph,
            "summary": build_summary(all_vulnerabilities, analyzed_files),
        }
    }
