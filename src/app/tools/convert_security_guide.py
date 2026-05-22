#!/usr/bin/env python3
"""Convert the 2019 Korean software security guide PDF into reference JSON.

The generated JSON is intentionally structured around implementation-stage
vulnerability items instead of arbitrary vector chunks.  Static-analysis
findings can then deterministically attach the right guideline entry by
detector type, CWE, or guide item before any LLM/RAG step runs.

Requirements:
  - poppler's `pdftotext` CLI must be installed and available on PATH.

Examples:
  uv run convert-security-guide convert
  uv run convert-security-guide query SQL_INJECTION
  uv run convert-security-guide list
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def find_project_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").exists():
            return parent
    raise RuntimeError("Could not locate project root containing pyproject.toml")


PROJECT_ROOT = find_project_root()
GUIDE_DIR = PROJECT_ROOT / "src" / "app" / "resources" / "guidelines" / "software-security-guide-2019"
DEFAULT_SOURCE = GUIDE_DIR / "source.pdf"
DEFAULT_OUTPUT = GUIDE_DIR / "references.json"

DOCUMENT_SOURCE = {
    "title": "소프트웨어 보안약점 진단가이드",
    "subtitle": "전자정부 SW개발보안 진단원을 위한 소프트웨어 보안약점 진단가이드",
    "version": "2019.6 개정",
    "publisher": "행정안전부",
    "source_file": str(DEFAULT_SOURCE.relative_to(PROJECT_ROOT)),
}


@dataclass(frozen=True)
class GuideItem:
    category: str
    item_no: str
    item: str
    page_start: int
    detector_types: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    page_end: int | None = field(default=None, compare=False)

    @property
    def slug(self) -> str:
        romanized = {
            "SQL 삽입": "sql-injection",
            "경로 조작 및 자원 삽입": "path-traversal",
            "크로스사이트 스크립트": "xss",
            "운영체제 명령어 삽입": "command-injection",
            "위험한 형식 파일 업로드": "dangerous-file-upload",
            "취약한 암호화 알고리즘 사용": "weak-crypto-algorithm",
            "하드코드된 비밀번호": "hardcoded-password",
            "적절하지 않은 난수값 사용": "insecure-random",
            "하드코드된 암호화 키": "hardcoded-crypto-key",
            "솔트 없이 일방향 해시함수 사용": "unsalted-one-way-hash",
        }
        if self.item in romanized:
            return romanized[self.item]
        value = re.sub(r"[^0-9A-Za-z가-힣]+", "-", self.item).strip("-").lower()
        return value or f"item-{self.item_no}"


IMPLEMENTATION_ITEMS: tuple[GuideItem, ...] = (
    GuideItem("입력데이터 검증 및 표현", "1", "SQL 삽입", 178, ("SQL_INJECTION",), ("CWE-89",), ("SQL Injection", "SQL 인젝션")),
    GuideItem("입력데이터 검증 및 표현", "2", "경로 조작 및 자원 삽입", 192, ("PATH_TRAVERSAL",), ("CWE-22",), ("Path Traversal",)),
    GuideItem("입력데이터 검증 및 표현", "3", "크로스사이트 스크립트", 202, ("XSS",), ("CWE-79",), ("Cross-site Scripting", "XSS")),
    GuideItem("입력데이터 검증 및 표현", "4", "운영체제 명령어 삽입", 214, ("COMMAND_INJECTION",), ("CWE-78",), ("OS Command Injection",)),
    GuideItem("입력데이터 검증 및 표현", "5", "위험한 형식 파일 업로드", 223, ("DANGEROUS_FILE_UPLOAD",), ("CWE-434",), ("Unrestricted File Upload",)),
    GuideItem("입력데이터 검증 및 표현", "6", "신뢰되지 않는 URL 주소로 자동접속 연결", 230),
    GuideItem("입력데이터 검증 및 표현", "7", "XQuery 삽입", 235),
    GuideItem("입력데이터 검증 및 표현", "8", "XPath 삽입", 241),
    GuideItem("입력데이터 검증 및 표현", "9", "LDAP 삽입", 249),
    GuideItem("입력데이터 검증 및 표현", "10", "크로스사이트 요청위조", 257),
    GuideItem("입력데이터 검증 및 표현", "11", "HTTP 응답분할", 261),
    GuideItem("입력데이터 검증 및 표현", "12", "정수형 오버플로우", 267),
    GuideItem("입력데이터 검증 및 표현", "13", "보안기능 결정에 사용되는 부적절한 입력값", 274),
    GuideItem("입력데이터 검증 및 표현", "14", "메모리 버퍼 오버플로우", 280),
    GuideItem("입력데이터 검증 및 표현", "15", "포맷 스트링 삽입", 286),
    GuideItem("보안기능", "1", "적절한 인증 없는 중요기능 허용", 291),
    GuideItem("보안기능", "2", "부적절한 인가", 296),
    GuideItem("보안기능", "3", "중요한 자원에 대한 잘못된 권한 설정", 302),
    GuideItem("보안기능", "4", "취약한 암호화 알고리즘 사용", 307, ("WEAK_HASH",), ("CWE-327", "CWE-328"), ("Weak Cryptographic Algorithm",)),
    GuideItem("보안기능", "5", "중요정보 평문저장", 314),
    GuideItem("보안기능", "6", "중요정보 평문전송", 319),
    GuideItem("보안기능", "7", "하드코드된 비밀번호", 327, ("HARDCODED_SECRET",), ("CWE-798",), ("Hardcoded Password",)),
    GuideItem("보안기능", "8", "충분하지 않은 키 길이 사용", 332),
    GuideItem("보안기능", "9", "적절하지 않은 난수값 사용", 336, ("INSECURE_RANDOM",), ("CWE-338",), ("Insecure Randomness",)),
    GuideItem("보안기능", "10", "하드코드된 암호화 키", 342, ("HARDCODED_SECRET",), ("CWE-321", "CWE-798"), ("Hardcoded Cryptographic Key",)),
    GuideItem("보안기능", "11", "취약한 비밀번호 허용", 348),
    GuideItem("보안기능", "12", "사용자 하드디스크에 저장되는 쿠키를 통한 정보노출", 353),
    GuideItem("보안기능", "13", "주석문 안에 포함된 시스템 주요정보", 357),
    GuideItem("보안기능", "14", "솔트 없이 일방향 해시함수 사용", 361, ("WEAK_HASH",), ("CWE-759",), ("Unsalted Hash",)),
    GuideItem("보안기능", "15", "무결성 검사 없는 코드 다운로드", 365),
    GuideItem("보안기능", "16", "반복된 인증시도 제한 기능 부재", 371),
    GuideItem("시간 및 상태", "1", "경쟁조건: 검사 시점과 사용 시점(TOCTOU)", 377),
    GuideItem("시간 및 상태", "2", "종료되지 않는 반복문 또는 재귀함수", 386),
    GuideItem("에러처리", "1", "오류 메시지를 통한 정보노출", 390),
    GuideItem("에러처리", "2", "오류 상황 대응 부재", 395),
    GuideItem("에러처리", "3", "부적절한 예외 처리", 399),
    GuideItem("코드오류", "1", "Null Pointer 역참조", 403),
    GuideItem("코드오류", "2", "부적절한 자원 해제", 416),
    GuideItem("코드오류", "3", "해제된 자원 사용", 425),
    GuideItem("코드오류", "4", "초기화되지 않은 변수 사용", 430),
    GuideItem("캡슐화", "1", "잘못된 세션에 의한 데이터 정보노출", 433),
    GuideItem("캡슐화", "2", "제거되지 않고 남은 디버그 코드", 440),
    GuideItem("캡슐화", "3", "시스템 데이터 정보노출", 445),
    GuideItem("캡슐화", "4", "Public 메서드로부터 반환된 Private 배열", 449),
    GuideItem("캡슐화", "5", "Private 배열에 Public 데이터 할당", 455),
    GuideItem("API 오용", "1", "DNS lookup에 의존한 보안결정", 460),
    GuideItem("API 오용", "2", "취약한 API 사용", 465),
)

SUBSECTION_NAMES = {
    "가": "overview",
    "나": "security_measures",
    "다": "code_examples",
    "라": "diagnosis",
    "마": "references",
    "바": "extra",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="Path to source PDF.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Path to generated JSON.")
    subparsers = parser.add_subparsers(dest="command")

    convert_parser = subparsers.add_parser("convert", help="Convert PDF to references JSON.")
    convert_parser.add_argument("--include-full-text", action="store_true", help="Include full item text in JSON.")

    query_parser = subparsers.add_parser("query", help="Query generated references by detector/CWE/item text.")
    query_parser.add_argument("term", help="Search term, e.g. SQL_INJECTION or SQL 삽입.")
    query_parser.add_argument("--limit", type=int, default=5)
    query_parser.add_argument(
        "--section",
        choices=["overview", "security_measures", "code_examples", "diagnosis", "references", "all"],
        help="Print a specific extracted content section instead of the short preview.",
    )
    query_parser.add_argument("--full", action="store_true", help="Print every extracted content section.")
    query_parser.add_argument(
        "--max-chars",
        type=int,
        default=0,
        help="Truncate detailed section output to this many characters. 0 means no truncation.",
    )

    subparsers.add_parser("list", help="List generated references.")

    args = parser.parse_args()
    command = args.command or "convert"

    if command == "convert":
        payload = convert_pdf(args.source, include_full_text=args.include_full_text)
        write_json(args.output, payload)
        print_conversion_summary(args.output, payload)
        return 0

    if command == "query":
        payload = read_json(args.output)
        query_references(
            payload,
            args.term,
            args.limit,
            section="all" if args.full else args.section,
            max_chars=args.max_chars,
        )
        return 0

    if command == "list":
        payload = read_json(args.output)
        list_references(payload)
        return 0

    parser.error(f"unknown command: {command}")
    return 2


def convert_pdf(source: Path, *, include_full_text: bool = False) -> dict[str, Any]:
    source = source.resolve()
    if not source.exists():
        raise SystemExit(f"source PDF not found: {source}")

    pdftotext = shutil.which("pdftotext")
    if pdftotext is None:
        raise SystemExit("pdftotext is required. Install poppler-utils and retry.")

    items = with_page_ends(IMPLEMENTATION_ITEMS)
    references: list[dict[str, Any]] = []
    quality: dict[str, Any] = {
        "expected_reference_count": len(items),
        "references_with_empty_text": [],
        "references_missing_security_measures": [],
        "references_missing_overview": [],
    }

    for item in items:
        assert item.page_end is not None
        raw_text = extract_pdf_text(pdftotext, source, item.page_start, item.page_end)
        cleaned_text = clean_text(raw_text)
        subsections = split_subsections(cleaned_text)
        reference = build_reference(item, subsections, cleaned_text if include_full_text else None, source)
        references.append(reference)

        if not cleaned_text.strip():
            quality["references_with_empty_text"].append(reference["id"])
        if not subsections.get("overview"):
            quality["references_missing_overview"].append(reference["id"])
        if not subsections.get("security_measures"):
            quality["references_missing_security_measures"].append(reference["id"])

    return {
        "schema_version": "1.0",
        "source": {
            **DOCUMENT_SOURCE,
            "source_file": str(source.relative_to(PROJECT_ROOT)) if source.is_relative_to(PROJECT_ROOT) else str(source),
        },
        "extraction": {
            "tool": "pdftotext -layout",
            "strategy": "implementation_item_page_ranges",
            "chapter": "제4장 구현단계 보안약점 진단",
        },
        "quality": {
            **quality,
            "reference_count": len(references),
        },
        "references": references,
    }


def with_page_ends(items: tuple[GuideItem, ...]) -> list[GuideItem]:
    enriched: list[GuideItem] = []
    for index, item in enumerate(items):
        next_start = items[index + 1].page_start if index + 1 < len(items) else 472
        enriched.append(
            GuideItem(
                category=item.category,
                item_no=item.item_no,
                item=item.item,
                page_start=item.page_start,
                detector_types=item.detector_types,
                cwe=item.cwe,
                aliases=item.aliases,
                page_end=next_start - 1,
            )
        )
    return enriched


def extract_pdf_text(pdftotext: str, source: Path, page_start: int, page_end: int) -> str:
    result = subprocess.run(
        [pdftotext, "-layout", "-f", str(page_start), "-l", str(page_end), str(source), "-"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def clean_text(value: str) -> str:
    lines: list[str] = []
    for raw_line in value.replace("\x0c", "\n").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            lines.append("")
            continue
        if stripped == "전자정부 SW개발보안 진단원을 위한 소프트웨어 보안약점 진단가이드":
            continue
        if stripped == "제4장 구현단계 보안약점 진단":
            continue
        if stripped in {"제1장 개요", "제2장 소프트웨어 개발보안", "제3장 분석·설계단계 보안항목 진단", "제4장 구현단계 보안약점 진단", "부록"}:
            continue
        if re.fullmatch(r"\d{1,3}", stripped):
            continue
        lines.append(line)

    cleaned = "\n".join(lines)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def split_subsections(text: str) -> dict[str, str]:
    heading_pattern = re.compile(
        r"(?m)^\s*([가-바])\.\s*(개요|보안대책|코드예제|진단방법|참고자료|기타)\s*$"
    )
    matches = list(heading_pattern.finditer(text))
    if not matches:
        return {}

    subsections: dict[str, str] = {}
    for index, match in enumerate(matches):
        key = SUBSECTION_NAMES.get(match.group(1), match.group(1))
        title = match.group(2).strip()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        subsections[key] = normalize_block(body)
        subsections[f"{key}_title"] = title
    return subsections


def normalize_block(value: str) -> str:
    value = re.sub(r"[ \t]{2,}", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def build_reference(
    item: GuideItem,
    subsections: dict[str, str],
    full_text: str | None,
    source: Path,
) -> dict[str, Any]:
    content = {
        "overview": subsections.get("overview", ""),
        "security_measures": subsections.get("security_measures", ""),
        "diagnosis": subsections.get("diagnosis", ""),
        "code_examples": subsections.get("code_examples", ""),
        "references": subsections.get("references", ""),
    }
    if full_text is not None:
        content["full_text"] = full_text

    page_range = [item.page_start, item.page_end]
    return {
        "id": f"kr-sw-security-guide-2019-{item.slug}",
        "source": {
            **DOCUMENT_SOURCE,
            "source_file": str(source.relative_to(PROJECT_ROOT)) if source.is_relative_to(PROJECT_ROOT) else str(source),
        },
        "scope": {
            "phase": "implementation",
            "chapter": "제4장 구현단계 보안약점 진단",
            "category": item.category,
            "item_no": item.item_no,
            "item": item.item,
            "page_start": item.page_start,
            "page_end": item.page_end,
        },
        "mapping": {
            "detector_types": list(item.detector_types),
            "cwe": list(item.cwe),
            "aliases": list(item.aliases),
            "guide_item": item.item,
            "guide_category": item.category,
        },
        "content": content,
        "citations": [
            {
                "source": DOCUMENT_SOURCE["title"],
                "version": DOCUMENT_SOURCE["version"],
                "page_start": page_range[0],
                "page_end": page_range[1],
                "section": f"{item.category} - {item.item}",
            }
        ],
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"references JSON not found: {path}. Run convert first.")
    return json.loads(path.read_text(encoding="utf-8"))


def print_conversion_summary(path: Path, payload: dict[str, Any]) -> None:
    quality = payload["quality"]
    print(f"wrote: {path}")
    print(f"references: {quality['reference_count']} / expected {quality['expected_reference_count']}")
    print(f"empty text: {len(quality['references_with_empty_text'])}")
    print(f"missing overview: {len(quality['references_missing_overview'])}")
    print(f"missing security measures: {len(quality['references_missing_security_measures'])}")
    print("try: uv run convert-security-guide query SQL_INJECTION")


def query_references(
    payload: dict[str, Any],
    term: str,
    limit: int,
    *,
    section: str | None = None,
    max_chars: int = 0,
) -> None:
    needle = term.casefold()
    results = []
    for reference in payload.get("references", []):
        haystack = " ".join(
            [
                reference.get("id", ""),
                reference.get("scope", {}).get("item", ""),
                reference.get("scope", {}).get("category", ""),
                " ".join(reference.get("mapping", {}).get("detector_types", [])),
                " ".join(reference.get("mapping", {}).get("cwe", [])),
                " ".join(reference.get("mapping", {}).get("aliases", [])),
            ]
        ).casefold()
        if needle in haystack:
            results.append(reference)

    if not results:
        print(f"no references matched: {term}")
        return

    for reference in results[: max(0, limit)]:
        scope = reference["scope"]
        mapping = reference["mapping"]
        content = reference["content"]
        overview = first_non_empty_line(content.get("overview", ""))
        measures = first_non_empty_line(content.get("security_measures", ""))
        print(f"- {reference['id']}")
        print(f"  item: {scope['category']} / {scope['item']}")
        print(f"  pages: {scope['page_start']}-{scope['page_end']}")
        print(f"  detectors: {', '.join(mapping.get('detector_types', [])) or '-'}")
        print(f"  cwe: {', '.join(mapping.get('cwe', [])) or '-'}")
        if section:
            print_detailed_content(reference, section, max_chars=max_chars)
        else:
            print(f"  overview: {overview[:220]}")
            print(f"  security_measures: {measures[:220]}")


def print_detailed_content(reference: dict[str, Any], section: str, *, max_chars: int) -> None:
    content = reference.get("content", {})
    sections = ["overview", "security_measures", "code_examples", "diagnosis", "references"]
    selected_sections = sections if section == "all" else [section]
    for section_name in selected_sections:
        value = str(content.get(section_name) or "").strip()
        print(f"\n## {section_name} ({len(value)} chars)")
        if not value:
            print("-")
            continue
        print(truncate_text(value, max_chars=max_chars))


def truncate_text(value: str, *, max_chars: int) -> str:
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    omitted = len(value) - max_chars
    return f"{value[:max_chars].rstrip()}\n... <truncated {omitted} chars>"


def first_non_empty_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return "-"


def list_references(payload: dict[str, Any]) -> None:
    for reference in payload.get("references", []):
        scope = reference["scope"]
        detectors = ",".join(reference.get("mapping", {}).get("detector_types", [])) or "-"
        print(f"{reference['id']}\t{scope['page_start']}-{scope['page_end']}\t{scope['category']}\t{scope['item']}\t{detectors}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr or str(exc))
        raise SystemExit(exc.returncode) from exc
