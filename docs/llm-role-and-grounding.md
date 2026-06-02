# LLM 역할과 Grounding 정책

이 문서는 DoUSECURE에서 LLM이 담당하는 범위와 담당하지 않는 범위를 명확히 정리한다.
핵심 원칙은 **탐지는 rule-based 정적 분석기가 수행하고, LLM은 이미 탐지된 finding을 설명하는 역할만 맡는다**는 것이다.

## 역할 분리

| 영역 | 담당 주체 | 설명 |
|---|---|---|
| 취약점 탐지 | rule-based detector | `tree-sitter-java` AST를 기반으로 source, propagation, sink, sanitizer 여부를 확인한다. |
| 공식 가이드 매핑 | rule-based metadata | detector 유형을 행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」 항목과 매핑한다. |
| evidence 생성 | rule-based detector | 탐지 근거, 호출 경로, 취약 코드 위치, 신뢰도 판단 근거를 결정론적으로 생성한다. |
| 상세 설명 생성 | LLM | detector가 만든 finding/evidence/guideline 범위 안에서 개발자가 이해하기 쉬운 한국어 설명을 작성한다. |
| 수정 방향 정리 | LLM + static fallback | LLM이 있으면 자연어 설명을 보강하고, 없거나 실패하면 detector metadata 기반 권고를 사용한다. |

## LLM이 하지 않는 것

LLM은 다음을 수행하지 않는다.

- 새로운 취약점 후보를 임의로 추가하지 않는다.
- detector가 찾지 못한 파일이나 라인을 추측하지 않는다.
- evidence에 없는 호출 경로를 만들어내지 않는다.
- 공식 가이드에 없는 항목을 임의로 인용하지 않는다.
- 탐지 결과의 severity/confidence를 단독으로 결정하지 않는다.

따라서 `OPENAI_API_KEY`가 비어 있거나 LLM 호출이 실패해도 정적 분석 탐지 결과는 유지된다.
차이는 상세 리포트 문장의 풍부함과 수정 가이드 자연어 보강 여부다.

## Grounding 입력

LLM 상세 리포트 생성 시 입력으로 제공되는 핵심 정보는 다음과 같다.

```text
finding.type
finding.file
finding.line
finding.function
finding.code_snippet
finding.call_chain
finding.evidence
finding.confidence_reason
finding.recommendation
finding.safe_example
guideline_refs
```

LLM은 이 근거 범위 안에서만 설명을 작성해야 하며, citation도 제공된 `guideline_refs` 안에서만 선택한다.

## 실패 시 동작

LLM이 비활성화되었거나 실패하면 백엔드는 다음 fallback을 제공한다.

- detector metadata 기반 `description`
- 정적 분석 evidence
- 공식 가이드 매핑
- `recommendation`
- `safe_example`
- finding별 fallback Markdown 리포트

이 구조 때문에 서비스는 LLM에 의존해 취약점을 “발견”하지 않는다.
LLM은 탐지 엔진 위에 얹힌 설명/리포트 계층이다.

## 발표 답변용 요약

```text
DoUSECURE의 취약점 탐지는 LLM이 아니라 tree-sitter 기반 rule-based detector가 수행합니다.
LLM은 detector가 만든 line, code, evidence, call chain, 공식 가이드 매핑을 근거로 상세 설명과 수정 가이드를 생성합니다.
따라서 LLM을 끄더라도 탐지 결과는 재현 가능하며, LLM은 리포트 가독성을 높이는 보조 계층입니다.
```
