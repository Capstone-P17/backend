from __future__ import annotations

from collections.abc import Callable
from typing import Any

from src.app.services.static_analysis.parser import iterate_all


def node_text(node: object | None) -> str:
    return node.text.decode() if node else ""  # type: ignore[attr-defined]


def argument_expressions(arguments_node: object | None) -> list[object]:
    if not arguments_node:
        return []
    return [child for child in arguments_node.children if child.is_named]  # type: ignore[attr-defined]


def identifiers(node: object | None) -> set[str]:
    if node is None:
        return set()
    return {node_text(child) for child in iterate_all(node) if child.type == "identifier"}


def referenced_vars(node: object | None, var_names: set[str] | dict[str, Any] | list[str] | tuple[str, ...]) -> list[str]:
    names = set(var_names)
    seen: set[str] = set()
    refs: list[str] = []
    if node is None:
        return refs
    for child in iterate_all(node):
        if child.type != "identifier":
            continue
        name = node_text(child)
        if name in names and name not in seen:
            seen.add(name)
            refs.append(name)
    return refs


def source_member_accesses(node: object | None, source_vars: set[str] | dict[str, Any] | list[str] | tuple[str, ...]) -> list[dict]:
    sources = set(source_vars)
    accesses: list[dict] = []
    if node is None:
        return accesses

    for child in iterate_all(node):
        if child.type == "method_invocation":
            object_node = child.child_by_field_name("object")
            name_node = child.child_by_field_name("name")
            object_name = node_text(object_node)
            if object_name in sources and name_node:
                accesses.append(
                    {
                        "source_var": object_name,
                        "expression": node_text(child),
                        "member": node_text(name_node),
                        "line": child.start_point[0] + 1,
                        "kind": "getter",
                    }
                )
        if child.type == "field_access":
            object_node = child.child_by_field_name("object")
            field_node = child.child_by_field_name("field")
            object_name = node_text(object_node)
            if object_name in sources and field_node:
                accesses.append(
                    {
                        "source_var": object_name,
                        "expression": node_text(child),
                        "member": node_text(field_node),
                        "line": child.start_point[0] + 1,
                        "kind": "field",
                    }
                )
    return accesses


def source_member_label(
    node: object | None,
    source_vars: set[str] | dict[str, Any] | list[str] | tuple[str, ...],
    *,
    source_labels: dict[str, str] | None = None,
) -> str | None:
    accesses = source_member_accesses(node, source_vars)
    if not accesses:
        return None
    access = accesses[0]
    base_label = (source_labels or {}).get(access["source_var"], f"`{access['source_var']}`")
    return f"`{access['expression']}` ({base_label})"


def unique_summaries(summaries: list[dict], key_fn: Callable[[dict], object]) -> list[dict]:
    unique: dict[object, dict] = {}
    for summary in summaries:
        unique.setdefault(key_fn(summary), summary)
    return list(unique.values())


def initialize_summary_cache(
    project_index: object | None,
    *,
    cache_attr: str,
    collect_fn: Callable[[object, dict[str, list[dict]]], list[dict]],
    key_fn: Callable[[dict], object],
    max_rounds: int = 4,
) -> dict[str, list[dict]]:
    """Build a fixed-point method summary cache for interprocedural detectors."""

    if project_index is None:
        return {}

    cached = getattr(project_index, cache_attr)
    if cached is not None:
        return cached

    methods = getattr(project_index, "methods")
    summaries_by_key: dict[str, list[dict]] = {method.signature_key: [] for method in methods}

    for method in methods:
        summaries_by_key[method.signature_key].extend(collect_fn(method, summaries_by_key))

    for _ in range(max_rounds):
        changed = False
        for method in methods:
            current = summaries_by_key.setdefault(method.signature_key, [])
            existing = {key_fn(summary) for summary in current}
            for summary in collect_fn(method, summaries_by_key):
                key = key_fn(summary)
                if key in existing:
                    continue
                current.append(summary)
                existing.add(key)
                changed = True
        if not changed:
            break

    setattr(project_index, cache_attr, summaries_by_key)
    return summaries_by_key
