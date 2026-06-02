from __future__ import annotations

from src.app.services.static_analysis.parser import iterate_all


class FakeNode:
    def __init__(self, children=None):
        self.children = list(children or [])


def test_iterate_all_handles_deep_tree_without_recursion_error() -> None:
    root = FakeNode()
    current = root
    for _ in range(2_000):
        child = FakeNode()
        current.children = [child]
        current = child

    assert sum(1 for _ in iterate_all(root)) == 2_001
