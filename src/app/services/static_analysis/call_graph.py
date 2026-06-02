from __future__ import annotations

from src.app.services.static_analysis.parser import find_parent_class, iterate_all


def build_call_graph(tree):
    call_graph = {}

    for node in iterate_all(tree.root_node):
        if node.type != "method_declaration":
            continue

        class_name = find_parent_class(node)
        name_node = node.child_by_field_name("name")
        if not name_node:
            continue

        method_name = name_node.text.decode()
        key = f"{class_name}.{method_name}" if class_name else method_name
        calls = []

        for child in iterate_all(node):
            if child is node or child.type != "method_invocation":
                continue

            child_name = child.child_by_field_name("name")
            object_node = child.child_by_field_name("object")
            if not child_name:
                continue

            if object_node:
                call_name = f"{object_node.text.decode()}.{child_name.text.decode()}"
            else:
                call_name = child_name.text.decode()
            if call_name not in calls:
                calls.append(call_name)

        if calls:
            call_graph[key] = calls
    return call_graph
