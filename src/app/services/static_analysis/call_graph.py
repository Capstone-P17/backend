from __future__ import annotations

from src.app.services.static_analysis.parser import find_parent_class


def build_call_graph(tree):
    call_graph = {}

    def visit(node):
        if node.type == "method_declaration":
            class_name = find_parent_class(node)
            name_node = node.child_by_field_name("name")
            if name_node:
                method_name = name_node.text.decode()
                key = f"{class_name}.{method_name}" if class_name else method_name
                calls = []
                collect_calls(node, calls)
                if calls:
                    call_graph[key] = calls
        for child in node.children:
            visit(child)

    def collect_calls(node, calls):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            object_node = node.child_by_field_name("object")
            if name_node:
                if object_node:
                    call_name = f"{object_node.text.decode()}.{name_node.text.decode()}"
                else:
                    call_name = name_node.text.decode()
                if call_name not in calls:
                    calls.append(call_name)
        for child in node.children:
            collect_calls(child, calls)

    visit(tree.root_node)
    return call_graph
