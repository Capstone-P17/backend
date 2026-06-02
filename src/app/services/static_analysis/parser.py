from __future__ import annotations

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))


def find_parent_method(node):
    current = node.parent
    while current:
        if current.type == "method_declaration":
            name_node = current.child_by_field_name("name")
            if name_node:
                return name_node.text.decode()
        current = current.parent
    return None


def find_parent_class(node):
    current = node.parent
    while current:
        if current.type == "class_declaration":
            name_node = current.child_by_field_name("name")
            if name_node:
                return name_node.text.decode()
        current = current.parent
    return None


def iterate_all(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def parse_file(filepath):
    with open(filepath, "r", encoding="utf-8") as file_handle:
        code = file_handle.read()
    tree = parser.parse(bytes(code, "utf-8"))
    return tree, code
