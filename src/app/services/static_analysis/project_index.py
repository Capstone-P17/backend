from __future__ import annotations

from dataclasses import dataclass, field

from src.app.services.static_analysis.parser import find_parent_class, iterate_all


@dataclass(frozen=True)
class MethodInfo:
    filepath: str
    tree: object
    node: object
    class_name: str | None
    method_name: str
    parameters: list[str]
    key: str


@dataclass
class ProjectIndex:
    methods: list[MethodInfo] = field(default_factory=list)
    methods_by_key: dict[str, MethodInfo] = field(default_factory=dict)
    methods_by_name: dict[str, list[MethodInfo]] = field(default_factory=dict)
    class_field_types: dict[str, dict[str, str]] = field(default_factory=dict)
    sql_summaries_by_key: dict[str, list[dict]] | None = None

    def variable_types_for(self, method: MethodInfo) -> dict[str, str]:
        variable_types = {}
        if method.class_name:
            variable_types.update(self.class_field_types.get(method.class_name, {}))

        for node in iterate_all(method.node):
            if node.type != "local_variable_declaration":
                continue
            type_name = _declaration_type_name(node)
            if not type_name:
                continue
            for child in node.children:
                if child.type != "variable_declarator":
                    continue
                name_node = child.child_by_field_name("name")
                if name_node:
                    variable_types[_node_text(name_node)] = type_name
        return variable_types

    def resolve_invocation(self, caller: MethodInfo, invocation_node: object, local_types: dict[str, str]) -> MethodInfo | None:
        if getattr(invocation_node, "type", None) != "method_invocation":
            return None

        name_node = invocation_node.child_by_field_name("name")
        if not name_node:
            return None
        callee_name = _node_text(name_node)

        object_node = invocation_node.child_by_field_name("object")
        if object_node:
            object_name = _node_text(object_node)
            class_name = local_types.get(object_name) or object_name
            method = self.methods_by_key.get(f"{class_name}.{callee_name}")
            if method:
                return method
            return _unique(self.methods_by_name.get(callee_name, []))

        if caller.class_name:
            method = self.methods_by_key.get(f"{caller.class_name}.{callee_name}")
            if method:
                return method
        return _unique(self.methods_by_name.get(callee_name, []))


def build_project_index(parsed_files: list[tuple[str, object, str]]) -> ProjectIndex:
    index = ProjectIndex()

    for filepath, tree, _code in parsed_files:
        for class_node in iterate_all(tree.root_node):
            if class_node.type != "class_declaration":
                continue
            class_name_node = class_node.child_by_field_name("name")
            if not class_name_node:
                continue
            class_name = _node_text(class_name_node)
            index.class_field_types.setdefault(class_name, {}).update(_field_types_for_class(class_node))

        for method_node in iterate_all(tree.root_node):
            if method_node.type != "method_declaration":
                continue
            method_name_node = method_node.child_by_field_name("name")
            if not method_name_node:
                continue
            class_name = find_parent_class(method_node)
            method_name = _node_text(method_name_node)
            key = f"{class_name}.{method_name}" if class_name else method_name
            method = MethodInfo(
                filepath=filepath,
                tree=tree,
                node=method_node,
                class_name=class_name,
                method_name=method_name,
                parameters=_parameter_names(method_node),
                key=key,
            )
            index.methods.append(method)
            index.methods_by_key[key] = method
            index.methods_by_name.setdefault(method_name, []).append(method)

    return index


def _field_types_for_class(class_node: object) -> dict[str, str]:
    field_types = {}
    for node in iterate_all(class_node):
        if node.type == "class_declaration" and node is not class_node:
            continue
        if node.type != "field_declaration":
            continue
        type_name = _declaration_type_name(node)
        if not type_name:
            continue
        for child in node.children:
            if child.type != "variable_declarator":
                continue
            name_node = child.child_by_field_name("name")
            if name_node:
                field_types[_node_text(name_node)] = type_name
    return field_types


def _parameter_names(method_node: object) -> list[str]:
    parameters = []
    for node in iterate_all(method_node):
        if node.type != "formal_parameter":
            continue
        name_node = node.child_by_field_name("name")
        if name_node and _node_text(name_node) not in parameters:
            parameters.append(_node_text(name_node))
    return parameters


def _declaration_type_name(declaration_node: object) -> str | None:
    type_node = declaration_node.child_by_field_name("type")
    if not type_node:
        return None
    type_text = _node_text(type_node).strip()
    if not type_text:
        return None
    return type_text.split("<", 1)[0].split("[", 1)[0].strip()


def _node_text(node: object) -> str:
    return node.text.decode()


def _unique(methods: list[MethodInfo]) -> MethodInfo | None:
    return methods[0] if len(methods) == 1 else None
