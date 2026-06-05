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
    source_parameters: set[str]
    key: str
    signature_key: str
    has_body: bool


@dataclass
class ProjectIndex:
    methods: list[MethodInfo] = field(default_factory=list)
    methods_by_key: dict[str, MethodInfo] = field(default_factory=dict)
    methods_by_qualified_name: dict[str, list[MethodInfo]] = field(default_factory=dict)
    methods_by_name: dict[str, list[MethodInfo]] = field(default_factory=dict)
    methods_by_node_id: dict[int, MethodInfo] = field(default_factory=dict)
    class_field_types: dict[str, dict[str, str]] = field(default_factory=dict)
    interface_implementations: dict[str, list[str]] = field(default_factory=dict)
    sql_summaries_by_key: dict[str, list[dict]] | None = None
    path_summaries_by_key: dict[str, list[dict]] | None = None
    xss_summaries_by_key: dict[str, list[dict]] | None = None

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
        arity = len(_argument_expressions(invocation_node.child_by_field_name("arguments")))

        object_node = invocation_node.child_by_field_name("object")
        if object_node:
            object_name = _normalize_object_name(_node_text(object_node))
            class_name = local_types.get(object_name) or object_name
            method = self._resolve_candidate(f"{class_name}.{callee_name}", arity=arity)
            if method:
                return method
            return _unique_by_arity(self.methods_by_name.get(callee_name, []), arity=arity)

        if caller.class_name:
            method = self._resolve_candidate(f"{caller.class_name}.{callee_name}", arity=arity)
            if method:
                return method
        return _unique_by_arity(self.methods_by_name.get(callee_name, []), arity=arity)

    def method_for_node(self, node: object) -> MethodInfo | None:
        return self.methods_by_node_id.get(id(node))

    def resolve_method(self, qualified_name: str, *, arity: int) -> MethodInfo | None:
        return self._resolve_candidate(qualified_name, arity=arity)

    def _resolve_candidate(self, qualified_name: str, *, arity: int) -> MethodInfo | None:
        method = _unique_by_arity(self.methods_by_qualified_name.get(qualified_name, []), arity=arity)
        if method and method.has_body:
            return method

        class_name, _, method_name = qualified_name.rpartition(".")
        if class_name:
            implementation_method = self._resolve_implementation_candidate(
                class_name,
                method_name=method_name,
                arity=arity,
            )
            if implementation_method:
                return implementation_method
        return method

    def _resolve_implementation_candidate(self, interface_name: str, *, method_name: str, arity: int) -> MethodInfo | None:
        implementations = self.interface_implementations.get(interface_name, [])
        candidates = []
        for implementation in implementations:
            method = _unique_by_arity(
                self.methods_by_qualified_name.get(f"{implementation}.{method_name}", []),
                arity=arity,
            )
            if method and method.has_body:
                candidates.append(method)
        return candidates[0] if len(candidates) == 1 else None


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
            for interface_name in _implemented_interfaces_for_class(class_node):
                index.interface_implementations.setdefault(interface_name, []).append(class_name)
            field_types = _field_types_for_class(class_node)
            field_types.update(_constructor_injected_field_types(class_node, field_types))
            index.class_field_types.setdefault(class_name, {}).update(field_types)

        for method_node in iterate_all(tree.root_node):
            if method_node.type != "method_declaration":
                continue
            method_name_node = method_node.child_by_field_name("name")
            if not method_name_node:
                continue
            class_name = _find_parent_type_name(method_node)
            method_name = _node_text(method_name_node)
            parameters = _parameter_names(method_node)
            key = f"{class_name}.{method_name}" if class_name else method_name
            method = MethodInfo(
                filepath=filepath,
                tree=tree,
                node=method_node,
                class_name=class_name,
                method_name=method_name,
                parameters=parameters,
                source_parameters=_spring_source_parameter_names(method_node),
                key=key,
                signature_key=f"{key}/{len(parameters)}",
                has_body=method_node.child_by_field_name("body") is not None,
            )
            index.methods.append(method)
            index.methods_by_key[method.signature_key] = method
            index.methods_by_qualified_name.setdefault(key, []).append(method)
            index.methods_by_name.setdefault(method_name, []).append(method)
            index.methods_by_node_id[id(method_node)] = method

    return index


def _find_parent_type_name(node: object) -> str | None:
    current = node.parent
    while current:
        if current.type in {"class_declaration", "interface_declaration"}:
            name_node = current.child_by_field_name("name")
            if name_node:
                return _node_text(name_node)
        current = current.parent
    return find_parent_class(node)


def _implemented_interfaces_for_class(class_node: object) -> list[str]:
    interfaces = []
    for child in class_node.children:
        if child.type != "super_interfaces":
            continue
        for node in iterate_all(child):
            if node.type.endswith("type_identifier"):
                name = _node_text(node)
                if name not in interfaces:
                    interfaces.append(name)
    return interfaces


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


def _constructor_injected_field_types(class_node: object, existing_field_types: dict[str, str]) -> dict[str, str]:
    injected_types = {}
    for constructor_node in iterate_all(class_node):
        if constructor_node.type != "constructor_declaration":
            continue

        parameter_types = _parameter_types_by_name(constructor_node)
        if not parameter_types:
            continue

        for node in iterate_all(constructor_node):
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if not left or not right or right.type != "identifier":
                continue

            field_name = _assigned_field_name(left)
            parameter_name = _node_text(right)
            parameter_type = parameter_types.get(parameter_name)
            if field_name and parameter_type:
                injected_types[field_name] = existing_field_types.get(field_name, parameter_type)
    return injected_types


def _parameter_types_by_name(method_or_constructor_node: object) -> dict[str, str]:
    parameter_types = {}
    for node in iterate_all(method_or_constructor_node):
        if node.type != "formal_parameter":
            continue
        name_node = node.child_by_field_name("name")
        type_node = node.child_by_field_name("type")
        if name_node and type_node:
            parameter_types[_node_text(name_node)] = _clean_type_name(_node_text(type_node))
    return parameter_types


def _assigned_field_name(node: object) -> str | None:
    if node.type == "identifier":
        return _node_text(node)
    if node.type == "field_access":
        field_node = node.child_by_field_name("field")
        if not field_node:
            identifiers = [child for child in node.children if child.type == "identifier"]
            field_node = identifiers[-1] if identifiers else None
        return _node_text(field_node) if field_node else None
    return None


def _parameter_names(method_node: object) -> list[str]:
    parameters = []
    for node in iterate_all(method_node):
        if node.type != "formal_parameter":
            continue
        name_node = node.child_by_field_name("name")
        if name_node and _node_text(name_node) not in parameters:
            parameters.append(_node_text(name_node))
    return parameters


SPRING_MVC_SOURCE_ANNOTATIONS = {
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestBody",
    "ModelAttribute",
}


def _spring_source_parameter_names(method_node: object) -> set[str]:
    source_parameters = set()
    for node in iterate_all(method_node):
        if node.type != "formal_parameter":
            continue
        name_node = node.child_by_field_name("name")
        if not name_node:
            continue
        parameter_text = _node_text(node)
        if any(f"@{annotation}" in parameter_text for annotation in SPRING_MVC_SOURCE_ANNOTATIONS):
            source_parameters.add(_node_text(name_node))
    return source_parameters


def _declaration_type_name(declaration_node: object) -> str | None:
    type_node = declaration_node.child_by_field_name("type")
    if not type_node:
        return None
    return _clean_type_name(_node_text(type_node))


def _clean_type_name(type_text: str) -> str | None:
    type_text = type_text.strip()
    if not type_text:
        return None
    return type_text.split("<", 1)[0].split("[", 1)[0].strip()


def _node_text(node: object) -> str:
    return node.text.decode()


def _normalize_object_name(name: str) -> str:
    return name[5:] if name.startswith("this.") else name


def _argument_expressions(arguments_node: object | None) -> list[object]:
    if not arguments_node:
        return []
    return [child for child in arguments_node.children if child.is_named]


def _unique_by_arity(methods: list[MethodInfo], *, arity: int) -> MethodInfo | None:
    matched = [method for method in methods if len(method.parameters) == arity]
    return matched[0] if len(matched) == 1 else None
