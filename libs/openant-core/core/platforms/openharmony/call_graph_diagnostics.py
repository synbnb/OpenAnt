"""Observation-only diagnostics for unresolved OpenHarmony C/C++ calls.

The collector deliberately does not mutate the native call graph or emit
semantic edges.  It records syntax-backed member-pointer dispatch and
separate lambda/std::function observations with bounded candidate targets so
later deterministic/LLM stages have auditable inputs.  For callable reads it
also joins a registration and a read when their normalized member field and
proven receiver type agree, while keeping that join observation-only.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser


SCHEMA_VERSION = 1
CPP_EXTENSIONS = {".cpp", ".hpp", ".cc", ".cxx", ".hxx", ".hh"}
C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    )


def _walk(root: Any):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _source_line(function: Mapping[str, Any], node: Any) -> int:
    start = function.get("start_line", function.get("startLine", 1))
    if not isinstance(start, int) or start < 1:
        start = 1
    return start + node.start_point[0]


def _mask_preserving_lines(code: str) -> str:
    """Blank comments and literals without changing line offsets."""

    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char in "\r\n" else " " for char in match.group(0))

    masked = re.sub(r"//[^\r\n]*|/\*.*?\*/", blank, code, flags=re.DOTALL)
    return re.sub(r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", blank, masked)


def _selector_text(node: Any, source: bytes) -> str:
    text = _node_text(node, source).strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1].strip()
    return text


def _leaf(text: str) -> str:
    return (
        text.strip()
        .rsplit("::", 1)[-1]
        .rsplit("->", 1)[-1]
        .rsplit(".", 1)[-1]
    )


def _qualified_target_name(raw_name: str, owner_class: Any) -> str:
    target = raw_name.strip()
    owner = str(owner_class or "").strip().rsplit("::", 1)[-1]
    if owner and "::" not in target and target:
        return f"{owner}::{target}"
    return target


def _target_resolution(
    target_name: str,
    owner_file: str,
    functions: Mapping[str, Any],
    owner_class: Any = None,
    argument_count: int | None = None,
) -> tuple[str | None, str]:
    names = [target_name]
    qualified = _qualified_target_name(target_name, owner_class)
    if qualified and qualified not in names:
        names.insert(0, qualified)
    leaf = _leaf(target_name)
    if leaf and leaf not in names:
        names.append(leaf)
    saw_match = False
    for candidate_name in names:
        matches = [
            function_id
            for function_id, function in functions.items()
            if isinstance(function, Mapping) and function.get("name") == candidate_name
        ]
        if argument_count is not None:
            arity_matches = [
                function_id
                for function_id in matches
                if isinstance(functions[function_id].get("parameters"), list)
                and len(functions[function_id]["parameters"]) == argument_count
            ]
            if arity_matches:
                matches = arity_matches
        if len(matches) == 1:
            return matches[0], "exact_function_id"

        same_file = [
            function_id
            for function_id in matches
            if functions[function_id].get("file_path") == owner_file
        ]
        if len(same_file) == 1:
            return same_file[0], "exact_function_id"
        if matches:
            saw_match = True
    if saw_match:
        return None, "ambiguous_target_function"
    return None, "unknown_target_function"


def _dispatch_assignment(
    node: Any,
    source: bytes,
    function_id: str,
    function: Mapping[str, Any],
    functions: Mapping[str, Any],
) -> dict[str, Any] | None:
    if node.type != "assignment_expression":
        return None
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    if left.type != "subscript_expression":
        return None

    table_node = left.child_by_field_name("argument")
    selector_node = left.child_by_field_name("indices")
    if table_node is None or selector_node is None:
        return None

    table = _node_text(table_node, source).strip()
    selector = _selector_text(selector_node, source)
    target_name, value_kind = _dispatch_target(right, source)
    if not table or not selector or not target_name:
        return None

    owner_file = str(function.get("file_path", ""))
    target_id, resolution = _target_resolution(
        target_name, owner_file, functions
    )
    line = _source_line(function, node)
    expression = _node_text(node, source).strip()
    value_text = _node_text(right, source).strip()
    permissions = _permission_tokens(value_text, target_name, value_kind)
    return {
        "owner_function_id": function_id,
        "owner_class": function.get("class_name"),
        "file": owner_file,
        "line": line,
        "table": table,
        "selector": selector,
        "target_name": target_name,
        "target_id": target_id,
        "resolution": resolution,
        "value_kind": value_kind,
        "permissions": permissions,
        "evidence": {
            "file": owner_file,
            "start_line": line,
            "end_line": line,
            "text": expression,
            "value_kind": value_kind,
            "permissions": permissions,
        },
    }


def _dispatch_target(node: Any, source: bytes) -> tuple[str | None, str]:
    """Extract a member-function target from a pointer or pair initializer.

    C++ services use both ``table[key] = &Stub::Handler`` and
    ``table[key] = {&Stub::Handler, metadata}``.  The latter is represented by
    tree-sitter as an ``initializer_list`` whose first relevant descendant is
    still a ``pointer_expression``.  Walking that structure keeps the rule
    independent of the table's identifier and of the metadata type.
    """
    if node.type == "pointer_expression":
        target_node = node.child_by_field_name("argument")
        target_name = _node_text(target_node, source).strip() if target_node else ""
        return (target_name if "::" in target_name else None, "member_function_pointer")
    if node.type == "initializer_list":
        for child in node.children:
            target_name, value_kind = _dispatch_target(child, source)
            if target_name:
                return target_name, "member_function_pair"
    return None, "unsupported"


def _called_name(node: Any, source: bytes) -> str:
    if node is None:
        return ""
    if node.type not in {
        "identifier",
        "field_expression",
        "qualified_identifier",
        "scoped_identifier",
    }:
        return ""
    text = _node_text(node, source).strip()
    if not text:
        return ""
    return text if "::" in text else _leaf(text)


def _parameter_types(function: Mapping[str, Any]) -> dict[str, str]:
    """Infer simple parameter-name to class-type hints from extractor data."""
    parameters = function.get("parameters", [])
    if not isinstance(parameters, list):
        return {}
    result: dict[str, str] = {}
    for parameter in parameters:
        if not isinstance(parameter, str):
            continue
        match = re.search(
            r"(?P<type>[A-Za-z_]\w*(?:(?:::|\s*<)[A-Za-z0-9_:<> ,*&]+)?)"
            r"\s*[&*]*\s*(?P<name>[A-Za-z_]\w*)\s*$",
            parameter.strip(),
        )
        if match:
            result[match.group("name")] = match.group("type").strip()
    return result


def _normalized_type(type_name: Any) -> str:
    """Return a conservative type key suitable for field-identity joins."""
    text = str(type_name or "").strip()
    if not text:
        return ""
    text = re.sub(r"\b(?:const|volatile|class|struct|typename)\b", "", text)
    text = re.sub(r"[\s*&]+", "", text)
    if not text:
        return ""
    return text.rsplit("::", 1)[-1]


def _table_expression(node: Any, source: bytes) -> str:
    """Keep a simple object/field expression used as a dispatch table."""
    if node is None:
        return ""
    text = re.sub(r"\s+", "", _node_text(node, source).strip())
    if re.fullmatch(
        r"(?:this|[A-Za-z_]\w*)(?:(?:->|\.|::)[A-Za-z_]\w*)*", text
    ):
        return text
    return ""


def _field_identity(
    table: str,
    owner_class: Any,
    parameter_types: Mapping[str, str],
) -> dict[str, str]:
    """Describe a dispatch field independently of its local receiver name.

    The identity intentionally stays small: an exact field name plus a
    receiver type that can be proven from ``this`` or a simple parameter.
    Unknown expressions do not receive a type and therefore cannot create a
    cross-function match.
    """
    normalized = re.sub(r"\s+", "", str(table or "").strip())
    owner_type = _normalized_type(owner_class)
    field = normalized
    receiver = "this"
    receiver_type = owner_type
    receiver_kind = "this"

    if normalized.startswith("this->"):
        field = normalized[len("this->") :]
    elif normalized.startswith("this."):
        field = normalized[len("this.") :]
    else:
        match = re.fullmatch(
            r"(?P<receiver>[A-Za-z_]\w*)(?:->|\.)(?P<field>[A-Za-z_]\w*)",
            normalized,
        )
        if match:
            receiver = match.group("receiver")
            field = match.group("field")
            if receiver in parameter_types:
                receiver_type = _normalized_type(parameter_types[receiver])
                receiver_kind = "parameter"
            elif receiver and receiver[0].isupper():
                receiver_type = _normalized_type(receiver)
                receiver_kind = "class"
            else:
                receiver_type = ""
                receiver_kind = "expression"
        else:
            scope_match = re.fullmatch(
                r"(?P<receiver>[A-Za-z_]\w*)::(?P<field>[A-Za-z_]\w*)",
                normalized,
            )
            if scope_match:
                receiver = scope_match.group("receiver")
                field = scope_match.group("field")
                receiver_type = _normalized_type(receiver)
                receiver_kind = "class"

    return {
        "field": field,
        "receiver": receiver,
        "receiver_type": receiver_type,
        "receiver_kind": receiver_kind,
    }


def _field_identities_match(
    registration: Mapping[str, Any], call_site: Mapping[str, Any]
) -> bool:
    """Require an exact field and proven receiver type for alias joins."""
    registration_type = _normalized_type(registration.get("receiver_type"))
    call_type = _normalized_type(call_site.get("receiver_type"))
    return bool(
        registration.get("field")
        and registration.get("field") == call_site.get("field")
        and registration_type
        and registration_type == call_type
    )


def _lambda_target_spec(
    called: Any,
    source: bytes,
    owner_class: Any,
    parameter_types: Mapping[str, str],
) -> dict[str, Any]:
    raw_name = _called_name(called, source)
    owner_hint = owner_class
    if called is not None and called.type == "field_expression":
        receiver = called.child_by_field_name("argument")
        receiver_name = _node_text(receiver, source).strip() if receiver else ""
        if receiver_name == "this":
            owner_hint = owner_class
        else:
            owner_hint = parameter_types.get(receiver_name)
    return {
        "name": _qualified_target_name(raw_name, owner_hint),
        "owner_hint": owner_hint,
    }


def _lambda_parameter_types(node: Any, source: bytes) -> dict[str, str]:
    """Infer receiver hints from a lambda's own parameter list."""
    for child in node.children:
        if child.type != "abstract_function_declarator":
            continue
        parameter_list = child.child_by_field_name("parameters")
        if parameter_list is None:
            continue
        parameters = [
            _node_text(parameter, source).strip()
            for parameter in parameter_list.children
            if parameter.is_named
        ]
        return _parameter_types({"parameters": parameters})
    return {}


def _lambda_call_targets(
    node: Any,
    source: bytes,
    owner_class: Any,
    parameter_types: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Collect direct calls made by one lambda and qualify stub methods.

    The target is accepted only as a source-level call expression.  Later
    resolution still requires a unique extracted function, so a lambda that
    calls an overloaded or unavailable method remains an explicit orphan.
    """
    body = node.child_by_field_name("body")
    if body is None:
        return []
    effective_parameter_types = dict(parameter_types)
    effective_parameter_types.update(_lambda_parameter_types(node, source))
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    for child in _walk(body):
        if child.type != "call_expression":
            continue
        called = child.child_by_field_name("function")
        target_spec = _lambda_target_spec(
            called, source, owner_class, effective_parameter_types
        )
        target_name = target_spec["name"]
        if not target_name:
            continue
        arguments = child.child_by_field_name("arguments")
        argument_count = None
        if arguments is not None:
            argument_count = sum(
                1 for argument in arguments.children if argument.is_named
            )
        key = (target_name, argument_count)
        if target_name and key not in seen:
            seen.add(key)
            targets.append(
                {
                    "name": target_name,
                    "owner_hint": target_spec["owner_hint"],
                    "argument_count": argument_count,
                    "expression": _node_text(child, source).strip(),
                }
            )
    return targets


def _lambda_capture(node: Any, source: bytes) -> str:
    for child in node.children:
        if child.type == "lambda_capture_specifier":
            return _node_text(child, source).strip()
    return ""


def _lambda_registration_records(
    *,
    table: str,
    selector: str,
    lambda_node: Any,
    source: bytes,
    owner_function_id: str,
    owner_file: str,
    owner_class: Any,
    parameter_types: Mapping[str, str],
    line: int,
    expression: str,
    functions: Mapping[str, Any],
    registration_form: str,
) -> list[dict[str, Any]]:
    """Build normalized evidence records for one Lambda registration."""
    if not table or not selector or lambda_node.type != "lambda_expression":
        return []
    field_identity = _field_identity(table, owner_class, parameter_types)
    lambda_text = _node_text(lambda_node, source).strip()
    lambda_targets = _lambda_call_targets(
        lambda_node, source, owner_class, parameter_types
    )
    if not lambda_targets:
        lambda_targets = [
            {"name": "", "argument_count": None, "expression": ""}
        ]
    capture = _lambda_capture(lambda_node, source)
    records: list[dict[str, Any]] = []
    target_names = [item["name"] for item in lambda_targets]
    for target_spec in lambda_targets:
        target_name = target_spec["name"]
        target_id: str | None = None
        resolution = "no_lambda_call_target"
        if target_name:
            target_id, resolution = _target_resolution(
                target_name,
                owner_file,
                functions,
                target_spec.get("owner_hint"),
                target_spec["argument_count"],
            )
        resolved_name = target_name
        if target_id:
            resolved = functions.get(target_id)
            if isinstance(resolved, Mapping):
                resolved_name = str(resolved.get("name") or target_name)
        records.append(
            {
                "owner_function_id": owner_function_id,
                "owner_class": owner_class,
                "file": owner_file,
                "line": line,
                "table": table,
                "field_identity": field_identity,
                "selector": selector,
                "target_name": resolved_name,
                "target_id": target_id,
                "resolution": resolution,
                "value_kind": "lambda",
                "registration_form": registration_form,
                "capture": capture,
                "lambda_calls": target_names,
                "call_argument_count": target_spec["argument_count"],
                "evidence": {
                    "file": owner_file,
                    "start_line": line,
                    "end_line": line,
                    "text": expression,
                    "value_kind": "lambda",
                    "registration_form": registration_form,
                    "field_identity": field_identity,
                    "capture": capture,
                    "lambda_calls": target_names,
                    "call_argument_count": target_spec["argument_count"],
                },
                "lambda_text": lambda_text,
            }
        )
    return records


def _initializer_lambda_entries(
    node: Any, source: bytes
) -> list[tuple[str, Any, str]]:
    """Return ``(selector, lambda, pair_text)`` entries from a map initializer."""
    if node is None or node.type != "initializer_list":
        return []
    entries: list[tuple[str, Any, str]] = []
    for pair in node.children:
        if pair.type != "initializer_list":
            continue
        lambda_nodes = [
            child
            for child in pair.children
            if child.type == "lambda_expression"
        ]
        if not lambda_nodes:
            continue
        lambda_node = lambda_nodes[0]
        key_nodes = [
            child
            for child in pair.children
            if child.is_named and child is not lambda_node
        ]
        if not key_nodes:
            continue
        entries.append(
            (
                _selector_text(key_nodes[0], source),
                lambda_node,
                _node_text(pair, source).strip(),
            )
        )
    return entries


def _lambda_dispatch_assignments(
    node: Any,
    source: bytes,
    function_id: str,
    function: Mapping[str, Any],
    functions: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Extract lambda registrations without treating them as native edges."""
    if node.type != "assignment_expression":
        return []
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return []
    owner_file = str(function.get("file_path", ""))
    owner_class = function.get("class_name")
    parameter_types = _parameter_types(function)
    if left.type == "subscript_expression" and right.type == "lambda_expression":
        table_node = left.child_by_field_name("argument")
        selector_node = left.child_by_field_name("indices")
        if table_node is None or selector_node is None:
            return []
        return _lambda_registration_records(
            table=_node_text(table_node, source).strip(),
            selector=_selector_text(selector_node, source),
            lambda_node=right,
            source=source,
            owner_function_id=function_id,
            owner_file=owner_file,
            owner_class=owner_class,
            parameter_types=parameter_types,
            line=_source_line(function, node),
            expression=_node_text(node, source).strip(),
            functions=functions,
            registration_form="subscript_assignment",
        )

    if right.type != "initializer_list":
        return []
    table = _table_expression(left, source)
    if not table:
        return []
    records: list[dict[str, Any]] = []
    for selector, lambda_node, pair_text in _initializer_lambda_entries(
        right, source
    ):
        records.extend(
            _lambda_registration_records(
                table=table,
                selector=selector,
                lambda_node=lambda_node,
                source=source,
                owner_function_id=function_id,
                owner_file=owner_file,
                owner_class=owner_class,
                parameter_types=parameter_types,
                line=_source_line(function, lambda_node),
                expression=pair_text,
                functions=functions,
                registration_form="initializer_list",
            )
        )
    return records


def _initializer_table_from_source(node: Any, source: bytes) -> str:
    """Find the declarator immediately to the left of a file-level ``= {``."""
    text = source.decode("utf-8", errors="replace")
    masked = _mask_preserving_lines(text)
    equals = masked.rfind("=", 0, node.start_byte)
    if equals < 0:
        return ""
    prefix_start = max(
        masked.rfind(";", 0, equals),
        masked.rfind("{", 0, equals),
        masked.rfind("}", 0, equals),
    ) + 1
    prefix = masked[prefix_start:equals]
    match = re.search(
        r"(?P<table>[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*$", prefix
    )
    return match.group("table") if match else ""


def _table_owner_class(table: str) -> str | None:
    """Infer a class owner from ``Class::field`` without treating namespaces as classes."""
    parts = [part for part in table.split("::") if part]
    return parts[-2] if len(parts) >= 2 else None


def _file_level_lambda_dispatch_assignments(
    source: bytes,
    file_path: str,
    functions: Mapping[str, Any],
    parser: Parser,
) -> list[dict[str, Any]]:
    """Observe Lambda entries in global/static map initializer lists.

    Global declarations are sometimes exposed by tree-sitter as ``ERROR``
    nodes (notably templated ``std::map`` declarations).  Walking initializer
    lists and recovering the declarator from the preceding ``=`` keeps this
    collector independent of that node shape while still requiring a concrete
    ``{key, lambda}`` entry.
    """
    root = parser.parse(source).root_node
    records: list[dict[str, Any]] = []
    seen_initializers: set[int] = set()
    for node in _walk(root):
        if node.type != "initializer_list":
            continue
        entries = _initializer_lambda_entries(node, source)
        if not entries or node.start_byte in seen_initializers:
            continue
        ancestor = node.parent
        inside_function = False
        while ancestor is not None:
            if ancestor.type == "function_definition":
                inside_function = True
                break
            ancestor = ancestor.parent
        if inside_function:
            continue
        table = _initializer_table_from_source(node, source)
        if not table:
            continue
        seen_initializers.add(node.start_byte)
        owner_class = _table_owner_class(table)
        owner_function_id = f"{file_path}:<file-level:{table}>"
        for selector, lambda_node, pair_text in entries:
            records.extend(
                _lambda_registration_records(
                    table=table,
                    selector=selector,
                    lambda_node=lambda_node,
                    source=source,
                    owner_function_id=owner_function_id,
                    owner_file=file_path,
                    owner_class=owner_class,
                    parameter_types={},
                    line=lambda_node.start_point[0] + 1,
                    expression=pair_text,
                    functions=functions,
                    registration_form="file_initializer_list",
                )
            )
    return records


def _source_file_records(
    extract_result: Mapping[str, Any],
) -> list[tuple[str, bytes, str]]:
    """Load the extractor's validated source-file index safely."""
    source_files = extract_result.get("source_files", {})
    if not isinstance(source_files, Mapping):
        return []
    repository = Path(str(extract_result.get("repository", ""))).resolve()
    records: list[tuple[str, bytes, str]] = []
    for relative_path, metadata in source_files.items():
        relative = str(relative_path)
        if not relative:
            continue
        code: Any = metadata.get("code") if isinstance(metadata, Mapping) else None
        language = (
            str(metadata.get("language", ""))
            if isinstance(metadata, Mapping)
            else ""
        )
        if isinstance(code, str):
            source = code.encode("utf-8", errors="replace")
        else:
            candidate = (repository / relative).resolve()
            try:
                candidate.relative_to(repository)
            except ValueError:
                continue
            try:
                source = candidate.read_bytes()
            except OSError:
                continue
        records.append((relative, source, language))
    return records


def _permission_tokens(value_text: str, target_name: str, value_kind: str) -> list[str]:
    """Preserve qualified permission metadata from a pair initializer."""
    if value_kind != "member_function_pair" or "," not in value_text:
        return []
    metadata = value_text.split(",", 1)[1]
    target_parts = set(target_name.split("::"))
    tokens = re.findall(r"(?:[A-Za-z_]\w*::)+[A-Za-z_]\w*", metadata)
    return sorted({token for token in tokens if token.rsplit("::", 1)[-1] not in target_parts})


def _identifier(node: Any, source: bytes) -> str | None:
    if node is None or node.type != "identifier":
        return None
    text = _node_text(node, source).strip()
    return text if text.isidentifier() else None


def _local_dispatch_flow(root: Any, source: bytes) -> tuple[dict[str, str], dict[str, str]]:
    member_to_iterator: dict[str, str] = {}
    iterator_to_table: dict[str, str] = {}
    for node in _walk(root):
        if node.type != "init_declarator":
            continue
        variable = _identifier(node.child_by_field_name("declarator"), source)
        value = node.child_by_field_name("value")
        if not variable or value is None:
            continue

        if value.type == "field_expression":
            field = value.child_by_field_name("field")
            field_name = _node_text(field, source) if field is not None else ""
            receiver_node = value.child_by_field_name("argument")
            receiver = _identifier(receiver_node, source)
            # ``it->second`` is a direct member-function value.  A
            # permission-bearing pair uses ``it->second.first``; retain the
            # iterator for both forms so the table can be recovered without
            # knowing its identifier.
            if field_name == "second" and receiver:
                member_to_iterator[variable] = receiver
            elif field_name == "first" and receiver_node is not None and receiver_node.type == "field_expression":
                inner_field = receiver_node.child_by_field_name("field")
                inner_receiver = _identifier(
                    receiver_node.child_by_field_name("argument"), source
                )
                if (
                    inner_receiver
                    and inner_field is not None
                    and _node_text(inner_field, source) == "second"
                ):
                    member_to_iterator[variable] = inner_receiver
            continue

        if value.type != "call_expression":
            continue
        called = value.child_by_field_name("function")
        if called is None or called.type != "field_expression":
            continue
        table = _table_expression(called.child_by_field_name("argument"), source)
        field = called.child_by_field_name("field")
        if table and field is not None and _node_text(field, source) == "find":
            iterator_to_table[variable] = table
    return member_to_iterator, iterator_to_table


def _indirect_target(function_text: str) -> tuple[str | None, str, str] | None:
    member_match = re.search(
        r"(?:->\*|\.\*)\s*(?:\(\s*)?"
        r"(?P<operand>[A-Za-z_]\w*(?:(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)|"
        r"(?:\s*\[[^\[\]]*\]))*)",
        function_text,
    )
    if member_match:
        return (
            member_match.group("operand").strip(),
            "indirect_member_call",
            "parenthesized_member_function_pointer",
        )
    pointer_match = re.search(r"\*\s*([A-Za-z_]\w*)", function_text)
    if pointer_match:
        return (
            pointer_match.group(1),
            "indirect_function_call",
            "parenthesized_function_pointer",
        )
    return None


def _callable_dispatch_target(
    called: Any,
    source: bytes,
    member_to_iterator: Mapping[str, str],
) -> str | None:
    """Return a lookup-derived callable expression, if one is present."""
    if called is None:
        return None
    if called.type == "identifier":
        variable = _node_text(called, source).strip()
        return variable if variable in member_to_iterator else None
    if called.type == "field_expression":
        text = re.sub(r"\s+", "", _node_text(called, source).strip())
        if re.fullmatch(r"[A-Za-z_]\w*->second(?:\.first)?", text):
            return text
    return None


def _lexical_member_pointer_calls(source: bytes) -> list[dict[str, str]]:
    """Recover member-pointer calls that tree-sitter exposes as ERROR nodes.

    Some tree-sitter C++ versions parse ``this->*(iterator->second)`` as an
    error subtree rather than a call expression.  The token sequence is still
    unambiguous, so a balanced, comment-masked scan supplies the same bounded
    operand evidence without depending on a repository-specific table name.
    """
    text = source.decode("utf-8", errors="replace")
    masked = _mask_preserving_lines(text)
    results: list[dict[str, str]] = []
    operand_re = re.compile(
        r"[A-Za-z_]\w*(?:(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)|"
        r"(?:\s*\[[^\[\]]*\]))*"
    )
    for operator in re.finditer(r"->\*|\.\*", masked):
        rest = masked[operator.end() :]
        leading = len(rest) - len(rest.lstrip())
        rest = rest.lstrip()
        wrapped = rest.startswith("(")
        if wrapped:
            depth = 0
            end = None
            for offset, char in enumerate(rest):
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        end = offset
                        break
            if end is None:
                continue
            operand = rest[1:end].strip()
            consumed = leading + end + 1
        else:
            match = operand_re.match(rest)
            if match is None:
                continue
            operand = match.group(0).strip()
            consumed = leading + match.end()
        if not operand:
            continue
        after = masked[operator.end() + consumed :].lstrip()
        # A member-pointer expression is invoked either as ``(...)(args)``
        # or directly as ``... (args)``.  Require the following call token so
        # member-pointer declarations are not reported as call sites.
        if after.startswith(")"):
            after = after[1:].lstrip()
        if not after.startswith("("):
            continue
        line = masked.count("\n", 0, operator.start())
        start = operator.start()
        while start > 0 and masked[start - 1] not in "\n;{}":
            start -= 1
        expression = text[start : operator.end() + consumed].strip()
        results.append(
            {
                "operand": operand,
                "expression": expression,
                "line": str(line),
            }
        )
    return results


def _dispatch_symbols(
    operand: str,
    member_to_iterator: Mapping[str, str],
    iterator_to_table: Mapping[str, str],
) -> tuple[str, str, str]:
    """Resolve an indirect operand to (operand, iterator, table)."""
    normalized = re.sub(r"\s+", "", operand)
    if normalized in member_to_iterator:
        iterator = member_to_iterator[normalized]
        return normalized, iterator, iterator_to_table.get(iterator, "")

    iterator_match = re.fullmatch(r"([A-Za-z_]\w*)->second(?:\.first)?", normalized)
    if iterator_match:
        iterator = iterator_match.group(1)
        return normalized, iterator, iterator_to_table.get(iterator, "")

    subscript_match = re.fullmatch(
        r"([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\[[^\[\]]*\]",
        normalized,
    )
    if subscript_match:
        return normalized, "", subscript_match.group(1)
    return normalized, "", ""


def _lambda_dispatch_matches(
    assignments: list[dict[str, Any]],
    table: str,
    owner_class: Any,
    field_identity: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Match callable reads and return explicit cross-function alias evidence."""
    matched: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    for item in assignments:
        if not item.get("target_id"):
            continue
        same_owner = (
            not owner_class
            or not item.get("owner_class")
            or item.get("owner_class") == owner_class
        )
        if table and item.get("table") == table and same_owner:
            matched.append(item)
            continue
        registration_identity = item.get("field_identity")
        if not isinstance(registration_identity, Mapping):
            continue
        if not _field_identities_match(registration_identity, field_identity):
            continue
        matched.append(item)
        aliases.append(item)
    return matched, aliases


def build_call_graph_diagnostics(
    extract_result: Mapping[str, Any],
    call_graph_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect syntax-backed residual calls without changing either input."""
    functions = extract_result.get("functions", {})
    if not isinstance(functions, Mapping):
        functions = {}

    c_parser = Parser(C_LANGUAGE)
    cpp_parser = Parser(CPP_LANGUAGE)
    parsed: dict[str, tuple[Any, bytes, Mapping[str, Any]]] = {}
    assignments: list[dict[str, Any]] = []
    lambda_assignments: list[dict[str, Any]] = []

    for function_id, function in functions.items():
        if not isinstance(function_id, str) or not isinstance(function, Mapping):
            continue
        code = function.get("code", "")
        if not isinstance(code, str) or not code:
            continue
        source = code.encode("utf-8", errors="replace")
        suffix = Path(str(function.get("file_path", ""))).suffix.lower()
        parser = cpp_parser if suffix in CPP_EXTENSIONS else c_parser
        root = parser.parse(source).root_node
        parsed[function_id] = (root, source, function)
        for node in _walk(root):
            item = _dispatch_assignment(
                node, source, function_id, function, functions
            )
            if item is not None:
                assignments.append(item)
            lambda_assignments.extend(
                _lambda_dispatch_assignments(
                    node, source, function_id, function, functions
                )
            )

    for file_path, source, language in _source_file_records(extract_result):
        suffix = Path(file_path).suffix.lower()
        parser = (
            cpp_parser
            if language == "cpp" or suffix in CPP_EXTENSIONS
            else c_parser
        )
        lambda_assignments.extend(
            _file_level_lambda_dispatch_assignments(
                source, file_path, functions, parser
            )
        )

    assignments.sort(
        key=lambda item: (item["file"], item["line"], item["selector"], item["target_name"])
    )
    sites: list[dict[str, Any]] = []
    lambda_sites: list[dict[str, Any]] = []
    field_alias_matches: list[dict[str, Any]] = []
    for function_id, (root, source, function) in parsed.items():
        member_to_iterator, iterator_to_table = _local_dispatch_flow(root, source)
        indirect_calls: list[dict[str, Any]] = []
        callable_calls: list[dict[str, Any]] = []
        seen_calls: set[tuple[str, int]] = set()
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            called = node.child_by_field_name("function")
            callable_target = _callable_dispatch_target(
                called, source, member_to_iterator
            )
            if callable_target is not None:
                callable_calls.append(
                    {
                        "target_variable": callable_target,
                        "ast_kind": "std_function_call",
                        "reason": "lookup_derived_callable",
                        "line": _source_line(function, node),
                        "expression": _node_text(node, source).strip(),
                    }
                )
            if called is None or called.type != "parenthesized_expression":
                continue
            target = _indirect_target(_node_text(called, source))
            if target is None:
                continue
            target_variable, ast_kind, reason = target
            line = _source_line(function, node)
            key = (target_variable or "", line)
            seen_calls.add(key)
            indirect_calls.append(
                {
                    "target_variable": target_variable,
                    "ast_kind": ast_kind,
                    "reason": reason,
                    "line": line,
                    "expression": _node_text(node, source).strip(),
                }
            )

        # Tree-sitter currently exposes some nested member-pointer calls as
        # ERROR nodes.  Add only the balanced token-level observations that
        # were not already captured by the AST traversal.
        for lexical in _lexical_member_pointer_calls(source):
            target_variable = lexical["operand"]
            start_line = function.get("start_line", function.get("startLine", 1))
            if not isinstance(start_line, int) or start_line < 1:
                start_line = 1
            line = start_line + int(lexical["line"])
            key = (target_variable, line)
            if key in seen_calls:
                continue
            seen_calls.add(key)
            indirect_calls.append(
                {
                    "target_variable": target_variable,
                    "ast_kind": "indirect_member_call",
                    "reason": "member_pointer_expression_token_scan",
                    "line": line,
                    "expression": lexical["expression"],
                }
            )

        for indirect in indirect_calls:
            target_variable, iterator_variable, table = _dispatch_symbols(
                indirect["target_variable"],
                member_to_iterator,
                iterator_to_table,
            )
            owner_class = function.get("class_name")

            matched = [
                item
                for item in assignments
                if table
                and item["table"] == table
                and item["target_id"]
                and (
                    not owner_class
                    or not item.get("owner_class")
                    or item.get("owner_class") == owner_class
                )
            ]
            target_ids = list(dict.fromkeys(item["target_id"] for item in matched))
            sites.append(
                {
                    "caller_id": function_id,
                    "file": function.get("file_path", ""),
                    "line": indirect["line"],
                    "expression": indirect["expression"],
                    "ast_kind": indirect["ast_kind"],
                    "static_resolution": "unresolved",
                    "reason": indirect["reason"],
                    "symbols": {
                        "target_variable": target_variable,
                        "iterator_variable": iterator_variable,
                        "dispatch_table": table,
                    },
                    "candidate_target_ids": target_ids,
                    "candidates": [
                        {
                            "target_id": item["target_id"],
                            "target_name": item["target_name"],
                            "selector": item["selector"],
                            "value_kind": item.get("value_kind", ""),
                            "permissions": item.get("permissions", []),
                            "evidence": item["evidence"],
                        }
                        for item in matched
                    ],
                }
            )

        for callable_call in callable_calls:
            target_variable, iterator_variable, table = _dispatch_symbols(
                callable_call["target_variable"],
                member_to_iterator,
                iterator_to_table,
            )
            owner_class = function.get("class_name")
            field_identity = _field_identity(
                table, owner_class, _parameter_types(function)
            )
            matched, aliases = _lambda_dispatch_matches(
                lambda_assignments, table, owner_class, field_identity
            )
            target_ids = list(dict.fromkeys(item["target_id"] for item in matched))
            for item in aliases:
                field_alias_matches.append(
                    {
                        "caller_id": function_id,
                        "call_site_line": callable_call["line"],
                        "registration_owner_function_id": item[
                            "owner_function_id"
                        ],
                        "registration_line": item["line"],
                        "dispatch_table": field_identity["field"],
                        "selector": item["selector"],
                        "target_id": item["target_id"],
                        "target_name": item["target_name"],
                        "reason": "same_field_receiver_type",
                        "confidence": "high",
                    }
                )
            lambda_sites.append(
                {
                    "caller_id": function_id,
                    "file": function.get("file_path", ""),
                    "line": callable_call["line"],
                    "expression": callable_call["expression"],
                    "ast_kind": callable_call["ast_kind"],
                    "static_resolution": "unresolved",
                    "reason": callable_call["reason"],
                    "symbols": {
                        "target_variable": target_variable,
                        "iterator_variable": iterator_variable,
                        "dispatch_table": table,
                    },
                    "field_identity": field_identity,
                    "candidate_target_ids": target_ids,
                    "candidates": [
                        {
                            "target_id": item["target_id"],
                            "target_name": item["target_name"],
                            "selector": item["selector"],
                            "value_kind": item.get("value_kind", "lambda"),
                            "capture": item.get("capture", ""),
                            "lambda_calls": item.get("lambda_calls", []),
                            "call_argument_count": item.get(
                                "call_argument_count"
                            ),
                            "evidence": item["evidence"],
                        }
                        for item in matched
                    ],
                }
            )

    sites.sort(key=lambda item: (item["file"], item["line"], item["caller_id"]))
    orphans = [
        {
            "owner_function_id": item["owner_function_id"],
            "file": item["file"],
            "line": item["line"],
            "table": item["table"],
            "selector": item["selector"],
            "target_name": item["target_name"],
            "reason": item["resolution"],
            "evidence": item["evidence"],
        }
        for item in assignments
        if not item["target_id"]
    ]

    lambda_sites.sort(
        key=lambda item: (item["file"], item["line"], item["caller_id"])
    )
    field_alias_matches.sort(
        key=lambda item: (
            item["caller_id"],
            item["call_site_line"],
            item["registration_owner_function_id"],
            item["registration_line"],
            item["target_id"],
        )
    )
    lambda_orphans = [
        {
            "owner_function_id": item["owner_function_id"],
            "file": item["file"],
            "line": item["line"],
            "table": item["table"],
            "selector": item["selector"],
            "target_name": item["target_name"],
            "reason": item["resolution"],
            "evidence": item["evidence"],
        }
        for item in lambda_assignments
        if not item["target_id"]
    ]

    summary = {
        "unresolved_call_sites": len(sites),
        "dispatch_assignments": len(assignments),
        "candidate_edges": sum(
            len(site["candidate_target_ids"]) for site in sites
        ),
        "unresolved_without_candidates": sum(
            not site["candidate_target_ids"] for site in sites
        ),
        "orphan_assignments": len(orphans),
    }
    if lambda_assignments or lambda_sites or lambda_orphans:
        lambda_summary = {
            "dispatch_assignments": len(lambda_assignments),
            "call_sites": len(lambda_sites),
            "candidate_edges": sum(
                len(site["candidate_target_ids"]) for site in lambda_sites
            ),
            "unresolved_without_candidates": sum(
                not site["candidate_target_ids"] for site in lambda_sites
            ),
            "orphan_assignments": len(lambda_orphans),
        }
        if field_alias_matches:
            lambda_summary["field_alias_matches"] = len(field_alias_matches)
        summary["lambda_dispatch"] = lambda_summary

    result = {
        "schema_version": SCHEMA_VERSION,
        "platform": "openharmony",
        "status": "complete",
        "repository": extract_result.get("repository", ""),
        "summary": summary,
        "unresolved_call_sites": sites,
        "dispatch_assignments": assignments,
        "orphans": orphans,
    }
    if lambda_assignments or lambda_sites or lambda_orphans:
        result["lambda_dispatch"] = {
            "summary": summary["lambda_dispatch"],
            "assignments": lambda_assignments,
            "call_sites": lambda_sites,
            "orphans": lambda_orphans,
        }
        if field_alias_matches:
            result["lambda_dispatch"]["field_alias_matches"] = field_alias_matches
    return result


__all__ = ["SCHEMA_VERSION", "build_call_graph_diagnostics"]
