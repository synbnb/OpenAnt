"""Observation-only diagnostics for unresolved OpenHarmony C/C++ calls.

The collector deliberately does not mutate the native call graph or emit
semantic edges.  It records syntax-backed member-pointer dispatch and
separate lambda/std::function observations with bounded candidate targets so
later deterministic/LLM stages have auditable inputs.  For callable reads it
also joins a registration and a read when their normalized member field and
proven receiver type agree, while keeping that join observation-only.  A
local member-function array is joined to a same-class helper only when it is
passed as a direct, uniquely resolved parameter; ambiguous or aliased flows
remain residuals.  Registration helpers are recognized structurally when a
callable parameter is written into a subscripted table, and concrete helper
calls are expanded only when the passed function reference exists in the
extracted function index.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Mapping

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
    if node is None:
        return ""
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
    name_index: Mapping[str, list[str]] | None = None,
    leaf_index: Mapping[str, list[str]] | None = None,
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
        if name_index is not None:
            matches = list(name_index.get(candidate_name, []))
        else:
            matches = [
                function_id
                for function_id, function in functions.items()
                if isinstance(function, Mapping)
                and function.get("name") == candidate_name
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
    # Extracted function names may retain the namespace while the source
    # initializer only spells ``Class::Method``.  A two-component qualified
    # suffix is still a concrete class/member identity, unlike a leaf-only
    # fallback.  Resolve it only when the suffix is unique (preferably in the
    # registration file), and keep arity filtering when the caller supplied
    # one.
    if "::" in target_name:
        target_parts = [part for part in target_name.split("::") if part]
        if len(target_parts) >= 2:
            suffix = "::".join(target_parts[-2:])
            if name_index is not None:
                suffix_matches = list(name_index.get(suffix, []))
                if not suffix_matches:
                    suffix_matches = [
                        function_id
                        for function_id, function in functions.items()
                        if isinstance(function, Mapping)
                        and str(function.get("name") or "").endswith(
                            f"::{suffix}"
                        )
                    ]
            else:
                suffix_matches = [
                    function_id
                    for function_id, function in functions.items()
                    if isinstance(function, Mapping)
                    and (
                        str(function.get("name") or "") == suffix
                        or str(function.get("name") or "").endswith(
                            f"::{suffix}"
                        )
                    )
                ]
            if argument_count is not None:
                arity_matches = [
                    function_id
                    for function_id in suffix_matches
                    if isinstance(functions[function_id].get("parameters"), list)
                    and len(functions[function_id]["parameters"]) == argument_count
                ]
                if arity_matches:
                    suffix_matches = arity_matches
            same_file = [
                function_id
                for function_id in suffix_matches
                if functions[function_id].get("file_path") == owner_file
            ]
            if len(same_file) == 1:
                return same_file[0], "qualified_suffix_same_file"
            if len(suffix_matches) == 1:
                return suffix_matches[0], "qualified_suffix"
            if suffix_matches:
                saw_match = True
    # Namespace-qualified free functions are often indexed as
    # ``OHOS::Namespace::Handler`` while the lambda call expression contains
    # only ``Handler``.  Resolve that spelling only when the unqualified name
    # is unique (preferably in the same source file) and, when available,
    # agrees with the call arity.  Never apply this fallback to an already
    # qualified target, where a leaf-only match could select the wrong class
    # or namespace overload.
    if "::" not in target_name and leaf:
        if leaf_index is not None:
            leaf_matches = list(leaf_index.get(leaf, []))
        else:
            leaf_matches = [
                function_id
                for function_id, function in functions.items()
                if isinstance(function, Mapping)
                and _leaf(str(function.get("name") or "")) == leaf
            ]
        if argument_count is not None:
            arity_matches = [
                function_id
                for function_id in leaf_matches
                if isinstance(functions[function_id].get("parameters"), list)
                and len(functions[function_id]["parameters"]) == argument_count
            ]
            if arity_matches:
                leaf_matches = arity_matches
        same_file = [
            function_id
            for function_id in leaf_matches
            if functions[function_id].get("file_path") == owner_file
        ]
        if len(same_file) == 1:
            return same_file[0], "leaf_name_same_file"
        if len(leaf_matches) == 1:
            return leaf_matches[0], "leaf_name"
        if leaf_matches:
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


def _initializer_member_function_assignments(
    node: Any,
    source: bytes,
    function_id: str,
    function: Mapping[str, Any],
    functions: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Observe class-owned function-pointer tables initialized as a whole.

    This deliberately handles only a simple assignment such as
    ``parseTable_ = {{Section::A, Class::Handle}}`` or a local array
    declaration such as ``Entry table[] = {{A, &Class::Handle}}``.  The
    registration class must match the containing method's class, which keeps
    enum/metadata maps and unrelated qualified values out of the dispatch
    evidence.  A local array is not considered callable across functions
    until a separate, explicit parameter-flow record joins it to a callee.
    """
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        registration_form = "initializer_member_function"
        table = _table_expression(left, source)
    elif node.type == "init_declarator":
        left = node.child_by_field_name("declarator")
        right = node.child_by_field_name("value")
        registration_form = "declaration_member_function_array"
        table = _declarator_table_expression(left, source)
    else:
        return []
    if left is None or right is None or right.type != "initializer_list":
        return []
    owner_file = str(function.get("file_path", ""))
    owner_class = _leaf(str(function.get("class_name") or ""))
    if not table or not owner_class:
        return []

    records: list[dict[str, Any]] = []
    for selector, target_name, value_kind, pair_text in (
        _initializer_member_function_entries(right, source)
    ):
        target_parts = [part for part in target_name.split("::") if part]
        if len(target_parts) < 2:
            continue
        target_class = _leaf("::".join(target_parts[:-1]))
        if target_class != owner_class:
            continue
        target_id, resolution = _target_resolution(
            target_name, owner_file, functions, owner_class
        )
        if target_id:
            resolved = functions.get(target_id)
            resolved_class = _leaf(
                str(resolved.get("class_name") or "")
            ) if isinstance(resolved, Mapping) else ""
            if resolved_class and resolved_class != owner_class:
                continue
        line = _source_line(function, node)
        permissions = _permission_tokens(pair_text, target_name, value_kind)
        records.append(
            {
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
                "registration_form": registration_form,
                "permissions": permissions,
                "evidence": {
                    "file": owner_file,
                    "start_line": line,
                    "end_line": line,
                    "text": pair_text,
                    "value_kind": value_kind,
                    "registration_form": registration_form,
                    "permissions": permissions,
                },
            }
        )
    return records


def _dispatch_target(
    node: Any, source: bytes, *, allow_reference: bool = False
) -> tuple[str | None, str]:
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
        if target_name and (allow_reference or "::" in target_name):
            value_kind = (
                "member_function_pointer"
                if "::" in target_name
                else "function_pointer"
            )
            return target_name, value_kind
        return None, "unsupported"
    if allow_reference and node.type in {
        "identifier",
        "qualified_identifier",
        "scoped_identifier",
    }:
        target_name = _node_text(node, source).strip()
        # A qualified reference such as ``Class::Handler`` or an unqualified
        # function name is a valid C++ callable initializer even when the
        # source omits ``&``.  Unqualified names are accepted here only as a
        # syntactic observation; callers must still resolve them uniquely in
        # the extracted function index before they become candidates.
        if not target_name:
            return None, "unsupported"
        value_kind = (
            "member_function_reference"
            if "::" in target_name
            else "function_reference"
        )
        return target_name, value_kind
    if node.type == "initializer_list":
        for child in node.children:
            target_name, value_kind = _dispatch_target(
                child, source, allow_reference=allow_reference
            )
            if target_name:
                return target_name, "member_function_pair"
    return None, "unsupported"


def _initializer_member_function_entries(
    node: Any, source: bytes
) -> list[tuple[str, str, str, str]]:
    """Return direct function references from ``{selector, target}`` pairs.

    The pair's final named child is intentionally used as the value.  This
    prevents a qualified selector such as ``SnapshotSection::THREAD_INFO``
    from being mistaken for a function target while still allowing a nested
    value pair such as ``{selector, {&Class::Handler, metadata}}``.
    """
    if node is None or node.type != "initializer_list":
        return []
    entries: list[tuple[str, str, str, str]] = []
    for pair in node.children:
        if pair.type != "initializer_list":
            continue
        named = [child for child in pair.children if child.is_named]
        if len(named) < 2:
            continue
        selector = _selector_text(named[0], source)
        target_name, value_kind = _dispatch_target(
            named[-1], source, allow_reference=True
        )
        if not selector or not target_name:
            continue
        entries.append(
            (
                selector,
                target_name,
                value_kind,
                _node_text(pair, source).strip(),
            )
        )
    return entries


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


def _declarator_table_expression(node: Any, source: bytes) -> str:
    """Extract the identifier represented by a simple array declarator."""
    current = node
    while current is not None:
        if current.type == "identifier":
            value = _node_text(current, source).strip()
            return value if value.isidentifier() else ""
        nested = current.child_by_field_name("declarator")
        if nested is not None and nested is not current:
            current = nested
            continue
        named = [child for child in current.children if child.is_named]
        if len(named) == 1 and named[0] is not current:
            current = named[0]
            continue
        break
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


def _initializer_callable_entries(
    node: Any, source: bytes
) -> list[tuple[str, str, str, str]]:
    """Return source-level function references from ``{key, callable}`` pairs.

    Unlike member-function initializers, the callable may be a free function
    written as an unqualified identifier.  A later resolution step still
    requires that identifier to map to exactly one extracted function, so
    enum constants and unknown symbols are not promoted to candidates.
    """
    if node is None or node.type != "initializer_list":
        return []
    entries: list[tuple[str, str, str, str]] = []
    for pair in node.children:
        if pair.type != "initializer_list":
            continue
        named = [child for child in pair.children if child.is_named]
        if len(named) < 2:
            continue
        selector = _selector_text(named[0], source)
        target_name, value_kind = _dispatch_target(
            named[-1], source, allow_reference=True
        )
        if not selector or not target_name:
            continue
        entries.append(
            (
                selector,
                target_name,
                value_kind,
                _node_text(pair, source).strip(),
            )
        )
    return entries


def _initializer_callable_assignments(
    node: Any,
    source: bytes,
    function_id: str,
    function: Mapping[str, Any],
    functions: Mapping[str, Any],
    name_index: Mapping[str, list[str]] | None = None,
    leaf_index: Mapping[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Observe map entries that point directly at indexed free functions.

    Existing member-table handling intentionally requires a class-qualified
    target.  This companion path covers tables such as
    ``{{CPP_CRASH, GetCppCrashSectionLogs}}`` while keeping the same strict
    function-index resolution requirement.
    """
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        table = _table_expression(left, source)
        registration_form = "initializer_function_reference"
    elif node.type == "init_declarator":
        left = node.child_by_field_name("declarator")
        right = node.child_by_field_name("value")
        table = _declarator_table_expression(left, source)
        registration_form = "declaration_function_reference"
    else:
        return []
    if right is None or right.type != "initializer_list" or not table:
        return []

    owner_file = str(function.get("file_path", ""))
    owner_class = function.get("class_name")
    owner_leaf = _leaf(str(owner_class or ""))
    records: list[dict[str, Any]] = []
    for selector, target_name, value_kind, pair_text in _initializer_callable_entries(
        right, source
    ):
        # Qualified members owned by the containing class are already emitted
        # by _initializer_member_function_assignments; avoid duplicate records.
        target_parts = [part for part in target_name.split("::") if part]
        if len(target_parts) >= 2 and owner_leaf:
            target_owner = _leaf("::".join(target_parts[:-1]))
            if target_owner == owner_leaf:
                continue
        target_id, resolution = _target_resolution(
            target_name,
            owner_file,
            functions,
            owner_class,
            name_index=name_index,
            leaf_index=leaf_index,
        )
        if not target_id:
            # An unresolved identifier is deliberately not treated as a
            # callable registration: it may be an enum/constant or external
            # symbol.  The surrounding residual call remains visible.
            continue
        line = _source_line(function, node)
        records.append(
            {
                "owner_function_id": function_id,
                "owner_class": owner_class,
                "file": owner_file,
                "line": line,
                "table": table,
                "selector": selector,
                "target_name": target_name,
                "target_id": target_id,
                "resolution": resolution,
                "value_kind": value_kind,
                "registration_form": registration_form,
                "permissions": [],
                "evidence": {
                    "file": owner_file,
                    "start_line": line,
                    "end_line": line,
                    "text": pair_text,
                    "value_kind": value_kind,
                    "registration_form": registration_form,
                },
            }
        )
    return records


def _lambda_method_registration_records(
    node: Any,
    source: bytes,
    function_id: str,
    function: Mapping[str, Any],
    functions: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Extract ``emplace/try_emplace/insert`` Lambda registrations.

    Only calls with a concrete Lambda argument are accepted.  ``insert`` is
    supported in its pair form, while ``emplace`` and ``try_emplace`` use the
    first argument before the Lambda as the selector.  No target is inferred
    from a method name or table name.
    """
    if node.type != "call_expression":
        return []
    called = node.child_by_field_name("function")
    if called is None or called.type != "field_expression":
        return []
    field = called.child_by_field_name("field")
    method = _node_text(field, source).strip() if field is not None else ""
    if method not in {"emplace", "try_emplace", "insert"}:
        return []
    table = _table_expression(called.child_by_field_name("argument"), source)
    arguments = node.child_by_field_name("arguments")
    if not table or arguments is None:
        return []
    args = [child for child in arguments.children if child.is_named]
    owner_file = str(function.get("file_path", ""))
    owner_class = function.get("class_name")
    parameter_types = _parameter_types(function)
    records: list[dict[str, Any]] = []
    if method == "insert" and len(args) == 1 and args[0].type == "initializer_list":
        entries = _initializer_lambda_entries(args[0], source)
        if not entries:
            # ``map.insert({key, lambda})`` exposes the pair itself as the
            # argument-list initializer, rather than nesting another
            # initializer_list node around it.
            named = [child for child in args[0].children if child.is_named]
            lambda_nodes = [
                child for child in named if child.type == "lambda_expression"
            ]
            if lambda_nodes and named.index(lambda_nodes[0]) > 0:
                entries = [
                    (
                        _selector_text(named[0], source),
                        lambda_nodes[0],
                        _node_text(args[0], source).strip(),
                    )
                ]
        for selector, lambda_node, pair_text in entries:
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
                    registration_form="method_insert",
                )
            )
        return records

    lambda_indices = [
        index for index, argument in enumerate(args)
        if argument.type == "lambda_expression"
    ]
    if not lambda_indices:
        return []
    lambda_index = lambda_indices[0]
    if lambda_index == 0:
        return []
    selector = _selector_text(args[0], source)
    if not selector:
        return []
    records.extend(
        _lambda_registration_records(
            table=table,
            selector=selector,
            lambda_node=args[lambda_index],
            source=source,
            owner_function_id=function_id,
            owner_file=owner_file,
            owner_class=owner_class,
            parameter_types=parameter_types,
            line=_source_line(function, args[lambda_index]),
            expression=_node_text(node, source).strip(),
            functions=functions,
            registration_form="method_emplace",
        )
    )
    return records


def _lambda_dispatch_assignments(
    node: Any,
    source: bytes,
    function_id: str,
    function: Mapping[str, Any],
    functions: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Extract lambda registrations without treating them as native edges."""
    if node.type == "call_expression":
        return _lambda_method_registration_records(
            node, source, function_id, function, functions
        )
    if node.type == "init_declarator":
        # A dispatch table can be scoped to one function instead of assigned
        # after declaration, e.g. ``std::map<int, Handler> handlers = { ...
        # };``.  The initializer list is still a concrete ``{selector,
        # lambda}`` registration and should use the same bounded matching as
        # assignment expressions.  Keep a distinct form so downstream users
        # can tell that this table is local to the owner function.
        left = node.child_by_field_name("declarator")
        right = node.child_by_field_name("value")
        if left is None or right is None or right.type != "initializer_list":
            return []
        table = _table_expression(left, source)
        if not table:
            return []
        registration_form = "declaration_initializer_list"
    elif node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return []
        table = ""
        registration_form = "initializer_list"
    else:
        return []

    owner_file = str(function.get("file_path", ""))
    owner_class = function.get("class_name")
    parameter_types = _parameter_types(function)
    if (
        node.type == "assignment_expression"
        and left.type == "subscript_expression"
        and right.type == "lambda_expression"
    ):
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
    if node.type == "assignment_expression":
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
                registration_form=registration_form,
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


def _lookup_table_from_call(node: Any, source: bytes) -> str:
    """Return a dispatch table used by a map-like lookup expression.

    The iterator may be declared with ``begin`` and assigned later with
    ``find`` (a common pattern in generated OpenHarmony code).  Treating both
    forms as table-producing operations is safe here because the table is
    still required to match a concrete registration before a candidate is
    emitted.
    """
    if node is None or node.type != "call_expression":
        return ""
    called = node.child_by_field_name("function")
    if called is None or called.type != "field_expression":
        return ""
    field = called.child_by_field_name("field")
    method = _node_text(field, source).strip() if field is not None else ""
    if method not in {
        "find",
        "begin",
        "cbegin",
        "lower_bound",
        "upper_bound",
    }:
        return ""
    return _table_expression(called.child_by_field_name("argument"), source)


def _member_value_iterator(node: Any, source: bytes) -> tuple[str, str] | None:
    """Return ``(member_variable, iterator)`` for ``it->second`` aliases."""
    if node is None or node.type != "field_expression":
        return None
    field = node.child_by_field_name("field")
    receiver_node = node.child_by_field_name("argument")
    receiver = _identifier(receiver_node, source)
    field_name = _node_text(field, source).strip() if field is not None else ""
    if receiver and field_name == "second":
        return _node_text(node, source).strip(), receiver
    if (
        field_name == "first"
        and receiver_node is not None
        and receiver_node.type == "field_expression"
    ):
        inner_field = receiver_node.child_by_field_name("field")
        inner_receiver = _identifier(
            receiver_node.child_by_field_name("argument"), source
        )
        if (
            inner_receiver
            and inner_field is not None
            and _node_text(inner_field, source).strip() == "second"
        ):
            return _node_text(node, source).strip(), inner_receiver
    return None


def _local_dispatch_flow(root: Any, source: bytes) -> tuple[dict[str, str], dict[str, str]]:
    member_to_iterator: dict[str, str] = {}
    iterator_to_table: dict[str, str] = {}
    for node in _walk(root):
        if node.type not in {"init_declarator", "assignment_expression"}:
            continue
        if node.type == "init_declarator":
            variable = _identifier(node.child_by_field_name("declarator"), source)
            value = node.child_by_field_name("value")
        else:
            variable = _identifier(node.child_by_field_name("left"), source)
            value = node.child_by_field_name("right")
        if not variable or value is None:
            continue

        member_value = _member_value_iterator(value, source)
        if member_value is not None:
            _, receiver = member_value
            # ``it->second`` is a direct member-function value.  A
            # permission-bearing pair uses ``it->second.first``; retain the
            # iterator for both forms so the table can be recovered without
            # knowing its identifier.
            member_to_iterator[variable] = receiver
            continue

        table = _lookup_table_from_call(value, source)
        if table:
            iterator_to_table[variable] = table
    return member_to_iterator, iterator_to_table


def _parameter_names(function: Mapping[str, Any]) -> list[str]:
    """Extract parameter names while preserving the extractor's order."""
    parameters = function.get("parameters", [])
    if not isinstance(parameters, list):
        return []
    names: list[str] = []
    for parameter in parameters:
        if not isinstance(parameter, str):
            names.append("")
            continue
        declaration = parameter.split("=", 1)[0].strip()
        match = re.search(r"(?P<name>[A-Za-z_]\w*)\s*(?:\[\s*\])?\s*$", declaration)
        if match:
            names.append(match.group("name"))
            continue
        # Function-pointer parameters are commonly rendered by the C/C++
        # extractor as ``void (Class::*func)(Args...)``.  The name is not at
        # the end of that declaration, so recover only the identifier
        # immediately following the pointer marker.
        pointer_match = re.findall(
            r"(?:\*|&)\s*(?:[A-Za-z_]\w*::)?(?P<name>[A-Za-z_]\w*)",
            declaration,
        )
        names.append(pointer_match[-1] if pointer_match else "")
    return names


def _registration_helper_specs(
    parsed: Mapping[str, tuple[Any, bytes, Mapping[str, Any]]]
) -> list[dict[str, Any]]:
    """Find helpers that store a callable parameter in a table.

    This is intentionally structural rather than name based.  A function is
    considered a registrar only when its body contains ``table[key] = p`` or
    ``table[key] = [capture p](...)`` and both ``key`` and ``p`` are declared
    parameters.  That pattern covers OpenHarmony factories, creator maps and
    HPAE-style wrapper lambdas without maintaining a repository-specific list
    of helper names.
    """
    specs: list[dict[str, Any]] = []
    for helper_id, (root, source, function) in parsed.items():
        parameter_names = _parameter_names(function)
        if not parameter_names:
            continue
        parameter_indices = {
            name: index for index, name in enumerate(parameter_names) if name
        }
        if len(parameter_indices) < 2:
            continue
        helper_name = _leaf(str(function.get("name") or ""))
        if not helper_name:
            continue
        for node in _walk(root):
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or left.type != "subscript_expression":
                continue
            table_node = left.child_by_field_name("argument")
            selector_node = left.child_by_field_name("indices")
            table = _table_expression(table_node, source)
            selector = _selector_text(selector_node, source)
            if not table or not selector or selector not in parameter_indices:
                continue

            callable_parameter = ""
            value_kind = "function_pointer"
            if right.type == "identifier":
                candidate = _identifier(right, source)
                if candidate in parameter_indices and candidate != selector:
                    callable_parameter = candidate
                    value_kind = "function_pointer"
            elif right.type == "lambda_expression":
                capture = _lambda_capture(right, source)
                captured_parameters = [
                    name
                    for name in parameter_indices
                    if name != selector
                    and re.search(rf"\b{re.escape(name)}\b", capture)
                ]
                if len(captured_parameters) == 1:
                    callable_parameter = captured_parameters[0]
                    value_kind = "lambda"
            if not callable_parameter:
                continue
            specs.append(
                {
                    "helper_function_id": helper_id,
                    "helper_function_name": helper_name,
                    "helper_owner_class": function.get("class_name"),
                    "helper_file": function.get("file_path", ""),
                    "table": table,
                    "selector_parameter": selector,
                    "selector_index": parameter_indices[selector],
                    "callable_parameter": callable_parameter,
                    "callable_index": parameter_indices[callable_parameter],
                    "value_kind": value_kind,
                    "evidence": {
                        "file": function.get("file_path", ""),
                        "start_line": _source_line(function, node),
                        "end_line": _source_line(function, node),
                        "text": _node_text(node, source).strip(),
                        "table": table,
                        "selector_parameter": selector,
                        "callable_parameter": callable_parameter,
                    },
                }
            )
    specs.sort(
        key=lambda item: (
            str(item.get("helper_file", "")),
            int(item.get("evidence", {}).get("start_line", 0)),
            str(item.get("helper_function_id", "")),
            str(item.get("table", "")),
        )
    )
    return specs


def _helper_parameter_registration_assignments(
    parsed: Mapping[str, tuple[Any, bytes, Mapping[str, Any]]],
    specs: Iterable[Mapping[str, Any]],
    functions: Mapping[str, Any],
    name_index: Mapping[str, list[str]] | None = None,
    leaf_index: Mapping[str, list[str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Expand registrar calls into bounded table assignments.

    The callsite must pass a concrete function reference (``&Class::Method``,
    ``Class::Method`` or a uniquely indexed free-function name).  A helper
    that stores a wrapper Lambda is emitted through the Lambda channel; a
    helper that stores the pointer directly is emitted through the native
    dispatch channel.  Both records retain the helper-body evidence.
    """
    helper_specs = [item for item in specs if isinstance(item, Mapping)]
    if not helper_specs:
        return [], []
    specs_by_name: dict[str, list[Mapping[str, Any]]] = {}
    for spec in helper_specs:
        helper_name = str(spec.get("helper_function_name") or "")
        if helper_name:
            specs_by_name.setdefault(helper_name, []).append(spec)
    assignments: list[dict[str, Any]] = []
    lambda_assignments: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for caller_id, (root, source, caller) in parsed.items():
        caller_owner = _leaf(str(caller.get("class_name") or ""))
        owner_file = str(caller.get("file_path", ""))
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            called = node.child_by_field_name("function")
            called_name = _called_name(called, source)
            arguments = node.child_by_field_name("arguments")
            if not called_name or arguments is None:
                continue
            argument_nodes = [child for child in arguments.children if child.is_named]
            if not argument_nodes:
                continue
            for spec in specs_by_name.get(called_name, []):
                helper_owner = _leaf(str(spec.get("helper_owner_class") or ""))
                if helper_owner or caller_owner:
                    if not helper_owner or not caller_owner or helper_owner != caller_owner:
                        continue
                if called_name != spec.get("helper_function_name"):
                    continue
                selector_index = spec.get("selector_index")
                callable_index = spec.get("callable_index")
                if not isinstance(selector_index, int) or not isinstance(callable_index, int):
                    continue
                if max(selector_index, callable_index) >= len(argument_nodes):
                    continue
                target_name, value_kind = _dispatch_target(
                    argument_nodes[callable_index], source, allow_reference=True
                )
                if not target_name:
                    continue
                target_id, resolution = _target_resolution(
                    target_name,
                    owner_file,
                    functions,
                    caller.get("class_name"),
                    name_index=name_index,
                    leaf_index=leaf_index,
                )
                if not target_id:
                    continue
                selector = _selector_text(argument_nodes[selector_index], source)
                table = str(spec.get("table") or "")
                if not selector or not table:
                    continue
                key = (caller_id, table, selector, target_id)
                if key in seen:
                    continue
                seen.add(key)
                line = _source_line(caller, node)
                registration_form = "helper_parameter_registration"
                evidence = {
                    "file": owner_file,
                    "start_line": line,
                    "end_line": line,
                    "text": _node_text(node, source).strip(),
                    "value_kind": value_kind,
                    "registration_form": registration_form,
                    "helper_function_id": spec.get("helper_function_id", ""),
                    "helper_function_name": spec.get("helper_function_name", ""),
                    "helper_evidence": dict(spec.get("evidence") or {}),
                }
                record = {
                    "owner_function_id": caller_id,
                    "owner_class": caller.get("class_name"),
                    "file": owner_file,
                    "line": line,
                    "table": table,
                    "selector": selector,
                    "target_name": target_name,
                    "target_id": target_id,
                    "resolution": resolution,
                    "value_kind": "lambda" if spec.get("value_kind") == "lambda" else value_kind,
                    "registration_form": registration_form,
                    "helper_function_id": spec.get("helper_function_id", ""),
                    "helper_function_name": spec.get("helper_function_name", ""),
                    "helper_parameter": spec.get("callable_parameter", ""),
                    "field_identity": _field_identity(
                        table, caller.get("class_name"), _parameter_types(caller)
                    ),
                    "permissions": [],
                    "evidence": evidence,
                }
                if spec.get("value_kind") == "lambda":
                    record["lambda_calls"] = [target_name]
                    record["capture"] = f"[{spec.get('callable_parameter', '')}]"
                    lambda_assignments.append(record)
                else:
                    assignments.append(record)
    assignments.sort(
        key=lambda item: (item["file"], item["line"], item["selector"], item["target_name"])
    )
    lambda_assignments.sort(
        key=lambda item: (item["file"], item["line"], item["selector"], item["target_name"])
    )
    return assignments, lambda_assignments


def _member_function_parameter_flows(
    parsed: Mapping[str, tuple[Any, bytes, Mapping[str, Any]]],
    assignments: Iterable[Mapping[str, Any]],
    functions: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Join a local member-function array to a direct callee parameter.

    Only an identifier argument that is registered in the caller's own
    ``declaration_member_function_array`` table is accepted.  The callee must
    resolve uniquely, have the corresponding parameter name, and belong to
    the same class.  This is intentionally a one-hop flow; no alias or
    transitive propagation is attempted.
    """
    registrations = [
        item
        for item in assignments
        if isinstance(item, Mapping)
        and item.get("registration_form") == "declaration_member_function_array"
    ]
    if not registrations:
        return []
    flows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for caller_id, (root, source, caller) in parsed.items():
        caller_owner = _leaf(str(caller.get("class_name") or ""))
        if not caller_owner:
            continue
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            called = node.child_by_field_name("function")
            called_name = _called_name(called, source)
            arguments = node.child_by_field_name("arguments")
            if not called_name or arguments is None:
                continue
            argument_nodes = [child for child in arguments.children if child.is_named]
            if not argument_nodes:
                continue
            callee_id, resolution = _target_resolution(
                called_name,
                str(caller.get("file_path", "")),
                functions,
                caller_owner,
                len(argument_nodes),
            )
            callee = functions.get(callee_id) if callee_id else None
            if not callee_id or not isinstance(callee, Mapping):
                continue
            callee_owner = _leaf(str(callee.get("class_name") or ""))
            if not callee_owner or callee_owner != caller_owner:
                continue
            callee_parameters = _parameter_names(callee)
            for index, argument in enumerate(argument_nodes):
                if argument.type != "identifier" or index >= len(callee_parameters):
                    continue
                source_table = _node_text(argument, source).strip()
                callee_parameter = callee_parameters[index]
                if not source_table or not callee_parameter:
                    continue
                matching = [
                    item
                    for item in registrations
                    if item.get("owner_function_id") == caller_id
                    and item.get("table") == source_table
                ]
                if not matching:
                    continue
                key = (caller_id, callee_id, index, source_table)
                if key in seen:
                    continue
                seen.add(key)
                flows.append(
                    {
                        "source_function_id": caller_id,
                        "callee_id": callee_id,
                        "argument_index": index,
                        "source_table": source_table,
                        "callee_parameter": callee_parameter,
                        "resolution": resolution,
                        "registration_form": "declaration_member_function_array",
                        "evidence": {
                            "file": caller.get("file_path", ""),
                            "start_line": _source_line(caller, node),
                            "end_line": _source_line(caller, node),
                            "text": _node_text(node, source).strip(),
                            "argument": source_table,
                            "parameter": callee_parameter,
                        },
                    }
                )
    flows.sort(
        key=lambda item: (
            item["callee_id"],
            item["argument_index"],
            item["source_function_id"],
            item["source_table"],
        )
    )
    return flows


def _parameter_flow_for_operand(
    caller_id: str,
    operand: str,
    flows_by_callee: Mapping[str, list[Mapping[str, Any]]],
) -> Mapping[str, Any] | None:
    """Return a unique parameter flow for ``parameter[index].member``."""
    normalized = re.sub(r"\s+", "", operand)
    match = re.fullmatch(
        r"(?P<parameter>[A-Za-z_]\w*)\[[^\[\]]+\]\.[A-Za-z_]\w*",
        normalized,
    )
    if match is None:
        return None
    candidates = [
        flow
        for flow in flows_by_callee.get(caller_id, [])
        if flow.get("callee_parameter") == match.group("parameter")
    ]
    origins = {
        (flow.get("source_function_id"), flow.get("source_table"))
        for flow in candidates
    }
    if len(origins) != 1:
        return None
    return candidates[0] if candidates else None


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
    caller_function_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Match callable reads and return explicit cross-function alias evidence."""
    matched: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    for item in assignments:
        if not item.get("target_id"):
            continue
        # A declaration initializer creates a function-local object.  The
        # same variable name in another method is a different table, so it
        # must not be joined through the class/field alias fallback.  Global
        # initializers and post-declaration member assignments retain their
        # existing cross-function behavior.
        if (
            item.get("registration_form") == "declaration_initializer_list"
            and item.get("owner_function_id") != caller_function_id
        ):
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


def _member_function_dispatch_matches(
    assignments: Iterable[Mapping[str, Any]],
    table: str,
    owner_class: Any,
) -> list[dict[str, Any]]:
    """Match a callable table read to class-owned function registrations."""
    owner = _leaf(str(owner_class or ""))
    if not table:
        return []
    matched: list[dict[str, Any]] = []
    for item in assignments:
        if not isinstance(item, Mapping) or not item.get("target_id"):
            continue
        if item.get("table") != table:
            continue
        registration_owner = _leaf(str(item.get("owner_class") or ""))
        # A class method may use a free-function callback table, while a
        # class-owned table must never be joined across unrelated classes.
        # Unknown receiver ownership is accepted only when both sides are
        # unknown; the target itself is still required to be indexed.
        if owner and registration_owner and registration_owner != owner:
            continue
        if owner and not registration_owner:
            continue
        if not owner and registration_owner:
            continue
        if item.get("value_kind") == "lambda":
            continue
        matched.append(dict(item))
    return matched


def build_call_graph_diagnostics(
    extract_result: Mapping[str, Any],
    call_graph_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect syntax-backed residual calls without changing either input."""
    functions = extract_result.get("functions", {})
    if not isinstance(functions, Mapping):
        functions = {}
    name_index: dict[str, list[str]] = {}
    leaf_index: dict[str, list[str]] = {}
    for function_id, function in functions.items():
        if not isinstance(function_id, str) or not isinstance(function, Mapping):
            continue
        name = str(function.get("name") or "")
        if not name:
            continue
        name_index.setdefault(name, []).append(function_id)
        leaf_index.setdefault(_leaf(name), []).append(function_id)
    for index in (name_index, leaf_index):
        for key in index:
            index[key].sort()

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
            assignments.extend(
                _initializer_member_function_assignments(
                    node, source, function_id, function, functions
                )
            )
            assignments.extend(
                _initializer_callable_assignments(
                    node,
                    source,
                    function_id,
                    function,
                    functions,
                    name_index,
                    leaf_index,
                )
            )
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

    registration_helpers = _registration_helper_specs(parsed)
    helper_wrapper_keys = {
        (str(item.get("helper_function_id") or ""), str(item.get("table") or ""))
        for item in registration_helpers
        if item.get("value_kind") == "lambda"
    }
    if helper_wrapper_keys:
        # The helper body itself contains a generic wrapper Lambda whose
        # target is a parameter (for example ``func``).  Keep the wrapper
        # represented by the concrete callsite expansion below instead of
        # emitting a duplicate orphan registration for its definition.
        lambda_assignments = [
            item
            for item in lambda_assignments
            if (
                item.get("owner_function_id"),
                item.get("table"),
            ) not in helper_wrapper_keys
        ]
    helper_assignments, helper_lambda_assignments = (
        _helper_parameter_registration_assignments(
            parsed,
            registration_helpers,
            functions,
            name_index,
            leaf_index,
        )
    )
    assignments.extend(helper_assignments)
    lambda_assignments.extend(helper_lambda_assignments)

    parameter_flows = _member_function_parameter_flows(
        parsed, assignments, functions
    )
    flows_by_callee: dict[str, list[dict[str, Any]]] = {}
    for flow in parameter_flows:
        flows_by_callee.setdefault(flow["callee_id"], []).append(flow)

    assignments.sort(
        key=lambda item: (item["file"], item["line"], item["selector"], item["target_name"])
    )
    lambda_assignments.sort(
        key=lambda item: (
            item["file"],
            item["line"],
            item["selector"],
            item["target_name"],
        )
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

            parameter_flow = _parameter_flow_for_operand(
                function_id,
                indirect["target_variable"],
                flows_by_callee,
            )
            if parameter_flow is not None:
                table = str(parameter_flow["source_table"])
                matched = [
                    item
                    for item in assignments
                    if item["table"] == table
                    and item["target_id"]
                    and item.get("owner_function_id")
                    == parameter_flow["source_function_id"]
                    and (
                        not owner_class
                        or not item.get("owner_class")
                        or item.get("owner_class") == owner_class
                    )
                ]
            else:
                matched = [
                    item
                    for item in assignments
                    if table
                    and item["table"] == table
                        and item["target_id"]
                        and (
                            item.get("registration_form")
                            != "declaration_member_function_array"
                            or item.get("owner_function_id") == function_id
                        )
                        and (
                        not owner_class
                        or not item.get("owner_class")
                        or item.get("owner_class") == owner_class
                    )
                ]
            target_ids = list(dict.fromkeys(item["target_id"] for item in matched))
            symbols = {
                "target_variable": target_variable,
                "iterator_variable": iterator_variable,
                "dispatch_table": table,
            }
            if parameter_flow is not None:
                symbols["parameter_flow"] = dict(parameter_flow)
            sites.append(
                {
                    "caller_id": function_id,
                    "file": function.get("file_path", ""),
                    "line": indirect["line"],
                    "expression": indirect["expression"],
                    "ast_kind": indirect["ast_kind"],
                    "static_resolution": "unresolved",
                    "reason": (
                        "parameter_derived_member_function_pointer"
                        if parameter_flow is not None
                        else indirect["reason"]
                    ),
                    "symbols": symbols,
                    "candidate_target_ids": target_ids,
                    "candidates": [
                        {
                            "target_id": item["target_id"],
                            "target_name": item["target_name"],
                            "selector": item["selector"],
                            "value_kind": item.get("value_kind", ""),
                            "permissions": item.get("permissions", []),
                            "registration_form": item.get(
                                "registration_form", ""
                            ),
                            "owner_class": item.get("owner_class"),
                            "registration_owner_function_id": item.get(
                                "owner_function_id", ""
                            ),
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
            member_matches = _member_function_dispatch_matches(
                assignments, table, owner_class
            )
            if member_matches:
                target_ids = list(
                    dict.fromkeys(item["target_id"] for item in member_matches)
                )
                sites.append(
                    {
                        "caller_id": function_id,
                        "file": function.get("file_path", ""),
                        "line": callable_call["line"],
                        "expression": callable_call["expression"],
                        "ast_kind": callable_call["ast_kind"],
                        "static_resolution": "unresolved",
                        "reason": "lookup_derived_member_function_pointer",
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
                                "registration_form": item.get(
                                    "registration_form", ""
                                ),
                                "owner_class": item.get("owner_class"),
                                "permissions": item.get("permissions", []),
                                "evidence": item["evidence"],
                            }
                            for item in member_matches
                        ],
                    }
                )
                continue
            field_identity = _field_identity(
                table, owner_class, _parameter_types(function)
            )
            matched, aliases = _lambda_dispatch_matches(
                lambda_assignments,
                table,
                owner_class,
                field_identity,
                function_id,
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
                            "registration_form": item.get(
                                "registration_form", ""
                            ),
                            "registration_owner_function_id": item.get(
                                "owner_function_id", ""
                            ),
                            "helper_function_id": item.get(
                                "helper_function_id", ""
                            ),
                            "helper_parameter": item.get(
                                "helper_parameter", ""
                            ),
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
    if parameter_flows:
        result["parameter_flows"] = parameter_flows
    if lambda_assignments or lambda_sites or lambda_orphans:
        result["lambda_dispatch"] = {
            "summary": summary["lambda_dispatch"],
            "assignments": lambda_assignments,
            "call_sites": lambda_sites,
            "orphans": lambda_orphans,
        }
        if field_alias_matches:
            result["lambda_dispatch"]["field_alias_matches"] = field_alias_matches
    if registration_helpers:
        result["registration_helpers"] = registration_helpers
    return result


__all__ = ["SCHEMA_VERSION", "build_call_graph_diagnostics"]
