"""Evidence-backed OpenHarmony IDL-to-native IPC graph resolution.

This resolver deliberately stays bounded and evidence-backed.  It consumes
already parsed IDL declarations, function metadata, and (when available) the
native call graph; it never executes build files, generated code, or repository
callbacks.  A relationship is emitted when the native side provides dispatch
evidence (a transaction token, numeric IPC literal, method call, explicit
handler reference, or a direct call-graph edge).  If generated dispatch code is
not present in the checkout, a narrower contract fallback may connect an IDL
method to an exact service method only when the extractor also proves that the
service class inherits the interface's Stub base.  Pure name matches remain
orphan diagnostics.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from core.platforms.graph import SemanticGraph


RESOLVER_VERSION = 1

_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_CASE_TOKEN_RE = re.compile(r"\bcase\s+(?P<token>[A-Za-z_][A-Za-z0-9_]*)\b")
_IPC_CASE_LITERAL_RE = re.compile(
    r"\bcase\s+(?P<code>[0-9]+)[uUlL]*\s*:"
)
_SEND_REQUEST_LITERAL_RE = re.compile(
    r"\bSendRequest(?:[A-Za-z0-9_]*)?\s*\(\s*(?P<code>[0-9]+)[uUlL]*\s*,"
)
_CALL_RE = re.compile(r"(?:(?:this|self)\s*->\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_QUALIFIED_CALL_RE = re.compile(
    r"(?:&\s*)?(?P<owner>[A-Za-z_][A-Za-z0-9_:]*)::(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _mask_code(value: str) -> str:
    """Mask comments and quoted literals before lexical evidence matching."""
    masked = re.sub(r"//[^\r\n]*|/\*.*?\*/", " ", value, flags=re.DOTALL)
    return re.sub(r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", " ", masked)


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _normalize_ipc_code(value: Any) -> int | None:
    """Return a non-negative integer IPC code without guessing other forms."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _literal_ipc_code_hits(
    code: str,
    ipc_code: Any,
    *,
    dispatch: bool = False,
    proxy: bool = False,
) -> list[str]:
    """Find exact decimal IPC literals in a bounded native IPC context.

    The caller supplies already masked source text.  We intentionally support
    only direct decimal literals in ``case`` labels and the first argument of
    ``SendRequest``.  Enum, macro, variable and cross-file constant evaluation
    remain separate work so a numeric coincidence cannot create a broad edge.
    """
    normalized_code = _normalize_ipc_code(ipc_code)
    if normalized_code is None or not (dispatch or proxy):
        return []
    patterns = []
    if dispatch:
        patterns.append(_IPC_CASE_LITERAL_RE)
    if proxy:
        patterns.append(_SEND_REQUEST_LITERAL_RE)
    hits: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(code):
            literal = match.group("code")
            if int(literal) == normalized_code:
                hits.add(literal)
    return sorted(hits, key=lambda value: (int(value), value))


def _leaf(name: str) -> str:
    return name.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()


def _owner(name: str) -> str:
    if "::" not in name:
        return ""
    return name.rsplit("::", 1)[-2].rsplit("::", 1)[-1].strip()


def _interface_stem(interface_name: str) -> str:
    stem = re.split(r"[.:]+", interface_name)[-1]
    if stem.startswith("I") and len(stem) > 1 and stem[1].isupper():
        stem = stem[1:]
    return stem


_INTERFACE_VARIANT_MARKERS = {
    "agent",
    "callback",
    "client",
    "listener",
    "lite",
    "observer",
    "scheduler",
    "server",
}


def _identifier_tokens(value: str) -> set[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", _text(value))
    return {
        token.lower()
        for token in re.split(r"[^A-Za-z0-9]+", spaced)
        if token
    }


def _interface_variant_affinity(interface_name: str, native_path: str) -> int:
    """Score explicit interface variants against a native source path/owner."""
    interface_tokens = _identifier_tokens(_interface_stem(interface_name))
    native_tokens = _identifier_tokens(native_path)
    score = 0
    for marker in _INTERFACE_VARIANT_MARKERS:
        in_interface = marker in interface_tokens
        in_native = marker in native_tokens
        if in_interface and in_native:
            score += 1
        elif in_interface and not in_native:
            score -= 2
        elif in_native and not in_interface:
            score -= 2
    return score


def _owner_matches_interface(function_name: str, interface_name: str) -> bool:
    owner = _normalize(_owner(function_name))
    stem = _normalize(_interface_stem(interface_name))
    if not owner or not stem:
        return False
    if owner == stem or owner.endswith(stem) or stem in owner:
        return True
    owner = re.sub(r"(?:stub|proxy|impl|skeleton|service)$", "", owner)
    return owner == stem or owner.endswith(stem) or stem in owner


def _method_variants(method_name: str) -> set[str]:
    base = method_name.strip()
    return {
        base,
        f"Handle{base}",
        f"{base}Inner",
        f"Handle{base}Inner",
        f"{base}Impl",
        f"Handle{base}Impl",
    }


def _transaction_tokens(method_name: str) -> set[str]:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", method_name)
    upper = re.sub(r"[^A-Za-z0-9]", "_", snake).upper()
    bases = {upper}
    for suffix in ("_INNER", "_IMPL"):
        if upper.endswith(suffix) and len(upper) > len(suffix):
            bases.add(upper[: -len(suffix)])
    tokens: set[str] = set()
    for base in bases:
        tokens.update(
            {
                base,
                f"CMD_{base}",
                f"COMMAND_{base}",
                f"SERVICE_CMD_{base}",
                f"TRANSACTION_{base}",
                f"SERVICE_TRANSACTION_{base}",
                f"CODE_{base}",
                f"{base}_TRANSACTION",
                f"{base}_COMMAND",
            }
        )
    return tokens


def _line_for_function(function: Mapping[str, Any]) -> int:
    value = _field(function, "start_line", _field(function, "startLine", 0))
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _class_bases_from_payload(functions: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Normalize the extractor's top-level ``class_bases`` evidence.

    ``FunctionExtractor.export()`` returns ``class_bases`` beside the nested
    ``functions`` map.  Older callers may pass only that nested map, so the
    absence of this evidence is intentionally represented by an empty mapping
    rather than reconstructed from a class name.
    """
    if not isinstance(functions, Mapping):
        return {}
    raw_bases = functions.get("class_bases")
    if not isinstance(raw_bases, Mapping):
        return {}
    normalized: dict[str, list[str]] = {}
    for class_name, bases in raw_bases.items():
        class_text = _text(class_name)
        if not class_text:
            continue
        if isinstance(bases, (list, tuple, set)):
            values = bases
        else:
            values = [bases]
        cleaned = []
        for base in values:
            base_text = _text(base)
            if base_text and base_text not in cleaned:
                cleaned.append(base_text)
        if cleaned:
            normalized[class_text] = cleaned
    return normalized


def _normalize_cpp_type(value: Any) -> str:
    """Normalize a C++/IDL type for a conservative shape comparison."""
    text = _text(value).lower()
    if not text:
        return ""
    text = re.sub(r"\b(?:const|volatile|class|struct|typename)\b", " ", text)
    text = text.replace("std::", "").replace("::", "")
    text = re.sub(r"\s+", "", text)
    text = text.replace("&", "").replace("*", "")
    return text


def _parameter_type(value: Any) -> str:
    """Remove a C++ formal parameter name while preserving its type shape."""
    text = _text(value)
    if not text or text == "...":
        return text
    # Defaults are not part of an IPC contract's type.
    text = text.split("=", 1)[0].strip()
    # FunctionExtractor records declarations with the parameter name at the
    # end.  Avoid stripping a final type token from a nameless declaration by
    # requiring a preceding type/pointer/reference separator.
    match = re.match(r"^(?P<type>.+?)(?:\s+|[*&])(?P<name>[A-Za-z_]\w*)$", text)
    if match and match.group("type").strip():
        return match.group("type").strip()
    return text


def _parameter_shape(value: Any) -> str:
    """Map equivalent IDL/C++ spellings to a small comparison vocabulary."""
    normalized = _normalize_cpp_type(_parameter_type(value))
    if not normalized:
        return "unknown"
    if normalized == "...":
        return "variadic"
    if any(token in normalized for token in ("vector", "list", "sequence", "array", "set")):
        return "sequence"
    if any(token in normalized for token in ("map", "unorderedmap", "hashmap")):
        return "map"
    if "string" in normalized or normalized in {"char", "char8", "char16", "char32"}:
        return "string"
    if normalized in {"bool", "boolean"}:
        return "bool"
    if re.fullmatch(
        r"(?:u?int(?:8|16|32|64)?(?:_t)?|u?long(?:long)?|short|size_t|ssize_t|"
        r"unsigned|unsignedint|unsignedlong|signed|signedint|float|double)",
        normalized,
    ):
        return "scalar"
    if normalized in {"void", "unit"}:
        return "void"
    return "object"


def _parameter_shapes(parameters: Any, *, idl: bool = False) -> list[str]:
    """Return normalized parameter shapes for IDL records or C++ strings."""
    if not isinstance(parameters, (list, tuple)):
        return []
    shapes = []
    for parameter in parameters:
        value = _field(parameter, "type", parameter) if idl else parameter
        shapes.append(_parameter_shape(value))
    return shapes


def _stub_base_names(interface_name: str) -> set[str]:
    """Return normalized Stub spellings derived from the IDL interface name."""
    leaf = _text(interface_name).rsplit(".", 1)[-1].rsplit(":", 1)[-1]
    stem = _interface_stem(interface_name)
    names = {
        _normalize(f"{stem}Stub"),
        _normalize(f"{leaf}Stub"),
    }
    return {name for name in names if name}


def _inherits_stub(
    owner: str,
    interface_name: str,
    class_bases: Mapping[str, list[str]],
) -> tuple[str, str] | None:
    """Find a bounded inheritance path from ``owner`` to the interface Stub."""
    if not owner or not class_bases:
        return None
    expected = _stub_base_names(interface_name)
    if not expected:
        return None
    by_class = {
        _normalize(class_name): (class_name, list(bases))
        for class_name, bases in class_bases.items()
        if _normalize(class_name)
    }
    start = _normalize(owner)
    if not start:
        return None
    queue: list[tuple[str, int]] = [(start, 0)]
    visited = {start}
    while queue:
        current, depth = queue.pop(0)
        if depth >= 8:
            continue
        entry = by_class.get(current)
        if entry is None:
            continue
        for base in entry[1]:
            base_text = _text(base)
            base_normalized = _normalize(base_text)
            if not base_normalized:
                continue
            # The extractor normally emits a simple type_identifier.  The
            # extra template check supports callers that preserve
            # ``IRemoteStub<IAudioPolicy>`` as a raw base string without
            # treating every IRemoteStub as this interface's Stub.
            interface_token = _normalize(_text(interface_name).rsplit(".", 1)[-1])
            is_interface_remote_stub = (
                "iremotestub" in base_normalized
                and interface_token
                and interface_token in base_normalized
            )
            if base_normalized in expected or is_interface_remote_stub:
                return base_text, entry[0]
            if base_normalized not in visited and base_normalized in by_class:
                visited.add(base_normalized)
                queue.append((base_normalized, depth + 1))
    return None


def _function_records(functions: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(functions, Mapping):
        nested = functions.get("functions")
        if isinstance(nested, Mapping):
            functions = nested
    records: list[dict[str, Any]] = []
    for function_id, raw in (functions or {}).items():
        if not isinstance(raw, Mapping):
            continue
        name = _text(_field(raw, "name", function_id))
        if not name:
            continue
        records.append(
            {
                "id": str(function_id),
                "name": name,
                "leaf": _leaf(name),
                "owner": _owner(name),
                "code": _text(_field(raw, "code", "")),
                "file_path": _text(_field(raw, "file_path", _field(raw, "filePath", ""))),
                "start_line": _line_for_function(raw),
                "end_line": _field(raw, "end_line", _field(raw, "endLine", 0)),
                "unit_type": _text(_field(raw, "unit_type", _field(raw, "unitType", ""))),
                "parameters": list(_field(raw, "parameters", []) or [])
                if isinstance(_field(raw, "parameters", []), (list, tuple))
                else [],
                "return_type": _text(_field(raw, "return_type", _field(raw, "returnType", ""))),
                "class_name": _text(_field(raw, "class_name", _field(raw, "className", ""))),
                "is_static": bool(_field(raw, "is_static", _field(raw, "isStatic", False))),
                "is_exported": bool(_field(raw, "is_exported", _field(raw, "isExported", False))),
            }
        )
    return sorted(records, key=lambda item: (item["id"], item["name"]))


def _call_graph_edges(call_graph: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Normalize the call-graph export used by the C pipeline.

    The resolver only needs forward edges for handler resolution.  Keeping the
    normalization separate means callers may pass the complete call-graph
    export without coupling the IPC resolver to the builder's other fields.
    """
    if not isinstance(call_graph, Mapping):
        return {}
    forward = call_graph.get("call_graph", call_graph.get("callGraph", {}))
    if not isinstance(forward, Mapping):
        return {}
    normalized: dict[str, list[str]] = {}
    for source_id, targets in forward.items():
        if not isinstance(targets, (list, tuple, set)):
            continue
        normalized[str(source_id)] = [str(target_id) for target_id in targets]
    return normalized


def _dispatch_call_graph_targets(
    functions: list[dict[str, Any]],
    call_graph: Mapping[str, list[str]],
    *,
    max_depth: int = 3,
    max_targets_per_dispatch: int = 256,
) -> dict[str, list[dict[str, Any]]]:
    """Index bounded call paths leaving native IPC dispatch callbacks.

    Generated OpenHarmony stubs do not always encode the IDL interface stem in
    their C++ class name, and some use an ``OnRemoteRequest`` wrapper before
    calling ``Handle<Method>``.  Indexing only these dispatch-shaped functions
    keeps the graph traversal bounded while preserving the method-specific
    signal needed by the resolver.
    """
    if not call_graph:
        return {}
    function_by_id = {function["id"]: function for function in functions}
    dispatch_ids = sorted(
        function_id
        for function_id, function in function_by_id.items()
        if function["leaf"] == "OnRemoteRequest"
    )
    indexed: dict[str, list[dict[str, Any]]] = {}
    for source_id in dispatch_ids:
        queue: list[tuple[str, list[str]]] = [(source_id, [source_id])]
        visited = {source_id}
        targets: list[dict[str, Any]] = []
        while queue and len(targets) < max_targets_per_dispatch:
            current_id, path = queue.pop(0)
            if len(path) - 1 >= max_depth:
                continue
            for target_id in call_graph.get(current_id, []):
                target_id = str(target_id)
                target = function_by_id.get(target_id)
                if target is None:
                    continue
                target_path = [*path, target_id]
                targets.append({"function": target, "path": target_path})
                if target_id not in visited:
                    visited.add(target_id)
                    queue.append((target_id, target_path))
                if len(targets) >= max_targets_per_dispatch:
                    break
        if targets:
            indexed[source_id] = targets
    return indexed


def _method_records(idl_result: Any) -> list[dict[str, Any]]:
    interfaces = _field(idl_result, "interfaces", [])
    records: list[dict[str, Any]] = []
    for interface in _items(interfaces):
        interface_name = _text(_field(interface, "name", ""))
        if not interface_name:
            continue
        for method in _items(_field(interface, "methods", [])):
            method_name = _text(_field(method, "name", ""))
            if not method_name:
                continue
            parameters = []
            for parameter in _items(_field(method, "parameters", [])):
                parameters.append(
                    {
                        "direction": _text(_field(parameter, "direction", "in")) or "in",
                        "type": _text(_field(parameter, "type", "")),
                        "name": _text(_field(parameter, "name", "")),
                        "line": _field(parameter, "line", 0),
                        "path": _text(_field(parameter, "path", _field(method, "path", ""))),
                    }
                )
            annotations = _field(method, "annotations", [])
            if not isinstance(annotations, (list, tuple)):
                annotations = []
            records.append(
                {
                    "interface": interface_name,
                    "interface_path": _text(_field(interface, "path", "")),
                    "interface_line": _field(interface, "line", 0),
                    "method": method_name,
                    "return_type": _text(_field(method, "return_type", "")),
                    "parameters": parameters,
                    "annotations": [_text(item) for item in annotations if _text(item)],
                    "ipc_code": _field(method, "ipc_code", _field(method, "ipcCode", None)),
                    "path": _text(_field(method, "path", _field(interface, "path", ""))),
                    "line": _field(method, "line", 0),
                }
            )
    return sorted(records, key=lambda item: (item["interface"], item["method"], item["path"], item["line"]))


def _function_node_id(function: Mapping[str, Any]) -> str:
    return f"function:{function['id']}"


def _function_attributes(function: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": function["name"],
        "file_path": function["file_path"],
        "start_line": function["start_line"],
        "end_line": function["end_line"],
        "unit_type": function["unit_type"],
    }


def _sa_records(sa_result: Any) -> list[dict[str, Any]]:
    """Normalize SAProfile/SAParseResult objects and dictionaries."""
    profiles = _field(sa_result, "profiles", sa_result if isinstance(sa_result, (list, tuple)) else [])
    grouped: dict[str, dict[str, Any]] = {}
    for profile in _items(profiles):
        profile_path = _text(_field(profile, "path", ""))
        process = _text(_field(profile, "process", ""))
        abilities = _field(profile, "system_abilities", _field(profile, "systemability", []))
        for ability in _items(abilities):
            sa_id = _text(_field(ability, "sa_id", _field(ability, "name", "")))
            if not sa_id:
                continue
            record = grouped.setdefault(
                sa_id,
                {
                    "sa_id": sa_id,
                    "profile_paths": set(),
                    "processes": set(),
                    "libpaths": set(),
                    "permissions": set(),
                    "extensions": set(),
                    "run_on_create": set(),
                    "distributed": set(),
                    "auto_restart": set(),
                    "dump_levels": set(),
                },
            )
            if profile_path:
                record["profile_paths"].add(profile_path)
            if process:
                record["processes"].add(process)
            for field_name, key in (
                ("libpaths", "libpath"),
                ("permissions", "permissions"),
                ("extensions", "extension"),
            ):
                value = _field(ability, key, [])
                values = value if isinstance(value, (list, tuple, set)) else [value]
                record[field_name].update(_text(item) for item in values if _text(item))
            for field_name, key in (
                ("run_on_create", "run_on_create"),
                ("distributed", "distributed"),
                ("auto_restart", "auto_restart"),
                ("dump_levels", "dump_level"),
            ):
                value = _field(ability, key, None)
                if value is not None:
                    record[field_name].add(value)

    normalized: list[dict[str, Any]] = []
    for record in grouped.values():
        paths = sorted(record["profile_paths"])
        processes = sorted(record["processes"])
        libpaths = sorted(record["libpaths"])
        normalized.append(
            {
                "sa_id": record["sa_id"],
                "profile_paths": paths,
                "processes": processes,
                "libpaths": libpaths,
                "permissions": sorted(record["permissions"]),
                "extensions": sorted(record["extensions"]),
                "run_on_create": sorted(record["run_on_create"], key=str),
                "distributed": sorted(record["distributed"], key=str),
                "auto_restart": sorted(record["auto_restart"], key=str),
                "dump_levels": sorted(record["dump_levels"], key=str),
            }
        )
    return sorted(normalized, key=lambda item: item["sa_id"])


def _sa_node_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
    processes = list(record["processes"])
    libpaths = list(record["libpaths"])
    return {
        "sa_id": record["sa_id"],
        "profile_paths": list(record["profile_paths"]),
        "process": processes[0] if len(processes) == 1 else "",
        "processes": processes,
        "libpath": libpaths[0] if len(libpaths) == 1 else "",
        "libpaths": libpaths,
        "permissions": list(record["permissions"]),
        "extensions": list(record["extensions"]),
        "run_on_create": list(record["run_on_create"]),
        "distributed": list(record["distributed"]),
        "auto_restart": list(record["auto_restart"]),
        "dump_levels": list(record["dump_levels"]),
    }


def _sa_match_tokens(interface_name: str) -> set[str]:
    stem = _normalize(_interface_stem(interface_name))
    tokens = {stem} if stem else set()
    for suffix in ("mgr", "manager", "service", "stub", "proxy"):
        if stem.endswith(suffix) and len(stem) > len(suffix):
            tokens.add(stem[: -len(suffix)])
    return tokens


def _sa_library_tokens(record: Mapping[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for value in [*record["libpaths"], *record["processes"]]:
        normalized = _normalize(value)
        if not normalized:
            continue
        tokens.add(normalized)
        core = re.sub(r"^lib", "", normalized)
        core = re.sub(r"(?:zso|so)$", "", core)
        core = re.sub(r"(?:ability|service|manager|process)$", "", core)
        if core:
            tokens.add(core)
    return tokens


class OpenHarmonyIPCResolver:
    """Resolve IDL declarations to native dispatch and handler functions."""

    def __init__(self, *, resolver_version: int = RESOLVER_VERSION) -> None:
        if isinstance(resolver_version, bool) or not isinstance(resolver_version, int) or resolver_version < 1:
            raise ValueError("resolver_version must be a positive integer")
        self.resolver_version = resolver_version

    def resolve(
        self,
        idl_result: Any,
        functions: Mapping[str, Any] | None = None,
        sa_result: Any | None = None,
        call_graph: Mapping[str, Any] | None = None,
    ) -> SemanticGraph:
        graph = SemanticGraph()
        class_bases = _class_bases_from_payload(functions)
        function_records = _function_records(functions)
        call_graph_edges = _call_graph_edges(call_graph)
        call_graph_targets = _dispatch_call_graph_targets(
            function_records,
            call_graph_edges,
        )
        methods = _method_records(idl_result)
        interfaces = sorted({record["interface"] for record in methods})

        for interface_name in interfaces:
            interface_records = [item for item in methods if item["interface"] == interface_name]
            method_counts: dict[str, int] = {}
            method_seen: dict[str, int] = {}
            for item in interface_records:
                method_counts[item["method"]] = method_counts.get(item["method"], 0) + 1
            interface_id = f"idl:interface:{interface_name}"
            first = interface_records[0]
            graph.add_node(
                {
                    "schema_version": graph.schema_version,
                    "id": interface_id,
                    "kind": "idl_interface",
                    "attributes": {
                        "name": interface_name,
                        "path": first["interface_path"],
                        "line": first["interface_line"],
                    },
                }
            )
            for method in interface_records:
                method_name = method["method"]
                ordinal = method_seen.get(method_name, 0)
                method_seen[method_name] = ordinal + 1
                transaction_id = self._transaction_id(
                    method,
                    ordinal=ordinal,
                    total=method_counts[method_name],
                )
                self._resolve_method(
                    graph,
                    method,
                    function_records,
                    interface_id,
                    transaction_id,
                    overload_index=ordinal if method_counts[method_name] > 1 else None,
                    call_graph=call_graph_edges,
                    call_graph_targets=call_graph_targets,
                    class_bases=class_bases,
                )
        if sa_result is not None:
            self._attach_system_abilities(graph, interfaces, function_records, sa_result)
        return graph

    def resolve_dict(
        self,
        idl_result: Any,
        functions: Mapping[str, Any] | None = None,
        sa_result: Any | None = None,
        call_graph: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Resolve and serialize in one call for pipeline adapters."""
        return self.resolve(idl_result, functions, sa_result, call_graph).to_dict()

    def _attach_system_abilities(
        self,
        graph: SemanticGraph,
        interfaces: list[str],
        functions: list[dict[str, Any]],
        sa_result: Any,
    ) -> None:
        records = _sa_records(sa_result)
        for record in records:
            graph.add_node(
                {
                    "schema_version": graph.schema_version,
                    "id": f"sa:{record['sa_id']}",
                    "kind": "system_ability",
                    "attributes": _sa_node_attributes(record),
                }
            )

        matched_sa_ids: set[str] = set()
        for interface_name in interfaces:
            candidates = []
            interface_tokens = _sa_match_tokens(interface_name)
            for record in records:
                library_tokens = _sa_library_tokens(record)
                matched_tokens = sorted(
                    token
                    for token in interface_tokens
                    if token and any(token in library for library in library_tokens)
                )
                native_matches = [
                    function
                    for function in functions
                    if _owner_matches_interface(function["name"], interface_name)
                    and any(
                        token in _normalize(function["file_path"])
                        or token in _normalize(function["owner"])
                        for token in library_tokens
                        if token
                    )
                ]
                if matched_tokens:
                    candidates.append(
                        {
                            "record": record,
                            "confidence": 0.95,
                            "signal": "interface_stem_in_sa_libpath_or_process",
                            "matched": matched_tokens,
                            "native_matches": native_matches,
                        }
                    )
                elif native_matches:
                    candidates.append(
                        {
                            "record": record,
                            "confidence": 0.85,
                            "signal": "interface_owner_in_sa_native_path",
                            "matched": [],
                            "native_matches": native_matches,
                        }
                    )

            interface_id = f"idl:interface:{interface_name}"
            if len(candidates) == 1:
                candidate = candidates[0]
                record = candidate["record"]
                matched_sa_ids.add(record["sa_id"])
                profile_path = record["profile_paths"][0] if record["profile_paths"] else ""
                graph.add_edge(
                    {
                        "schema_version": graph.schema_version,
                        "source_id": f"sa:{record['sa_id']}",
                        "target_id": interface_id,
                        "kind": "system_ability_to_interface",
                        "evidence": [
                            {
                                "source": "sa_profile",
                                "path": profile_path,
                                "sa_id": record["sa_id"],
                                "process": record["processes"][0] if record["processes"] else "",
                                "libpath": record["libpaths"][0] if record["libpaths"] else "",
                                "signal": candidate["signal"],
                                "matched": candidate["matched"],
                            }
                        ],
                        "confidence": candidate["confidence"],
                        "resolver_version": self.resolver_version,
                        "attributes": {
                            "interface": interface_name,
                            "sa_id": record["sa_id"],
                            "permissions": list(record["permissions"]),
                        },
                    }
                )
            elif len(candidates) > 1:
                graph.add_orphan(
                    kind="ambiguous_system_ability_interface",
                    reason="multiple SA profiles matched the IDL interface",
                    evidence=[
                        {
                            "source": "sa_profile",
                            "sa_id": item["record"]["sa_id"],
                            "matched": item["matched"],
                        }
                        for item in candidates
                    ],
                    attributes={"interface": interface_name},
                )
            else:
                graph.add_orphan(
                    kind="unresolved_interface_system_ability",
                    reason="no SA profile evidence matched the IDL interface",
                    evidence=[{"source": "idl", "interface": interface_name}],
                    attributes={"interface": interface_name},
                )

        for record in records:
            if record["sa_id"] not in matched_sa_ids:
                graph.add_orphan(
                    kind="unresolved_system_ability_interface",
                    reason="SA profile has no matched IDL interface",
                    evidence=[
                        {
                            "source": "sa_profile",
                            "path": record["profile_paths"][0] if record["profile_paths"] else "",
                            "sa_id": record["sa_id"],
                            "libpath": record["libpaths"][0] if record["libpaths"] else "",
                        }
                    ],
                    attributes={"sa_id": record["sa_id"]},
                )

    def _resolve_method(
        self,
        graph: SemanticGraph,
        method: Mapping[str, Any],
        functions: list[dict[str, Any]],
        interface_id: str,
        transaction_id: str,
        *,
        overload_index: int | None = None,
        call_graph: Mapping[str, list[str]] | None = None,
        call_graph_targets: Mapping[str, list[dict[str, Any]]] | None = None,
        class_bases: Mapping[str, list[str]] | None = None,
    ) -> None:
        interface_name = method["interface"]
        method_name = method["method"]
        transaction_attributes = {
            "interface": interface_name,
            "method": method_name,
            "return_type": method["return_type"],
            "parameters": list(method["parameters"]),
            "path": method["path"],
            "line": method["line"],
        }
        if method.get("annotations"):
            transaction_attributes["annotations"] = list(method["annotations"])
        if method.get("ipc_code") is not None:
            transaction_attributes["ipc_code"] = method["ipc_code"]
        if overload_index is not None:
            transaction_attributes["overload_index"] = overload_index
        graph.add_node(
            {
                "schema_version": graph.schema_version,
                "id": transaction_id,
                "kind": "ipc_transaction",
                "attributes": transaction_attributes,
            }
        )
        idl_evidence = {
            "source": "idl",
            "path": method["path"],
            "line": method["line"],
            "interface": interface_name,
            "method": method_name,
        }
        if method.get("annotations"):
            idl_evidence["annotations"] = list(method["annotations"])
        if method.get("ipc_code") is not None:
            idl_evidence["ipc_code"] = method["ipc_code"]
        graph.add_edge(
            {
                "schema_version": graph.schema_version,
                "source_id": interface_id,
                "target_id": transaction_id,
                "kind": "interface_to_transaction",
                "evidence": [idl_evidence],
                "confidence": 1.0,
                "resolver_version": self.resolver_version,
            }
        )

        proxies = self._proxy_candidates(method, functions)
        if not proxies:
            graph.add_orphan(
                kind="unresolved_ipc_proxy",
                reason="no native SendRequest evidence matched the IDL method",
                evidence=[idl_evidence],
                attributes={"interface": interface_name, "method": method_name},
            )
        elif len(proxies) > 1:
            graph.add_orphan(
                kind="ambiguous_ipc_proxy",
                reason="multiple native proxy functions matched the IDL method",
                evidence=[item["evidence"] for item in proxies],
                attributes={"interface": interface_name, "method": method_name},
            )
        else:
            proxy = proxies[0]
            proxy_record = proxy["function"]
            graph.add_node(
                {
                    "schema_version": graph.schema_version,
                    "id": _function_node_id(proxy_record),
                    "kind": "function",
                    "attributes": _function_attributes(proxy_record),
                }
            )
            graph.add_edge(
                {
                    "schema_version": graph.schema_version,
                    "source_id": _function_node_id(proxy_record),
                    "target_id": transaction_id,
                    "kind": "proxy_to_transaction",
                    "evidence": [proxy["evidence"]],
                    "confidence": proxy["confidence"],
                    "resolver_version": self.resolver_version,
                    "attributes": {"interface": interface_name, "method": method_name},
                }
            )

        stubs = self._dispatch_candidates(
            method,
            functions,
            call_graph_targets=call_graph_targets,
        )
        if not stubs:
            # Generated ZIDL stubs are often produced under the build output
            # directory and are therefore absent from a source-only checkout.
            # A contract match is safe only when the service class is proven to
            # inherit the interface-specific Stub base; it is not a name-only
            # fallback.
            contract_handlers = self._contract_handler_candidates(
                method,
                functions,
                class_bases=class_bases,
            )
            if len(contract_handlers) == 1:
                handler = contract_handlers[0]
                handler_record = handler["function"]
                graph.add_node(
                    {
                        "schema_version": graph.schema_version,
                        "id": _function_node_id(handler_record),
                        "kind": "function",
                        "attributes": _function_attributes(handler_record),
                    }
                )
                graph.add_edge(
                    {
                        "schema_version": graph.schema_version,
                        "source_id": transaction_id,
                        "target_id": _function_node_id(handler_record),
                        "kind": "transaction_to_handler",
                        "evidence": [handler["evidence"]],
                        "confidence": handler["confidence"],
                        "resolver_version": self.resolver_version,
                        "attributes": {
                            "interface": interface_name,
                            "method": method_name,
                            "dispatch_mode": "generated_code_missing",
                            "evidence_source": "idl_handler_contract",
                        },
                    }
                )
                return
            if len(contract_handlers) > 1:
                graph.add_orphan(
                    kind="ambiguous_ipc_handler_contract",
                    reason="multiple Stub-derived service methods matched the IDL contract",
                    evidence=[item["evidence"] for item in contract_handlers],
                    attributes={"interface": interface_name, "method": method_name},
                )
            graph.add_orphan(
                kind="unresolved_ipc_stub",
                reason="no native dispatch evidence matched the IDL method",
                evidence=[idl_evidence],
                attributes={"interface": interface_name, "method": method_name},
            )
            return
        if len(stubs) > 1:
            graph.add_orphan(
                kind="ambiguous_ipc_stub",
                reason="multiple native dispatch functions matched the IDL method",
                evidence=[item["evidence"] for item in stubs],
                attributes={"interface": interface_name, "method": method_name},
            )
            return

        stub = stubs[0]
        stub_record = stub["function"]
        graph.add_node(
            {
                "schema_version": graph.schema_version,
                "id": _function_node_id(stub_record),
                "kind": "function",
                "attributes": _function_attributes(stub_record),
            }
        )
        graph.add_edge(
            {
                "schema_version": graph.schema_version,
                "source_id": _function_node_id(stub_record),
                "target_id": transaction_id,
                "kind": "stub_to_transaction",
                "evidence": [stub["evidence"]],
                "confidence": stub["confidence"],
                "resolver_version": self.resolver_version,
                "attributes": {"interface": interface_name, "method": method_name},
            }
        )

        handlers = self._handler_candidates(
            method,
            stub_record,
            functions,
            call_graph=call_graph,
            call_graph_targets=call_graph_targets,
        )
        if not handlers:
            contract_handlers = self._contract_handler_candidates(
                method,
                functions,
                class_bases=class_bases,
            )
            if len(contract_handlers) == 1:
                handler = contract_handlers[0]
                handler_record = handler["function"]
                graph.add_node(
                    {
                        "schema_version": graph.schema_version,
                        "id": _function_node_id(handler_record),
                        "kind": "function",
                        "attributes": _function_attributes(handler_record),
                    }
                )
                graph.add_edge(
                    {
                        "schema_version": graph.schema_version,
                        "source_id": transaction_id,
                        "target_id": _function_node_id(handler_record),
                        "kind": "transaction_to_handler",
                        "evidence": [handler["evidence"]],
                        "confidence": handler["confidence"],
                        "resolver_version": self.resolver_version,
                        "attributes": {
                            "interface": interface_name,
                            "method": method_name,
                            "dispatch_mode": "generated_code_missing",
                            "evidence_source": "idl_handler_contract",
                        },
                    }
                )
                return
            if len(contract_handlers) > 1:
                graph.add_orphan(
                    kind="ambiguous_ipc_handler_contract",
                    reason="multiple Stub-derived service methods matched the IDL contract",
                    evidence=[item["evidence"] for item in contract_handlers],
                    attributes={"interface": interface_name, "method": method_name},
                )
            graph.add_orphan(
                kind="unresolved_ipc_handler",
                reason="dispatch evidence exists but no native handler matched",
                evidence=[stub["evidence"]],
                attributes={"interface": interface_name, "method": method_name},
            )
            return
        if len(handlers) > 1:
            graph.add_orphan(
                kind="ambiguous_ipc_handler",
                reason="multiple native handler functions matched the IDL method",
                evidence=[item["evidence"] for item in handlers],
                attributes={"interface": interface_name, "method": method_name},
            )
            return

        handler = handlers[0]
        handler_record = handler["function"]
        graph.add_node(
            {
                "schema_version": graph.schema_version,
                "id": _function_node_id(handler_record),
                "kind": "function",
                "attributes": _function_attributes(handler_record),
            }
        )
        graph.add_edge(
            {
                "schema_version": graph.schema_version,
                "source_id": transaction_id,
                "target_id": _function_node_id(handler_record),
                "kind": "transaction_to_handler",
                "evidence": [handler["evidence"]],
                "confidence": handler["confidence"],
                "resolver_version": self.resolver_version,
                "attributes": {"interface": interface_name, "method": method_name},
            }
        )

    @staticmethod
    def _transaction_id(
        method: Mapping[str, Any],
        *,
        ordinal: int,
        total: int,
    ) -> str:
        base = f"idl:transaction:{method['interface']}:{method['method']}"
        if total <= 1:
            return base
        return f"{base}:overload:{ordinal}"

    def _dispatch_candidates(
        self,
        method: Mapping[str, Any],
        functions: list[dict[str, Any]],
        *,
        call_graph_targets: Mapping[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        method_name = method["method"]
        interface_name = method["interface"]
        tokens = _transaction_tokens(method_name)
        variants = _method_variants(method_name)
        candidates: list[dict[str, Any]] = []
        for function in functions:
            if not _owner_matches_interface(function["name"], interface_name):
                continue
            code = _mask_code(function["code"])
            leaf = function["leaf"]
            token_hits = sorted(token for token in tokens if re.search(rf"\b{re.escape(token)}\b", code))
            method_hit = bool(re.search(rf"\b{re.escape(method_name)}\b", code))
            handler_hits = sorted(
                variant
                for variant in variants
                if re.search(rf"\b{re.escape(variant)}\b", code)
            )
            ipc_code_hits = _literal_ipc_code_hits(
                code,
                method.get("ipc_code"),
                dispatch=leaf == "OnRemoteRequest",
            )
            if leaf == "OnRemoteRequest" and (
                token_hits or method_hit or handler_hits or ipc_code_hits
            ):
                if ipc_code_hits:
                    signal = "ipc_code_literal"
                    matched = ipc_code_hits[0]
                else:
                    signal = "transaction_token" if token_hits else "method_call"
                    matched = token_hits[0] if token_hits else (handler_hits[0] if handler_hits else method_name)
                evidence = {
                    "source": "native",
                    "path": function["file_path"],
                    "line": function["start_line"],
                    "function": function["name"],
                    "signal": signal,
                    "matched": matched,
                }
                normalized_ipc_code = _normalize_ipc_code(method.get("ipc_code"))
                if ipc_code_hits and normalized_ipc_code is not None:
                    evidence["ipc_code"] = normalized_ipc_code
                candidates.append(
                    {
                        "function": function,
                        "confidence": 0.93 if ipc_code_hits else (0.95 if token_hits else 0.85),
                        "evidence": evidence,
                    }
                )
                continue
            has_send_request = re.search(
                r"\bSendRequest(?:[A-Za-z0-9_]*)?\s*\(", code
            )
            if leaf != "OnRemoteRequest" and token_hits and handler_hits and not has_send_request:
                candidates.append(
                    {
                        "function": function,
                        "confidence": 0.9,
                        "evidence": {
                            "source": "native",
                            "path": function["file_path"],
                            "line": function["start_line"],
                            "function": function["name"],
                            "signal": "transaction_table",
                            "matched": f"{token_hits[0]}->{handler_hits[0]}",
                        },
                    }
                )
        # A generated stub can have an owner unrelated to the IDL interface
        # stem (for example, ScreenSessionManagerLiteStub implements
        # IDisplayManagerLite).  A bounded call path to Handle<Method> is
        # stronger evidence than that owner heuristic, so prefer it whenever
        # available for this transaction.
        if call_graph_targets:
            function_by_id = {function["id"]: function for function in functions}
            graph_candidates: list[dict[str, Any]] = []
            for stub_id, targets in call_graph_targets.items():
                stub = function_by_id.get(stub_id)
                if stub is None or stub["leaf"] != "OnRemoteRequest":
                    continue
                if (
                    _interface_variant_affinity(
                        method["interface"],
                        f"{stub['file_path']} {stub['owner']}",
                    )
                    < 0
                ):
                    continue
                matching_targets = [
                    item
                    for item in targets
                    if item["function"]["leaf"] in variants
                    and (
                        item["function"]["leaf"] != method_name
                        or len(item["path"]) == 2
                    )
                    and not _normalize(item["function"]["owner"]).endswith("proxy")
                ]
                if not matching_targets:
                    continue
                match = matching_targets[0]
                path = match["path"]
                graph_candidates.append(
                    {
                        "function": stub,
                        "confidence": 0.97,
                        "evidence": {
                            "source": "call_graph",
                            "path": stub["file_path"],
                            "line": stub["start_line"],
                            "function": stub["name"],
                            "signal": "dispatch_to_handler_variant",
                            "matched": match["function"]["leaf"],
                            "call_path": [
                                function_by_id[item_id]["name"]
                                for item_id in path
                                if item_id in function_by_id
                            ],
                        },
                    }
                )
            if graph_candidates:
                return graph_candidates

        # Prefer the framework callback itself when both it and a constructor/
        # dispatch-table initializer carry the same token.  The latter remains
        # useful as a fallback, but should not make an otherwise unambiguous
        # OnRemoteRequest relationship look ambiguous.
        remote_callbacks = [
            candidate
            for candidate in candidates
            if candidate["function"]["leaf"] == "OnRemoteRequest"
        ]
        return remote_callbacks or candidates

    def _proxy_candidates(
        self,
        method: Mapping[str, Any],
        functions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Find client-side functions that issue this transaction."""
        method_name = method["method"]
        interface_name = method["interface"]
        tokens = _transaction_tokens(method_name)
        candidates: list[dict[str, Any]] = []
        for function in functions:
            if not _owner_matches_interface(function["name"], interface_name):
                continue
            code = _mask_code(function["code"])
            send_match = re.search(r"\bSendRequest(?:[A-Za-z0-9_]*)?\s*\(", code)
            if send_match is None:
                continue
            token_hits = sorted(
                token for token in tokens if re.search(rf"\b{re.escape(token)}\b", code)
            )
            method_hit = bool(re.search(rf"\b{re.escape(method_name)}\b", code))
            ipc_code_hits = _literal_ipc_code_hits(
                code,
                method.get("ipc_code"),
                proxy=True,
            )
            if not token_hits and not method_hit and not ipc_code_hits:
                continue
            if ipc_code_hits:
                signal = "ipc_code_literal"
                matched = ipc_code_hits[0]
            else:
                signal = "transaction_token" if token_hits else "method_name"
                matched = token_hits[0] if token_hits else method_name
            evidence = {
                "source": "native",
                "path": function["file_path"],
                "line": function["start_line"],
                "function": function["name"],
                "signal": signal,
                "matched": matched,
                "call": send_match.group(0).strip().rstrip("("),
            }
            normalized_ipc_code = _normalize_ipc_code(method.get("ipc_code"))
            if ipc_code_hits and normalized_ipc_code is not None:
                evidence["ipc_code"] = normalized_ipc_code
            candidates.append(
                {
                    "function": function,
                    "confidence": 0.93 if ipc_code_hits else (0.95 if token_hits else 0.8),
                    "evidence": evidence,
                }
            )
        return candidates

    def _handler_candidates(
        self,
        method: Mapping[str, Any],
        stub: Mapping[str, Any],
        functions: list[dict[str, Any]],
        *,
        call_graph: Mapping[str, list[str]] | None = None,
        call_graph_targets: Mapping[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        variants = _method_variants(method["method"])

        # A bounded native call path is stronger than the historical same-owner
        # heuristic.  OpenHarmony commonly places OnRemoteRequest in a Stub
        # class while the business implementation lives in a sibling Service
        # class, and generated ZIDL stubs commonly call Handle<Method> helpers.
        # Restrict the call-path candidates by method variants so a
        # generic helper call cannot become an IPC handler merely because it
        # is reachable from the dispatch callback.
        if call_graph_targets:
            function_by_id = {function["id"]: function for function in functions}
            path_candidates: list[dict[str, Any]] = []
            for item in call_graph_targets.get(str(stub.get("id", "")), []):
                function = item["function"]
                if function["leaf"] not in variants:
                    continue
                if function["leaf"] == method["method"] and len(item["path"]) > 2:
                    continue
                if _normalize(function["owner"]).endswith("proxy"):
                    continue
                path = item["path"]
                path_candidates.append(
                    {
                        "function": function,
                        "confidence": 0.98,
                        "evidence": {
                            "source": "call_graph",
                            "path": function["file_path"],
                            "line": function["start_line"],
                            "function": function["name"],
                            "caller": stub["name"],
                            "signal": (
                                "direct_dispatch_call"
                                if len(path) == 2
                                else "dispatch_call_path"
                            ),
                            "matched": function["leaf"],
                            "call_path": [
                                function_by_id[item_id]["name"]
                                for item_id in path
                                if item_id in function_by_id
                            ],
                        },
                    }
                )
            if path_candidates:
                return path_candidates

        if call_graph:
            function_by_id = {function["id"]: function for function in functions}
            direct_candidates: list[dict[str, Any]] = []
            for target_id in call_graph.get(str(stub.get("id", "")), []):
                function = function_by_id.get(str(target_id))
                if function is None or function["id"] == stub.get("id"):
                    continue
                if function["leaf"] not in variants:
                    continue
                if _normalize(function["owner"]).endswith("proxy"):
                    continue
                direct_candidates.append(
                    {
                        "function": function,
                        "confidence": 0.98,
                        "evidence": {
                            "source": "call_graph",
                            "path": function["file_path"],
                            "line": function["start_line"],
                            "function": function["name"],
                            "caller": stub["name"],
                            "signal": "direct_dispatch_call",
                            "matched": function["leaf"],
                        },
                    }
                )
            if direct_candidates:
                return direct_candidates

        stub_code = _mask_code(_text(stub.get("code", "")))
        explicit_names = set(
            match.group("name") for match in _CALL_RE.finditer(stub_code)
        )
        explicit_names.update(match.group("name") for match in _QUALIFIED_CALL_RE.finditer(stub_code))
        stub_owner = _normalize(_text(stub.get("owner", "")))
        candidates: list[dict[str, Any]] = []
        for function in functions:
            if function["id"] == stub.get("id"):
                continue
            if not _owner_matches_interface(function["name"], method["interface"]):
                continue
            # A proxy often has the same method name as the service handler;
            # keep handler resolution on the dispatch object's owner.
            if stub_owner and _normalize(function["owner"]) != stub_owner:
                continue
            if function["leaf"] not in variants:
                continue
            exact = function["leaf"] == method["method"]
            referenced = function["leaf"] in explicit_names or function["leaf"] in stub_code
            if not referenced and not exact:
                continue
            candidates.append(
                {
                    "function": function,
                    "confidence": 0.95 if exact and referenced else (0.9 if exact else 0.8),
                    "evidence": {
                        "source": "native",
                        "path": function["file_path"],
                        "line": function["start_line"],
                        "function": function["name"],
                        "signal": "handler_reference" if referenced else "exact_method_name",
                        "matched": function["leaf"],
                    },
                }
            )
        return candidates

    def _contract_handler_candidates(
        self,
        method: Mapping[str, Any],
        functions: list[dict[str, Any]],
        *,
        class_bases: Mapping[str, list[str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Find an exact Stub-derived implementation when generated code is absent.

        This is deliberately narrower than ``_handler_candidates``: it only
        considers an exact IDL method name, a non-static member function, and
        a class whose inheritance evidence reaches the interface-specific Stub
        base.  Parameter arity and normalized type shapes rank overloads, but
        the IDL return type is not required to equal the native return type
        because OpenHarmony server callbacks commonly return an IPC status
        while the IDL declaration is ``void``.
        """
        if not class_bases:
            return []
        method_name = _text(method.get("method", ""))
        interface_name = _text(method.get("interface", ""))
        if not method_name or not interface_name:
            return []
        idl_shapes = _parameter_shapes(method.get("parameters", []), idl=True)
        candidates: list[dict[str, Any]] = []
        for function in functions:
            if function.get("leaf") != method_name or function.get("is_static"):
                continue
            owner = _text(function.get("class_name")) or _text(function.get("owner"))
            inheritance = _inherits_stub(owner, interface_name, class_bases)
            if inheritance is None:
                continue

            native_parameters = function.get("parameters", [])
            native_has_signature = isinstance(native_parameters, (list, tuple)) and bool(
                native_parameters
            )
            native_shapes = _parameter_shapes(native_parameters)
            if native_has_signature and len(native_shapes) != len(idl_shapes):
                # Arity is a hard contract boundary.  It prevents an overload
                # with a coincidentally identical name from being selected.
                continue
            known_pairs = [
                (expected, actual)
                for expected, actual in zip(idl_shapes, native_shapes)
                if expected != "unknown" and actual != "unknown"
            ]
            matches = sum(expected == actual for expected, actual in known_pairs)
            mismatches = sum(expected != actual for expected, actual in known_pairs)
            if known_pairs and mismatches and matches == 0:
                # A wholly incompatible shape is stronger evidence against a
                # candidate than a missing/aliased type is in favour of it.
                continue
            score = 100
            if native_has_signature:
                score += 20
                score += matches * 8
                score -= mismatches * 8
            else:
                native_shapes = []
            base_class, declaring_class = inheritance
            evidence = {
                "source": "idl_handler_contract",
                "path": function["file_path"],
                "line": function["start_line"],
                "function": function["name"],
                "signal": "service_inherits_stub",
                "class": declaring_class,
                "base_class": base_class,
                "idl_path": method.get("path", ""),
                "idl_line": method.get("line", 0),
                "parameter_match": {
                    "mode": "shape" if native_has_signature else "arity_unknown",
                    "idl_count": len(idl_shapes),
                    "native_count": len(native_shapes) if native_has_signature else None,
                    "idl_shapes": idl_shapes,
                    "native_shapes": native_shapes,
                    "matched": matches,
                    "mismatched": mismatches,
                },
            }
            candidates.append(
                {
                    "function": function,
                    "confidence": 0.9 if native_has_signature and mismatches == 0 else 0.84,
                    "evidence": evidence,
                    "_score": score,
                }
            )

        if not candidates:
            return []
        best_score = max(item["_score"] for item in candidates)
        selected = [item for item in candidates if item["_score"] == best_score]
        for item in selected:
            item.pop("_score", None)
        return selected


IPCGraphResolver = OpenHarmonyIPCResolver


__all__ = ["IPCGraphResolver", "OpenHarmonyIPCResolver", "RESOLVER_VERSION"]
