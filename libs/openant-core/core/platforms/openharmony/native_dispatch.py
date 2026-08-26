"""Evidence-backed native OpenHarmony dispatch graph resolution.

OpenHarmony services often dispatch Binder transactions through a C++ member
function table.  A native call-graph builder cannot recover the target of
``(this->*memberFunc)(...)`` from ordinary call syntax, even though the table
initialisation is explicit in the source.  This module turns that narrow,
syntax-backed evidence into an additive semantic graph.  It intentionally
does not modify the native call graph and never guesses a target from a name
alone.

The first supported form is a ``baseFuncs_``-style member-function table:

``baseFuncs_[CODE] = &Stub::HandleInner;``
``(this->*memberFunc)(data, reply);``

When a handler directly calls a method implemented by a class that is proven
to inherit the stub (for example ``MedicalSensorService`` inheriting
``MedicalSensorServiceStub``), a second evidence-backed edge is emitted to
the concrete service method.  Ambiguous or unsupported relationships are
recorded as semantic orphans rather than being silently promoted.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser

from core.platforms.graph import SemanticGraph


RESOLVER_VERSION = 1
HANDLER_EDGE_KIND = "native_dispatch_to_handler"
SERVICE_EDGE_KIND = "native_dispatch_to_service"
_CPP_EXTENSIONS = frozenset({".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"})
_BASE_TABLE_RE = re.compile(r"(?:^|[^A-Za-z0-9_])(?P<table>[A-Za-z_][A-Za-z0-9_]*)$")
_CLASS_RE = re.compile(
    r"\bclass\s+(?P<class>[A-Za-z_]\w*)\s*"
    r"(?:(?:final)\s*)?(?::\s*(?P<bases>[^\{;]+))?\{",
    re.DOTALL,
)
_ACCESS_RE = re.compile(r"\b(?:public|protected|private|virtual)\b")
_LEXICAL_CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")

C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _leaf(name: str) -> str:
    return _text(name).rsplit("::", 1)[-1].rsplit(".", 1)[-1]


def _owner(name: str, class_name: Any = None) -> str:
    explicit = _text(class_name)
    if explicit:
        return explicit.rsplit("::", 1)[-1]
    qualified = _text(name)
    if "::" not in qualified:
        return ""
    return qualified.rsplit("::", 1)[-2].rsplit("::", 1)[-1]


def _line(function: Mapping[str, Any], row: int = 0) -> int:
    value = _field(function, "start_line", _field(function, "startLine", 1))
    try:
        start = int(value)
    except (TypeError, ValueError):
        start = 1
    return max(1, start) + max(0, int(row))


def _records(functions: Any) -> list[dict[str, Any]]:
    """Normalize the extractor/call-graph function maps."""
    if isinstance(functions, Mapping) and isinstance(functions.get("functions"), Mapping):
        functions = functions["functions"]
    if not isinstance(functions, Mapping):
        return []
    records: list[dict[str, Any]] = []
    for function_id, raw in functions.items():
        if not isinstance(raw, Mapping):
            continue
        function_id = _text(function_id)
        name = _text(_field(raw, "name", function_id))
        if not function_id or not name:
            continue
        records.append(
            {
                "id": function_id,
                "name": name,
                "leaf": _leaf(name),
                "owner": _owner(name, _field(raw, "class_name")),
                "file_path": _text(_field(raw, "file_path", _field(raw, "filePath", ""))),
                "start_line": _field(raw, "start_line", _field(raw, "startLine", 1)),
                "end_line": _field(raw, "end_line", _field(raw, "endLine", 0)),
                "unit_type": _text(_field(raw, "unit_type", _field(raw, "unitType", "function")))
                or "function",
                "code": _text(_field(raw, "code", "")),
            }
        )
    return sorted(records, key=lambda item: item["id"])


def _function_node_id(record: Mapping[str, Any]) -> str:
    return f"function:{record['id']}"


def _function_attributes(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": record["name"],
        "file_path": record["file_path"],
        "start_line": record["start_line"],
        "end_line": record["end_line"],
        "unit_type": record["unit_type"],
    }


def _is_base_table(value: Any) -> bool:
    """Recognize the deliberately narrow ``baseFuncs_`` table family."""
    table = _text(value)
    if not table:
        return False
    table = table.replace("->", ".").split(".")[-1]
    match = _BASE_TABLE_RE.fullmatch(table)
    if not match:
        return False
    normalized = match.group("table").lower().rstrip("_")
    return normalized in {"basefuncs", "base_funcs"}


def _parser_for(path: str) -> Parser:
    return Parser(CPP_LANGUAGE if Path(path).suffix.lower() in _CPP_EXTENSIONS else C_LANGUAGE)


def _walk(root: Any) -> Iterable[Any]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _mask_preserving_lines(code: str) -> str:
    """Blank comments/literals without changing line offsets."""

    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char in "\r\n" else " " for char in match.group(0))

    masked = re.sub(r"//[^\r\n]*|/\*.*?\*/", blank, code, flags=re.DOTALL)
    return re.sub(r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", blank, masked)


def _called_name(node: Any, source: bytes) -> str:
    """Return a call-expression leaf without interpreting receiver types."""
    if node is None:
        return ""
    if node.type == "identifier":
        return _node_text(node, source).strip()
    if node.type in {"field_expression", "qualified_identifier", "scoped_identifier"}:
        return _leaf(_node_text(node, source))
    text = _node_text(node, source).strip()
    return _leaf(text) if text else ""


def _direct_calls(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect direct call expressions while ignoring comments and literals."""
    code = _text(record.get("code"))
    if not code:
        return []
    source = code.encode("utf-8", errors="replace")
    try:
        root = _parser_for(_text(record.get("file_path"))).parse(source).root_node
    except (TypeError, ValueError):
        return []
    calls: list[dict[str, Any]] = []
    for node in _walk(root):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        name = _called_name(callee, source)
        if not name:
            continue
        calls.append(
            {
                "name": name,
                "line": _line(record, node.start_point[0]),
                "expression": _node_text(node, source).strip(),
            }
        )
    # C++'s most-vexing-parse form can represent ``GetSensorList()`` as a
    # parameter declaration inside a function declarator rather than as a
    # ``call_expression``.  Keep a masked lexical fallback for that narrow
    # case.  It is only used later when the name resolves to a concrete
    # inherited service method, so control keywords and unrelated symbols do
    # not become edges.
    masked = _mask_preserving_lines(code)
    known = {(item["name"], item["line"]) for item in calls}
    for match in _LEXICAL_CALL_RE.finditer(masked):
        name = match.group("name")
        line = _line(record, masked.count("\n", 0, match.start()))
        if (name, line) in known:
            continue
        calls.append(
            {
                "name": name,
                "line": line,
                "expression": f"{name}()",
            }
        )
    return sorted(calls, key=lambda item: (item["line"], item["name"], item["expression"]))


def _class_bases(records: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    """Extract direct C++ base-class declarations from parsed class units."""
    result: dict[str, set[str]] = defaultdict(set)
    for record in records:
        code = _text(record.get("code"))
        if not code:
            continue
        for match in _CLASS_RE.finditer(code):
            class_name = _text(match.group("class"))
            bases_text = _text(match.group("bases"))
            if not class_name or not bases_text:
                continue
            for raw_base in bases_text.split(","):
                base = _ACCESS_RE.sub(" ", raw_base)
                base = base.split("<", 1)[0].strip()
                base = re.sub(r"\s+", "", base).rsplit("::", 1)[-1]
                if base and re.fullmatch(r"[A-Za-z_]\w*", base):
                    result[class_name].add(base)
    return {name: set(bases) for name, bases in result.items()}


def _class_declaration_evidence(
    records: Iterable[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Keep source locations for class inheritance declarations."""
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        code = _text(record.get("code"))
        if not code:
            continue
        for match in _CLASS_RE.finditer(code):
            class_name = _text(match.group("class"))
            bases_text = _text(match.group("bases"))
            if not class_name or not bases_text:
                continue
            bases: list[str] = []
            for raw_base in bases_text.split(","):
                base = _ACCESS_RE.sub(" ", raw_base)
                base = base.split("<", 1)[0].strip()
                base = re.sub(r"\s+", "", base).rsplit("::", 1)[-1]
                if base and re.fullmatch(r"[A-Za-z_]\w*", base):
                    bases.append(base)
            if not bases:
                continue
            result[class_name].append(
                {
                    "path": _text(record.get("file_path")),
                    "line": _line(record, code[: match.start()].count("\n")),
                    "text": match.group(0).strip(),
                    "derived_class": class_name,
                    "base_classes": sorted(set(bases)),
                }
            )
    return {
        class_name: sorted(
            declarations,
            key=lambda item: (item["path"], item["line"], item["text"]),
        )
        for class_name, declarations in result.items()
    }


def _inherits(class_name: str, ancestor: str, bases: Mapping[str, set[str]]) -> bool:
    if not class_name or not ancestor or class_name == ancestor:
        return class_name == ancestor and bool(class_name)
    pending = [class_name]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        for base in bases.get(current, set()):
            if base == ancestor:
                return True
            if base not in visited:
                pending.append(base)
    return False


def _diagnostic_lists(diagnostics: Mapping[str, Any] | None) -> tuple[list[Any], list[Any]]:
    if not isinstance(diagnostics, Mapping):
        return [], []
    assignments = diagnostics.get("dispatch_assignments", [])
    sites = diagnostics.get("unresolved_call_sites", [])
    return (
        assignments if isinstance(assignments, list) else [],
        sites if isinstance(sites, list) else [],
    )


def _add_function_node(graph: SemanticGraph, record: Mapping[str, Any]) -> None:
    graph.add_node(
        {
            "schema_version": graph.schema_version,
            "id": _function_node_id(record),
            "kind": "function",
            "attributes": _function_attributes(record),
        }
    )


def _assignment_index(assignments: Iterable[Any]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in assignments:
        if not isinstance(item, Mapping):
            continue
        if not _is_base_table(item.get("table")):
            continue
        target_id = _text(item.get("target_id"))
        if not target_id:
            continue
        key = (target_id, _text(item.get("table")), _text(item.get("selector")))
        index[key].append(dict(item))
    return index


def _candidate_evidence(
    site: Mapping[str, Any],
    candidate: Mapping[str, Any],
    assignment: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    site_evidence = {
        "source": "native_dispatch",
        "path": _text(site.get("file")),
        "line": site.get("line", 0),
        "function": _text(site.get("caller_id")),
        "signal": "baseFuncs_member_function_call",
        "matched": _text(site.get("expression")),
    }
    evidence.append(site_evidence)
    candidate_evidence = candidate.get("evidence")
    if isinstance(candidate_evidence, Mapping):
        evidence.append({"source": "native_dispatch_assignment", **dict(candidate_evidence)})
    if isinstance(assignment, Mapping) and assignment.get("evidence"):
        assignment_evidence = assignment.get("evidence")
        if isinstance(assignment_evidence, Mapping):
            evidence.append(
                {"source": "native_dispatch_assignment", **dict(assignment_evidence)}
            )
    return evidence


def _add_orphan_for_site(graph: SemanticGraph, site: Mapping[str, Any]) -> None:
    graph.add_orphan(
        kind="unresolved_native_dispatch",
        reason="baseFuncs_ member-function dispatch has no resolved handler candidate",
        evidence=[
            {
                "source": "native_dispatch",
                "path": _text(site.get("file")),
                "line": site.get("line", 0),
                "function": _text(site.get("caller_id")),
                "signal": "baseFuncs_member_function_call",
                "matched": _text(site.get("expression")),
            }
        ],
        attributes={
            "caller_id": _text(site.get("caller_id")),
            "dispatch_table": _text((site.get("symbols") or {}).get("dispatch_table")),
        },
    )


def _resolve_dispatch_edges(
    graph: SemanticGraph,
    records_by_id: Mapping[str, Mapping[str, Any]],
    assignments: list[Any],
    sites: list[Any],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Emit OnRemoteRequest -> handler edges and return resolved pairs."""
    assignment_by_target = _assignment_index(assignments)
    resolved: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    dispatch_callers: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for raw_site in sites:
        if not isinstance(raw_site, Mapping):
            continue
        caller_id = _text(raw_site.get("caller_id"))
        caller = records_by_id.get(caller_id)
        symbols = raw_site.get("symbols")
        table = symbols.get("dispatch_table") if isinstance(symbols, Mapping) else ""
        if not caller or caller.get("leaf") != "OnRemoteRequest" or not _is_base_table(table):
            continue
        dispatch_callers[caller_id].append(raw_site)
        candidates = raw_site.get("candidates")
        if not isinstance(candidates, list):
            candidates = []
        valid_candidates = [
            item
            for item in candidates
            if isinstance(item, Mapping)
            and _text(item.get("target_id")) in records_by_id
        ]
        if not valid_candidates:
            _add_orphan_for_site(graph, raw_site)
            continue
        for candidate in valid_candidates:
            target_id = _text(candidate.get("target_id"))
            target = records_by_id[target_id]
            selector = _text(candidate.get("selector"))
            table_key = (target_id, _text(table), selector)
            assignment = assignment_by_target.get(table_key, [None])[0]
            _add_function_node(graph, caller)
            _add_function_node(graph, target)
            graph.add_edge(
                {
                    "schema_version": graph.schema_version,
                    "source_id": _function_node_id(caller),
                    "target_id": _function_node_id(target),
                    "kind": HANDLER_EDGE_KIND,
                    "evidence": _candidate_evidence(raw_site, candidate, assignment),
                    "confidence": 0.98,
                    "resolver_version": RESOLVER_VERSION,
                    "attributes": {
                        "dispatch_table": _text(table),
                        "selector": selector,
                        "stub_class": caller.get("owner", ""),
                    },
                }
            )
            resolved.append((caller, target))

    # A diagnostic may contain assignments but no indirect-call site (for
    # example, an unsupported AST shape).  Match only when exactly one
    # OnRemoteRequest in the same class exists; otherwise keep the evidence as
    # an orphan instead of choosing between unrelated stubs.
    dispatch_functions = [
        record
        for record in records_by_id.values()
        if record.get("leaf") == "OnRemoteRequest"
    ]
    for raw_assignment in assignments:
        if not isinstance(raw_assignment, Mapping):
            continue
        if not _is_base_table(raw_assignment.get("table")):
            continue
        target_id = _text(raw_assignment.get("target_id"))
        target = records_by_id.get(target_id)
        if target is None:
            continue
        owners = [
            caller
            for caller in dispatch_functions
            if _text(raw_assignment.get("owner_class"))
            and caller.get("owner") == _text(raw_assignment.get("owner_class"))
        ]
        if len(owners) != 1 or owners[0]["id"] in dispatch_callers:
            continue
        caller = owners[0]
        _add_function_node(graph, caller)
        _add_function_node(graph, target)
        graph.add_edge(
            {
                "schema_version": graph.schema_version,
                "source_id": _function_node_id(caller),
                "target_id": _function_node_id(target),
                "kind": HANDLER_EDGE_KIND,
                "evidence": [
                    {
                        "source": "native_dispatch_assignment",
                        **dict(raw_assignment.get("evidence") or {}),
                    }
                ],
                "confidence": 0.94,
                "resolver_version": RESOLVER_VERSION,
                "attributes": {
                    "dispatch_table": _text(raw_assignment.get("table")),
                    "selector": _text(raw_assignment.get("selector")),
                    "stub_class": caller.get("owner", ""),
                },
            }
        )
        resolved.append((caller, target))
    return resolved


def _resolve_service_edges(
    graph: SemanticGraph,
    records: list[Mapping[str, Any]],
    handler_pairs: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> None:
    bases = _class_bases(records)
    declaration_evidence = _class_declaration_evidence(records)
    records_by_leaf: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        if record.get("leaf"):
            records_by_leaf[record["leaf"]].append(record)

    seen_handlers: set[str] = set()
    for _caller, handler in handler_pairs:
        handler_id = _text(handler.get("id"))
        if not handler_id or handler_id in seen_handlers:
            continue
        seen_handlers.add(handler_id)
        handler_owner = _text(handler.get("owner"))
        if not handler_owner:
            continue
        for call in _direct_calls(handler):
            method_name = _text(call.get("name"))
            if not method_name:
                continue
            candidates = [
                target
                for target in records_by_leaf.get(method_name, [])
                if _text(target.get("owner"))
                and _text(target.get("owner")) != handler_owner
                and _inherits(_text(target.get("owner")), handler_owner, bases)
            ]
            if len(candidates) != 1:
                if len(candidates) > 1:
                    graph.add_orphan(
                        kind="ambiguous_native_dispatch_service",
                        reason="handler call matches multiple service implementations",
                        evidence=[
                            {
                                "source": "native_dispatch_service_call",
                                "path": _text(handler.get("file_path")),
                                "line": call.get("line", 0),
                                "function": handler.get("name", ""),
                                "signal": "stub_inherited_service_method",
                                "matched": call.get("expression", ""),
                            }
                        ],
                        attributes={
                            "handler_id": handler_id,
                            "method": method_name,
                            "candidate_ids": [item.get("id", "") for item in candidates],
                        },
                    )
                continue
            target = candidates[0]
            _add_function_node(graph, handler)
            _add_function_node(graph, target)
            inheritance_evidence = declaration_evidence.get(
                _text(target.get("owner")), []
            )
            if inheritance_evidence:
                inheritance_item = dict(inheritance_evidence[0])
                inheritance_item["base_class"] = handler_owner
            else:
                # This fallback is reachable only for an unusual extractor
                # record that supplied inheritance through another source but
                # did not retain the declaration text.  Keep the evidence
                # explicit rather than pointing at an unrelated method line.
                inheritance_item = {
                    "source": "native_class_inheritance",
                    "path": _text(target.get("file_path")),
                    "line": target.get("start_line", 0),
                    "derived_class": target.get("owner", ""),
                    "base_class": handler_owner,
                    "signal": "inherited_class_without_declaration_text",
                }
            graph.add_edge(
                {
                    "schema_version": graph.schema_version,
                    "source_id": _function_node_id(handler),
                    "target_id": _function_node_id(target),
                    "kind": SERVICE_EDGE_KIND,
                    "evidence": [
                        {
                            "source": "native_dispatch_service_call",
                            "path": _text(handler.get("file_path")),
                            "line": call.get("line", 0),
                            "function": handler.get("name", ""),
                            "signal": "stub_inherited_service_method",
                            "matched": call.get("expression", ""),
                            "target": target.get("name", ""),
                        },
                        {
                            "source": "native_class_inheritance",
                            **inheritance_item,
                        },
                    ],
                    "confidence": 0.96,
                    "resolver_version": RESOLVER_VERSION,
                    "attributes": {
                        "method": method_name,
                        "handler_class": handler_owner,
                        "service_class": target.get("owner", ""),
                    },
                }
            )


def build_native_dispatch_graph(
    extract_result: Mapping[str, Any],
    call_graph_result: Mapping[str, Any] | None = None,
    diagnostics: Mapping[str, Any] | None = None,
) -> SemanticGraph | None:
    """Build the bounded native-dispatch semantic overlay.

    ``diagnostics`` should normally be the already persisted
    ``call_graph_residuals`` result.  If omitted, the observation-only
    diagnostics collector is invoked once.  The function returns ``None``
    when no ``baseFuncs_`` evidence exists, preserving the previous optional
    semantic-graph behavior for unrelated repositories.
    """
    if not isinstance(extract_result, Mapping):
        return None
    records = _records(extract_result.get("functions", extract_result))
    if not records:
        return None
    records_by_id = {record["id"]: record for record in records}
    if diagnostics is None:
        from core.platforms.openharmony.call_graph_diagnostics import (
            build_call_graph_diagnostics,
        )

        diagnostics = build_call_graph_diagnostics(extract_result, call_graph_result)
    assignments, sites = _diagnostic_lists(diagnostics)
    has_base_evidence = any(
        isinstance(item, Mapping) and _is_base_table(item.get("table"))
        for item in [*assignments, *sites]
    )
    if not has_base_evidence:
        return None

    graph = SemanticGraph()
    handler_pairs = _resolve_dispatch_edges(
        graph,
        records_by_id,
        assignments,
        sites,
    )
    _resolve_service_edges(graph, records, handler_pairs)
    return graph


def merge_semantic_graphs(*graphs: Any) -> SemanticGraph | None:
    """Merge validated semantic graphs while preserving all evidence."""
    merged = SemanticGraph()
    present = False
    for payload in graphs:
        if payload is None:
            continue
        graph = payload if isinstance(payload, SemanticGraph) else SemanticGraph.from_dict(payload)
        present = True
        for node in graph.nodes.values():
            merged.add_node(node)
        for edge in graph.edges.values():
            merged.add_edge(edge)
        for orphan in graph.orphans:
            merged.add_orphan(
                kind=orphan["kind"],
                reason=orphan["reason"],
                evidence=orphan.get("evidence", []),
                attributes=orphan.get("attributes", {}),
            )
    return merged if present else None


__all__ = [
    "HANDLER_EDGE_KIND",
    "RESOLVER_VERSION",
    "SERVICE_EDGE_KIND",
    "build_native_dispatch_graph",
    "merge_semantic_graphs",
]
