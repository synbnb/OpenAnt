"""Load source-backed Clang semantic call edges as an optional overlay.

The C/C++ Tree-sitter graph remains the production baseline.  This module is
an explicit sidecar boundary for a Clang/libTooling proof of concept: it only
accepts a direct call when the artifact identifies the resolver, both function
endpoints, a call-site span, target evidence, and (when requested) the source
revision.  It never edits ``call_graph.json`` and never treats a model-only
assertion as a Clang binding.

Input schema (``openant.clang.semantic-edge.v1``)::

    {
      "schema_version": 1,
      "source_revision": "<commit>",
      "edges": [{
        "caller_id": "file.cpp:Caller",
        "callee_id": "other.cpp:Target::method",
        "edge_kind": "direct_member_call",
        "resolver": "clang",
        "binding_status": "resolved",
        "callsite": {
          "file": "file.cpp", "line": 42,
          "expression": "object.method()"
        },
        "evidence": [
          {"kind": "call_site", "file": "file.cpp", "start_line": 42,
           "end_line": 42, "text": "object.method()"},
          {"kind": "target", "file": "other.cpp", "start_line": 10,
           "end_line": 12, "text": "Target::method", "function_id": "..."}
        ]
      }]
    }

``load_clang_semantic_overlay`` returns the normal ``SemanticGraph`` payload
plus a bounded validation summary.  Rejected records are retained in the
artifact so a failed binding is visible rather than silently becoming an
unreachable function.
"""

from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from core.platforms.graph import SemanticGraph


SCHEMA_VERSION = 1
TASK = "openharmony_clang_semantic_edge_overlay"
EDGE_KIND = "clang_direct_call"
RESOLVER_VERSION = 1


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _endpoint(value: Any) -> str:
    value = _text(value)
    return value[len("function:") :] if value.startswith("function:") else value


def _line(value: Any, default: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, parsed)


def _file(function: Mapping[str, Any]) -> str:
    return _text(function.get("file_path") or function.get("filePath"))


def _span(function: Mapping[str, Any]) -> tuple[int, int]:
    start = _line(function.get("start_line", function.get("startLine", 1)))
    end = _line(function.get("end_line", function.get("endLine", start)), start)
    return start, max(start, end)


def _path_equal(left: Any, right: Any) -> bool:
    left_text = _text(left).replace("\\", "/")
    right_text = _text(right).replace("\\", "/")
    return bool(left_text and right_text and left_text == right_text)


def _line_in_function(function: Mapping[str, Any], line: Any) -> bool:
    start, end = _span(function)
    value = _line(line)
    return start <= value <= end


def _function_attributes(function_id: str, function: Mapping[str, Any]) -> dict[str, Any]:
    start, end = _span(function)
    return {
        "name": _text(function.get("name")) or function_id,
        "file_path": _file(function),
        "start_line": start,
        "end_line": end,
        "unit_type": _text(function.get("unit_type") or function.get("unitType"))
        or "function",
    }


def _short_function_name(function_id: str, function: Mapping[str, Any]) -> str:
    """Return the terminal method name used for a cheap evidence sanity check.

    The overlay validator is deliberately not a C++ type checker.  It can,
    however, reject an otherwise well-shaped record whose quoted call site and
    target declaration clearly mention a different method.  This prevents a
    stale/ambiguous extractor record from becoming a trusted graph edge merely
    because both source spans exist.
    """
    name = _text(function.get("name")) or _endpoint(function_id)
    name = name.split("::")[-1].strip()
    return name


def _evidence_mentions_method(text: str, method_name: str) -> bool:
    if not method_name or method_name.startswith("operator"):
        return True
    return method_name in text


def _explicit_true(value: Any) -> bool:
    if value is True:
        return True
    return _text(value).lower() in {"1", "true", "yes"}


def _payload_symbols(payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Read declaration-only symbols supplied by a Clang batch extractor."""
    symbols: dict[str, Mapping[str, Any]] = {}
    raw = payload.get("symbols")
    if isinstance(raw, Mapping):
        for raw_id, value in raw.items():
            symbol_id = _endpoint(raw_id)
            if symbol_id and isinstance(value, Mapping):
                symbols[symbol_id] = value
    elif isinstance(raw, list):
        for value in raw:
            if not isinstance(value, Mapping):
                continue
            symbol_id = _endpoint(
                value.get("id") or value.get("function_id") or value.get("symbol_id")
            )
            if symbol_id:
                symbols[symbol_id] = value
    return symbols


def _load_payload(payload_or_path: Mapping[str, Any] | str | Path) -> Mapping[str, Any]:
    if isinstance(payload_or_path, Mapping):
        return payload_or_path
    with Path(payload_or_path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise ValueError("Clang semantic overlay must be a JSON object")
    return payload


def _evidence_list(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = record.get("evidence", [])
    if not isinstance(raw, list):
        return []
    return [dict(item) for item in raw if isinstance(item, Mapping)]


def _reject(summary: dict[str, Any], rejected: list[dict[str, Any]],
           record: Any, reason: str) -> None:
    summary["rejected"] += 1
    rejected.append({
        "reason": reason,
        "record": dict(record) if isinstance(record, Mapping) else {},
    })


def load_clang_semantic_overlay(
    payload_or_path: Mapping[str, Any] | str | Path,
    functions: Mapping[str, Mapping[str, Any]],
    *,
    expected_source_revision: str | None = None,
) -> dict[str, Any]:
    """Validate and convert a Clang sidecar into a semantic graph payload.

    ``expected_source_revision`` is deliberately optional for exploratory POC
    runs.  When supplied, a missing or mismatching record revision is rejected;
    this prevents a binding produced from another OpenHarmony checkout from
    silently entering the current scan.
    """
    payload = _load_payload(payload_or_path)
    graph = SemanticGraph()
    summary: dict[str, Any] = {
        "accepted_input": 0,
        "projected_edges": 0,
        "rejected": 0,
        "revision_checked": bool(_text(expected_source_revision)),
        "revision_unknown": 0,
        "resolver": "clang",
        "declaration_only_targets": 0,
    }
    rejected: list[dict[str, Any]] = []

    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        _reject(summary, rejected, payload, "unsupported_schema_version")
        result = graph.to_dict()
        result.update({
            "schema_version": SCHEMA_VERSION,
            "task": TASK,
            "status": "invalid",
            "summary": summary,
            "rejected": rejected,
        })
        return result

    raw_edges = payload.get("edges", [])
    if not isinstance(raw_edges, list):
        _reject(summary, rejected, payload, "edges_not_a_list")
        raw_edges = []

    payload_revision = _text(payload.get("source_revision"))
    payload_build_status = _text(
        payload.get("build_status") or payload.get("build_context_status")
    ) or "unknown"
    payload_product_config_verified = _explicit_true(
        payload.get("product_config_verified")
        or payload.get("product_configuration_verified")
    )
    declaration_symbols = _payload_symbols(payload)
    for record in raw_edges:
        summary["accepted_input"] += 1
        if not isinstance(record, Mapping):
            _reject(summary, rejected, record, "malformed_edge")
            continue

        caller_id = _endpoint(record.get("caller_id"))
        callee_id = _endpoint(record.get("callee_id") or record.get("target_id"))
        caller = functions.get(caller_id)
        callee = functions.get(callee_id) or declaration_symbols.get(callee_id)
        callee_has_body = callee_id in functions
        callsite = record.get("callsite")
        evidence = _evidence_list(record)
        record_revision = _text(record.get("source_revision")) or payload_revision
        reason = ""

        if not caller_id or not callee_id:
            reason = "missing_endpoint_id"
        elif caller is None:
            reason = "caller_not_in_function_index"
        elif callee is None:
            # Keep the legacy reason for callers that did not provide a
            # declaration symbol table; the richer reason is used once the
            # batch extractor supplies one.
            reason = (
                "endpoint_not_in_symbol_index"
                if declaration_symbols
                else "endpoint_not_in_function_index"
            )
        elif _text(record.get("resolver")).lower() != "clang":
            reason = "resolver_is_not_clang"
        elif _text(record.get("binding_status")).lower() != "resolved":
            reason = "binding_not_resolved"
        elif _text(record.get("edge_kind")) not in {
            "direct_call", "direct_member_call", "member_call",
        }:
            reason = "unsupported_edge_kind"
        elif not isinstance(callsite, Mapping):
            reason = "callsite_missing"
        elif not _path_equal(callsite.get("file"), _file(caller)):
            reason = "callsite_file_mismatch"
        elif not _line_in_function(caller, callsite.get("line")):
            reason = "callsite_outside_caller_span"
        elif not _text(callsite.get("expression")):
            reason = "callsite_expression_missing"
        elif not evidence:
            reason = "source_evidence_missing"
        elif expected_source_revision and not record_revision:
            reason = "source_revision_missing"
        elif expected_source_revision and record_revision != expected_source_revision:
            reason = "source_revision_mismatch"
        else:
            # A Clang binding must carry both a call-site quote and a target
            # declaration/definition quote.  The local checker verifies the
            # file and span against the function index; it does not claim to
            # replace Clang's type system.
            has_call_site = False
            has_target = False
            callee_short_name = _short_function_name(callee_id, callee)
            for item in evidence:
                kind = _text(item.get("kind"))
                item_file = _text(item.get("file"))
                text = _text(item.get("text"))
                start = _line(item.get("start_line", item.get("line", 1)))
                end = _line(item.get("end_line", start), start)
                if not text or end < start:
                    continue
                if kind == "call_site":
                    has_call_site = (
                        _path_equal(item_file, _file(caller))
                        and start <= _line(callsite.get("line")) <= end
                        and text in _text(caller.get("code"))
                        and _evidence_mentions_method(text, callee_short_name)
                    )
                elif kind in {"target", "declaration", "definition"}:
                    target_id = _text(item.get("function_id"))
                    has_target = (
                        _path_equal(item_file, _file(callee))
                        and start <= _span(callee)[1]
                        and end >= _span(callee)[0]
                        and (not target_id or target_id == callee_id)
                        and _evidence_mentions_method(text, callee_short_name)
                    )
                if has_call_site and has_target:
                    break
            if not has_call_site:
                reason = "call_site_evidence_not_verified"
            elif not has_target:
                reason = "target_evidence_not_verified"

        if reason:
            if expected_source_revision and not record_revision:
                summary["revision_unknown"] += 1
            _reject(summary, rejected, record, reason)
            continue

        if not expected_source_revision and not record_revision:
            summary["revision_unknown"] += 1

        graph.add_node({
            "schema_version": SCHEMA_VERSION,
            "id": f"function:{caller_id}",
            "kind": "function",
            "attributes": _function_attributes(caller_id, caller),
        })
        callee_attributes = _function_attributes(callee_id, callee)
        if not callee_has_body:
            callee_attributes["declaration_only"] = True
        graph.add_node({
            "schema_version": SCHEMA_VERSION,
            "id": f"function:{callee_id}",
            "kind": "function" if callee_has_body else "symbol",
            "attributes": callee_attributes,
        })
        # A hand-reconstructed command line is useful semantic evidence, but
        # it does not prove that the product configuration used the same
        # headers/macros.  Keep such edges in the candidate layer until a
        # matching compile database (or an explicitly complete build
        # context) is available.
        strict_build_statuses = {"compile_database", "complete", "verified"}
        dispatch_kind = _text(record.get("dispatch_kind")).lower() or "direct"
        candidate_completeness = (
            _text(record.get("candidate_completeness")).lower() or "complete"
        )
        dynamic_dispatch = dispatch_kind in {
            "virtual", "indirect", "callback", "dynamic"
        }
        reachability_tier = (
            "strict" if payload_build_status in strict_build_statuses else "candidate"
        )
        if dynamic_dispatch or candidate_completeness not in {
            "complete", "exhaustive", "closed_world"
        }:
            reachability_tier = "candidate"
        product_config_verified = payload_product_config_verified or _explicit_true(
            record.get("product_config_verified")
            or record.get("product_configuration_verified")
        )
        graph.add_edge({
            "schema_version": SCHEMA_VERSION,
            "source_id": f"function:{caller_id}",
            "target_id": f"function:{callee_id}",
            "kind": EDGE_KIND,
            "evidence": evidence,
            "confidence": 1.0,
            "resolver_version": RESOLVER_VERSION,
            "attributes": {
                "resolver": "clang",
                "binding_status": "resolved",
                "edge_kind": _text(record.get("edge_kind")),
                "dispatch_kind": dispatch_kind,
                "candidate_completeness": candidate_completeness,
                "dynamic_dispatch": dynamic_dispatch,
                "binding_evidence": dict(record.get("binding_evidence"))
                if isinstance(record.get("binding_evidence"), Mapping) else {},
                "call_site": dict(callsite),
                "source_revision": record_revision or None,
                "build_status": _text(record.get("build_status")) or payload_build_status,
                "evidence_quality": "semantic_binding_validated",
                "reachability_tier": reachability_tier,
                "build_admission": (
                    "product_config_verified"
                    if reachability_tier == "strict" and product_config_verified
                    else "concrete_configuration_verified"
                    if reachability_tier == "strict"
                    else "candidate_only_manual_or_unknown_context"
                ),
                "product_config_verified": product_config_verified,
                "validation_record": {
                    "id": (
                        "clang:"
                        + caller_id
                        + "->"
                        + callee_id
                        + ":"
                        + str(_line(callsite.get("line")))
                    ),
                    "status": "accepted",
                    "validator": "openharmony_clang_semantic_overlay",
                },
            },
        })
        summary["projected_edges"] += 1
        if not callee_has_body:
            summary["declaration_only_targets"] += 1

    # Preserve declaration-only symbols even when the current batch did not
    # produce an accepted edge for them.  This is especially important for a
    # Clang-discovered caller that is absent from the parser function index:
    # the symbol remains auditable and can be matched/loaded in a later batch,
    # but it is not converted into an analyzable dataset unit or an entry.
    for symbol_id, symbol in sorted(declaration_symbols.items()):
        node_id = f"function:{symbol_id}"
        if node_id in graph.nodes:
            continue
        attributes = dict(symbol)
        attributes.setdefault("declaration_only", True)
        attributes.setdefault("body_available", False)
        graph.add_node({
            "schema_version": SCHEMA_VERSION,
            "id": node_id,
            "kind": "symbol",
            "attributes": attributes,
        })

    result = graph.to_dict()
    result.update({
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "source_revision": payload_revision or None,
        "status": "complete" if summary["projected_edges"] or not summary["accepted_input"] else "partial",
        "summary": summary,
        "rejected": rejected,
    })
    return result


__all__ = ["EDGE_KIND", "SCHEMA_VERSION", "TASK", "load_clang_semantic_overlay"]
