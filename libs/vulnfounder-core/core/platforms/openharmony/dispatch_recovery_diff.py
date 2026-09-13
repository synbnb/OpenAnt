"""Deterministic reports for OpenHarmony dispatch-edge recovery.

The OpenHarmony call-graph recovery stages are intentionally additive.  The
native C/C++ graph remains the baseline, while SemanticGraph edges are
projected into a temporary reachability overlay.  This module turns the two
views (and the diagnostic residuals that motivated the projection) into a
stable, JSON-serialisable report.  It never mutates its inputs and never calls
an LLM or a network service.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any

from .reachability import build_semantic_reachability_overlay


SCHEMA_VERSION = 1


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _nonempty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _line(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _normalise_id_set(value: Iterable[str] | None) -> set[str] | None:
    """Copy an optional iterable of function IDs into a validated set."""

    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        return None
    try:
        return {
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        }
    except TypeError:
        return None


def _native_edge_pairs(call_graph_result: Mapping[str, Any] | None) -> tuple[set[tuple[str, str]], int]:
    """Collect valid native edges from both graph directions.

    Some parser versions omit one direction or leave an empty adjacency list,
    so the report uses the union of ``call_graph`` and
    ``reverse_call_graph``.  Invalid entries are ignored and counted for
    diagnostics rather than causing a scan to fail.
    """

    graph = _mapping(call_graph_result)
    if graph is None:
        return set(), 0

    pairs: set[tuple[str, str]] = set()
    ignored = 0
    direct = graph.get("call_graph", {})
    if isinstance(direct, Mapping):
        for raw_source, raw_targets in direct.items():
            source = _nonempty_string(raw_source)
            if source is None or isinstance(raw_targets, (str, bytes)):
                ignored += 1
                continue
            try:
                targets = list(raw_targets)
            except TypeError:
                ignored += 1
                continue
            for raw_target in targets:
                target = _nonempty_string(raw_target)
                if target is None:
                    ignored += 1
                    continue
                pairs.add((source, target))
    elif direct is not None:
        ignored += 1

    reverse = graph.get("reverse_call_graph", {})
    if isinstance(reverse, Mapping):
        for raw_target, raw_callers in reverse.items():
            target = _nonempty_string(raw_target)
            if target is None or isinstance(raw_callers, (str, bytes)):
                ignored += 1
                continue
            try:
                callers = list(raw_callers)
            except TypeError:
                ignored += 1
                continue
            for raw_caller in callers:
                caller = _nonempty_string(raw_caller)
                if caller is None:
                    ignored += 1
                    continue
                pairs.add((caller, target))
    elif reverse is not None:
        ignored += 1
    return pairs, ignored


def _semantic_payload(semantic_graph: Any) -> Mapping[str, Any] | None:
    if isinstance(semantic_graph, Mapping):
        return semantic_graph
    to_dict = getattr(semantic_graph, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        return payload if isinstance(payload, Mapping) else None
    return None


def _semantic_edges(semantic_graph: Any) -> tuple[list[dict[str, Any]], int]:
    """Return valid semantic edges with their auditable evidence fields."""

    payload = _semantic_payload(semantic_graph)
    if payload is None:
        return [], 0
    raw_edges = payload.get("edges", [])
    if not isinstance(raw_edges, list):
        return [], 1

    records: list[dict[str, Any]] = []
    ignored = 0
    for raw_edge in raw_edges:
        edge = _mapping(raw_edge)
        if edge is None:
            ignored += 1
            continue
        source = _nonempty_string(edge.get("source_id"))
        target = _nonempty_string(edge.get("target_id"))
        kind = _nonempty_string(edge.get("kind"))
        if source is None or target is None or kind is None:
            ignored += 1
            continue
        record: dict[str, Any] = {
            "source_id": source,
            "target_id": target,
            "kind": kind,
        }
        # Preserve optional provenance without imposing a schema on older
        # semantic graph producers.
        for key in ("confidence", "resolver_version", "attributes", "evidence"):
            if key in edge:
                record[key] = copy.deepcopy(edge[key])
        records.append(record)
    records.sort(
        key=lambda item: (
            item["source_id"],
            item["target_id"],
            item["kind"],
            repr(item.get("evidence", [])),
        )
    )
    return records, ignored


def _candidate_ids(site: Mapping[str, Any]) -> list[str]:
    values = site.get("candidate_target_ids")
    if not isinstance(values, list):
        candidates = site.get("candidates")
        values = (
            [item.get("target_id") for item in candidates if isinstance(item, Mapping)]
            if isinstance(candidates, list)
            else []
        )
    return sorted({item.strip() for item in values if isinstance(item, str) and item.strip()})


def _residual_site(site: Any, dispatch_kind: str) -> dict[str, Any] | None:
    item = _mapping(site)
    if item is None:
        return None
    caller = _nonempty_string(item.get("caller_id"))
    file_path = _nonempty_string(item.get("file"))
    line = _line(item.get("line"))
    expression = _nonempty_string(item.get("expression"))
    reason = _nonempty_string(item.get("reason"))
    # A partial diagnostic is not a useful residual record.  Ignore it rather
    # than inventing a source location or a reason in the report.
    if None in (caller, file_path, line, expression, reason):
        return None
    candidates = _candidate_ids(item)
    result: dict[str, Any] = {
        "dispatch_kind": dispatch_kind,
        "caller_id": caller,
        "file": file_path,
        "line": line,
        "expression": expression,
        "reason": reason,
        "candidate_target_ids": candidates,
        "candidate_count": len(candidates),
    }
    if "symbols" in item:
        result["symbols"] = copy.deepcopy(item["symbols"])
    if "field_identity" in item:
        result["field_identity"] = copy.deepcopy(item["field_identity"])
    return result


def _residual_sites(diagnostics: Any) -> tuple[list[dict[str, Any]], int]:
    payload = _mapping(diagnostics)
    if payload is None:
        return [], 0
    records: list[dict[str, Any]] = []
    ignored = 0
    ordinary = payload.get("unresolved_call_sites", [])
    if isinstance(ordinary, list):
        for site in ordinary:
            record = _residual_site(site, "native")
            if record is None:
                ignored += 1
            else:
                records.append(record)
    elif ordinary is not None:
        ignored += 1

    lambda_payload = _mapping(payload.get("lambda_dispatch"))
    if lambda_payload is not None:
        lambda_sites = lambda_payload.get("call_sites", [])
        if isinstance(lambda_sites, list):
            for site in lambda_sites:
                record = _residual_site(site, "lambda")
                if record is None:
                    ignored += 1
                else:
                    records.append(record)
        elif lambda_sites is not None:
            ignored += 1
    records.sort(
        key=lambda item: (
            item["file"],
            item["line"],
            item["dispatch_kind"],
            item["caller_id"],
        )
    )
    return records, ignored


def _orphan(item: Any, dispatch_kind: str) -> dict[str, Any] | None:
    payload = _mapping(item)
    if payload is None:
        return None
    owner = _nonempty_string(payload.get("owner_function_id"))
    file_path = _nonempty_string(payload.get("file"))
    line = _line(payload.get("line"))
    target_name = _nonempty_string(payload.get("target_name"))
    reason = _nonempty_string(payload.get("reason"))
    if None in (owner, file_path, line, target_name, reason):
        return None
    result: dict[str, Any] = {
        "dispatch_kind": dispatch_kind,
        "owner_function_id": owner,
        "file": file_path,
        "line": line,
        "target_name": target_name,
        "reason": reason,
    }
    if "evidence" in payload:
        result["evidence"] = copy.deepcopy(payload["evidence"])
    return result


def _orphans(diagnostics: Any) -> tuple[list[dict[str, Any]], int]:
    payload = _mapping(diagnostics)
    if payload is None:
        return [], 0
    records: list[dict[str, Any]] = []
    ignored = 0
    ordinary = payload.get("orphans", [])
    if isinstance(ordinary, list):
        for item in ordinary:
            record = _orphan(item, "native")
            if record is None:
                ignored += 1
            else:
                records.append(record)
    elif ordinary is not None:
        ignored += 1

    lambda_payload = _mapping(payload.get("lambda_dispatch"))
    if lambda_payload is not None:
        lambda_orphans = lambda_payload.get("orphans", [])
        if isinstance(lambda_orphans, list):
            for item in lambda_orphans:
                record = _orphan(item, "lambda")
                if record is None:
                    ignored += 1
                else:
                    records.append(record)
        elif lambda_orphans is not None:
            ignored += 1
    records.sort(
        key=lambda item: (
            item["file"],
            item["line"],
            item["dispatch_kind"],
            item["owner_function_id"],
            item["target_name"],
        )
    )
    return records, ignored


def _reachability_report(
    baseline_reachable: Iterable[str] | None,
    recovered_reachable: Iterable[str] | None,
) -> dict[str, Any]:
    baseline = _normalise_id_set(baseline_reachable)
    recovered = _normalise_id_set(recovered_reachable)
    if baseline is None or recovered is None:
        return {
            "status": "not_evaluated",
            "baseline_count": None,
            "recovered_count": None,
            "added_function_ids": [],
            "removed_function_ids": [],
            "missing_from_recovered": [],
        }
    removed = sorted(baseline - recovered)
    return {
        "status": "violation" if removed else "preserved",
        "baseline_count": len(baseline),
        "recovered_count": len(recovered),
        "added_function_ids": sorted(recovered - baseline),
        "removed_function_ids": removed,
        "missing_from_recovered": removed.copy(),
    }


def build_dispatch_recovery_diff(
    call_graph_result: Mapping[str, Any] | None,
    diagnostics: Mapping[str, Any] | None,
    semantic_graph: Mapping[str, Any] | Any | None,
    *,
    baseline_reachable: Iterable[str] | None = None,
    recovered_reachable: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a stable, additive dispatch-recovery report.

    ``baseline_reachable`` and ``recovered_reachable`` are optional so the
    function can be used immediately after graph construction and again after
    the reachability filter.  When both are provided, ``baseline`` must be a
    subset of ``recovered``; a violation is reported explicitly and does not
    get hidden by a defensive union in a caller.
    """

    native_pairs, ignored_native = _native_edge_pairs(call_graph_result)
    native_edges = [
        {"source_id": source, "target_id": target}
        for source, target in sorted(native_pairs)
    ]

    semantic_records, ignored_semantic = _semantic_edges(semantic_graph)
    semantic_payload = _semantic_payload(semantic_graph)
    functions = _mapping(call_graph_result).get("functions", {}) if _mapping(call_graph_result) else {}
    known_function_ids = (
        {item for item in functions if isinstance(item, str) and item.strip()}
        if isinstance(functions, Mapping)
        else set()
    )
    projected_raw: Mapping[str, Any] | None = None
    ignored_overlay = 0
    if semantic_payload is not None:
        try:
            projected_raw = build_semantic_reachability_overlay(
                semantic_payload,
                known_function_ids,
            )
        except (TypeError, ValueError, AttributeError):
            ignored_overlay = 1
    projected_edges: list[dict[str, Any]] = []
    for raw_edge in (projected_raw or {}).get("edges", []) or []:
        edge = _mapping(raw_edge)
        if edge is None:
            ignored_overlay += 1
            continue
        source = _nonempty_string(edge.get("source_id"))
        target = _nonempty_string(edge.get("target_id"))
        edge_kinds = edge.get("edge_kinds")
        if source is None or target is None or not isinstance(edge_kinds, list):
            ignored_overlay += 1
            continue
        kinds = sorted({item for item in edge_kinds if isinstance(item, str) and item.strip()})
        if not kinds:
            ignored_overlay += 1
            continue
        projected_edges.append(
            {
                "source_id": source,
                "target_id": target,
                "edge_kinds": kinds,
                "is_new": (source, target) not in native_pairs,
            }
        )
    projected_edges.sort(
        key=lambda item: (item["source_id"], item["target_id"], item["edge_kinds"])
    )
    added_edges = [
        {
            "source_id": item["source_id"],
            "target_id": item["target_id"],
            "edge_kinds": item["edge_kinds"],
        }
        for item in projected_edges
        if item["is_new"]
    ]
    retained_edges = [
        {
            "source_id": item["source_id"],
            "target_id": item["target_id"],
            "edge_kinds": item["edge_kinds"],
        }
        for item in projected_edges
        if not item["is_new"]
    ]

    residual_sites, ignored_sites = _residual_sites(diagnostics)
    orphan_records, ignored_orphans = _orphans(diagnostics)
    candidate_pairs = {
        (site["caller_id"], target_id)
        for site in residual_sites
        for target_id in site["candidate_target_ids"]
    }
    reachability = _reachability_report(
        baseline_reachable,
        recovered_reachable,
    )
    ignored_records = {
        "native_edges": ignored_native,
        "semantic_edges": ignored_semantic,
        "projected_edges": ignored_overlay,
        "residual_sites": ignored_sites,
        "orphans": ignored_orphans,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "platform": "openharmony",
        "status": "complete",
        "native_edges": native_edges,
        "semantic_edges": semantic_records,
        "projected_edges": projected_edges,
        "added_edges": added_edges,
        "retained_edges": retained_edges,
        "residual_sites": residual_sites,
        "orphans": orphan_records,
        "reachability": reachability,
        "summary": {
            "native_edge_count": len(native_edges),
            "projected_edge_count": len(projected_edges),
            "new_edge_count": len(added_edges),
            "retained_edge_count": len(retained_edges),
            "residual_site_count": len(residual_sites),
            "residual_sites_with_candidates": sum(
                site["candidate_count"] > 0 for site in residual_sites
            ),
            "residual_sites_without_candidates": sum(
                site["candidate_count"] == 0 for site in residual_sites
            ),
            "candidate_edge_count": len(candidate_pairs),
            "orphan_count": len(orphan_records),
            "semantic_edge_count": len(semantic_records),
        },
        "ignored_records": ignored_records,
    }


__all__ = ["SCHEMA_VERSION", "build_dispatch_recovery_diff"]
