"""可审计的调用图缺口汇总。

调用点台账中的一个站点可能产生很多候选目标。若直接统计
``candidate_facts``，候选数量会被误认为缺边数量。本模块以调用点为主键
聚合未决关系，并把候选记录数、目标数、绑定状态和缺口原因分开保存。

该报告是诊断产物，不会改变有效图、dataset 或可达性结果。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from utilities.file_io import read_json, write_json


# Version 2 adds explicit unique-site reason and source-file aggregation fields
# while retaining the legacy candidate-record counters.
SCHEMA_VERSION = 2
REPORT_FILENAME = "call_graph_gap_report.json"


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _load(path: str | Path) -> Mapping[str, Any] | None:
    try:
        payload = read_json(path)
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _stable_site_key(record: Mapping[str, Any]) -> str:
    """Prefer the producer's site id, with a deterministic fallback."""
    site_id = _text(record.get("site_id"))
    if site_id:
        return site_id
    evidence = record.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    attrs = record.get("attributes")
    attrs = attrs if isinstance(attrs, Mapping) else {}
    file_path = _text(evidence.get("file") or attrs.get("file"))
    line = _text(evidence.get("line_start") or attrs.get("line_start"))
    expression = _text(evidence.get("expression") or attrs.get("expression"))
    caller = _text(record.get("caller_id"))
    return "fallback:" + "|".join((caller, file_path, line, expression))


def _reason_codes(record: Mapping[str, Any]) -> set[str]:
    attrs = record.get("attributes")
    attrs = attrs if isinstance(attrs, Mapping) else {}
    reasons: set[str] = set()
    binding = _text(attrs.get("binding_status")).lower()
    graph = _text(attrs.get("graph_status")).lower()
    completeness = _text(attrs.get("candidate_completeness")).lower()
    parse_status = _text(attrs.get("parse_status")).lower()
    build_status = _text(attrs.get("build_status")).lower()
    repair_reason = _text(record.get("repair_reason"))
    if graph == "edge_missing":
        reasons.add("edge_missing")
    if binding in {"partial", "unresolved", "unknown", ""}:
        reasons.add("binding_incomplete")
    if completeness not in {"complete", "exhaustive", "closed_world"}:
        reasons.add("candidate_set_incomplete_or_unknown")
    if parse_status in {"syntax_error", "parse_failed", "incomplete", "unknown", ""}:
        reasons.add("parse_context_incomplete")
    if build_status in {"unknown", "", "incomplete", "manual", "manual_rebuild"}:
        reasons.add("build_context_unknown_or_non_product")
    if build_status in {"disabled", "not_enabled", "wrong_configuration"}:
        reasons.add("configuration_disabled")
    if repair_reason:
        reasons.add("repair_blocked:" + repair_reason)
    if not _text(record.get("callee_id")):
        reasons.add("no_candidate_target")
    return reasons or {"candidate_not_promoted"}


def _iter_ledger_sites(payload: Mapping[str, Any] | None) -> Iterable[Mapping[str, Any]]:
    if not isinstance(payload, Mapping):
        return []
    sites = payload.get("call_sites")
    if isinstance(sites, list):
        return (item for item in sites if isinstance(item, Mapping))
    nested = payload.get("residual")
    if isinstance(nested, Mapping) and isinstance(nested.get("call_sites"), list):
        return (item for item in nested["call_sites"] if isinstance(item, Mapping))
    return []


def _record_group(groups: dict[str, dict[str, Any]], record: Mapping[str, Any]) -> dict[str, Any]:
    key = _stable_site_key(record)
    group = groups.get(key)
    if group is None:
        evidence = record.get("evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        attrs = record.get("attributes")
        attrs = attrs if isinstance(attrs, Mapping) else {}
        group = {
            "site_key": key,
            "site_id": _text(record.get("site_id")) or None,
            "caller_id": _text(record.get("caller_id")) or None,
            "file": evidence.get("file") or attrs.get("file"),
            "line_start": evidence.get("line_start") or attrs.get("line_start"),
            "line_end": evidence.get("line_end") or attrs.get("line_end"),
            "expression": evidence.get("expression") or attrs.get("expression"),
            "candidate_targets": set(),
            "candidate_record_count": 0,
            "ledger_edge_missing": False,
            "ledger_unrepaired": False,
            "binding_statuses": set(),
            "graph_statuses": set(),
            "candidate_completeness": set(),
            "reason_codes": set(),
            "resolvers": set(),
            "source_kinds": set(),
        }
        groups[key] = group
    target = _text(record.get("callee_id"))
    if target:
        group["candidate_targets"].add(target)
    if _text(record.get("source_kind")) != "ledger_site":
        group["candidate_record_count"] += 1
    if _text(record.get("source_kind")) == "ledger_site":
        group["ledger_edge_missing"] = True
        group["ledger_unrepaired"] = bool(record.get("_ledger_unrepaired"))
    attrs = record.get("attributes")
    attrs = attrs if isinstance(attrs, Mapping) else {}
    for field, key_name in (
        ("binding_status", "binding_statuses"),
        ("graph_status", "graph_statuses"),
        ("candidate_completeness", "candidate_completeness"),
    ):
        value = _text(attrs.get(field))
        if value:
            group[key_name].add(value)
    resolver = _text(record.get("resolver"))
    source_kind = _text(record.get("source_kind"))
    if resolver:
        group["resolvers"].add(resolver)
    if source_kind:
        group["source_kinds"].add(source_kind)
    group["reason_codes"].update(_reason_codes(record))
    return group


def _freeze_group(group: dict[str, Any]) -> dict[str, Any]:
    result = dict(group)
    for key in (
        "candidate_targets",
        "binding_statuses",
        "graph_statuses",
        "candidate_completeness",
        "reason_codes",
        "resolvers",
        "source_kinds",
    ):
        result[key] = sorted(str(item) for item in group[key] if str(item))
    result["candidate_target_count"] = len(result["candidate_targets"])
    if result["candidate_target_count"]:
        result["reason_codes"] = [
            item for item in result["reason_codes"] if item != "no_candidate_target"
        ]
    result["candidate_only"] = bool(result["candidate_record_count"])
    return result


def _source_file_key(value: Any) -> str:
    """Return a stable display key for a call-site source file.

    Gap reports intentionally do not resolve paths against the checkout: the
    same report can be compared across machines and across graph directories.
    Normalising separators and leading ``./`` is enough for grouping while
    preserving the repository-relative path supplied by the parser.
    """
    text = _text(value).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def build_call_graph_gap_report(
    graph_paths: Iterable[str | Path],
    *,
    repository: str | None = None,
    source_revision: str | None = None,
    build_config_id: str | None = None,
) -> dict[str, Any]:
    """Aggregate unresolved sites across effective graph directories.

    Every ledger site is included when it is ``edge_missing``; candidate facts
    enrich the same group with possible targets. Thus a site with no candidates
    is still visible, and a site with 20 candidates is counted once.
    """
    groups: dict[str, dict[str, Any]] = {}
    reason_counts: Counter[str] = Counter()
    graph_summaries: list[dict[str, Any]] = []
    graph_count = 0
    ledger_site_count = 0
    ledger_edge_missing = 0
    candidate_fact_records = 0
    candidate_resolvers: Counter[str] = Counter()
    for raw_path in graph_paths:
        graph_path = Path(raw_path)
        graph = _load(graph_path)
        if graph is None:
            continue
        graph_count += 1
        summary = graph.get("summary") if isinstance(graph.get("summary"), Mapping) else {}
        graph_summaries.append({
            "path": str(graph_path),
            "graph_version": graph.get("graph_version") or (graph.get("provenance") or {}).get("graph_version"),
            "source_revision": (graph.get("provenance") or {}).get("source_revision", "unknown"),
            "build_config_id": (graph.get("provenance") or {}).get("build_config_id", "unknown"),
            "summary": dict(summary),
        })
        ledger = _load(graph_path.parent / "callsite_ledger.json")
        if ledger is None:
            ledger = _load(graph_path.parent / "call_graph_residuals.json")
        for site in _iter_ledger_sites(ledger):
            ledger_site_count += 1
            if _text(site.get("graph_status")).lower() != "edge_missing":
                continue
            ledger_edge_missing += 1
            caller_id = _text(site.get("caller_id"))
            effective_forward = graph.get("call_graph")
            effective_targets = set(
                effective_forward.get(caller_id, [])
                if isinstance(effective_forward, Mapping)
                and isinstance(effective_forward.get(caller_id, []), list)
                else []
            )
            candidate_ids = {
                _text(value)
                for value in site.get("candidate_target_ids", [])
                if _text(value)
            }
            record = {
                "site_id": site.get("site_id"),
                "caller_id": caller_id,
                "callee_id": None,
                "resolver": "callsite_ledger",
                "source_kind": "ledger_site",
                "evidence": {
                    "file": site.get("file"),
                    "line_start": site.get("line_start"),
                    "line_end": site.get("line_end"),
                    "expression": site.get("expression"),
                },
                "attributes": {
                    key: site.get(key)
                    for key in (
                        "binding_status", "graph_status", "candidate_completeness",
                        "parse_status", "build_status",
                    )
                },
                "_ledger_unrepaired": not bool(candidate_ids & effective_targets),
            }
            _record_group(groups, record)
        for record in graph.get("candidate_facts", []) if isinstance(graph.get("candidate_facts"), list) else []:
            if not isinstance(record, Mapping):
                continue
            candidate_fact_records += 1
            resolver = _text(record.get("resolver")) or "unknown"
            candidate_resolvers[resolver] += 1
            _record_group(groups, record)
    frozen_groups = [_freeze_group(groups[key]) for key in sorted(groups)]
    reason_site_counts: Counter[str] = Counter()
    unrepaired_reason_site_counts: Counter[str] = Counter()
    unrepaired_source_file_counts: Counter[str] = Counter()
    for group in frozen_groups:
        # ``reason_counts`` is retained for backwards compatibility, but the
        # new counters below are explicitly site-level: one call site can
        # emit many candidate records and must contribute at most once per
        # reason.  This is the number that should be used to prioritize work.
        reason_counts.update(group["reason_codes"])
        for reason in set(group["reason_codes"]):
            reason_site_counts[reason] += 1
            if group["ledger_unrepaired"]:
                unrepaired_reason_site_counts[reason] += 1
        if group["ledger_unrepaired"]:
            source_file = _source_file_key(group.get("file")) or "<unknown>"
            unrepaired_source_file_counts[source_file] += 1
    unique_gap_sites = sum(1 for group in frozen_groups if group["ledger_edge_missing"])
    unrepaired_gap_sites = sum(
        1 for group in frozen_groups if group["ledger_unrepaired"]
    )
    candidate_groups = sum(1 for group in frozen_groups if group["candidate_record_count"] > 0)
    no_candidate_groups = sum(1 for group in frozen_groups if group["candidate_target_count"] == 0)
    resolved_unrepaired = sum(
        int(item.get("summary", {}).get("resolved_edge_missing_unrepaired", 0) or 0)
        for item in graph_summaries
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "call_graph_gap_report",
        "repository": repository,
        "provenance": {
            "source_revision": source_revision or "unknown",
            "build_config_id": build_config_id or "unknown",
            "graph_count": graph_count,
            "graphs": graph_summaries,
        },
        "summary": {
            "ledger_call_sites": ledger_site_count,
            "ledger_edge_missing_sites": ledger_edge_missing,
            "unique_gap_sites": unique_gap_sites,
            "unrepaired_edge_missing_sites": unrepaired_gap_sites,
            "all_grouped_sites": len(frozen_groups),
            "candidate_callsite_groups": candidate_groups,
            "no_candidate_callsite_groups": no_candidate_groups,
            "candidate_fact_records": candidate_fact_records,
            "resolved_edge_missing_unrepaired": resolved_unrepaired,
            # Candidate-record counts remain useful for auditing model output,
            # while these counters represent unique source call sites.
            "reason_counts": dict(sorted(reason_counts.items())),
            "reason_site_counts": dict(sorted(reason_site_counts.items())),
            "unrepaired_reason_site_counts": dict(
                sorted(unrepaired_reason_site_counts.items())
            ),
            "unrepaired_source_file_counts": dict(
                sorted(unrepaired_source_file_counts.items())
            ),
            "candidate_resolver_counts": dict(sorted(candidate_resolvers.items())),
        },
        "sites": frozen_groups,
    }


def write_call_graph_gap_report(
    output_path: str | Path,
    graph_paths: Iterable[str | Path],
    *,
    repository: str | None = None,
    source_revision: str | None = None,
    build_config_id: str | None = None,
) -> dict[str, Any]:
    report = build_call_graph_gap_report(
        graph_paths,
        repository=repository,
        source_revision=source_revision,
        build_config_id=build_config_id,
    )
    write_json(output_path, report, indent=2)
    return report


__all__ = [
    "REPORT_FILENAME",
    "SCHEMA_VERSION",
    "build_call_graph_gap_report",
    "write_call_graph_gap_report",
]
