"""统一的调用关系事实库与有效调用图生成器。

本模块把解析器原生调用图、调用点台账以及已经通过校验的语义 overlay
汇总为一个可审计的 ``effective_call_graph.json``。原生
``call_graph.json`` 永远只读保留；有效图是可重复生成的派生产物。

这里有意把“关系存在”和“关系可以参与严格可达性”分开：

* native 和已核验的 resolved call-site 是 confirmed facts；
* partial/unresolved、候选集合完整性未知的关系只进入 candidate_facts；
* 端点不存在、证据不完整或格式不受支持的关系进入 exclusions。

这样，后续 BFS 不再需要猜测某个阶段的临时产物是否已经覆盖原生图，
同时可以定位“台账已经 resolved，但有效图没有边”的第一个断点。
"""

from __future__ import annotations

import os
import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from utilities.file_io import read_json, write_json


SCHEMA_VERSION = 1
EFFECTIVE_FILENAME = "effective_call_graph.json"

_COMPLETE_CANDIDATE_VALUES = {"complete", "exhaustive", "closed_world"}
_STRICT_VALIDATION_STATUSES = {"accepted", "verified", "validated", "complete"}
_STRICT_EVIDENCE_QUALITIES = {
    "relation_supported",
    "type_supported",
    "semantic_binding_validated",
}


def _string(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else []


def _normalize_endpoint(value: Any) -> str:
    endpoint = _string(value)
    if endpoint.startswith("function:"):
        endpoint = endpoint[len("function:") :]
    return endpoint


def _native_adjacency(native_graph: Mapping[str, Any]) -> dict[str, list[str]]:
    raw = native_graph.get("call_graph", {})
    if not isinstance(raw, Mapping):
        return {}
    adjacency: dict[str, list[str]] = {}
    for caller, targets in raw.items():
        caller_id = _normalize_endpoint(caller)
        if not caller_id:
            continue
        values = sorted(
            {
                _normalize_endpoint(target)
                for target in _as_list(targets)
                if _normalize_endpoint(target)
            }
        )
        adjacency[caller_id] = values
    return adjacency


def _reverse(adjacency: Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
    reverse: dict[str, set[str]] = {}
    for caller, targets in adjacency.items():
        for target in targets:
            reverse.setdefault(str(target), set()).add(str(caller))
    return {target: sorted(callers) for target, callers in sorted(reverse.items())}


def _function_ids(native_graph: Mapping[str, Any], adjacency: Mapping[str, list[str]]) -> set[str]:
    functions = native_graph.get("functions", {})
    ids = {
        _normalize_endpoint(function_id)
        for function_id in functions
        if _normalize_endpoint(function_id)
    } if isinstance(functions, Mapping) else set()
    # A graph may contain an external/library node without a function body. It
    # remains visible in the graph, but cannot be used for a dataset unit.
    ids.update(adjacency)
    for targets in adjacency.values():
        ids.update(targets)
    return ids


def _known_function_body_ids(native_graph: Mapping[str, Any]) -> set[str]:
    functions = native_graph.get("functions", {})
    if not isinstance(functions, Mapping):
        return set()
    return {
        _normalize_endpoint(function_id)
        for function_id in functions
        if _normalize_endpoint(function_id)
    }


def _load_optional(path: Path) -> Mapping[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = read_json(path)
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _canonical_fingerprint(value: Any) -> str:
    """Return a stable content fingerprint for graph provenance.

    The graph version is deliberately derived from the actual inputs rather
    than from wall-clock time.  This lets a resumed scan prove whether its
    effective graph was built from the same native graph, ledger and overlays.
    """
    def canonical(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {
                str(key): canonical(item[key])
                for key in sorted(item, key=lambda key: str(key))
            }
        if isinstance(item, (list, tuple, set)):
            # Parser workers may emit equivalent adjacency/candidate lists in
            # different orders.  Graph provenance must not change merely due
            # to that ordering; list values are therefore normalized by their
            # canonical JSON representation for hashing only.
            normalized = [canonical(child) for child in item]
            return sorted(
                normalized,
                key=lambda child: json.dumps(
                    child, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
            )
        return item

    try:
        encoded = json.dumps(
            canonical(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(value).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_completeness(value: Any) -> str:
    value = _string(value).lower()
    return "complete" if value in _COMPLETE_CANDIDATE_VALUES else "unknown"


def _binding_evidence_is_sufficient(site: Mapping[str, Any]) -> bool:
    """Check that a deterministic ledger binding has an auditable basis.

    ``resolved`` and a single candidate are necessary but intentionally not
    sufficient: a bounded parser shortlist can contain one item while an
    unindexed overload or implementation still exists.  A site is strict
    only when the producer declared a complete set and recorded its binding
    rule/evidence (for example qualified-name+arity, or a trusted Clang
    resolver).  Older ledgers remain visible as candidates rather than being
    silently promoted.
    """
    if not isinstance(site, Mapping):
        return False
    if _candidate_completeness(
        site.get("candidate_completeness") or site.get("candidate_set_completeness")
    ) != "complete":
        return False
    basis = _string(site.get("binding_basis") or site.get("binding_rule"))
    evidence = site.get("binding_evidence")
    if not basis or not isinstance(evidence, Mapping):
        return False
    rule = _string(evidence.get("binding_rule") or basis)
    if rule != basis:
        return False
    if basis == "qualified_name_and_arity":
        return bool(
            evidence.get("signature_match") is True
            and _string(evidence.get("target_id"))
            and _string(evidence.get("qualified_callee"))
        )
    # Future deterministic resolvers may provide their own complete rule, but
    # they must explicitly say which declaration/type facts were checked.
    return bool(
        evidence.get("declaration_verified") is True
        and evidence.get("type_verified") is True
    )


def _validation_record_is_trusted(
    edge: Mapping[str, Any], attrs: Mapping[str, Any]
) -> tuple[bool, str]:
    """Return whether an overlay carries a real validation decision.

    A model- or hand-authored ``validated=true`` flag is only an assertion.
    Strict projection requires a non-empty validation record, an accepted
    status, a recognized evidence quality, and at least one source evidence
    item.  Clang gets the same treatment; its loader emits the record when
    source spans and binding checks pass.
    """
    evidence_quality = _string(attrs.get("evidence_quality")).lower()
    if evidence_quality not in _STRICT_EVIDENCE_QUALITIES:
        return False, "evidence_quality_not_trusted"
    evidence = edge.get("evidence")
    if not isinstance(evidence, (Mapping, list)) or not evidence:
        return False, "source_evidence_missing"
    record = attrs.get("validation_record")
    record_id = _string(
        attrs.get("validation_record_id")
        or (record.get("id") if isinstance(record, Mapping) else "")
    )
    status = _string(
        attrs.get("validation_status")
        or (record.get("status") if isinstance(record, Mapping) else "")
    ).lower()
    validator = _string(
        attrs.get("validated_by")
        or (record.get("validator") if isinstance(record, Mapping) else "")
    )
    if not record_id or status not in _STRICT_VALIDATION_STATUSES or not validator:
        return False, "validation_record_missing_or_untrusted"
    return True, ""


def _build_status_allows_strict(attrs: Mapping[str, Any]) -> tuple[bool, str]:
    """Keep incomplete/manual build facts out of product strict paths.

    ``compile_database`` means Clang successfully replayed a concrete
    configuration; it is strict for that analysis configuration while still
    carrying no claim that every product configuration matches it.  Explicit
    ``unknown``/manual states remain candidate facts.
    """
    status = _string(attrs.get("build_status") or attrs.get("build_context_status")).lower()
    if status in {
        "unknown", "", "incomplete", "manual", "manual_rebuild",
        "reconstructed_candidate", "candidate", "candidate_only",
    }:
        return False, "build_context_incomplete_or_manual"
    if status in {"disabled", "not_enabled", "wrong_configuration"}:
        return False, "build_configuration_disabled"
    return True, ""


def _ledger_sites(ledger: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if not isinstance(ledger, Mapping):
        return []
    sites = ledger.get("call_sites")
    if isinstance(sites, list):
        return [site for site in sites if isinstance(site, Mapping)]
    nested = ledger.get("residual")
    if isinstance(nested, Mapping) and isinstance(nested.get("call_sites"), list):
        return [site for site in nested["call_sites"] if isinstance(site, Mapping)]
    return []


def _ledger_evidence_index(
    ledger: Mapping[str, Any] | None,
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Index source callsites by the caller/target pair they support.

    The native parser graph is retained as a confirmed structural fact, but
    its compact adjacency normally does not carry the call expression.  When
    the callsite ledger has a matching target, attach that source span to the
    native edge as audit evidence.  This is deliberately evidence enrichment:
    it never upgrades a partial/ambiguous ledger binding and never creates a
    graph edge by itself.
    """
    indexed: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for site in _ledger_sites(ledger):
        caller = _normalize_endpoint(site.get("caller_id"))
        if not caller:
            continue
        linked = {
            _normalize_endpoint(value)
            for value in _as_list(site.get("linked_target_ids"))
            if _normalize_endpoint(value)
        }
        candidates = {
            _normalize_endpoint(value)
            for value in _as_list(site.get("candidate_target_ids"))
            if _normalize_endpoint(value)
        }
        # ``graph_target_ids_for_caller`` is an aggregate reverse index, not
        # a target list for this individual callsite.  Using it here would
        # attach one expression (often a logging macro) to every edge emitted
        # by the caller.  Only per-site linked/candidate targets are eligible
        # for source-span association.
        targets = linked
        # A resolved, single-target record is also useful when an older
        # ledger omitted ``linked_target_ids`` but kept its candidate list.
        if (
            not targets
            and _string(site.get("binding_status")).lower() == "resolved"
            and len(candidates) == 1
        ):
            targets = candidates
        if not targets:
            continue
        evidence = {
            "kind": "callsite_ledger",
            "site_id": site.get("site_id"),
            "file": site.get("file"),
            "line_start": site.get("line_start"),
            "line_end": site.get("line_end"),
            "byte_start": site.get("byte_start"),
            "byte_end": site.get("byte_end"),
            "expression": site.get("expression"),
            "callee_spelling": site.get("callee_spelling"),
            "binding_status": site.get("binding_status"),
            "graph_status": site.get("graph_status"),
            "candidate_completeness": site.get("candidate_completeness"),
            "binding_basis": site.get("binding_basis"),
        }
        # Do not emit empty evidence records.  A site without a source span is
        # still useful for diagnostics but cannot support edge auditability.
        if not evidence.get("file") or evidence.get("line_start") is None:
            continue
        for target in sorted(targets):
            indexed.setdefault((caller, target), []).append(evidence)
    for key, values in indexed.items():
        # Stable, bounded output keeps effective graphs manageable while
        # preserving all distinct source locations encountered first.
        seen: set[tuple[Any, ...]] = set()
        bounded: list[dict[str, Any]] = []
        for value in values:
            marker = (
                value.get("site_id"), value.get("file"),
                value.get("line_start"), value.get("line_end"),
            )
            if marker in seen:
                continue
            seen.add(marker)
            bounded.append(value)
            if len(bounded) >= 8:
                break
        indexed[key] = bounded
    return indexed


def _native_source_evidence(
    native_graph: Mapping[str, Any], caller: str, target: str
) -> list[dict[str, Any]]:
    """Find a bounded source excerpt for a native edge without inventing one.

    Most direct native edges are enriched from the callsite ledger.  Parser
    generated callback/lambda and member-through-field edges may not have a
    linked ledger target, although the caller body still contains an obvious
    invocation or callback submission.  This helper records that lexical
    source as *structural* evidence only; it does not change binding status or
    promote a candidate edge.
    """
    functions = native_graph.get("functions", {})
    if not isinstance(functions, Mapping):
        return []
    raw = functions.get(caller)
    if not isinstance(raw, Mapping) or not isinstance(raw.get("code"), str):
        return []
    code = raw["code"]
    try:
        start_line = int(raw.get("start_line", 1))
    except (TypeError, ValueError):
        start_line = 1
    target_name = _string(
        functions.get(target, {}).get("name")
        if isinstance(functions.get(target), Mapping)
        else target.rsplit(":", 1)[-1]
    )
    short_name = target_name.rsplit("::", 1)[-1]
    lines = code.splitlines()
    matches: list[tuple[int, str, str]] = []
    # A synthetic lambda node represents a callback body registered from its
    # lexical owner.  The registration call is the best source evidence for
    # the function-level edge when no direct call expression exists.
    target_symbol = target.split(":", 1)[1] if ":" in target else target
    synthetic = "." in target_symbol
    for offset, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if not synthetic:
            # Match a call to the exact unqualified method, not a prefix such
            # as Start() inside StartHapCollecting().
            import re

            if short_name and re.search(rf"\b{re.escape(short_name)}\s*\(", stripped):
                matches.append((start_line + offset, stripped, "native_call_expression"))
        elif any(token in stripped for token in (
            "std::thread", "submit(", "submit (", "post(", "post (",
            "dispatch", "schedule", "async", "task_attr",
        )):
            matches.append((start_line + offset, stripped, "callback_registration"))
    if not matches:
        return []
    line_number, text, kind = matches[0]
    return [{
        "kind": kind,
        "file": raw.get("file_path") or raw.get("filePath"),
        "line_start": line_number,
        "line_end": line_number,
        "relation": "native_call_graph_source_excerpt",
        "status": "confirmed_structural",
        "excerpt": text[:600],
    }]


def _overlay_payloads(payload: Any) -> Iterable[Mapping[str, Any]]:
    """Yield graph payloads from both direct and report-wrapped artifacts."""
    if isinstance(payload, Mapping):
        if (
            isinstance(payload.get("edges"), list)
            or isinstance(payload.get("nodes"), list)
            or isinstance(payload.get("symbols"), (Mapping, list))
            or isinstance(payload.get("external_nodes"), (Mapping, list))
        ):
            yield payload
        for key in ("overlay", "semantic_graph", "projection", "report"):
            child = payload.get(key)
            if isinstance(child, Mapping):
                yield from _overlay_payloads(child)
        reports = payload.get("reports")
        if isinstance(reports, list):
            for report in reports:
                yield from _overlay_payloads(report)
    elif isinstance(payload, list):
        for item in payload:
            yield from _overlay_payloads(item)


def _overlay_edges(payload: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    for edge in payload.get("edges", []) if isinstance(payload.get("edges"), list) else []:
        if isinstance(edge, Mapping):
            yield edge


def _overlay_nodes(payload: Mapping[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    """Return symbol nodes declared by a semantic overlay.

    A node may have a declaration but no body in the current dataset.  Such a
    node is useful for cross-TU and external-library edges, so it is kept in
    the effective graph's symbol index even though it is not a dataset unit.
    """
    raw_nodes = payload.get("nodes")
    if isinstance(raw_nodes, list):
        for item in raw_nodes:
            if not isinstance(item, Mapping):
                continue
            node_id = _normalize_endpoint(
                item.get("id") or item.get("source_id") or item.get("function_id")
            )
            if node_id:
                attrs = item.get("attributes") if isinstance(item.get("attributes"), Mapping) else {}
                yield node_id, dict(attrs)
    for field in ("symbols", "external_nodes"):
        raw = payload.get(field)
        if isinstance(raw, Mapping):
            for raw_id, raw_attrs in raw.items():
                node_id = _normalize_endpoint(raw_id)
                if not node_id:
                    continue
                attrs = raw_attrs if isinstance(raw_attrs, Mapping) else {}
                yield node_id, dict(attrs)
        elif isinstance(raw, list):
            for item in raw:
                if not isinstance(item, Mapping):
                    continue
                node_id = _normalize_endpoint(
                    item.get("id") or item.get("source_id") or item.get("function_id")
                )
                if node_id:
                    attrs = item.get("attributes") if isinstance(item.get("attributes"), Mapping) else {}
                    yield node_id, dict(attrs)


def _edge_record(
    source: str,
    target: str,
    *,
    resolver: str,
    status: str,
    source_kind: str,
    evidence: Any = None,
    site_id: str = "",
    attributes: Mapping[str, Any] | None = None,
    repair_reason: str = "",
) -> dict[str, Any]:
    if isinstance(evidence, Mapping):
        evidence_value: Any = dict(evidence)
    elif isinstance(evidence, list):
        evidence_value = [dict(item) if isinstance(item, Mapping) else item for item in evidence]
    else:
        evidence_value = {}
    return {
        "caller_id": source,
        "callee_id": target,
        "resolver": resolver,
        "status": status,
        "source_kind": source_kind,
        "site_id": site_id or None,
        "evidence": evidence_value,
        "attributes": dict(attributes or {}),
        "repair_reason": repair_reason or None,
    }


def build_effective_call_graph(
    native_graph: Mapping[str, Any],
    *,
    ledger: Mapping[str, Any] | None = None,
    semantic_overlays: Iterable[Mapping[str, Any]] = (),
    source_revision: str | None = None,
    build_config_id: str | None = None,
    input_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Build an effective graph without mutating the native graph payload."""
    semantic_overlays = list(semantic_overlays)
    if input_fingerprint is None:
        input_fingerprint = _canonical_fingerprint(
            {
                "native_graph": native_graph,
                "ledger": ledger,
                "semantic_overlays": semantic_overlays,
                "source_revision": source_revision or "unknown",
                "build_config_id": build_config_id or "unknown",
            }
        )
    graph_version = _canonical_fingerprint(
        {
            "schema_version": SCHEMA_VERSION,
            "input_fingerprint": input_fingerprint,
            "source_revision": source_revision or "unknown",
            "build_config_id": build_config_id or "unknown",
        }
    )
    native_forward = _native_adjacency(native_graph)
    node_ids = _function_ids(native_graph, native_forward)
    body_ids = _known_function_body_ids(native_graph)
    # Semantic overlays may carry declaration-only or external symbols that
    # the parser's dataset did not materialize as function bodies.  Keep them
    # as graph nodes, but do not treat them as analyzable dataset units.
    external_nodes: dict[str, dict[str, Any]] = {}
    overlay_payloads: list[Mapping[str, Any]] = []
    for payload in semantic_overlays:
        for graph_payload in _overlay_payloads(payload):
            overlay_payloads.append(graph_payload)
            for node_id, attrs in _overlay_nodes(graph_payload):
                if node_id in body_ids:
                    continue
                existing = external_nodes.get(node_id, {})
                external_nodes[node_id] = {**existing, **attrs}
    node_ids.update(external_nodes)
    effective: dict[str, set[str]] = {
        caller: set(targets) for caller, targets in native_forward.items()
    }
    edge_facts: list[dict[str, Any]] = []
    candidate_facts: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    fact_keys: set[tuple[str, str, str, str]] = set()
    candidate_keys: set[tuple[str, str, str, str]] = set()
    expected_revision = _string(source_revision) or "unknown"
    ledger_revision = _string((ledger or {}).get("revision"))
    ledger_revision_mismatch = bool(
        expected_revision != "unknown"
        and ledger_revision
        and ledger_revision != expected_revision
    )
    ledger_evidence = _ledger_evidence_index(ledger)

    def add_exclusion(reason: str, record: Mapping[str, Any] | None = None, **extra: Any) -> None:
        item = {"reason": reason}
        if isinstance(record, Mapping):
            for key in ("site_id", "caller_id", "callee_id", "expression", "resolver"):
                if record.get(key) not in (None, ""):
                    item[key] = record[key]
        item.update(extra)
        exclusions.append(item)

    def add_confirmed(
        source: str,
        target: str,
        *,
        resolver: str,
        source_kind: str,
        evidence: Mapping[str, Any] | None = None,
        site_id: str = "",
        attributes: Mapping[str, Any] | None = None,
        repair_reason: str = "",
        allow_external_nodes: bool = False,
    ) -> bool:
        source = _normalize_endpoint(source)
        target = _normalize_endpoint(target)
        if not source or not target:
            add_exclusion("empty_endpoint", {"site_id": site_id})
            return False
        source_known = source in body_ids or (allow_external_nodes and source in external_nodes)
        target_known = target in body_ids or (allow_external_nodes and target in external_nodes)
        if not source_known or not target_known:
            add_exclusion(
                "endpoint_not_in_function_index",
                {
                    "site_id": site_id,
                    "caller_id": source,
                    "callee_id": target,
                },
                caller_in_function_index=source in body_ids,
                callee_in_function_index=target in body_ids,
                endpoint_in_symbol_index=(source in node_ids and target in node_ids),
                external_nodes_allowed=allow_external_nodes,
            )
            return False
        key = (source, target, resolver, site_id)
        if key not in fact_keys:
            edge_facts.append(
                _edge_record(
                    source,
                    target,
                    resolver=resolver,
                    status="confirmed",
                    source_kind=source_kind,
                    evidence=evidence,
                    site_id=site_id,
                    attributes=attributes,
                    repair_reason=repair_reason,
                )
            )
            fact_keys.add(key)
        effective.setdefault(source, set()).add(target)
        return True

    # Native edges are confirmed parser facts and are retained as-is for all
    # graph consumers. The functions index remains the authoritative body set.
    # When possible, enrich each edge with the matching source callsite from
    # the ledger so an effective-graph reviewer can audit the exact expression
    # instead of relying only on a compact adjacency pair.
    for caller, targets in native_forward.items():
        for target in targets:
            if caller in body_ids and target in body_ids:
                source_evidence = ledger_evidence.get((caller, target), [])
                if not source_evidence:
                    source_evidence = _native_source_evidence(native_graph, caller, target)
                first_site = source_evidence[0] if source_evidence else {}
                add_confirmed(
                    caller,
                    target,
                    resolver="native",
                    source_kind="native_call_graph",
                    evidence=source_evidence,
                    site_id=_string(first_site.get("site_id")),
                    attributes={
                        "evidence_level": "native_parser_graph",
                        "source_revision": source_revision or "unknown",
                        "build_config_id": build_config_id or "unknown",
                        "ledger_callsite_count": len(source_evidence),
                    },
                )
            else:
                add_exclusion(
                    "native_endpoint_not_in_function_index",
                    {"caller_id": caller, "callee_id": target},
                )

    resolved_sites = 0
    edge_missing_sites = 0
    repaired_sites = 0
    unrepaired_sites = 0
    for site in _ledger_sites(ledger):
        binding_status = _string(site.get("binding_status")).lower()
        graph_status = _string(site.get("graph_status")).lower()
        parse_status = _string(site.get("parse_status")).lower()
        build_status = _string(site.get("build_status")).lower()
        binding_eligible = (
            binding_status == "resolved"
            and parse_status not in {"syntax_error", "parse_failed", "incomplete"}
            and build_status not in {"disabled", "not_enabled", "wrong_configuration"}
            and _binding_evidence_is_sufficient(site)
            and not ledger_revision_mismatch
        )
        caller = _normalize_endpoint(site.get("caller_id"))
        site_id = _string(site.get("site_id"))
        linked = [
            _normalize_endpoint(value)
            for value in _as_list(site.get("linked_target_ids"))
            if _normalize_endpoint(value)
        ]
        candidates = [
            _normalize_endpoint(value)
            for value in _as_list(site.get("candidate_target_ids"))
            if _normalize_endpoint(value)
        ]
        candidates = sorted(set(candidates))
        linked = sorted(set(linked))
        if binding_status == "resolved":
            resolved_sites += 1
        if graph_status == "edge_missing":
            edge_missing_sites += 1

        targets: list[str] = []
        repair_reason = ""
        if linked and binding_eligible and len(candidates) == 1 and len(linked) == 1:
            targets = linked
        elif binding_eligible and len(candidates) == 1:
            # This is the key deterministic repair: the parser/ledger already
            # established one target, while graph serialization lost the edge.
            targets = candidates
            repair_reason = "resolved_callsite_edge_missing"
        elif binding_eligible and len(candidates) > 1:
            for target in candidates:
                if caller not in body_ids or target not in body_ids:
                    add_exclusion(
                        "callsite_candidate_endpoint_not_in_function_index",
                        {
                            "site_id": site_id,
                            "caller_id": caller,
                            "callee_id": target,
                        },
                    )
                    continue
                candidate_key = (caller, target, "callsite_ledger", site_id)
                if candidate_key not in candidate_keys:
                    candidate_facts.append(
                        _edge_record(
                            caller,
                            target,
                            resolver="callsite_ledger",
                            status="candidate",
                            source_kind="resolved_ambiguous_callsite",
                            site_id=site_id,
                            evidence={
                                "file": site.get("file"),
                                "line_start": site.get("line_start"),
                                "line_end": site.get("line_end"),
                                "expression": site.get("expression"),
                            },
                            attributes={
                                "candidate_completeness": site.get("candidate_completeness", "unknown"),
                                "binding_basis": site.get("binding_basis"),
                                "binding_evidence": site.get("binding_evidence", {}),
                                "parse_status": parse_status,
                                "build_status": build_status,
                                "source_revision": expected_revision,
                                "ledger_revision": ledger_revision or "unknown",
                                "revision_mismatch": ledger_revision_mismatch,
                            },
                        )
                    )
                    candidate_keys.add(candidate_key)
            if graph_status == "edge_missing":
                unrepaired_sites += 1
            continue
        else:
            # Partial/unresolved candidates are valuable diagnostics but must
            # not silently become strict edges.
            for target in candidates:
                if caller not in body_ids or target not in body_ids:
                    add_exclusion(
                        "callsite_candidate_endpoint_not_in_function_index",
                        {
                            "site_id": site_id,
                            "caller_id": caller,
                            "callee_id": target,
                        },
                    )
                    continue
                candidate_key = (caller, target, "callsite_ledger", site_id)
                if candidate_key not in candidate_keys:
                    candidate_facts.append(
                        _edge_record(
                            caller,
                            target,
                            resolver="callsite_ledger",
                            status="candidate",
                            source_kind="candidate_callsite",
                            site_id=site_id,
                            evidence={
                                "file": site.get("file"),
                                "line_start": site.get("line_start"),
                                "line_end": site.get("line_end"),
                                "expression": site.get("expression"),
                            },
                            attributes={
                                "binding_status": binding_status,
                                "graph_status": graph_status,
                                "candidate_completeness": site.get("candidate_completeness", "unknown"),
                                "binding_basis": site.get("binding_basis"),
                                "binding_evidence": site.get("binding_evidence", {}),
                                "parse_status": parse_status,
                                "build_status": build_status,
                                "source_revision": expected_revision,
                                "ledger_revision": ledger_revision or "unknown",
                                "revision_mismatch": ledger_revision_mismatch,
                            },
                        )
                    )
                    candidate_keys.add(candidate_key)
            if graph_status == "edge_missing":
                unrepaired_sites += 1
            continue

        evidence = {
            "file": site.get("file"),
            "line_start": site.get("line_start"),
            "line_end": site.get("line_end"),
            "byte_start": site.get("byte_start"),
            "byte_end": site.get("byte_end"),
            "expression": site.get("expression"),
            "callee_spelling": site.get("callee_spelling"),
        }
        for target in targets:
            if add_confirmed(
                caller,
                target,
                resolver="callsite_ledger",
                source_kind="resolved_callsite",
                evidence=evidence,
                site_id=site_id,
                attributes={
                    "binding_status": binding_status,
                    "graph_status": graph_status,
                    "candidate_completeness": site.get("candidate_completeness", "unknown"),
                    "binding_basis": site.get("binding_basis"),
                    "binding_evidence": site.get("binding_evidence", {}),
                    "evidence_level": "parser_binding_validated",
                    "source_revision": source_revision or "unknown",
                    "build_config_id": build_config_id or "unknown",
                    "parse_status": parse_status,
                    "build_status": build_status,
                },
                repair_reason=repair_reason,
            ) and repair_reason:
                repaired_sites += 1
        if graph_status == "edge_missing" and not targets:
            unrepaired_sites += 1

    # Only validated strict overlays become effective edges. Model recovery
    # reports themselves are intentionally not consumed here.
    overlay_count = 0
    overlay_strict_rejected = 0
    overlay_seen: set[tuple[str, str, str, str]] = set()
    for graph_payload in overlay_payloads:
            for edge in _overlay_edges(graph_payload):
                source = _normalize_endpoint(
                    edge.get("source") or edge.get("source_id") or edge.get("caller_id")
                )
                target = _normalize_endpoint(
                    edge.get("target") or edge.get("target_id") or edge.get("callee_id")
                )
                attrs = edge.get("attributes") if isinstance(edge.get("attributes"), Mapping) else {}
                resolver = _string(edge.get("resolver") or attrs.get("resolver") or "semantic_overlay")
                site_key = _string(edge.get("site_id") or attrs.get("site_id") or attrs.get("call_site"))
                overlay_key = (source, target, resolver, site_key)
                if overlay_key in overlay_seen:
                    continue
                overlay_seen.add(overlay_key)
                overlay_revision = _string(
                    attrs.get("source_revision")
                    or edge.get("source_revision")
                    or graph_payload.get("source_revision")
                )
                revision_reason = ""
                if expected_revision != "unknown":
                    if not overlay_revision:
                        revision_reason = "overlay_source_revision_missing"
                    elif overlay_revision != expected_revision:
                        revision_reason = "overlay_source_revision_mismatch"
                overlay_build_config = _string(
                    attrs.get("build_config_id")
                    or edge.get("build_config_id")
                    or graph_payload.get("build_config_id")
                )
                build_config_reason = ""
                # Clang facts are configuration-specific.  When the caller
                # supplies a concrete graph configuration, an overlay from a
                # different configuration (or an old artifact without a
                # configuration fingerprint) must remain candidate-only.
                if resolver.lower() == "clang" and build_config_id and build_config_id != "unknown":
                    if not overlay_build_config:
                        build_config_reason = "overlay_build_config_missing"
                    elif overlay_build_config != build_config_id:
                        build_config_reason = "overlay_build_config_mismatch"
                strict, strict_reason = _validation_record_is_trusted(edge, attrs)
                # Clang facts have an additional admission boundary beyond
                # source-span validation: a candidate/manual/reconstructed
                # build must never become a strict product edge merely because
                # the artifact carries an accepted validation record.  Other
                # semantic resolvers (for example LLM-reviewed framework
                # relations) do not require a compiler build-status field.
                if strict and resolver.lower() == "clang":
                    tier = _string(attrs.get("reachability_tier")).lower()
                    if tier and tier != "strict":
                        strict = False
                        strict_reason = "semantic_overlay_candidate_tier"
                    else:
                        strict, strict_reason = _build_status_allows_strict(attrs)
                if revision_reason:
                    strict = False
                    strict_reason = revision_reason
                elif build_config_reason:
                    strict = False
                    strict_reason = build_config_reason
                overlay_count += 1
                if not source or not target or source not in node_ids or target not in node_ids:
                    add_exclusion(
                        "overlay_endpoint_not_in_symbol_index",
                        {"caller_id": source, "callee_id": target, "resolver": resolver},
                    )
                    continue
                evidence = edge.get("evidence") if isinstance(
                    edge.get("evidence"), (Mapping, list)
                ) else {}
                if strict:
                    add_confirmed(
                        source,
                        target,
                        resolver=resolver,
                        source_kind="validated_semantic_overlay",
                        evidence=evidence,
                        site_id=site_key,
                        attributes=attrs,
                        allow_external_nodes=True,
                    )
                else:
                    overlay_strict_rejected += 1
                    key = (source, target, resolver, site_key)
                    if key not in candidate_keys:
                        candidate_facts.append(
                            _edge_record(
                                source,
                                target,
                                resolver=resolver,
                                status="candidate",
                                source_kind="unvalidated_semantic_overlay",
                                evidence=evidence,
                                site_id=site_key,
                                attributes=attrs,
                                repair_reason=strict_reason,
                            )
                        )
                        candidate_keys.add(key)

    effective_forward = {
        caller: sorted(targets)
        for caller, targets in sorted(effective.items())
        if targets
    }
    effective_reverse = _reverse(effective_forward)
    native_edges = sum(len(targets) for targets in native_forward.values())
    effective_edges = sum(len(targets) for targets in effective_forward.values())
    native_pairs = {
        (caller, target)
        for caller, targets in native_forward.items()
        for target in targets
    }
    effective_pairs = {
        (caller, target)
        for caller, targets in effective_forward.items()
        for target in targets
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "graph_type": "effective_call_graph",
        "nodes": sorted(node_ids),
        "functions": native_graph.get("functions", {}),
        "external_nodes": {
            node_id: external_nodes[node_id]
            for node_id in sorted(external_nodes)
        },
        "call_graph": effective_forward,
        "reverse_call_graph": effective_reverse,
        "edge_facts": edge_facts,
        "candidate_facts": candidate_facts,
        "exclusions": exclusions,
        "summary": {
            "native_edges": native_edges,
            "effective_edges": effective_edges,
            "confirmed_added": len(effective_pairs - native_pairs),
            "candidate_edges": len(candidate_facts),
            "overlay_edges_seen": overlay_count,
            "overlay_strict_rejected": overlay_strict_rejected,
            "ledger_revision_mismatch": ledger_revision_mismatch,
            "resolved_call_sites": resolved_sites,
            "graph_edge_missing_sites": edge_missing_sites,
            "resolved_edge_missing_repaired": repaired_sites,
            "resolved_edge_missing_unrepaired": unrepaired_sites,
            "invalid_facts": len(exclusions),
        },
        "provenance": {
            "native_graph": "call_graph.json",
            "ledger": "callsite_ledger.json" if ledger is not None else None,
            "source_revision": source_revision or "unknown",
            "build_config_id": build_config_id or "unknown",
            "input_fingerprint": input_fingerprint,
            "graph_version": graph_version,
            "overlay_count": len(semantic_overlays),
        },
        "graph_version": graph_version,
    }


def _graph_dirs(output_dir: str | os.PathLike[str]) -> list[Path]:
    root = Path(output_dir)
    dirs: list[Path] = []
    index_payload = _load_optional(root / "call_graphs.json")
    if index_payload:
        for relative in index_payload.values():
            if not isinstance(relative, str):
                continue
            candidate = root / relative
            if candidate.is_file() and candidate.name == "call_graph.json":
                dirs.append(candidate.parent)
    root_graph = root / "call_graph.json"
    if root_graph.is_file():
        dirs.append(root)
    if not dirs and root.is_dir():
        for graph_path in sorted(root.rglob("call_graph.json")):
            dirs.append(graph_path.parent)
    unique: list[Path] = []
    seen: set[Path] = set()
    for directory in dirs:
        resolved = directory.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def refresh_effective_call_graph(
    graph_dir: str | os.PathLike[str],
    *,
    semantic_overlays: Iterable[Mapping[str, Any]] = (),
    source_revision: str | None = None,
    build_config_id: str | None = None,
    include_persisted_overlays: bool = True,
    include_object_flow_overlay: bool = True,
) -> dict[str, Any] | None:
    """Refresh one graph directory and write ``effective_call_graph.json``."""
    directory = Path(graph_dir)
    native_path = directory / "call_graph.json"
    native = _load_optional(native_path)
    if native is None:
        return None
    ledger = _load_optional(directory / "callsite_ledger.json")
    ledger_name = "callsite_ledger.json" if ledger is not None else None
    if ledger is None:
        residual = _load_optional(directory / "call_graph_residuals.json")
        if residual is not None:
            ledger = residual
            ledger_name = "call_graph_residuals.json"
    if not source_revision:
        source_revision = _string(
            (ledger or {}).get("revision")
            or native.get("source_revision")
            or "unknown"
        ) or "unknown"
    if not build_config_id:
        build_config_id = _string(native.get("build_config_id")) or "unknown"
    overlays: list[Mapping[str, Any]] = []
    if include_persisted_overlays:
        for filename in (
            "clang_semantic_overlay.json",
            "llm_call_graph_overlay.json",
        ):
            payload = _load_optional(directory / filename)
            if payload is not None:
                overlays.append(payload)
    # Object/value-flow facts are emitted by the current parser pass and are
    # deliberately candidate-only.  They are safe to load even when strict
    # semantic overlays are disabled: the graph builder keeps them out of the
    # executable strict adjacency while exposing them through candidate_facts.
    # This lets medium/candidate reachability and later evidence recovery see
    # indirect-call frontiers without replaying stale LLM/Clang projections.
    if include_object_flow_overlay:
        payload = _load_optional(directory / "object_flow_candidate_overlay.json")
        if payload is not None:
            overlays.append(payload)
    overlays.extend(list(semantic_overlays))
    effective = build_effective_call_graph(
        native,
        ledger=ledger,
        semantic_overlays=overlays,
        source_revision=source_revision,
        build_config_id=build_config_id,
    )
    effective.setdefault("provenance", {})["ledger"] = ledger_name
    write_json(directory / EFFECTIVE_FILENAME, effective)
    return effective


def refresh_effective_call_graphs(
    output_dir: str | os.PathLike[str],
    *,
    semantic_overlays: Iterable[Mapping[str, Any]] = (),
    source_revision: str | None = None,
    build_config_id: str | None = None,
    include_persisted_overlays: bool = True,
    include_object_flow_overlay: bool = True,
) -> list[dict[str, Any]]:
    """Refresh every language graph in a scan output directory."""
    overlays = list(semantic_overlays)
    results: list[dict[str, Any]] = []
    for directory in _graph_dirs(output_dir):
        effective = refresh_effective_call_graph(
            directory,
            semantic_overlays=overlays,
            source_revision=source_revision,
            build_config_id=build_config_id,
            include_persisted_overlays=include_persisted_overlays,
            include_object_flow_overlay=include_object_flow_overlay,
        )
        if effective is not None:
            results.append(
                {
                    "path": str(directory / EFFECTIVE_FILENAME),
                    "summary": effective.get("summary", {}),
                }
            )
    return results


def synchronize_dataset_dependencies(
    dataset_path: str | os.PathLike[str],
    effective_graph_paths: Iterable[str | os.PathLike[str]],
) -> dict[str, int]:
    """Project effective callers/callees into unit metadata for later stages.

    The dataset remains the unit-level analysis contract, so enhancement and
    Stage 1 must not continue using stale parser-only ``direct_calls`` after a
    graph repair.  This function only updates dependency metadata; the source
    code and native graph are untouched.
    """
    path = Path(dataset_path)
    payload = _load_optional(path)
    if payload is None or not isinstance(payload.get("units"), list):
        return {"units_seen": 0, "units_updated": 0, "edges_loaded": 0}
    forward: dict[str, list[str]] = {}
    reverse: dict[str, list[str]] = {}
    graph_provenance: list[dict[str, Any]] = []
    edges_loaded = 0
    for raw_path in effective_graph_paths:
        graph = _load_optional(Path(raw_path))
        if graph is None:
            continue
        provenance = graph.get("provenance")
        if isinstance(provenance, Mapping):
            graph_provenance.append(
                {
                    "path": str(raw_path),
                    "graph_version": provenance.get("graph_version")
                    or graph.get("graph_version"),
                    "source_revision": provenance.get("source_revision", "unknown"),
                    "build_config_id": provenance.get("build_config_id", "unknown"),
                }
            )
        graph_forward = graph.get("call_graph", {})
        graph_reverse = graph.get("reverse_call_graph", {})
        if isinstance(graph_forward, Mapping):
            for caller, targets in graph_forward.items():
                if not isinstance(targets, list):
                    continue
                existing = set(forward.get(str(caller), []))
                existing.update(str(target) for target in targets if target)
                edges_loaded += len(existing) - len(forward.get(str(caller), []))
                forward[str(caller)] = sorted(existing)
        if isinstance(graph_reverse, Mapping):
            for callee, callers in graph_reverse.items():
                if not isinstance(callers, list):
                    continue
                existing = set(reverse.get(str(callee), []))
                existing.update(str(caller) for caller in callers if caller)
                reverse[str(callee)] = sorted(existing)
    metadata_root = payload.get("metadata")
    if not isinstance(metadata_root, dict):
        metadata_root = {}
        payload["metadata"] = metadata_root
    metadata_root["effective_call_graphs"] = graph_provenance
    updated = 0
    for unit in payload["units"]:
        if not isinstance(unit, Mapping):
            continue
        unit_id = _string(unit.get("id"))
        if not unit_id or (unit_id not in forward and unit_id not in reverse):
            continue
        metadata = unit.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
            unit["metadata"] = metadata
        metadata["direct_calls"] = list(forward.get(unit_id, []))
        metadata["direct_callers"] = list(reverse.get(unit_id, []))
        metadata["call_graph_source"] = "effective_call_graph.json"
        metadata["call_graph_evidence"] = "native_plus_audited_facts"
        if graph_provenance:
            versions = [
                item.get("graph_version")
                for item in graph_provenance
                if item.get("graph_version")
            ]
            if versions:
                metadata["call_graph_versions"] = versions
        updated += 1
    write_json(path, payload)
    return {
        "units_seen": len(payload["units"]),
        "units_updated": updated,
        "edges_loaded": edges_loaded,
    }
