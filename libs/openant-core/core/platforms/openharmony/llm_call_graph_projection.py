"""Project validated OpenHarmony LLM recovery decisions into an overlay.

The recovery reviewer deliberately produces an advisory report.  This module
is the next, still side-effect-free boundary: it turns only high-confidence,
source-backed decisions into a :class:`SemanticGraph` payload.  The native
``call_graph.json`` is never changed here and no reachability filtering is
performed.  Callers can persist the returned payload as a separate artifact
and decide, in a later stage, whether to merge it into an in-memory overlay.

The extra checks in this module are intentionally independent of the model
response parser.  A future caller may load a hand-edited or old recovery
artifact, so projection must re-check endpoint IDs, candidate membership,
confidence, source spans, and evidence before emitting an edge.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from core.platforms.graph import SemanticGraph


PROJECTION_SCHEMA_VERSION = 1
PROJECTION_TASK = "openharmony_llm_call_graph_overlay"
EDGE_KIND = "llm_confirmed_indirect_call"
RESOLVER_VERSION = 1

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_EVIDENCE_KINDS = {"call_site", "registration", "target", "type"}
_GENERIC_TOKENS = {
    "this",
    "return",
    "data",
    "reply",
    "args",
    "arg",
    "event",
    "call",
    "func",
    "handler",
    "request",
    "function",
}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _line(value: Any, default: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, parsed)


def _normalize_functions(functions: Any) -> dict[str, Mapping[str, Any]]:
    if isinstance(functions, Mapping) and isinstance(functions.get("functions"), Mapping):
        functions = functions["functions"]
    if not isinstance(functions, Mapping):
        return {}
    return {
        _text(function_id): function
        for function_id, function in functions.items()
        if _text(function_id) and isinstance(function, Mapping)
    }


def _function_code(function: Mapping[str, Any]) -> str:
    code = function.get("code", "")
    if isinstance(code, Mapping):
        return _text(code.get("primary_code") or code.get("source"))
    return _text(code)


def _function_name(function_id: str, function: Mapping[str, Any]) -> str:
    return _text(function.get("name")) or function_id


def _leaf(name: str) -> str:
    return _text(name).rsplit("::", 1)[-1].rsplit(".", 1)[-1]


def _owner(function: Mapping[str, Any]) -> str:
    explicit = _text(function.get("class_name") or function.get("className"))
    if explicit:
        return _leaf(explicit)
    name = _function_name("", function)
    return name.rsplit("::", 1)[-2] if "::" in name else ""


def _file(function: Mapping[str, Any]) -> str:
    return _text(function.get("file_path") or function.get("filePath"))


def _line_span(function: Mapping[str, Any]) -> tuple[int, int]:
    start = _line(function.get("start_line", function.get("startLine", 1)))
    end = _line(function.get("end_line", function.get("endLine", start)), start)
    return start, max(start, end)


def _function_attributes(function_id: str, function: Mapping[str, Any]) -> dict[str, Any]:
    start, end = _line_span(function)
    return {
        "name": _function_name(function_id, function),
        "file_path": _file(function),
        "start_line": start,
        "end_line": end,
        "unit_type": _text(function.get("unit_type") or function.get("unitType"))
        or "function",
    }


def _normalize_ws(value: Any) -> str:
    return re.sub(r"\s+", " ", _text(value)).strip()


def _identifier_tokens(value: Any) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z_]\w*", _text(value))
        if len(token) >= 3 and token.lower() not in _GENERIC_TOKENS
    }


def _line_matches(
    evidence: Mapping[str, Any],
    expected_line: int,
) -> bool:
    start = _line(evidence.get("start_line", 1))
    end = _line(evidence.get("end_line", start), start)
    return start <= expected_line <= max(start, end)


def _evidence_file_matches(
    evidence_file: str,
    *expected_files: str,
) -> bool:
    if not evidence_file:
        return False
    candidates = {item for item in expected_files if item}
    return not candidates or evidence_file in candidates


def _call_site_evidence_valid(
    evidence: Mapping[str, Any],
    site: Mapping[str, Any],
    caller: Mapping[str, Any],
) -> bool:
    if _text(evidence.get("kind")) != "call_site":
        return False
    site_file = _text(site.get("file")) or _file(caller)
    evidence_file = _text(evidence.get("file"))
    if not _evidence_file_matches(evidence_file, site_file, _file(caller)):
        return False
    if not _line_matches(evidence, _line(site.get("line"))):
        return False
    evidence_text = _normalize_ws(evidence.get("text"))
    expression = _normalize_ws(site.get("expression"))
    if not evidence_text or not expression:
        return False
    if evidence_text in expression or expression in evidence_text:
        return True
    # Parser and model may differ in harmless punctuation/receiver spelling.
    # Require at least two non-generic identifiers instead of accepting a
    # generic phrase such as "the handler call".
    shared = _identifier_tokens(evidence_text) & _identifier_tokens(expression)
    if len(shared) < 2:
        return False
    caller_code = _normalize_ws(_function_code(caller))
    return evidence_text in caller_code or expression in caller_code


def _target_evidence_valid(
    evidence: Mapping[str, Any],
    target_id: str,
    target: Mapping[str, Any],
    caller: Mapping[str, Any],
) -> bool:
    kind = _text(evidence.get("kind"))
    if kind not in {"target", "registration", "type"}:
        return False
    evidence_file = _text(evidence.get("file"))
    if not _evidence_file_matches(evidence_file, _file(target), _file(caller)):
        return False
    if _line(evidence.get("start_line", 1)) < 1:
        return False
    evidence_text = _normalize_ws(evidence.get("text"))
    if not evidence_text:
        return False
    if kind == "target" and _text(evidence.get("function_id")) == target_id:
        return True
    target_name = _function_name(target_id, target)
    target_leaf = _leaf(target_name)
    if not target_leaf:
        return False
    return target_leaf.lower() in evidence_text.lower()


def _valid_evidence(
    evidence: Any,
    *,
    site: Mapping[str, Any],
    caller: Mapping[str, Any],
    target_id: str,
    target: Mapping[str, Any],
) -> tuple[bool, str]:
    if not isinstance(evidence, list) or not evidence:
        return False, "missing_evidence"
    has_call_site = False
    has_target = False
    for item in evidence:
        if not isinstance(item, Mapping):
            return False, "malformed_evidence"
        kind = _text(item.get("kind"))
        if kind not in _EVIDENCE_KINDS:
            return False, "unsupported_evidence_kind"
        if not _text(item.get("file")) or not _text(item.get("text")):
            return False, "incomplete_evidence"
        if kind == "call_site":
            has_call_site = has_call_site or _call_site_evidence_valid(
                item, site, caller
            )
        elif kind in {"target", "registration", "type"}:
            has_target = has_target or _target_evidence_valid(
                item, target_id, target, caller
            )
    if not has_call_site:
        return False, "call_site_evidence_not_source_backed"
    if not has_target:
        return False, "target_or_registration_evidence_not_source_backed"
    return True, ""


def _orphan(
    *,
    proposal: Mapping[str, Any] | None,
    site: Mapping[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    evidence = proposal.get("evidence", []) if isinstance(proposal, Mapping) else []
    attributes = {
        "site_id": _text(proposal.get("site_id")) if isinstance(proposal, Mapping) else "",
        "caller_id": _text(site.get("caller_id")) if isinstance(site, Mapping) else "",
        "target_id": _text(proposal.get("target_id")) if isinstance(proposal, Mapping) else "",
        "decision": _text(proposal.get("decision")) if isinstance(proposal, Mapping) else "",
        "confidence": _text(proposal.get("confidence")) if isinstance(proposal, Mapping) else "",
    }
    return {
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "kind": "llm_recovery_rejected",
        "reason": reason,
        "evidence": copy.deepcopy(evidence) if isinstance(evidence, list) else [],
        "attributes": attributes,
    }


def project_recovery_overlay(
    recovery_report: Mapping[str, Any] | None,
    functions: Any,
    *,
    minimum_confidence: str = "high",
    max_edges: int = 1_000,
) -> dict[str, Any]:
    """Project safe LLM decisions into an independent semantic graph payload.

    The function is deliberately pure: both inputs are treated as read-only,
    and the returned graph is JSON serialisable.  Only entries already present
    in ``validation.accepted`` are considered.  The checks are repeated here
    because artifacts may be loaded after the original validation step or may
    have been edited by a reviewer.

    ``minimum_confidence`` currently defaults to ``high``.  Lowering it is
    allowed for audit experiments, but callers should not feed such an overlay
    into production reachability without an explicit review policy.
    """
    index = _normalize_functions(functions)
    report = recovery_report if isinstance(recovery_report, Mapping) else {}
    worklist_raw = report.get("worklist", [])
    if not isinstance(worklist_raw, list):
        worklist_raw = []
    validation = report.get("validation")
    accepted_raw = validation.get("accepted", []) if isinstance(validation, Mapping) else []
    worklist = {
        _text(item.get("site_id")): item
        for item in worklist_raw
        if isinstance(item, Mapping) and _text(item.get("site_id"))
    }
    try:
        threshold = _CONFIDENCE_RANK[minimum_confidence]
    except KeyError:
        threshold = _CONFIDENCE_RANK["high"]
        minimum_confidence = "high"
    try:
        edge_limit = max(0, int(max_edges))
    except (TypeError, ValueError):
        edge_limit = 1_000

    graph = SemanticGraph()
    summary = {
        "accepted_input": len(accepted_raw) if isinstance(accepted_raw, list) else 0,
        "projected_edges": 0,
        "rejected": 0,
        "duplicate_edges": 0,
        "edge_limit": edge_limit,
        "minimum_confidence": minimum_confidence,
    }
    rejected: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()

    if not isinstance(validation, Mapping):
        payload = graph.to_dict()
        payload.update(
            {
                "schema_version": PROJECTION_SCHEMA_VERSION,
                "task": PROJECTION_TASK,
                "source_task": _text(report.get("task")) or "unknown",
                "status": "invalid",
                "summary": summary,
                "rejected": [{
                    "reason": "missing_validation_block",
                    "attributes": {},
                    "evidence": [],
                }],
            }
        )
        return payload

    for raw_proposal in accepted_raw if isinstance(accepted_raw, list) else []:
        if not isinstance(raw_proposal, Mapping):
            summary["rejected"] += 1
            rejected.append(_orphan(proposal=None, site=None, reason="malformed_proposal"))
            continue

        proposal = dict(raw_proposal)
        site_id = _text(proposal.get("site_id"))
        site = worklist.get(site_id)
        target_id = _text(proposal.get("target_id"))
        caller_id = _text(site.get("caller_id")) if isinstance(site, Mapping) else ""
        caller = index.get(caller_id)
        target = index.get(target_id)
        reason = ""
        confidence = _text(proposal.get("confidence"))

        if _text(proposal.get("decision")) != "add_edge":
            reason = "decision_is_not_add_edge"
        elif not site:
            reason = "unknown_site"
        elif not caller:
            reason = "unknown_caller"
        elif not target:
            reason = "unknown_target"
        elif _CONFIDENCE_RANK.get(confidence, -1) < threshold:
            reason = "confidence_below_projection_threshold"
        else:
            raw_candidate_ids = site.get("candidate_target_ids", [])
            if not isinstance(raw_candidate_ids, list):
                raw_candidate_ids = []
            candidate_ids = {_text(item) for item in raw_candidate_ids if _text(item)}
            raw_retrieval_candidates = site.get("retrieval_candidates", [])
            if not isinstance(raw_retrieval_candidates, list):
                raw_retrieval_candidates = []
            retrieval_ids = {
                _text(item.get("function_id"))
                for item in raw_retrieval_candidates
                if isinstance(item, Mapping) and _text(item.get("function_id"))
            }
            # Candidate-bearing sites must stay within the parser-provided
            # candidate set.  A genuinely unresolved site has no such set;
            # in that case the bounded retrieval shortlist (checked below)
            # is the only permitted target universe.  Keeping the two cases
            # distinct lets iterative recovery promote a source-backed target
            # without allowing the model to invent a function ID.
            if candidate_ids and target_id not in candidate_ids:
                reason = "target_not_in_site_candidates"
            elif target_id not in retrieval_ids:
                reason = "target_not_in_retrieval_candidates"
            else:
                valid, evidence_reason = _valid_evidence(
                    proposal.get("evidence"),
                    site=site,
                    caller=caller,
                    target_id=target_id,
                    target=target,
                )
                if not valid:
                    reason = evidence_reason

        if reason:
            summary["rejected"] += 1
            rejected.append(_orphan(proposal=proposal, site=site, reason=reason))
            continue

        pair = (caller_id, target_id)
        if pair in seen_edges:
            summary["duplicate_edges"] += 1
            summary["rejected"] += 1
            rejected.append(_orphan(proposal=proposal, site=site, reason="duplicate_edge"))
            continue
        if summary["projected_edges"] >= edge_limit:
            summary["rejected"] += 1
            rejected.append(_orphan(proposal=proposal, site=site, reason="edge_limit_exceeded"))
            continue

        seen_edges.add(pair)
        graph.add_node(
            {
                "schema_version": PROJECTION_SCHEMA_VERSION,
                "id": f"function:{caller_id}",
                "kind": "function",
                "attributes": _function_attributes(caller_id, caller),
            }
        )
        graph.add_node(
            {
                "schema_version": PROJECTION_SCHEMA_VERSION,
                "id": f"function:{target_id}",
                "kind": "function",
                "attributes": _function_attributes(target_id, target),
            }
        )
        evidence = copy.deepcopy(proposal.get("evidence", []))
        graph.add_edge(
            {
                "schema_version": PROJECTION_SCHEMA_VERSION,
                "source_id": f"function:{caller_id}",
                "target_id": f"function:{target_id}",
                "kind": EDGE_KIND,
                "evidence": evidence,
                "confidence": 0.95,
                "resolver_version": RESOLVER_VERSION,
                "attributes": {
                    "site_id": site_id,
                    "source": "llm_recovery",
                    "model_confidence": confidence,
                    "reason": _text(proposal.get("reason"))[:500],
                    "call_site": {
                        "file": _text(site.get("file")),
                        "line": _line(site.get("line")),
                        "expression": _text(site.get("expression")),
                    },
                },
            }
        )
        summary["projected_edges"] += 1

    payload = graph.to_dict()
    status = "complete" if summary["projected_edges"] or not summary["accepted_input"] else "partial"
    payload.update(
        {
            "schema_version": PROJECTION_SCHEMA_VERSION,
            "task": PROJECTION_TASK,
            "source_task": _text(report.get("task")) or "unknown",
            "source_status": _text(report.get("status")) or "unknown",
            "status": status,
            "summary": summary,
            "rejected": rejected,
        }
    )
    # Keep the graph's own orphan list and the projection rejection list
    # separate: the former is part of SemanticGraph's schema, while the latter
    # explains why an accepted model decision was not projected.
    return payload


__all__ = [
    "EDGE_KIND",
    "PROJECTION_SCHEMA_VERSION",
    "PROJECTION_TASK",
    "RESOLVER_VERSION",
    "project_recovery_overlay",
]
