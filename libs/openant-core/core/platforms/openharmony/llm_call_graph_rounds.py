"""入口驱动的 OpenHarmony 间接调用边逐轮恢复。

本模块把一次性的残余审核组织成一个有界的 BFS 调度器。它不修改原生
``call_graph.json``，也不把模型输出直接当成调用边：每一轮仍然复用
``run_recovery_review`` 的严格 JSON/候选/证据校验，再通过
``project_recovery_overlay`` 产生独立的语义叠加图。只有通过投影的边才
能把新的函数加入下一轮前沿。

调度器同时沿用已存在的原生调用边和确定性 semantic graph 边。这样入口
可以先到达一个普通函数，再在该函数上发现残余间接调用；模型失败时只会
保留残余并安全降级，不会凭空扩展 BFS。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from pathlib import Path
import time
from typing import Any, Callable

from core.platforms.graph import SemanticGraph

from .llm_call_graph_projection import project_recovery_overlay
from .llm_call_graph_recovery import (
    DEFAULT_MAX_CODE_BYTES,
    DEFAULT_MAX_SHORTLIST,
    DEFAULT_REGISTRATION_CONTEXT_MAX_CHARS,
    DEFAULT_REGISTRATION_CONTEXT_MAX_FILE_BYTES,
    DEFAULT_REGISTRATION_CONTEXT_MAX_FILES,
    build_recovery_worklist,
    run_recovery_review,
)
from .reachability import build_semantic_reachability_overlay


ROUND_SCHEMA_VERSION = 1
ROUND_TASK = "openharmony_iterative_call_edge_recovery"
DEFAULT_MAX_ROUNDS = 8
DEFAULT_MAX_SITES = 200
DEFAULT_MAX_EDGES = 1_000
DEFAULT_MAX_LLM_CALLS = 32


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


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


def _normalize_ids(value: Iterable[str] | None, known: set[str]) -> set[str]:
    if value is None or isinstance(value, (str, bytes)):
        return set()
    try:
        return {
            _text(item)
            for item in value
            if _text(item) in known
        }
    except TypeError:
        return set()


def _bound_int(value: Any, default: int, *, minimum: int = 0) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


def _optional_budget(value: Any, default: int) -> int:
    """Normalize a non-negative budget; ``-1`` means unlimited."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return -1 if parsed < 0 else parsed


def _edge_adjacency(
    call_graph: Mapping[str, Any] | None,
    semantic_graph: Mapping[str, Any] | SemanticGraph | None,
    known: set[str],
) -> dict[str, tuple[str, ...]]:
    """Normalize native and deterministic semantic edges to known IDs."""
    adjacency: dict[str, set[str]] = {}
    payload: Any = call_graph
    if isinstance(payload, Mapping) and isinstance(payload.get("call_graph"), Mapping):
        payload = payload["call_graph"]
    if isinstance(payload, Mapping):
        for raw_source, raw_targets in payload.items():
            source = _text(raw_source)
            if source not in known or isinstance(raw_targets, (str, bytes)):
                continue
            try:
                targets = list(raw_targets)
            except TypeError:
                continue
            for raw_target in targets:
                target = _text(raw_target)
                if target in known and target != source:
                    adjacency.setdefault(source, set()).add(target)

    semantic_payload: Mapping[str, Any] | None
    if isinstance(semantic_graph, SemanticGraph):
        semantic_payload = semantic_graph.to_dict()
    elif isinstance(semantic_graph, Mapping):
        semantic_payload = semantic_graph
    else:
        semantic_payload = None
    if semantic_payload is not None:
        collapsed = build_semantic_reachability_overlay(
            semantic_payload,
            known,
        )
        for raw_edge in collapsed.get("edges", []):
            if not isinstance(raw_edge, Mapping):
                continue
            source_node = _text(raw_edge.get("source_id"))
            target_node = _text(raw_edge.get("target_id"))
            if not source_node.startswith("function:") or not target_node.startswith("function:"):
                continue
            source = source_node[len("function:"):]
            target = target_node[len("function:"):]
            if source in known and target in known and source != target:
                adjacency.setdefault(source, set()).add(target)
    return {
        source: tuple(sorted(targets))
        for source, targets in sorted(adjacency.items())
        if targets
    }


def _seed_ids(
    functions: Mapping[str, Mapping[str, Any]],
    entry_point_ids: Iterable[str] | None,
) -> list[str]:
    known = set(functions)
    explicit = _normalize_ids(entry_point_ids, known)
    structural = {
        function_id
        for function_id, function in functions.items()
        if function.get("is_entry_point") is True
    }
    return sorted(explicit | structural)


def _item_callers(item: Mapping[str, Any]) -> set[str]:
    raw_ids = item.get("caller_ids")
    if isinstance(raw_ids, list):
        callers = {_text(value) for value in raw_ids if _text(value)}
    else:
        callers = set()
    caller_id = _text(item.get("caller_id"))
    if caller_id:
        callers.add(caller_id)
    return callers


def _empty_graph() -> dict[str, Any]:
    return SemanticGraph().to_dict()


def _round_summary(
    *,
    round_index: int,
    frontier: list[str],
    selected_ids: list[str],
    review: Mapping[str, Any] | None,
    overlay: Mapping[str, Any] | None,
    expanded: list[str],
    direct_targets: list[str],
    new_targets: list[str],
    deferred_site_count: int,
) -> dict[str, Any]:
    review_summary = review.get("summary", {}) if isinstance(review, Mapping) else {}
    overlay_summary = overlay.get("summary", {}) if isinstance(overlay, Mapping) else {}
    return {
        "round": round_index,
        "frontier_function_ids": frontier,
        "site_ids": selected_ids,
        "review_status": (
            _text(review.get("status")) if isinstance(review, Mapping) else "no_sites"
        ),
        "review_summary": copy.deepcopy(review_summary)
        if isinstance(review_summary, Mapping)
        else {},
        "overlay_summary": copy.deepcopy(overlay_summary)
        if isinstance(overlay_summary, Mapping)
        else {},
        "expanded_function_ids": expanded,
        "direct_target_ids": direct_targets,
        "new_target_ids": new_targets,
        "deferred_site_count": deferred_site_count,
        "review": copy.deepcopy(review) if review is not None else None,
        "overlay": copy.deepcopy(overlay) if overlay is not None else _empty_graph(),
    }


def run_iterative_recovery_review(
    diagnostics: Mapping[str, Any],
    functions: Any,
    *,
    binding: Any = None,
    completion: Callable[[str], str] | None = None,
    entry_point_ids: Iterable[str] | None = None,
    call_graph: Mapping[str, Any] | None = None,
    semantic_graph: Mapping[str, Any] | SemanticGraph | None = None,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    max_sites: int = DEFAULT_MAX_SITES,
    max_sites_per_round: int = 50,
    max_edges: int = DEFAULT_MAX_EDGES,
    max_llm_calls: int = DEFAULT_MAX_LLM_CALLS,
    max_shortlist: int = DEFAULT_MAX_SHORTLIST,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
    include_candidate_sites: bool = False,
    security_relevant_only: bool = False,
    include_registration_context: bool = True,
    registration_context_max_files: int = DEFAULT_REGISTRATION_CONTEXT_MAX_FILES,
    registration_context_max_file_bytes: int = DEFAULT_REGISTRATION_CONTEXT_MAX_FILE_BYTES,
    registration_context_max_chars: int = DEFAULT_REGISTRATION_CONTEXT_MAX_CHARS,
    repository: str | Path | None = None,
    max_retries: int = 2,
    retry_backoff_seconds: float = 1.0,
    max_tokens: int = 20_000,
    max_seconds: float | None = None,
    tracker: Any = None,
) -> dict[str, Any]:
    """Run bounded entry-driven residual reviews and expand a semantic overlay.

    The input graph and diagnostics are treated as read-only.  Native edges
    are used only to discover the next frontier; a newly discovered target is
    added by the model only after strict validation *and* projection.  A site
    is scheduled at most once, while a caller can be revisited when a per-round
    site budget deferred some of its residuals.
    """
    index = _normalize_functions(functions)
    known = set(index)
    seeds = _seed_ids(index, entry_point_ids)
    normalized_rounds = _bound_int(max_rounds, DEFAULT_MAX_ROUNDS)
    site_budget = _optional_budget(max_sites, DEFAULT_MAX_SITES)
    per_round_budget = _optional_budget(max_sites_per_round, 50)
    edge_budget = _optional_budget(max_edges, DEFAULT_MAX_EDGES)
    llm_budget = _optional_budget(max_llm_calls, DEFAULT_MAX_LLM_CALLS)
    started = time.monotonic()

    all_worklist = build_recovery_worklist(
        diagnostics,
        index,
        max_sites=-1,
        max_shortlist=max_shortlist,
        max_code_bytes=max_code_bytes,
        include_candidate_sites=include_candidate_sites,
        security_relevant_only=security_relevant_only,
        include_registration_context=include_registration_context,
        registration_context_max_files=registration_context_max_files,
        registration_context_max_file_bytes=registration_context_max_file_bytes,
        registration_context_max_chars=registration_context_max_chars,
        repository=repository,
        call_graph=call_graph,
    )
    adjacency = _edge_adjacency(call_graph, semantic_graph, known)

    def has_pending_work(function_id: str) -> bool:
        """Whether a function can reach an unprocessed residual site.

        A plain outgoing-edge check keeps walking every reachable native
        function even after all residual sites have been handled.  That made
        a successful recovery look like ``partial/max_rounds`` on repositories
        with a long ordinary call chain.  Restrict the future frontier to
        nodes that can actually reach a remaining residual caller; deferred
        sites are still requeued explicitly by the caller below.
        """
        pending_callers = {
            caller
            for item in all_worklist
            if _text(item.get("site_id")) not in processed_sites
            for caller in _item_callers(item)
            if caller in known
        }
        if function_id not in known or not pending_callers:
            return False
        if function_id in pending_callers:
            return True

        seen = {function_id}
        frontier = [function_id]
        while frontier:
            current = frontier.pop()
            for target in adjacency.get(current, ()):
                if target in pending_callers:
                    return True
                if target not in seen:
                    seen.add(target)
                    frontier.append(target)
        return False

    result: dict[str, Any] = {
        "schema_version": ROUND_SCHEMA_VERSION,
        "task": ROUND_TASK,
        "status": "complete",
        "entry_point_ids": seeds,
        "rounds": [],
        "graph": _empty_graph(),
        "errors": [],
        "summary": {
            "entry_points": len(seeds),
            "worklist_sites": len(all_worklist),
            "rounds": 0,
            "sites_scheduled": 0,
            "sites_reviewed": 0,
            "unreviewed_sites": len(all_worklist),
            # Keep the one-shot review counters in the iterative envelope as
            # well.  The scheduler counters below describe BFS progress,
            # while these counters describe what the model actually returned.
            # Without both views, the stage report cannot distinguish
            # "reviewed and unresolved" from "never attempted".
            "attempts": 0,
            "parsed_decisions": 0,
            "accepted": 0,
            "kept_unresolved": 0,
            "rejected": 0,
            "accepted_decisions": 0,
            "projected_edges": 0,
            "duplicate_edges": 0,
            "request_batches": 0,
            "llm_calls": 0,
            "retry_count": 0,
            "failed_rounds": 0,
            "budget": {
                "max_rounds": normalized_rounds,
                "max_sites": site_budget,
                "max_sites_per_round": per_round_budget,
                "max_edges": edge_budget,
                "max_llm_calls": llm_budget,
                "max_seconds": max_seconds,
            },
            "termination_reason": "not_started",
        },
    }
    summary = result["summary"]

    if not seeds:
        result["status"] = "no_entry_points"
        summary["termination_reason"] = "no_entry_points"
        summary["unreviewed_sites"] = len(all_worklist)
        return result
    if not normalized_rounds:
        result["status"] = "partial" if all_worklist else "complete"
        summary["termination_reason"] = "max_rounds"
        return result
    if not all_worklist:
        summary["termination_reason"] = "no_sites"
        return result

    pending = set(seeds)
    expanded_functions: set[str] = set()
    processed_sites: set[str] = set()
    projected_pairs: set[tuple[str, str]] = set()
    overlays: list[Mapping[str, Any]] = []
    round_index = 0

    while pending and round_index < normalized_rounds:
        if max_seconds is not None:
            try:
                elapsed_limit = float(max_seconds)
            except (TypeError, ValueError):
                elapsed_limit = None
            if elapsed_limit is not None and elapsed_limit >= 0 and time.monotonic() - started >= elapsed_limit:
                summary["termination_reason"] = "max_seconds"
                result["status"] = "partial"
                break

        frontier = sorted(function_id for function_id in pending if function_id in known)
        pending.clear()
        if not frontier:
            break

        eligible = [
            item
            for item in all_worklist
            if _text(item.get("site_id")) not in processed_sites
            and _item_callers(item) & set(frontier)
        ]
        remaining_sites = (
            len(all_worklist) - len(processed_sites)
            if site_budget < 0
            else max(0, site_budget - len(processed_sites))
        )
        if per_round_budget < 0:
            selected_limit = remaining_sites
        else:
            selected_limit = min(remaining_sites, per_round_budget)
        selected = eligible[:selected_limit]
        selected_ids = [_text(item.get("site_id")) for item in selected]
        processed_sites.update(selected_ids)
        deferred = eligible[len(selected):]
        deferred_callers = sorted(
            caller
            for item in deferred
            for caller in _item_callers(item)
            if caller in known
        )

        review: Mapping[str, Any] | None = None
        overlay: Mapping[str, Any] | None = None
        expanded_now: list[str] = []
        direct_targets: set[str] = set()
        new_targets: set[str] = set()

        if selected and edge_budget != 0 and llm_budget != 0:
            used_calls = int(summary["llm_calls"])
            remaining_calls = (
                llm_budget - used_calls if llm_budget >= 0 else -1
            )
            if remaining_calls != 0:
                retry_budget = _bound_int(max_retries, 2)
                if remaining_calls > 0:
                    retry_budget = min(retry_budget, max(0, remaining_calls - 1))
                review = run_recovery_review(
                    diagnostics,
                    index,
                    binding=binding,
                    completion=completion,
                    entry_point_ids=seeds,
                    max_sites=-1,
                    max_shortlist=max_shortlist,
                    max_code_bytes=max_code_bytes,
                    include_candidate_sites=include_candidate_sites,
                    security_relevant_only=security_relevant_only,
                    include_registration_context=include_registration_context,
                    registration_context_max_files=registration_context_max_files,
                    registration_context_max_file_bytes=registration_context_max_file_bytes,
                    registration_context_max_chars=registration_context_max_chars,
                    repository=repository,
                    call_graph=call_graph,
                    max_retries=retry_budget,
                    retry_backoff_seconds=retry_backoff_seconds,
                    max_tokens=max_tokens,
                    tracker=tracker,
                    site_ids=selected_ids,
                )
                overlay = project_recovery_overlay(
                    review,
                    index,
                    max_edges=(
                        edge_budget - len(projected_pairs)
                        if edge_budget >= 0
                        else DEFAULT_MAX_EDGES
                    ),
                )
                overlays.append(overlay)
                review_summary = review.get("summary", {})
                if isinstance(review_summary, Mapping):
                    for key in (
                        "attempts",
                        "parsed_decisions",
                        "accepted",
                        "kept_unresolved",
                        "rejected",
                    ):
                        try:
                            summary[key] += int(review_summary.get(key, 0) or 0)
                        except (TypeError, ValueError):
                            continue
                    summary["sites_reviewed"] += int(review_summary.get("worklist_sites", 0) or 0)
                    summary["accepted_decisions"] += int(review_summary.get("accepted", 0) or 0)
                    summary["request_batches"] += int(review_summary.get("request_batches", 0) or 0)
                    summary["llm_calls"] += int(review_summary.get("llm_calls", 0) or 0)
                    summary["retry_count"] += int(review_summary.get("retry_count", 0) or 0)
                if _text(review.get("status")) == "failed":
                    summary["failed_rounds"] += 1
                    result["status"] = "partial"
                overlay_summary = overlay.get("summary", {})
                if isinstance(overlay_summary, Mapping):
                    summary["duplicate_edges"] += int(overlay_summary.get("duplicate_edges", 0) or 0)
                for edge in overlay.get("edges", []):
                    if not isinstance(edge, Mapping):
                        continue
                    source_node = _text(edge.get("source_id"))
                    target_node = _text(edge.get("target_id"))
                    if not source_node.startswith("function:") or not target_node.startswith("function:"):
                        continue
                    pair = (source_node, target_node)
                    if pair in projected_pairs:
                        summary["duplicate_edges"] += 1
                        continue
                    if edge_budget >= 0 and len(projected_pairs) >= edge_budget:
                        break
                    projected_pairs.add(pair)
                    target_id = target_node[len("function:"):]
                    if target_id in known:
                        new_targets.add(target_id)
                if review.get("errors"):
                    result["errors"].extend(copy.deepcopy(review["errors"]))
            else:
                summary["termination_reason"] = "max_llm_calls"
                result["status"] = "partial"
        elif selected and edge_budget == 0:
            summary["termination_reason"] = "max_edges"
            result["status"] = "partial"
        elif selected and llm_budget == 0:
            summary["termination_reason"] = "max_llm_calls"
            result["status"] = "partial"

        for caller_id in frontier:
            if caller_id in expanded_functions:
                continue
            expanded_now.append(caller_id)
            direct_targets.update(adjacency.get(caller_id, ()))
            expanded_functions.add(caller_id)

        next_frontier = direct_targets | new_targets
        next_frontier = {
            function_id
            for function_id in next_frontier
            if function_id not in expanded_functions and has_pending_work(function_id)
        }
        # A caller can be expanded already while still owning residual sites
        # deferred by ``max_sites_per_round``.  Keep it pending explicitly so
        # the next round consumes those sites instead of silently dropping
        # them.
        pending.update(next_frontier)
        pending.update(deferred_callers)
        result["rounds"].append(
            _round_summary(
                round_index=round_index,
                frontier=frontier,
                selected_ids=selected_ids,
                review=review,
                overlay=overlay,
                expanded=sorted(expanded_now),
                direct_targets=sorted(direct_targets),
                new_targets=sorted(new_targets),
                deferred_site_count=len(deferred),
            )
        )
        round_index += 1
        summary["rounds"] = round_index
        summary["sites_scheduled"] = len(processed_sites)
        summary["unreviewed_sites"] = max(0, len(all_worklist) - len(processed_sites))
        summary["projected_edges"] = len(projected_pairs)

        if site_budget >= 0 and len(processed_sites) >= site_budget:
            summary["termination_reason"] = "max_sites"
            result["status"] = "partial"
            break
        if per_round_budget == 0 and deferred:
            summary["termination_reason"] = "max_sites_per_round"
            result["status"] = "partial"
            break
        if edge_budget >= 0 and len(projected_pairs) >= edge_budget:
            summary["termination_reason"] = "max_edges"
            result["status"] = "partial"
            break
        if llm_budget >= 0 and int(summary["llm_calls"]) >= llm_budget:
            summary["termination_reason"] = "max_llm_calls"
            result["status"] = "partial"
            break

    if not summary["termination_reason"] or summary["termination_reason"] == "not_started":
        if round_index >= normalized_rounds and pending:
            summary["termination_reason"] = "max_rounds"
            result["status"] = "partial"
        else:
            summary["termination_reason"] = "frontier_exhausted"
    elif summary["termination_reason"] == "not_started":
        summary["termination_reason"] = "frontier_exhausted"
    if summary["termination_reason"] == "frontier_exhausted" and summary["failed_rounds"]:
        result["status"] = "partial"

    merged = SemanticGraph()
    for overlay in overlays:
        try:
            graph = SemanticGraph.from_dict(dict(overlay))
        except (TypeError, ValueError) as exc:
            result["errors"].append({
                "type": type(exc).__name__,
                "message": str(exc)[:500],
            })
            result["status"] = "partial"
            continue
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
    result["graph"] = merged.to_dict()
    return result


__all__ = [
    "DEFAULT_MAX_EDGES",
    "DEFAULT_MAX_LLM_CALLS",
    "DEFAULT_MAX_ROUNDS",
    "DEFAULT_MAX_SITES",
    "ROUND_SCHEMA_VERSION",
    "ROUND_TASK",
    "run_iterative_recovery_review",
]
