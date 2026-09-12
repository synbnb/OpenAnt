"""Four-way reachability ablation for fixed OpenHarmony scan artifacts.

The ablation deliberately reuses the same unfiltered dataset and native graph
for all four arms.  Only two switches change:

* whether a validated semantic overlay is present; and
* whether medium-confidence candidate seeds are allowed to expand their
  separate candidate frontier.

This is an offline diagnostic artifact.  It does not call a model and never
modifies the native graph or the caller's dataset.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _unit_ids(units: Any, predicate) -> set[str]:
    if not isinstance(units, list):
        return set()
    return {
        _text(unit.get("id"))
        for unit in units
        if isinstance(unit, Mapping)
        and _text(unit.get("id"))
        and predicate(unit)
    }


def _write_graph(directory: Path, graph: Mapping[str, Any]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "call_graph.json").write_text(
        json.dumps(graph, ensure_ascii=False), encoding="utf-8"
    )


def _run_arm(
    dataset: Mapping[str, Any],
    graph: Mapping[str, Any],
    *,
    platform: str,
    processing_level: str,
    semantic_overlay: Mapping[str, Any] | None,
    candidate_seed_ids: set[str],
) -> dict[str, Any]:
    # Import lazily to keep the report helper usable from lightweight tooling.
    from core.parser_adapter import apply_reachability_filter

    units = dataset.get("units", []) if isinstance(dataset, Mapping) else []
    entry_ids = _unit_ids(
        units,
        lambda unit: unit.get("is_entry_point") is True,
    )
    strict_seed_ids = _unit_ids(
        units,
        lambda unit: unit.get("semantic_reachability_seed") is True,
    )
    with tempfile.TemporaryDirectory(prefix="openant-ablation-") as temp_dir:
        graph_dir = Path(temp_dir)
        _write_graph(graph_dir, graph)
        arm_dataset = copy.deepcopy(dict(dataset))
        # The source dataset may already carry medium markers from a prior
        # pass.  Remove them for *every* arm, then re-introduce only the
        # explicitly requested ``candidate_seed_ids`` through the filter
        # argument below.  Otherwise A/B would accidentally inherit the
        # medium frontier whenever C/D have seeds, invalidating the ablation.
        for unit in arm_dataset.get("units", []):
            if not isinstance(unit, dict):
                continue
            for key in (
                "semantic_reachability_candidate_seed",
                "semantic_reachability_retain_only",
                "reachability_retain_only",
            ):
                unit.pop(key, None)
        filtered = apply_reachability_filter(
            arm_dataset,
            str(graph_dir),
            processing_level,
            extra_entry_points=entry_ids,
            extra_reachability_seeds=strict_seed_ids,
            extra_candidate_reachability_seeds=(
                candidate_seed_ids if candidate_seed_ids else set()
            ),
            platform=platform,
            semantic_graph_overlay=semantic_overlay,
        )
    output_units = filtered.get("units", [])
    metadata = filtered.get("metadata", {})
    reachability = (
        metadata.get("reachability_filter", {})
        if isinstance(metadata, Mapping)
        else {}
    )
    if not isinstance(reachability, Mapping):
        reachability = {}
    strict_ids = {
        _text(unit.get("id"))
        for unit in output_units
        if isinstance(unit, Mapping)
        and _text(unit.get("id"))
        and unit.get("reachability_status") == "strict_reachable"
    }
    candidate_ids = {
        _text(unit.get("id"))
        for unit in output_units
        if isinstance(unit, Mapping)
        and _text(unit.get("id"))
        and unit.get("reachability_status") == "candidate_reachable"
    }
    fallback_only_ids = {
        _text(unit.get("id"))
        for unit in output_units
        if isinstance(unit, Mapping)
        and _text(unit.get("id"))
        and (
            unit.get("analysis_arrangement") == "unfiltered_fallback"
            or unit.get("reachability_status") == "unfiltered_no_strict_seed"
        )
    }
    fallback_triggered = bool(
        reachability.get("reachability_evidence") == "insufficient_seed_evidence"
        or fallback_only_ids
    )
    final_ids = {
        _text(unit.get("id"))
        for unit in output_units
        if isinstance(unit, Mapping) and _text(unit.get("id"))
    }
    return {
        "unit_count": len(output_units),
        "unit_ids": sorted(
            _text(unit.get("id"))
            for unit in output_units
            if isinstance(unit, Mapping) and _text(unit.get("id"))
        ),
        "strict_reachable_count": len(strict_ids),
        "candidate_reachable_count": len(candidate_ids),
        "strict_reachable_ids": sorted(strict_ids),
        "candidate_reachable_ids": sorted(candidate_ids),
        "candidate_reachable_added": int(
            reachability.get("candidate_reachable_added", len(candidate_ids)) or 0
        ),
        "strict_path_coverage_count": len(strict_ids),
        "candidate_path_coverage_count": len(candidate_ids),
        "fallback_only_count": len(fallback_only_ids),
        "fallback_only_ids": sorted(fallback_only_ids),
        "final_analysis_count": len(final_ids),
        "final_analysis_ids": sorted(final_ids),
        "fallback_triggered": fallback_triggered,
        "fallback_reason": (
            reachability.get("warning")
            or reachability.get("reachability_evidence")
            if fallback_triggered
            else ""
        ),
        "filtered_out": int(reachability.get("filtered_out", 0) or 0),
        "reachability_evidence": reachability.get(
            "reachability_evidence", "unknown"
        ),
    }


def run_reachability_ablation(
    dataset: Mapping[str, Any],
    native_graph: Mapping[str, Any],
    *,
    semantic_overlay: Mapping[str, Any] | None = None,
    candidate_seed_ids: Iterable[str] | None = None,
    platform: str = "openharmony",
    processing_level: str = "reachable",
    target_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Run and return the fixed-input A/B/C/D reachability comparison.

    A = native graph without medium candidate propagation
    B = recovered/overlay graph without medium candidate propagation
    C = native graph with medium candidate propagation
    D = recovered/overlay graph with medium candidate propagation
    """
    if not isinstance(dataset, Mapping):
        raise TypeError("dataset must be an object")
    if not isinstance(native_graph, Mapping):
        raise TypeError("native_graph must be an object")
    seeds = {
        _text(value)
        for value in (candidate_seed_ids or [])
        if _text(value)
    }
    known_ids = {
        _text(unit.get("id"))
        for unit in dataset.get("units", [])
        if isinstance(unit, Mapping) and _text(unit.get("id"))
    }
    seeds &= known_ids
    arms = {
        "A_native_without_medium": (None, set()),
        "B_recovered_without_medium": (semantic_overlay, set()),
        "C_native_with_medium": (None, seeds),
        "D_recovered_with_medium": (semantic_overlay, seeds),
    }
    results = {
        name: _run_arm(
            dataset,
            native_graph,
            platform=platform,
            processing_level=processing_level,
            semantic_overlay=overlay,
            candidate_seed_ids=arm_seeds,
        )
        for name, (overlay, arm_seeds) in arms.items()
    }
    requested_targets = sorted(
        {
            _text(value)
            for value in (target_ids or [])
            if _text(value) in known_ids
        }
    )
    target_matrix = {
        target_id: {
            arm: (
                "strict"
                if target_id in result.get("strict_reachable_ids", [])
                else "candidate"
                if target_id in result.get("candidate_reachable_ids", [])
                else "fallback-only"
                if target_id in result.get("fallback_only_ids", [])
                else "not_retained"
            )
            for arm, result in results.items()
        }
        for target_id in requested_targets
    }
    return {
        "schema_version": 1,
        "task": "openharmony_reachability_four_way_ablation",
        "platform": platform,
        "processing_level": processing_level,
        "fixed_input": {
            "dataset_units": len(dataset.get("units", [])),
            "native_graph_functions": len(native_graph.get("functions", {}))
            if isinstance(native_graph.get("functions"), Mapping)
            else 0,
            "native_graph_edges": sum(
                len(targets)
                for targets in (native_graph.get("call_graph", {}) or {}).values()
                if isinstance(targets, list)
            )
            if isinstance(native_graph.get("call_graph"), Mapping)
            else 0,
            "semantic_overlay_present": isinstance(semantic_overlay, Mapping),
            "candidate_seed_ids": sorted(seeds),
        },
        "arms": results,
        "target_matrix": target_matrix,
    }


def write_reachability_ablation(
    path: str | Path,
    dataset: Mapping[str, Any],
    native_graph: Mapping[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """Run the comparison and write one JSON artifact."""
    report = run_reachability_ablation(dataset, native_graph, **kwargs)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report


__all__ = ["run_reachability_ablation", "write_reachability_ablation"]
