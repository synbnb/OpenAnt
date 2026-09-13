"""Fixed-input four-way reachability ablation tests."""

from __future__ import annotations

from core.reachability_ablation import run_reachability_ablation


def test_four_way_ablation_separates_overlay_and_medium_frontier():
    entry = "a:main"
    medium = "a:medium"
    child = "a:child"
    recovered = "a:recovered"
    dead = "a:dead"
    graph = {
        "functions": {
            item: {
                "name": item,
                "unit_type": "main" if item == entry else "function",
            }
            for item in (entry, medium, child, recovered, dead)
        },
        "call_graph": {entry: [], medium: [child]},
        "reverse_call_graph": {child: [medium]},
    }
    dataset = {
        "units": [
            {"id": entry, "is_entry_point": True},
            {"id": medium, "semantic_reachability_candidate_seed": True},
            {"id": child},
            {"id": recovered},
            {"id": dead},
        ],
        "metadata": {},
    }
    overlay = {
        "edges": [
            {
                "source_id": f"function:{entry}",
                "target_id": f"function:{recovered}",
                "kind": "llm_confirmed_indirect_call",
            }
        ]
    }

    report = run_reachability_ablation(
        dataset,
        graph,
        semantic_overlay=overlay,
        candidate_seed_ids=[medium],
        target_ids=[child, recovered],
    )

    assert child not in report["arms"]["A_native_without_medium"]["unit_ids"]
    assert child in report["arms"]["C_native_with_medium"]["unit_ids"]
    assert recovered not in report["arms"]["A_native_without_medium"]["unit_ids"]
    assert recovered in report["arms"]["B_recovered_without_medium"]["unit_ids"]
    assert report["target_matrix"][child]["C_native_with_medium"] == "candidate"
    assert report["target_matrix"][recovered]["B_recovered_without_medium"] == "strict"


def test_four_way_ablation_labels_no_strict_seed_as_fallback_only():
    medium = "a:medium"
    child = "a:child"
    graph = {
        "functions": {
            medium: {"name": medium, "unit_type": "function"},
            child: {"name": child, "unit_type": "function"},
        },
        "call_graph": {medium: [child]},
        "reverse_call_graph": {child: [medium]},
    }
    dataset = {
        "units": [
            {"id": medium, "semantic_reachability_candidate_seed": True},
            {"id": child},
        ],
        "metadata": {},
    }

    report = run_reachability_ablation(
        dataset,
        graph,
        candidate_seed_ids=[medium],
        target_ids=[medium, child],
    )

    assert report["arms"]["A_native_without_medium"]["fallback_triggered"] is True
    assert report["target_matrix"][medium]["A_native_without_medium"] == (
        "fallback-only"
    )
    assert report["target_matrix"][child]["C_native_with_medium"] == "candidate"
    assert report["arms"]["C_native_with_medium"]["fallback_only_count"] == 0


def test_candidate_tier_overlay_does_not_bridge_candidate_bfs():
    entry = "a:main"
    medium = "a:medium"
    recovered = "a:recovered"
    graph = {
        "functions": {
            entry: {"name": entry, "unit_type": "main"},
            medium: {"name": medium, "unit_type": "function"},
            recovered: {"name": recovered, "unit_type": "function"},
        },
        "call_graph": {entry: [], medium: []},
        "reverse_call_graph": {},
    }
    dataset = {
        "units": [
            {"id": entry, "is_entry_point": True},
            {"id": medium, "semantic_reachability_candidate_seed": True},
            {"id": recovered},
        ],
        "metadata": {},
    }
    overlay = {
        "edges": [
            {
                "source_id": f"function:{entry}",
                "target_id": f"function:{recovered}",
                "kind": "llm_confirmed_indirect_call",
                "attributes": {"reachability_tier": "candidate"},
            }
        ]
    }

    report = run_reachability_ablation(
        dataset,
        graph,
        semantic_overlay=overlay,
        candidate_seed_ids=[medium],
        target_ids=[recovered],
    )

    assert report["target_matrix"][recovered]["B_recovered_without_medium"] == (
        "not_retained"
    )
    assert report["target_matrix"][recovered]["D_recovered_with_medium"] == (
        "not_retained"
    )
