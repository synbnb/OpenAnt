"""Tests for the P1 Clang batch acceptance report."""

from __future__ import annotations

from core.platforms.openharmony.clang_p1_validation import (
    build_clang_batch_acceptance_report,
)


def test_report_keeps_manual_context_candidate_only_and_counts_scope():
    ledger = {
        "call_sites": [
            {
                "site_id": "site:1",
                "caller_id": "a.cpp:Caller",
                "file": "a.cpp",
                "line_start": 10,
                "line_end": 10,
                "expression": "obj.run()",
                "binding_status": "resolved",
                "graph_status": "edge_missing",
                "candidate_target_ids": ["b.cpp:Target::run"],
            },
            {
                "site_id": "site:2",
                "caller_id": "outside.cpp:Other",
                "file": "outside.cpp",
                "line_start": 4,
                "line_end": 4,
                "expression": "other()",
                "binding_status": "resolved",
                "graph_status": "edge_missing",
                "candidate_target_ids": [],
            },
        ]
    }
    gap = {
        "sites": [
            {
                "site_id": "site:1",
                "caller_id": "a.cpp:Caller",
                "file": "a.cpp",
                "line_start": 10,
                "line_end": 10,
                "expression": "obj.run()",
                "ledger_unrepaired": True,
                "reason_codes": ["edge_missing"],
            },
            {
                "site_id": "site:2",
                "caller_id": "outside.cpp:Other",
                "file": "outside.cpp",
                "line_start": 4,
                "line_end": 4,
                "expression": "other()",
                "ledger_unrepaired": True,
                "reason_codes": ["edge_missing"],
            },
        ]
    }
    batch = {
        "repository": "fixture",
        "source_revision": "rev",
        "build_status": "manual_rebuild",
        "file_results": [{"file": "a.cpp"}],
        "batch_summary": {"caller_not_in_index": 1},
        "summary": {"projected_edges": 1},
        "edges": [
            {
                "source_id": "function:a.cpp:Caller",
                "target_id": "function:b.cpp:Target::run",
                "attributes": {
                    "call_site": {
                        "file": "a.cpp",
                        "line": 10,
                        "expression": "obj.run()",
                    },
                    "edge_kind": "direct_member_call",
                    "resolver": "clang",
                    "binding_status": "resolved",
                    "reachability_tier": "candidate",
                    "build_status": "manual_rebuild",
                    "build_admission": "candidate_only_manual_or_unknown_context",
                },
            }
        ],
        "unindexed_calls": [],
        "rejected": [],
    }
    report = build_clang_batch_acceptance_report(ledger, gap, batch)
    assert report["scope"]["unresolved_input_sites"] == 2
    assert report["scope"]["unresolved_sites_in_batch_scope"] == 1
    assert report["build_context"]["admission"] == "candidate_only"
    assert report["unresolved_site_outcomes"]["counts"] == {
        "outside_batch_scope": 1,
        "semantic_fact_observed_candidate_only": 1,
    }
