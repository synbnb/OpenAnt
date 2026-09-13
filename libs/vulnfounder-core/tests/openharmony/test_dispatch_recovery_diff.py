"""OH-22E-1: deterministic dispatch-recovery diff and reachability checks."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.dispatch_recovery_diff import (  # noqa: E402
    build_dispatch_recovery_diff,
)


ENTRY = "app.cpp:Main"
STUB = "service.cpp:ServiceStub::OnRemoteRequest"
EXISTING = "service.cpp:ServiceStub::Validate"
HANDLER = "service.cpp:Service::Enable"
DEAD = "service.cpp:unused"
TX = "idl:transaction:OHOS.IService:ENABLE"


def _semantic_graph() -> dict:
    return {
        "schema_version": 1,
        "nodes": [
            {"id": f"function:{STUB}", "kind": "function"},
            {"id": TX, "kind": "ipc_transaction"},
            {"id": f"function:{HANDLER}", "kind": "function"},
        ],
        "edges": [
            {
                "source_id": f"function:{STUB}",
                "target_id": TX,
                "kind": "stub_to_transaction",
                "confidence": 0.91,
                "evidence": [{"file": "service.idl", "line": 8}],
            },
            {
                "source_id": TX,
                "target_id": f"function:{HANDLER}",
                "kind": "transaction_to_handler",
                "confidence": 0.95,
                "evidence": [{"file": "service_stub.cpp", "line": 42}],
            },
        ],
        "orphans": [],
    }


def _diagnostics() -> dict:
    return {
        "summary": {
            "unresolved_call_sites": 1,
            "candidate_edges": 1,
            "unresolved_without_candidates": 0,
            "orphan_assignments": 0,
        },
        "unresolved_call_sites": [
            {
                "caller_id": STUB,
                "file": "service.cpp",
                "line": 42,
                "expression": "(this->*member)(data, reply)",
                "reason": "parenthesized_member_function_pointer",
                "candidate_target_ids": [HANDLER],
                "candidates": [
                    {
                        "target_id": HANDLER,
                        "target_name": "ServiceStub::Enable",
                        "evidence": {"file": "service.cpp", "line": 12},
                    }
                ],
            }
        ],
        "dispatch_assignments": [],
        "orphans": [],
        "lambda_dispatch": {
            "call_sites": [
                {
                    "caller_id": STUB,
                    "file": "service.cpp",
                    "line": 50,
                    "expression": "callback(data)",
                    "reason": "lookup_derived_callable",
                    "candidate_target_ids": [],
                    "candidates": [],
                }
            ],
            "orphans": [
                {
                    "owner_function_id": STUB,
                    "file": "service.cpp",
                    "line": 10,
                    "target_name": "MissingHandler",
                    "reason": "unknown_target_function",
                }
            ],
        },
    }


def test_diff_reports_new_projected_edges_and_all_residual_kinds_deterministically():
    call_graph = {
        "functions": {item: {} for item in (ENTRY, STUB, EXISTING, HANDLER, DEAD)},
        "call_graph": {ENTRY: [STUB], STUB: [EXISTING]},
        "reverse_call_graph": {STUB: [ENTRY], EXISTING: [STUB]},
    }
    diagnostics = _diagnostics()
    semantic_graph = _semantic_graph()
    before = copy.deepcopy((call_graph, diagnostics, semantic_graph))

    report = build_dispatch_recovery_diff(
        call_graph,
        diagnostics,
        semantic_graph,
        baseline_reachable={ENTRY, STUB, EXISTING},
        recovered_reachable={ENTRY, STUB, EXISTING, HANDLER},
    )

    assert (call_graph, diagnostics, semantic_graph) == before
    assert report["schema_version"] == 1
    assert report["platform"] == "openharmony"
    assert report["status"] == "complete"
    assert report["native_edges"] == [
        {"source_id": ENTRY, "target_id": STUB},
        {"source_id": STUB, "target_id": EXISTING},
    ]
    assert report["projected_edges"] == [
        {
            "source_id": STUB,
            "target_id": HANDLER,
            "edge_kinds": ["stub_to_transaction", "transaction_to_handler"],
            "is_new": True,
        }
    ]
    assert report["added_edges"] == [
        {
            "source_id": STUB,
            "target_id": HANDLER,
            "edge_kinds": ["stub_to_transaction", "transaction_to_handler"],
        }
    ]
    assert report["residual_sites"] == [
        {
            "dispatch_kind": "native",
            "caller_id": STUB,
            "file": "service.cpp",
            "line": 42,
            "expression": "(this->*member)(data, reply)",
            "reason": "parenthesized_member_function_pointer",
            "candidate_target_ids": [HANDLER],
            "candidate_count": 1,
        },
        {
            "dispatch_kind": "lambda",
            "caller_id": STUB,
            "file": "service.cpp",
            "line": 50,
            "expression": "callback(data)",
            "reason": "lookup_derived_callable",
            "candidate_target_ids": [],
            "candidate_count": 0,
        },
    ]
    assert report["orphans"] == [
        {
            "dispatch_kind": "lambda",
            "owner_function_id": STUB,
            "file": "service.cpp",
            "line": 10,
            "target_name": "MissingHandler",
            "reason": "unknown_target_function",
        }
    ]
    assert report["summary"] == {
        "native_edge_count": 2,
        "projected_edge_count": 1,
        "new_edge_count": 1,
        "retained_edge_count": 0,
        "residual_site_count": 2,
        "residual_sites_with_candidates": 1,
        "residual_sites_without_candidates": 1,
        "candidate_edge_count": 1,
        "orphan_count": 1,
        "semantic_edge_count": 2,
    }
    assert report["reachability"] == {
        "status": "preserved",
        "baseline_count": 3,
        "recovered_count": 4,
        "added_function_ids": [HANDLER],
        "removed_function_ids": [],
        "missing_from_recovered": [],
    }


def test_diff_marks_reachability_violation_without_mutating_sets():
    baseline = {ENTRY, STUB, EXISTING}
    recovered = {ENTRY, STUB}

    report = build_dispatch_recovery_diff(
        {"functions": {}, "call_graph": {}, "reverse_call_graph": {}},
        {},
        None,
        baseline_reachable=baseline,
        recovered_reachable=recovered,
    )

    assert report["reachability"] == {
        "status": "violation",
        "baseline_count": 3,
        "recovered_count": 2,
        "added_function_ids": [],
        "removed_function_ids": [EXISTING],
        "missing_from_recovered": [EXISTING],
    }
    assert baseline == {ENTRY, STUB, EXISTING}
    assert recovered == {ENTRY, STUB}


def test_diff_can_report_unavailable_reachability_and_ignores_malformed_records():
    report = build_dispatch_recovery_diff(
        {
            "functions": {ENTRY: {}},
            "call_graph": {ENTRY: [None, ""]},
            "reverse_call_graph": {None: [ENTRY], "": [ENTRY]},
        },
        {
            "unresolved_call_sites": [None, {"caller_id": ENTRY}],
            "lambda_dispatch": {"call_sites": ["bad"], "orphans": [None]},
            "orphans": ["bad"],
        },
        {"nodes": [], "edges": [], "orphans": []},
    )

    assert report["reachability"] == {
        "status": "not_evaluated",
        "baseline_count": None,
        "recovered_count": None,
        "added_function_ids": [],
        "removed_function_ids": [],
        "missing_from_recovered": [],
    }
    assert report["native_edges"] == []
    assert report["residual_sites"] == []
    assert report["orphans"] == []
    assert report["summary"]["native_edge_count"] == 0
