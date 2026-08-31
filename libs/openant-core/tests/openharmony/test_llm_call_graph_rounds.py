"""Tests for entry-driven, bounded OpenHarmony recovery rounds."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.llm_call_graph_recovery import (  # noqa: E402
    build_recovery_worklist,
)
from core.platforms.openharmony.llm_call_graph_rounds import (  # noqa: E402
    run_iterative_recovery_review,
)


SOURCE = "services/network/net_stub.cpp"
ENTRY = f"{SOURCE}:NetStub::OnRemoteRequest"
HANDLER = f"{SOURCE}:NetStub::HandleRequest"
LEAF = f"{SOURCE}:NetStub::FinishRequest"


def _functions(*, two_entry_sites: bool = False) -> dict[str, dict]:
    entry_expression = "return dispatchHandler(data);"
    functions = {
        ENTRY: {
            "name": "NetStub::OnRemoteRequest",
            "file_path": SOURCE,
            "start_line": 10,
            "end_line": 16,
            "class_name": "NetStub",
            "is_entry_point": True,
            "code": (
                "int32_t NetStub::OnRemoteRequest() { "
                f"{entry_expression} }}"
            ),
        },
        HANDLER: {
            "name": "NetStub::HandleRequest",
            "file_path": SOURCE,
            "start_line": 20,
            "end_line": 26,
            "class_name": "NetStub",
            "code": "int32_t NetStub::HandleRequest() { return finishHandler(data); }",
        },
        LEAF: {
            "name": "NetStub::FinishRequest",
            "file_path": SOURCE,
            "start_line": 30,
            "end_line": 34,
            "class_name": "NetStub",
            "code": "int32_t NetStub::FinishRequest() { return 0; }",
        },
    }
    if two_entry_sites:
        functions[f"{SOURCE}:NetStub::OtherHandler"] = {
            "name": "NetStub::OtherHandler",
            "file_path": SOURCE,
            "start_line": 40,
            "end_line": 44,
            "class_name": "NetStub",
            "code": "int32_t NetStub::OtherHandler() { return 0; }",
        }
    return functions


def _diagnostics(*, two_entry_sites: bool = False) -> dict:
    sites = [
        {
            "caller_id": ENTRY,
            "file": SOURCE,
            "line": 12,
            "expression": "return dispatchHandler(data);",
            "reason": "unknown_function_pointer",
            "candidate_target_ids": [],
        },
        {
            "caller_id": HANDLER,
            "file": SOURCE,
            "line": 22,
            "expression": "return finishHandler(data);",
            "reason": "unknown_function_pointer",
            "candidate_target_ids": [],
        },
    ]
    if two_entry_sites:
        sites.insert(
            1,
            {
                "caller_id": ENTRY,
                "file": SOURCE,
                "line": 13,
                "expression": "return dispatchHandler(data, reply);",
                "reason": "second_unknown_function_pointer",
                "candidate_target_ids": [],
            },
        )
    return {"unresolved_call_sites": sites}


def _completion_for(functions: dict[str, dict], diagnostics: dict):
    worklist = build_recovery_worklist(diagnostics, functions, max_sites=-1)
    by_site = {item["site_id"]: item for item in worklist}
    targets = {
        ENTRY: HANDLER,
        HANDLER: LEAF,
    }

    def completion(prompt: str) -> str:
        site_id = re.findall(r'"site_id": "([^"]+)"', prompt)[-1]
        item = by_site[site_id]
        target_id = targets[item["caller_id"]]
        target = functions[target_id]
        return json.dumps(
            {
                "schema_version": 1,
                "decisions": [
                    {
                        "site_id": site_id,
                        "decision": "add_edge",
                        "target_id": target_id,
                        "confidence": "high",
                        "reason": "The bounded local dispatch resolves to this indexed target.",
                        "evidence": [
                            {
                                "kind": "call_site",
                                "file": item["file"],
                                "start_line": item["line"],
                                "end_line": item["line"],
                                "text": item["expression"],
                            },
                            {
                                "kind": "target",
                                "function_id": target_id,
                                "file": target["file_path"],
                                "start_line": target["start_line"],
                                "end_line": target["end_line"],
                                "text": target["name"],
                            },
                        ],
                    }
                ],
            }
        )

    return completion


def test_two_hop_recovery_only_expands_after_projected_edge():
    functions = _functions()
    report = run_iterative_recovery_review(
        _diagnostics(),
        functions,
        completion=_completion_for(functions, _diagnostics()),
        max_rounds=4,
        max_sites_per_round=10,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "complete"
    assert report["entry_point_ids"] == [ENTRY]
    assert report["summary"]["rounds"] == 2
    assert report["summary"]["sites_scheduled"] == 2
    assert report["summary"]["sites_reviewed"] == 2
    assert report["summary"]["projected_edges"] == 2
    assert report["summary"]["llm_calls"] == 2
    assert report["summary"]["termination_reason"] == "frontier_exhausted"
    assert [item["frontier_function_ids"] for item in report["rounds"]] == [
        [ENTRY],
        [HANDLER],
    ]
    assert sorted([
        (edge["source_id"], edge["target_id"])
        for edge in report["graph"]["edges"]
    ]) == sorted([
        (f"function:{ENTRY}", f"function:{HANDLER}"),
        (f"function:{HANDLER}", f"function:{LEAF}"),
    ])


def test_native_edge_reaches_residual_without_llm_edge_on_entry():
    functions = _functions()
    diagnostics = {
        "unresolved_call_sites": [
            {
                "caller_id": HANDLER,
                "file": SOURCE,
                "line": 22,
                "expression": "return finishHandler(data);",
                "reason": "unknown_function_pointer",
                "candidate_target_ids": [],
            }
        ]
    }
    report = run_iterative_recovery_review(
        diagnostics,
        functions,
        call_graph={ENTRY: [HANDLER]},
        completion=_completion_for(functions, diagnostics),
        max_rounds=4,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "complete"
    assert report["summary"]["rounds"] == 2
    assert report["summary"]["llm_calls"] == 1
    assert report["rounds"][0]["site_ids"] == []
    assert report["rounds"][1]["frontier_function_ids"] == [HANDLER]
    assert report["summary"]["projected_edges"] == 1


def test_stops_after_reachable_residuals_are_processed():
    functions = _functions()
    diagnostics = {
        "unresolved_call_sites": [
            {
                "caller_id": ENTRY,
                "file": SOURCE,
                "line": 12,
                "expression": "return dispatchHandler(data);",
                "reason": "unknown_function_pointer",
                "candidate_target_ids": [],
            }
        ]
    }
    report = run_iterative_recovery_review(
        diagnostics,
        functions,
        call_graph={ENTRY: [HANDLER], HANDLER: [LEAF], LEAF: []},
        completion=_completion_for(functions, diagnostics),
        max_rounds=4,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "complete"
    assert report["summary"]["rounds"] == 1
    assert report["summary"]["llm_calls"] == 1
    assert report["summary"]["unreviewed_sites"] == 0
    assert report["summary"]["termination_reason"] == "frontier_exhausted"
    assert report["rounds"][0]["frontier_function_ids"] == [ENTRY]


def test_per_round_site_budget_requeues_expanded_caller_for_deferred_sites():
    functions = _functions(two_entry_sites=True)
    diagnostics = _diagnostics(two_entry_sites=True)

    # Both entry residuals intentionally resolve to the same indexed handler;
    # the scheduler must still review both source spans in separate rounds.
    report = run_iterative_recovery_review(
        diagnostics,
        functions,
        completion=_completion_for(functions, diagnostics),
        max_rounds=3,
        max_sites_per_round=1,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "complete"
    assert report["summary"]["sites_scheduled"] == 3
    assert report["summary"]["sites_reviewed"] == 3
    assert report["rounds"][0]["deferred_site_count"] == 1
    assert set(report["rounds"][1]["frontier_function_ids"]) == {ENTRY, HANDLER}


def test_missing_entry_points_never_invokes_model():
    functions = _functions()
    for function in functions.values():
        function.pop("is_entry_point", None)
    calls: list[str] = []

    def completion(prompt: str) -> str:
        calls.append(prompt)
        return "{}"

    report = run_iterative_recovery_review(
        _diagnostics(),
        functions,
        completion=completion,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "no_entry_points"
    assert report["summary"]["termination_reason"] == "no_entry_points"
    assert calls == []
