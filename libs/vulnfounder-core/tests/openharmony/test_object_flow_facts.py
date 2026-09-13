"""P2 第一批：对象/值流事实保持候选层并可审计。"""

from __future__ import annotations

import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.call_graph_facts import refresh_effective_call_graph  # noqa: E402
from core.platforms.openharmony.object_flow_facts import (  # noqa: E402
    build_object_flow_facts,
)


def test_object_flow_facts_normalize_dispatch_callback_and_parameter_records():
    extract = {
        "repository": "/fixture",
        "revision": "r1",
        "functions": {
            "stub.cpp:Stub::OnRequest": {},
            "stub.cpp:Stub::Handle": {},
            "stub.cpp:Stub::Register": {},
        },
    }
    diagnostics = {
        "dispatch_assignments": [
            {
                "owner_function_id": "stub.cpp:Stub::Register",
                "file": "stub.cpp",
                "line": 12,
                "table": "handlers_",
                "selector": "CODE",
                "target_name": "Stub::Handle",
                "target_id": "stub.cpp:Stub::Handle",
                "value_kind": "member_function_pointer",
                "resolution": "exact_function_id",
                "evidence": {"text": "handlers_[CODE] = &Stub::Handle"},
            }
        ],
        "lambda_dispatch": {
            "assignments": [
                {
                    "owner_function_id": "stub.cpp:Stub::Register",
                    "file": "stub.cpp",
                    "line": 13,
                    "table": "callbacks_",
                    "selector": "CODE",
                    "target_name": "Stub::Handle",
                    "target_id": "stub.cpp:Stub::Handle",
                    "capture": "[this]",
                    "lambda_calls": ["Stub::Handle"],
                    "evidence": {"text": "callbacks_[CODE] = [this] { Handle(); }"},
                }
            ]
        },
        "parameter_flows": [
            {
                "source_function_id": "stub.cpp:Stub::Register",
                "callee_id": "stub.cpp:Stub::OnRequest",
                "argument_index": 1,
                "source_table": "handlers",
                "callee_parameter": "table",
                "evidence": {"file": "stub.cpp", "start_line": 14, "text": "OnRequest(code, handlers)"},
            }
        ],
        "unresolved_call_sites": [],
        "call_sites": [],
    }

    result = build_object_flow_facts(extract, diagnostics, {"call_graph": {}})

    kinds = {item["fact_kind"] for item in result["facts"]}
    assert {"dispatch_registration", "callback_registration", "parameter_flow"} <= kinds
    assert result["summary"]["strict_edges_added"] == 0
    assert all(item["status"] == "candidate" for item in result["facts"])
    assert result["candidate_overlay"]["edges"]
    assert all(
        edge["attributes"]["reachability_tier"] == "candidate"
        for edge in result["candidate_overlay"]["edges"]
    )


def test_object_flow_overlay_is_loaded_as_candidate_only(tmp_path):
    native = {
        "functions": {"caller": {}, "target": {}},
        "call_graph": {"caller": []},
        "reverse_call_graph": {},
    }
    (tmp_path / "call_graph.json").write_text(
        json.dumps(native), encoding="utf-8"
    )
    (tmp_path / "object_flow_candidate_overlay.json").write_text(
        json.dumps(
            {
                "graph_type": "openharmony_object_flow_candidate_overlay",
                "source_revision": "unknown",
                "edges": [
                    {
                        "source_id": "caller",
                        "target_id": "target",
                        "resolver": "openharmony_object_flow",
                        "site_id": "object-flow:test",
                        "evidence": {"file": "x.cpp", "start_line": 3, "text": "fn()"},
                        "attributes": {
                            "evidence_quality": "syntax_observation",
                            "reachability_tier": "candidate",
                            "strict_admission": False,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = refresh_effective_call_graph(tmp_path, include_persisted_overlays=False)

    assert result is not None
    assert result["call_graph"].get("caller", []) == []
    assert any(
        item["resolver"] == "openharmony_object_flow"
        for item in result["candidate_facts"]
    )
    assert result["summary"]["overlay_strict_rejected"] == 1


def test_cross_function_summary_and_symbol_frontier_are_candidate_only():
    extract = {
        "repository": "/fixture",
        "revision": "r2",
        "functions": {
            "a.cpp:Demo::Caller": {
                "name": "Demo::Caller",
                "class_name": "Demo",
                "file_path": "a.cpp",
                "start_line": 1,
                "parameters": ["const std::string &input"],
                "code": "void Demo::Caller(const std::string &input) {\n"
                "  auto value = Factory::GetInstance();\n"
                "  auto result = Target(value, input);\n"
                "}\n",
            },
            "b.cpp:Target::Target": {
                "name": "Target::Target",
                "class_name": "Target",
                "file_path": "b.cpp",
                "parameters": ["Value value", "const std::string &input"],
                "code": "void Target::Target(Value value, const std::string &input) {}",
            },
        },
    }
    diagnostics = {
        "call_sites": [
            {
                "site_id": "callsite:target",
                "caller_id": "a.cpp:Demo::Caller",
                "file": "a.cpp",
                "line_start": 3,
                "line_end": 3,
                "expression": "Target(value, input)",
                "callee_spelling": "Target",
                "call_kind": "direct",
                "binding_status": "partial",
                "graph_status": "edge_missing",
                "candidate_target_ids": ["b.cpp:Target::Target", "external:Target::Target"],
                "candidate_completeness": "unknown",
            }
        ],
        "unresolved_call_sites": [],
    }

    result = build_object_flow_facts(extract, diagnostics, {"call_graph": {}})
    kinds = {item["fact_kind"] for item in result["facts"]}
    assert "function_summary" in kinds
    assert "cross_function_argument_flow" in kinds
    assert "cross_function_return_flow" in kinds
    assert any(
        node["id"] == "external:Target::Target"
        and node["attributes"]["symbol_status"] == "declaration_only"
        for node in result["symbol_nodes"]
    )
    assert any(
        edge["target_id"] == "b.cpp:Target::Target"
        and edge["attributes"]["strict_admission"] is False
        for edge in result["candidate_overlay"]["edges"]
    )
    assert result["summary"]["cross_function_fact_count"] >= 2


def test_source_pointer_and_callback_sites_keep_targets_as_candidates():
    extract = {
        "repository": "/fixture",
        "revision": "r3",
        "functions": {
            "demo.cpp:Demo::Register": {
                "name": "Demo::Register",
                "class_name": "Demo",
                "file_path": "demo.cpp",
                "start_line": 1,
                "code": "void Demo::Register() {\n"
                "  using Handler = void(*)();\n"
                "  Handler handler = &Demo::Handle;\n"
                "  handler();\n"
                "  std::thread([this]() { this->Handle(); });\n"
                "}\n",
            },
            "demo.cpp:Demo::Handle": {
                "name": "Demo::Handle",
                "class_name": "Demo",
                "file_path": "demo.cpp",
                "start_line": 10,
                "code": "void Demo::Handle() {}",
            },
        },
    }
    result = build_object_flow_facts(extract, {}, {"call_graph": {}})
    kinds = {item["fact_kind"] for item in result["facts"]}
    assert {"function_pointer_assignment", "function_pointer_call", "callback_registration"} <= kinds
    assert any(item["fact_kind"] == "lambda_invocation" and item["target_id"] == "demo.cpp:Demo::Handle" for item in result["facts"])
    assert all(
        edge["attributes"]["reachability_tier"] == "candidate"
        for edge in result["candidate_overlay"]["edges"]
    )
