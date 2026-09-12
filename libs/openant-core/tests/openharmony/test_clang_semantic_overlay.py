"""Tests for the opt-in Clang semantic edge sidecar."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.clang_semantic_overlay import (  # noqa: E402
    load_clang_semantic_overlay,
)
from core.platforms.openharmony.reachability import (  # noqa: E402
    build_semantic_reachability_overlay,
    merge_reachability_graph,
)
from utilities.agentic_enhancer.reachability_analyzer import (  # noqa: E402
    ReachabilityAnalyzer,
)


CALLER = "sp_thread_socket.cpp:SpThreadSocket::EditorRecv"
TARGET = "control_call_cmd.cpp:ControlCallCmd::GetResult"
REVISION = "19ee2d0950c35b6e5b87b4177540a97639bd1a7e"


FUNCTIONS = {
    CALLER: {
        "name": "SpThreadSocket::EditorRecv",
        "class_name": "SpThreadSocket",
        "file_path": "sp_thread_socket.cpp",
        "start_line": 360,
        "end_line": 381,
        "code": "void SpThreadSocket::EditorRecv() { controlCallCmd.GetResult(vec); }",
        "unit_type": "method",
    },
    TARGET: {
        "name": "ControlCallCmd::GetResult",
        "class_name": "ControlCallCmd",
        "file_path": "control_call_cmd.cpp",
        "start_line": 30,
        "end_line": 70,
        "code": "std::string ControlCallCmd::GetResult(...) { return result; }",
        "unit_type": "method",
    },
}


def _payload(**overrides):
    record = {
        "caller_id": CALLER,
        "callee_id": TARGET,
        "edge_kind": "direct_member_call",
        "resolver": "clang",
        "binding_status": "resolved",
        "source_revision": REVISION,
        "callsite": {
            "file": "sp_thread_socket.cpp",
            "line": 378,
            "expression": "controlCallCmd.GetResult(vec)",
        },
        "evidence": [
            {
                "kind": "call_site",
                "file": "sp_thread_socket.cpp",
                "start_line": 378,
                "end_line": 378,
                "text": "controlCallCmd.GetResult(vec)",
            },
            {
                "kind": "target",
                "file": "control_call_cmd.cpp",
                "start_line": 36,
                "end_line": 65,
                "text": "ControlCallCmd::GetResult",
                "function_id": TARGET,
            },
        ],
    }
    record.update(overrides)
    return {
        "schema_version": 1,
        "source_revision": REVISION,
        "edges": [record],
    }


def test_clang_overlay_accepts_revision_and_source_spans():
    result = load_clang_semantic_overlay(
        _payload(), FUNCTIONS, expected_source_revision=REVISION
    )
    assert result["status"] == "complete"
    assert result["summary"]["projected_edges"] == 1
    assert result["rejected"] == []
    edge = result["edges"][0]
    assert edge["kind"] == "clang_direct_call"
    assert edge["attributes"]["evidence_quality"] == "semantic_binding_validated"
    assert edge["attributes"]["reachability_tier"] == "candidate"
    assert edge["attributes"]["build_admission"] == "candidate_only_manual_or_unknown_context"


def test_clang_overlay_requires_method_consistent_evidence():
    payload = _payload()
    payload["edges"][0]["evidence"][0]["text"] = "otherObject.OtherMethod()"
    result = load_clang_semantic_overlay(payload, FUNCTIONS)
    assert result["summary"]["projected_edges"] == 0
    assert result["rejected"][0]["reason"] == "call_site_evidence_not_verified"


def test_clang_overlay_marks_verified_build_context_strict():
    result = load_clang_semantic_overlay(
        {**_payload(), "build_status": "compile_database"}, FUNCTIONS
    )
    assert result["summary"]["projected_edges"] == 1
    edge = result["edges"][0]
    assert edge["attributes"]["reachability_tier"] == "strict"
    assert edge["attributes"]["build_admission"] == "concrete_configuration_verified"
    assert edge["attributes"]["product_config_verified"] is False


def test_clang_overlay_rejects_revision_mismatch_and_bad_callsite():
    bad_revision = load_clang_semantic_overlay(
        _payload(source_revision="other"),
        FUNCTIONS,
        expected_source_revision=REVISION,
    )
    assert bad_revision["summary"]["projected_edges"] == 0
    assert bad_revision["rejected"][0]["reason"] == "source_revision_mismatch"

    bad_callsite = _payload(
        callsite={
            "file": "sp_thread_socket.cpp",
            "line": 999,
            "expression": "controlCallCmd.GetResult(vec)",
        }
    )
    result = load_clang_semantic_overlay(bad_callsite, FUNCTIONS)
    assert result["summary"]["projected_edges"] == 0
    assert result["rejected"][0]["reason"] == "callsite_outside_caller_span"


def test_clang_overlay_is_additive_and_reaches_target():
    validated = load_clang_semantic_overlay(_payload(), FUNCTIONS)
    overlay = build_semantic_reachability_overlay(validated, FUNCTIONS)
    merged_call, merged_reverse = merge_reachability_graph(
        {CALLER: []}, {}, overlay
    )
    reachable = ReachabilityAnalyzer(
        {CALLER: {}, TARGET: {}}, merged_reverse, {CALLER}
    ).get_all_reachable()
    assert TARGET in reachable
    assert merged_call[CALLER] == [TARGET]


def test_clang_overlay_rejects_unknown_endpoint_without_inventing_node():
    payload = _payload(callee_id="missing.cpp:Nope::method")
    result = load_clang_semantic_overlay(payload, FUNCTIONS)
    assert result["summary"]["projected_edges"] == 0
    assert result["rejected"][0]["reason"] == "endpoint_not_in_function_index"
    assert result["nodes"] == []


def test_clang_overlay_accepts_declaration_only_symbol_node():
    # Keep the call-site quote and declaration name consistent: the overlay
    # checker intentionally rejects a declaration-only target whose method
    # name does not occur in the quoted call.
    target = "external.hpp:External::GetResult"
    payload = _payload(callee_id=target)
    payload["edges"][0]["evidence"][1].update({
        "file": "external.hpp",
        "text": "External::GetResult",
        "function_id": target,
    })
    payload["symbols"] = {
        target: {
            "name": "External::GetResult",
            "file_path": "external.hpp",
            "start_line": 10,
            "end_line": 10,
            "unit_type": "declaration",
        }
    }
    payload["edges"][0]["evidence"][1]["start_line"] = 10
    payload["edges"][0]["evidence"][1]["end_line"] = 10
    result = load_clang_semantic_overlay(payload, FUNCTIONS)

    assert result["summary"]["projected_edges"] == 1
    assert result["summary"]["declaration_only_targets"] == 1
    symbol_nodes = [node for node in result["nodes"] if node["id"] == f"function:{target}"]
    assert symbol_nodes and symbol_nodes[0]["kind"] == "symbol"


def test_clang_overlay_preserves_symbols_without_an_accepted_edge():
    symbol = "generated.cpp:Generated::Handle"
    result = load_clang_semantic_overlay(
        {
            "schema_version": 1,
            "symbols": {
                symbol: {
                    "name": "Generated::Handle",
                    "file_path": "generated.cpp",
                    "start_line": 4,
                    "end_line": 8,
                    "unit_type": "symbol",
                    "index_status": "caller_not_in_function_index",
                }
            },
            "edges": [],
        },
        FUNCTIONS,
    )
    symbol_nodes = [node for node in result["nodes"] if node["id"] == f"function:{symbol}"]
    assert symbol_nodes and symbol_nodes[0]["kind"] == "symbol"
    assert symbol_nodes[0]["attributes"]["index_status"] == "caller_not_in_function_index"
