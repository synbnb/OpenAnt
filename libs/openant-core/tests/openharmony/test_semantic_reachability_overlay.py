"""Tests for additive OpenHarmony semantic reachability edges.

The native C/C++ call graph remains the source of truth for ordinary calls.
These tests pin the narrower contract for semantic IPC edges: a valid
``function -> transaction -> function`` path may add a temporary reachability
edge, but it must never remove a function that was reachable natively.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
C_PARSER_ROOT = CORE_ROOT / "parsers" / "c"
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))
if str(C_PARSER_ROOT) not in sys.path:
    sys.path.insert(0, str(C_PARSER_ROOT))

from core.platforms.openharmony.reachability import (  # noqa: E402
    build_semantic_reachability_overlay,
    merge_reachability_graph,
)
from utilities.agentic_enhancer.reachability_analyzer import (  # noqa: E402
    ReachabilityAnalyzer,
)


ENTRY = "app.cpp:Main"
STUB = "service.cpp:ServiceStub::OnRemoteRequest"
HANDLER = "service.cpp:Service::Enable"
NATIVE = "service.cpp:Service::Validate"
DEAD = "service.cpp:unused"
TX = "idl:transaction:OHOS.IService:ENABLE"


def _semantic_graph(*, include_interface_edge: bool = False) -> dict:
    edges = [
        {
            "source_id": f"function:{STUB}",
            "target_id": TX,
            "kind": "stub_to_transaction",
        },
        {
            "source_id": TX,
            "target_id": f"function:{HANDLER}",
            "kind": "transaction_to_handler",
        },
    ]
    if include_interface_edge:
        edges.insert(
            0,
            {
                "source_id": "interface:OHOS.IService",
                "target_id": TX,
                "kind": "interface_to_transaction",
            },
        )
    return {
        "schema_version": 1,
        "nodes": [
            {"id": f"function:{STUB}", "kind": "function"},
            {"id": TX, "kind": "ipc_transaction"},
            {"id": f"function:{HANDLER}", "kind": "function"},
        ],
        "edges": edges,
    }


def test_semantic_ipc_path_adds_native_function_edge():
    known = {ENTRY, STUB, HANDLER, NATIVE, DEAD}
    overlay = build_semantic_reachability_overlay(_semantic_graph(), known)

    assert overlay["edges"] == [
        {
            "source_id": STUB,
            "target_id": HANDLER,
            "edge_kinds": ["stub_to_transaction", "transaction_to_handler"],
        }
    ]

    native_reverse = {STUB: [ENTRY], NATIVE: [ENTRY]}
    native_call = {ENTRY: [STUB, NATIVE]}
    merged_call, merged_reverse = merge_reachability_graph(
        native_call, native_reverse, overlay
    )

    native_reachable = ReachabilityAnalyzer(
        {func_id: {} for func_id in known}, native_reverse, {ENTRY}
    ).get_all_reachable()
    combined_reachable = ReachabilityAnalyzer(
        {func_id: {} for func_id in known}, merged_reverse, {ENTRY}
    ).get_all_reachable()

    assert merged_call[STUB] == [HANDLER]
    assert merged_reverse[HANDLER] == [STUB]
    assert native_reachable <= combined_reachable
    assert combined_reachable == {ENTRY, STUB, HANDLER, NATIVE}


def test_interface_only_edges_are_not_used_and_overlay_is_monotonic():
    known = {ENTRY, STUB, HANDLER, NATIVE, DEAD}
    overlay = build_semantic_reachability_overlay(
        _semantic_graph(include_interface_edge=True), known
    )
    assert all(
        edge["source_id"] != "interface:OHOS.IService"
        for edge in overlay["edges"]
    )

    native_reverse = {NATIVE: [ENTRY]}
    _, merged_reverse = merge_reachability_graph({}, native_reverse, overlay)
    native_reachable = ReachabilityAnalyzer(
        {func_id: {} for func_id in known}, native_reverse, {ENTRY}
    ).get_all_reachable()
    combined_reachable = ReachabilityAnalyzer(
        {func_id: {} for func_id in known}, merged_reverse, {ENTRY}
    ).get_all_reachable()

    assert native_reachable <= combined_reachable
    assert HANDLER not in combined_reachable


def test_transaction_handler_edge_can_seed_external_ipc_entry_point():
    """A missing generated Stub node must not hide a validated service handler."""
    graph = {
        "nodes": [
            {"id": TX, "kind": "ipc_transaction"},
            {"id": f"function:{HANDLER}", "kind": "function"},
        ],
        "edges": [
            {
                "source_id": TX,
                "target_id": f"function:{HANDLER}",
                "kind": "transaction_to_handler",
            },
        ],
    }
    overlay = build_semantic_reachability_overlay(graph, {HANDLER, DEAD})

    assert overlay["edges"] == []
    assert overlay["entry_points"] == [HANDLER]
    _, merged_reverse = merge_reachability_graph({}, {}, overlay)
    reachable = ReachabilityAnalyzer(
        {HANDLER: {}, DEAD: {}}, merged_reverse, set(overlay["entry_points"])
    ).get_all_reachable()
    assert HANDLER in reachable
    assert DEAD not in reachable


def test_compact_semantic_graph_without_nodes_keeps_explicit_function_endpoints():
    compact_graph = _semantic_graph()
    compact_graph.pop("nodes")
    overlay = build_semantic_reachability_overlay(
        compact_graph, {STUB, HANDLER}
    )
    assert overlay["candidate_edges"] == 1
    assert overlay["edges"][0]["source_id"] == STUB
    assert overlay["edges"][0]["target_id"] == HANDLER


def _load_c_pipeline():
    pipeline_path = C_PARSER_ROOT / "test_pipeline.py"
    spec = importlib.util.spec_from_file_location(
        "isolated_c_semantic_reachability_pipeline", pipeline_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_parser_adapter():
    parser_adapter_path = CORE_ROOT / "core" / "parser_adapter.py"
    spec = importlib.util.spec_from_file_location(
        "isolated_openharmony_semantic_parser_adapter", parser_adapter_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_c_reachability_filter_uses_semantic_overlay_without_pruning_native_units(
    tmp_path,
):
    pipeline_module = _load_c_pipeline()
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    functions = {
        ENTRY: {"name": "Main", "unit_type": "main", "code": "dispatch();"},
        STUB: {"name": "OnRemoteRequest", "unit_type": "method", "code": ""},
        HANDLER: {"name": "Enable", "unit_type": "method", "code": ""},
        DEAD: {"name": "unused", "unit_type": "function", "code": ""},
    }
    call_graph = {
        "functions": functions,
        "call_graph": {ENTRY: [STUB]},
        "reverse_call_graph": {STUB: [ENTRY]},
    }
    units = [
        {
            "id": unit_id,
            "metadata": {
                "direct_calls": [STUB] if unit_id == ENTRY else [],
                "direct_callers": [ENTRY] if unit_id == STUB else [],
            },
        }
        for unit_id in (ENTRY, STUB, HANDLER, DEAD)
    ]
    (output_dir / "analyzer.json").write_text(json.dumps({"functions": functions}))
    (output_dir / "call_graph.json").write_text(json.dumps(call_graph))
    (output_dir / "dataset.json").write_text(json.dumps({"units": units}))
    (output_dir / "semantic_graph.json").write_text(json.dumps(_semantic_graph()))

    pipeline = pipeline_module.CPipelineTest(
        str(tmp_path),
        output_dir=str(output_dir),
        processing_level=pipeline_module.ProcessingLevel.REACHABLE,
        platform="openharmony",
    )
    pipeline.analyzer_output_file = str(output_dir / "analyzer.json")
    pipeline.dataset_file = str(output_dir / "dataset.json")
    pipeline.call_graph_file = str(output_dir / "call_graph.json")
    pipeline.semantic_graph_file = str(output_dir / "semantic_graph.json")

    assert pipeline.apply_reachability_filter() is True
    dataset = json.loads((output_dir / "dataset.json").read_text())
    ids = {unit["id"] for unit in dataset["units"]}
    assert ids == {ENTRY, STUB, HANDLER}
    assert DEAD not in ids

    metadata = dataset["metadata"]["reachability_filter"]
    assert metadata["native_reachable_units"] == 2
    assert metadata["semantic_reachable_added"] == 1
    assert metadata["semantic_overlay"]["edges_added"] == 1
    assert metadata["semantic_overlay"]["monotonicity_violation"] is False


def test_generic_parser_adapter_openharmony_overlay_is_additive(tmp_path):
    parser_adapter = _load_parser_adapter()
    bridge = "adapter.cpp:bridge"
    handler = "adapter.cpp:handle"
    dead = "adapter.cpp:dead"
    entry = "adapter.cpp:main"
    tx = "idl:transaction:OHOS.IAdapter:BRIDGE"
    functions = {
        entry: {"name": "main", "unit_type": "main", "code": "bridge();"},
        bridge: {"name": "bridge", "unit_type": "function", "code": ""},
        handler: {"name": "handle", "unit_type": "function", "code": ""},
        dead: {"name": "dead", "unit_type": "function", "code": ""},
    }
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": functions,
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
            }
        )
    )
    (tmp_path / "semantic_graph.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": f"function:{bridge}", "kind": "function"},
                    {"id": tx, "kind": "ipc_transaction"},
                    {"id": f"function:{handler}", "kind": "function"},
                ],
                "edges": [
                    {
                        "source_id": f"function:{bridge}",
                        "target_id": tx,
                        "kind": "stub_to_transaction",
                    },
                    {
                        "source_id": tx,
                        "target_id": f"function:{handler}",
                        "kind": "transaction_to_handler",
                    },
                ],
            }
        )
    )
    dataset = {
        "units": [{"id": item} for item in (entry, bridge, handler, dead)],
        "metadata": {},
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset,
        str(tmp_path),
        "reachable",
        platform="openharmony",
    )

    assert {unit["id"] for unit in filtered["units"]} == {entry, bridge, handler}
    metadata = filtered["metadata"]["reachability_filter"]
    assert metadata["native_reachable_units"] == 2
    assert metadata["semantic_reachable_added"] == 1
    assert metadata["semantic_overlay"]["edges_added"] == 1
    assert metadata["semantic_overlay"]["monotonicity_violation"] is False


def test_generic_parser_adapter_ignores_openharmony_semantic_graph(tmp_path):
    parser_adapter = _load_parser_adapter()
    entry = "generic.cpp:main"
    bridge = "generic.cpp:bridge"
    handler = "generic.cpp:handle"
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": {
                    entry: {"name": "main", "unit_type": "main", "code": ""},
                    bridge: {"name": "bridge", "unit_type": "function", "code": ""},
                    handler: {"name": "handle", "unit_type": "function", "code": ""},
                },
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
            }
        )
    )
    (tmp_path / "semantic_graph.json").write_text(json.dumps(_semantic_graph()))
    dataset = {
        "units": [{"id": item} for item in (entry, bridge, handler)],
        "metadata": {},
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset, str(tmp_path), "reachable", platform="generic"
    )

    assert {unit["id"] for unit in filtered["units"]} == {entry, bridge}
    assert "semantic_overlay" not in filtered["metadata"]["reachability_filter"]


def test_parser_adapter_accepts_llm_overlay_as_additive_bfs_input(tmp_path):
    parser_adapter = _load_parser_adapter()
    entry = "adapter.cpp:main"
    bridge = "adapter.cpp:bridge"
    handler = "adapter.cpp:llm_handle"
    dead = "adapter.cpp:dead"
    functions = {
        entry: {"name": "main", "unit_type": "main", "code": "bridge();"},
        bridge: {"name": "bridge", "unit_type": "function", "code": ""},
        handler: {"name": "llm_handle", "unit_type": "function", "code": ""},
        dead: {"name": "dead", "unit_type": "function", "code": ""},
    }
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": functions,
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
            }
        )
    )
    (tmp_path / "semantic_graph.json").write_text(
        json.dumps({"schema_version": 1, "nodes": [], "edges": []})
    )
    dataset = {
        "units": [{"id": item} for item in (entry, bridge, handler, dead)],
        "metadata": {},
    }
    llm_overlay = {
        "schema_version": 1,
        "nodes": [
            {"id": f"function:{bridge}", "kind": "function"},
            {"id": f"function:{handler}", "kind": "function"},
        ],
        "edges": [
            {
                "source_id": f"function:{bridge}",
                "target_id": f"function:{handler}",
                "kind": "llm_confirmed_indirect_call",
            },
        ],
        "orphans": [],
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset,
        str(tmp_path),
        "reachable",
        platform="openharmony",
        semantic_graph_overlay=llm_overlay,
    )

    assert {unit["id"] for unit in filtered["units"]} == {entry, bridge, handler}
    metadata = filtered["metadata"]["reachability_filter"]
    assert metadata["native_reachable_units"] == 2
    assert metadata["semantic_reachable_added"] == 1
    assert metadata["semantic_overlay"]["edges_added"] == 1
    assert metadata["semantic_overlay"]["sources"][-1]["source"] == (
        "llm_call_graph_overlay.json"
    )


def test_parser_adapter_keeps_reference_only_llm_edge_as_candidate_path(tmp_path):
    parser_adapter = _load_parser_adapter()
    entry = "adapter.cpp:main"
    bridge = "adapter.cpp:bridge"
    handler = "adapter.cpp:llm_handle"
    functions = {
        entry: {"name": "main", "unit_type": "main", "code": "bridge();"},
        bridge: {"name": "bridge", "unit_type": "function", "code": ""},
        handler: {"name": "llm_handle", "unit_type": "function", "code": ""},
    }
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": functions,
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
            }
        )
    )
    (tmp_path / "semantic_graph.json").write_text(
        json.dumps({"schema_version": 1, "nodes": [], "edges": []})
    )
    dataset = {
        "units": [
            {"id": entry, "is_entry_point": True},
            {"id": bridge, "semantic_reachability_candidate_seed": True},
            {"id": handler},
        ],
        "metadata": {},
    }
    llm_overlay = {
        "schema_version": 1,
        "nodes": [
            {"id": f"function:{bridge}", "kind": "function"},
            {"id": f"function:{handler}", "kind": "function"},
        ],
        "edges": [
            {
                "source_id": f"function:{bridge}",
                "target_id": f"function:{handler}",
                "kind": "llm_confirmed_indirect_call",
                "attributes": {
                    "evidence_quality": "reference_validated",
                    "reachability_tier": "candidate",
                },
            },
        ],
        "orphans": [],
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset,
        str(tmp_path),
        "reachable",
        platform="openharmony",
        semantic_graph_overlay=llm_overlay,
    )

    by_id = {unit["id"]: unit for unit in filtered["units"]}
    assert by_id[handler]["reachability_status"] == "candidate_reachable"
    metadata = filtered["metadata"]["reachability_filter"]["semantic_overlay"]
    assert metadata["candidate_only_edges"] == 1
    assert metadata["strict_edges"] == 0


def test_effective_graph_candidate_facts_expand_candidate_frontier_only(tmp_path):
    parser_adapter = _load_parser_adapter()
    entry = "adapter.cpp:main"
    bridge = "adapter.cpp:bridge"
    handler = "adapter.cpp:clang_candidate"
    dead = "adapter.cpp:dead"
    functions = {
        entry: {"name": "main", "unit_type": "function", "code": ""},
        bridge: {"name": "bridge", "unit_type": "function", "code": ""},
        handler: {
            "name": "clang_candidate",
            "unit_type": "function",
            "code": "",
        },
        dead: {"name": "dead", "unit_type": "function", "code": ""},
    }
    # The effective graph contains only strict edges in its adjacency.  The
    # reconstructed Clang relationship stays in candidate_facts and must be
    # visible only to the lower-trust candidate frontier.
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": functions,
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
            }
        )
    )
    (tmp_path / "effective_call_graph.json").write_text(
        json.dumps(
            {
                "functions": functions,
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
                "candidate_facts": [
                    {
                        "caller_id": bridge,
                        "callee_id": handler,
                        "status": "candidate",
                        "resolver": "clang",
                    }
                ],
            }
        )
    )
    dataset = {
        "units": [
            {"id": entry},
            {"id": bridge, "semantic_reachability_candidate_seed": True},
            {"id": handler},
            {"id": dead},
        ],
        "metadata": {},
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset,
        str(tmp_path),
        "reachable",
        platform="openharmony",
        extra_entry_points={entry},
    )

    by_id = {unit["id"]: unit for unit in filtered["units"]}
    assert set(by_id) == {entry, bridge, handler}
    assert by_id[handler]["reachability_status"] == "candidate_reachable"
    metadata = filtered["metadata"]["reachability_filter"]
    assert metadata["candidate_fact_records"] == 1
    assert metadata["candidate_fact_edges"] == 1
    assert metadata["candidate_path_coverage_ids"] == [handler]


def test_parser_adapter_seeds_handler_from_transaction_contract(tmp_path):
    parser_adapter = _load_parser_adapter()
    entry = "adapter.cpp:main"
    handler = "service.cpp:Service::Enable"
    dead = "service.cpp:Service::unused"
    tx = "idl:transaction:OHOS.IService:ENABLE"
    functions = {
        entry: {"name": "main", "unit_type": "main", "code": ""},
        handler: {"name": "Service::Enable", "unit_type": "method", "code": ""},
        dead: {"name": "Service::unused", "unit_type": "method", "code": ""},
    }
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": functions,
                "call_graph": {},
                "reverse_call_graph": {},
            }
        )
    )
    (tmp_path / "semantic_graph.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": tx, "kind": "ipc_transaction"},
                    {"id": f"function:{handler}", "kind": "function"},
                ],
                "edges": [
                    {
                        "source_id": tx,
                        "target_id": f"function:{handler}",
                        "kind": "transaction_to_handler",
                    }
                ],
            }
        )
    )
    dataset = {
        "units": [{"id": item} for item in (entry, handler, dead)],
        "metadata": {},
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset,
        str(tmp_path),
        "reachable",
        platform="openharmony",
    )

    assert {unit["id"] for unit in filtered["units"]} == {entry, handler}
    metadata = filtered["metadata"]["reachability_filter"]
    assert metadata["semantic_overlay"]["entry_points_added"] == 1
    assert metadata["semantic_reachable_added"] == 1


def test_parser_adapter_ignores_malformed_llm_overlay_without_pruning_native_units(
    tmp_path,
):
    parser_adapter = _load_parser_adapter()
    entry = "adapter.cpp:main"
    bridge = "adapter.cpp:bridge"
    dead = "adapter.cpp:dead"
    (tmp_path / "call_graph.json").write_text(
        json.dumps(
            {
                "functions": {
                    entry: {"name": "main", "unit_type": "main", "code": ""},
                    bridge: {"name": "bridge", "unit_type": "function", "code": ""},
                    dead: {"name": "dead", "unit_type": "function", "code": ""},
                },
                "call_graph": {entry: [bridge]},
                "reverse_call_graph": {bridge: [entry]},
            }
        )
    )
    dataset = {
        "units": [{"id": item} for item in (entry, bridge, dead)],
        "metadata": {},
    }

    filtered = parser_adapter.apply_reachability_filter(
        dataset,
        str(tmp_path),
        "reachable",
        platform="openharmony",
        semantic_graph_overlay=["not", "an", "object"],
    )

    assert {unit["id"] for unit in filtered["units"]} == {entry, bridge}
    assert filtered["metadata"]["reachability_filter"]["semantic_overlay"][
        "edges_added"
    ] == 0
