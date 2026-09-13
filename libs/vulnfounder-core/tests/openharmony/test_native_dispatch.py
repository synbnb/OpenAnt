"""Tests for the additive OpenHarmony native dispatch semantic graph."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.native_dispatch import (  # noqa: E402
    HANDLER_EDGE_KIND,
    SERVICE_EDGE_KIND,
    build_native_dispatch_graph,
)
from core.platforms.openharmony.reachability import (  # noqa: E402
    build_semantic_reachability_overlay,
)
from parsers.c.unit_generator import UnitGenerator  # noqa: E402


STUB_FILE = "services/health/health_stub.cpp"
SERVICE_FILE = "services/health/health_service.cpp"
STUB = f"{STUB_FILE}:HealthServiceStub::OnRemoteRequest"
CONSTRUCTOR = f"{STUB_FILE}:HealthServiceStub::HealthServiceStub"
ENABLE_INNER = f"{STUB_FILE}:HealthServiceStub::EnableInner"
LIST_INNER = f"{STUB_FILE}:HealthServiceStub::ListInner"
ENABLE = f"{SERVICE_FILE}:HealthService::Enable"
LIST = f"{SERVICE_FILE}:HealthService::List"
UNRELATED = f"other.cpp:Other::Enable"


def _function(
    name: str,
    code: str,
    *,
    file_path: str,
    start_line: int,
    class_name: str | None = None,
    unit_type: str = "method",
) -> dict:
    return {
        "name": name,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line + len(code.splitlines()) - 1,
        "class_name": class_name,
        "unit_type": unit_type,
        "code": code,
    }


def _fixture() -> tuple[dict, dict]:
    functions = {
        CONSTRUCTOR: _function(
            "HealthServiceStub::HealthServiceStub",
            """HealthServiceStub::HealthServiceStub()
{
    baseFuncs_[ENABLE_CODE] = &HealthServiceStub::EnableInner;
    baseFuncs_[LIST_CODE] = &HealthServiceStub::ListInner;
}""",
            file_path=STUB_FILE,
            start_line=10,
            class_name="HealthServiceStub",
            unit_type="constructor",
        ),
        STUB: _function(
            "HealthServiceStub::OnRemoteRequest",
            """int32_t HealthServiceStub::OnRemoteRequest(uint32_t code)
{
    auto it = baseFuncs_.find(code);
    auto member = it->second;
    return (this->*member)(data, reply);
}""",
            file_path=STUB_FILE,
            start_line=20,
            class_name="HealthServiceStub",
        ),
        ENABLE_INNER: _function(
            "HealthServiceStub::EnableInner",
            """ErrCode HealthServiceStub::EnableInner(MessageParcel &data)
{
    return Enable(data.ReadUint32());
}""",
            file_path=STUB_FILE,
            start_line=30,
            class_name="HealthServiceStub",
        ),
        LIST_INNER: _function(
            "HealthServiceStub::ListInner",
            """ErrCode HealthServiceStub::ListInner(MessageParcel &data)
{
    std::vector<int> values(List());
    return values.empty() ? 0 : 1;
}""",
            file_path=STUB_FILE,
            start_line=40,
            class_name="HealthServiceStub",
        ),
        # This declaration is the evidence that HealthService is a concrete
        # implementation of the stub, not merely another same-named class.
        "include/health_service.h:HealthService": _function(
            "HealthService",
            "class HealthService : public SystemAbility, public HealthServiceStub {\n};",
            file_path="include/health_service.h",
            start_line=5,
            class_name=None,
            unit_type="class",
        ),
        ENABLE: _function(
            "HealthService::Enable",
            "ErrCode HealthService::Enable(uint32_t value) { return value; }",
            file_path=SERVICE_FILE,
            start_line=50,
            class_name="HealthService",
        ),
        LIST: _function(
            "HealthService::List",
            "std::vector<int> HealthService::List() { return {}; }",
            file_path=SERVICE_FILE,
            start_line=60,
            class_name="HealthService",
        ),
        UNRELATED: _function(
            "Other::Enable",
            "int Other::Enable(uint32_t value) { return value; }",
            file_path="other.cpp",
            start_line=1,
            class_name="Other",
        ),
    }
    extract = {"repository": "/fixture", "functions": functions}
    call_graph = {
        "repository": "/fixture",
        "functions": functions,
        "call_graph": {STUB: []},
        "reverse_call_graph": {},
    }
    return extract, call_graph


def test_base_funcs_edges_recover_handler_and_concrete_service_method():
    extract, call_graph = _fixture()
    before = copy.deepcopy(call_graph)
    graph = build_native_dispatch_graph(extract, call_graph)

    assert graph is not None
    assert call_graph == before
    handler_edges = [edge for edge in graph.edges.values() if edge.kind == HANDLER_EDGE_KIND]
    service_edges = [edge for edge in graph.edges.values() if edge.kind == SERVICE_EDGE_KIND]
    assert {(edge.source_id, edge.target_id) for edge in handler_edges} == {
        (f"function:{STUB}", f"function:{ENABLE_INNER}"),
        (f"function:{STUB}", f"function:{LIST_INNER}"),
    }
    assert {(edge.source_id, edge.target_id) for edge in service_edges} == {
        (f"function:{ENABLE_INNER}", f"function:{ENABLE}"),
        (f"function:{LIST_INNER}", f"function:{LIST}"),
    }
    assert all(edge.evidence for edge in graph.edges.values())
    enable_edge = next(edge for edge in handler_edges if edge.target_id.endswith(ENABLE_INNER))
    assert enable_edge.attributes["dispatch_table"] == "baseFuncs_"
    assert enable_edge.attributes["selector"] == "ENABLE_CODE"
    service_edge = next(edge for edge in service_edges if edge.target_id.endswith(ENABLE))
    assert any(item["source"] == "native_class_inheritance" for item in service_edge.evidence)
    assert not any(edge.target_id.endswith(UNRELATED) for edge in graph.edges.values())


def test_member_function_initializer_list_projects_same_class_non_remote_site():
    """A class-owned parser table can be consumed outside OnRemoteRequest."""
    source = "services/snapshot/kernel_snapshot_parser.cpp"
    caller_id = f"{source}:KernelSnapshotParser::ProcessSnapshotSection"
    initializer_id = f"{source}:KernelSnapshotParser::InitializeParseTable"
    target_id = f"{source}:KernelSnapshotParser::ParseTransStart"
    functions = {
        caller_id: _function(
            "KernelSnapshotParser::ProcessSnapshotSection",
            "void KernelSnapshotParser::ProcessSnapshotSection() {}",
            file_path=source,
            start_line=20,
            class_name="KernelSnapshotParser",
        ),
        initializer_id: _function(
            "KernelSnapshotParser::InitializeParseTable",
            "void KernelSnapshotParser::InitializeParseTable() {}",
            file_path=source,
            start_line=10,
            class_name="KernelSnapshotParser",
        ),
        target_id: _function(
            "KernelSnapshotParser::ParseTransStart",
            "void KernelSnapshotParser::ParseTransStart() {}",
            file_path=source,
            start_line=30,
            class_name="KernelSnapshotParser",
        ),
    }
    assignment = {
        "owner_function_id": initializer_id,
        "owner_class": "KernelSnapshotParser",
        "file": source,
        "line": 12,
        "table": "parseTable_",
        "selector": "SnapshotSection::TRANSACTION_START",
        "target_name": "KernelSnapshotParser::ParseTransStart",
        "target_id": target_id,
        "resolution": "exact_function_id",
        "value_kind": "member_function_reference",
        "registration_form": "initializer_member_function",
        "permissions": [],
        "evidence": {
            "file": source,
            "start_line": 12,
            "end_line": 12,
            "text": "{SnapshotSection::TRANSACTION_START, KernelSnapshotParser::ParseTransStart}",
            "value_kind": "member_function_reference",
            "registration_form": "initializer_member_function",
        },
    }
    diagnostics = {
        "dispatch_assignments": [assignment],
        "unresolved_call_sites": [
            {
                "caller_id": caller_id,
                "file": source,
                "line": 24,
                "expression": "it->second(cell, output)",
                "ast_kind": "std_function_call",
                "static_resolution": "unresolved",
                "reason": "lookup_derived_member_function_pointer",
                "symbols": {
                    "target_variable": "it->second",
                    "iterator_variable": "it",
                    "dispatch_table": "parseTable_",
                },
                "candidate_target_ids": [target_id],
                "candidates": [
                    {
                        "target_id": target_id,
                        "target_name": assignment["target_name"],
                        "selector": assignment["selector"],
                        "value_kind": assignment["value_kind"],
                        "registration_form": assignment["registration_form"],
                        "owner_class": assignment["owner_class"],
                        "permissions": [],
                        "evidence": assignment["evidence"],
                    }
                ],
            }
        ],
    }

    graph = build_native_dispatch_graph(
        {"repository": "/fixture", "functions": functions}, {}, diagnostics
    )

    assert graph is not None
    edges = [edge for edge in graph.edges.values() if edge.kind == HANDLER_EDGE_KIND]
    assert {(edge.source_id, edge.target_id) for edge in edges} == {
        (f"function:{caller_id}", f"function:{target_id}")
    }
    assert edges[0].attributes["registration_form"] == (
        "initializer_member_function"
    )
    assert edges[0].attributes["value_kind"] == "member_function_reference"


def test_parameterized_decoder_projects_local_member_array_with_source_scope():
    """A decoder's parameter must retain the unique caller-local table scope."""
    source = "interfaces/innerkits/unwinder/exidx_entry_parser.cpp"
    eval_id = f"{source}:ExidxEntryParser::Eval"
    decode_id = f"{source}:ExidxEntryParser::Decode"
    target_id = f"{source}:ExidxEntryParser::Decode00xxxxxx"
    functions = {
        eval_id: _function(
            "ExidxEntryParser::Eval",
            "bool ExidxEntryParser::Eval() {}",
            file_path=source,
            start_line=1,
            class_name="ExidxEntryParser",
        ),
        decode_id: _function(
            "ExidxEntryParser::Decode",
            "bool ExidxEntryParser::Decode(DecodeTable decodeTable[], size_t size) {}",
            file_path=source,
            start_line=10,
            class_name="ExidxEntryParser",
        ),
        target_id: _function(
            "ExidxEntryParser::Decode00xxxxxx",
            "bool ExidxEntryParser::Decode00xxxxxx() { return true; }",
            file_path=source,
            start_line=20,
            class_name="ExidxEntryParser",
        ),
    }
    assignment = {
        "owner_function_id": eval_id,
        "owner_class": "ExidxEntryParser",
        "file": source,
        "line": 3,
        "table": "decodeTable",
        "selector": "0xc0/0x00",
        "target_name": "ExidxEntryParser::Decode00xxxxxx",
        "target_id": target_id,
        "resolution": "exact_function_id",
        "value_kind": "member_function_pointer",
        "registration_form": "declaration_member_function_array",
        "permissions": [],
        "evidence": {"file": source, "start_line": 3, "text": "{0xc0, 0x00, &ExidxEntryParser::Decode00xxxxxx}"},
    }
    diagnostics = {
        "dispatch_assignments": [assignment],
        "unresolved_call_sites": [
            {
                "caller_id": decode_id,
                "file": source,
                "line": 12,
                "expression": "(this->*(decodeTable[0].decoder))()",
                "ast_kind": "indirect_member_call",
                "static_resolution": "unresolved",
                "reason": "parameter_derived_member_function_pointer",
                "symbols": {
                    "target_variable": "decodeTable[0].decoder",
                    "dispatch_table": "decodeTable",
                    "parameter_flow": {
                        "source_function_id": eval_id,
                        "callee_id": decode_id,
                        "argument_index": 0,
                        "source_table": "decodeTable",
                        "callee_parameter": "decodeTable",
                        "registration_form": "declaration_member_function_array",
                    },
                },
                "candidate_target_ids": [target_id],
                "candidates": [
                    {
                        "target_id": target_id,
                        "target_name": assignment["target_name"],
                        "selector": assignment["selector"],
                        "value_kind": assignment["value_kind"],
                        "registration_form": assignment["registration_form"],
                        "owner_class": assignment["owner_class"],
                        "registration_owner_function_id": eval_id,
                        "permissions": [],
                        "evidence": assignment["evidence"],
                    }
                ],
            }
        ],
    }

    graph = build_native_dispatch_graph(
        {"repository": "/fixture", "functions": functions}, {}, diagnostics
    )

    assert graph is not None
    edges = [edge for edge in graph.edges.values() if edge.kind == HANDLER_EDGE_KIND]
    assert {(edge.source_id, edge.target_id) for edge in edges} == {
        (f"function:{decode_id}", f"function:{target_id}")
    }
    edge = edges[0]
    assert edge.attributes["registration_form"] == (
        "declaration_member_function_array"
    )
    assert edge.attributes["registration_owner_function_id"] == eval_id
    assert edge.attributes["parameter_flow"]["source_function_id"] == eval_id


def test_lambda_dispatch_candidates_are_projected_with_registration_evidence():
    source = "services/core/common_event_hub.cpp"
    caller_id = f"{source}:CommonEventHub::OnReceive"
    target_id = f"{source}:CommonEventHub::HandleReady"
    functions = {
        caller_id: _function(
            "CommonEventHub::OnReceive",
            "void CommonEventHub::OnReceive(const Event &event) { return it->second(event); }",
            file_path=source,
            start_line=20,
            class_name="CommonEventHub",
        ),
        target_id: _function(
            "CommonEventHub::HandleReady",
            "void CommonEventHub::HandleReady(const Event &) {}",
            file_path=source,
            start_line=30,
            class_name="CommonEventHub",
        ),
    }
    field_identity = {
        "field": "actionHandlersMap_",
        "receiver": "this",
        "receiver_type": "CommonEventHub",
        "receiver_kind": "this",
    }
    assignment = {
        "owner_function_id": f"{source}:CommonEventHub::InitHandlers",
        "owner_class": "CommonEventHub",
        "file": source,
        "line": 10,
        "table": "actionHandlersMap_",
        "field_identity": field_identity,
        "selector": "READY",
        "target_name": "CommonEventHub::HandleReady",
        "target_id": target_id,
        "resolution": "exact_function_id",
        "value_kind": "lambda",
        "registration_form": "initializer_list",
        "evidence": {
            "file": source,
            "start_line": 10,
            "end_line": 10,
            "text": "{READY, [this](event) { HandleReady(event); }}",
            "value_kind": "lambda",
            "registration_form": "initializer_list",
            "field_identity": field_identity,
        },
    }
    diagnostics = {
        "lambda_dispatch": {
            "assignments": [assignment],
            "call_sites": [
                {
                    "caller_id": caller_id,
                    "file": source,
                    "line": 22,
                    "expression": "it->second(event)",
                    "ast_kind": "std_function_call",
                    "reason": "lookup_derived_callable",
                    "symbols": {
                        "target_variable": "it->second",
                        "iterator_variable": "it",
                        "dispatch_table": "actionHandlersMap_",
                    },
                    "field_identity": field_identity,
                    "candidate_target_ids": [target_id],
                    "candidates": [
                        {
                            "target_id": target_id,
                            "target_name": "CommonEventHub::HandleReady",
                            "selector": "READY",
                            "value_kind": "lambda",
                            "evidence": assignment["evidence"],
                        }
                    ],
                }
            ],
        }
    }
    extract = {"repository": "/fixture", "functions": functions}
    call_graph = {
        "repository": "/fixture",
        "functions": functions,
        "call_graph": {caller_id: []},
        "reverse_call_graph": {},
    }

    graph = build_native_dispatch_graph(extract, call_graph, diagnostics)

    assert graph is not None
    assert call_graph["call_graph"] == {caller_id: []}
    edges = [edge for edge in graph.edges.values() if edge.kind == HANDLER_EDGE_KIND]
    assert {(edge.source_id, edge.target_id) for edge in edges} == {
        (f"function:{caller_id}", f"function:{target_id}")
    }
    edge = edges[0]
    assert edge.attributes["callable_kind"] == "lambda"
    assert edge.attributes["dispatch_table"] == "actionHandlersMap_"
    assert edge.attributes["registration_form"] == "initializer_list"
    assert edge.attributes["selector"] == "READY"
    assert any(
        item.get("source") == "lambda_dispatch_call_site"
        for item in edge.evidence
    )
    assert any(
        item.get("source") == "lambda_dispatch_assignment"
        for item in edge.evidence
    )

    known = set(functions)
    overlay = build_semantic_reachability_overlay(graph.to_dict(), known)
    assert overlay["candidate_edges"] == 1
    assert {
        (item["source_id"], item["target_id"])
        for item in overlay["edges"]
    } == {(caller_id, target_id)}
    assert overlay["edges"][0]["edge_kinds"] == [HANDLER_EDGE_KIND]

    generator = UnitGenerator(call_graph, {"semantic_graph": graph.to_dict()})
    caller_unit = generator.create_unit(caller_id, functions[caller_id])
    assert {
        item["id"] for item in caller_unit["metadata"]["context_functions"]
    } == {target_id}


def test_lambda_dispatch_unknown_target_is_not_projected():
    source = "services/core/common_event_hub.cpp"
    caller_id = f"{source}:CommonEventHub::OnReceive"
    unknown_id = f"{source}:Missing::Handle"
    field_identity = {
        "field": "actionHandlersMap_",
        "receiver": "this",
        "receiver_type": "CommonEventHub",
        "receiver_kind": "this",
    }
    extract = {
        "repository": "/fixture",
        "functions": {
            caller_id: _function(
                "CommonEventHub::OnReceive",
                "void CommonEventHub::OnReceive() { return it->second(); }",
                file_path=source,
                start_line=20,
                class_name="CommonEventHub",
            )
        },
    }
    diagnostics = {
        "lambda_dispatch": {
            "assignments": [
                {
                    "owner_function_id": f"{source}:CommonEventHub::InitHandlers",
                    "owner_class": "CommonEventHub",
                    "file": source,
                    "line": 10,
                    "table": "actionHandlersMap_",
                    "field_identity": field_identity,
                    "selector": "READY",
                    "target_name": "Missing::Handle",
                    "target_id": unknown_id,
                    "resolution": "exact_function_id",
                    "value_kind": "lambda",
                    "registration_form": "initializer_list",
                    "evidence": {"file": source, "start_line": 10},
                }
            ],
            "call_sites": [
                {
                    "caller_id": caller_id,
                    "file": source,
                    "line": 22,
                    "expression": "it->second()",
                    "symbols": {
                        "dispatch_table": "actionHandlersMap_",
                    },
                    "field_identity": field_identity,
                    "candidate_target_ids": [unknown_id],
                    "candidates": [
                        {
                            "target_id": unknown_id,
                            "selector": "READY",
                            "evidence": {"file": source, "start_line": 10},
                        }
                    ],
                }
            ],
        }
    }

    graph = build_native_dispatch_graph(extract, {}, diagnostics)

    assert graph is None


def test_local_lambda_registration_scope_is_rechecked_before_projection():
    source = "services/core/common_event_hub.cpp"
    caller_id = f"{source}:CommonEventHub::OnReceive"
    target_id = f"{source}:CommonEventHub::HandleReady"
    field_identity = {
        "field": "handlers",
        "receiver": "this",
        "receiver_type": "CommonEventHub",
        "receiver_kind": "this",
    }
    functions = {
        caller_id: _function(
            "CommonEventHub::OnReceive",
            "void CommonEventHub::OnReceive() { return it->second(); }",
            file_path=source,
            start_line=20,
            class_name="CommonEventHub",
        ),
        target_id: _function(
            "CommonEventHub::HandleReady",
            "void CommonEventHub::HandleReady() {}",
            file_path=source,
            start_line=30,
            class_name="CommonEventHub",
        ),
    }
    assignment = {
        "owner_function_id": f"{source}:CommonEventHub::InitHandlers",
        "owner_class": "CommonEventHub",
        "file": source,
        "line": 10,
        "table": "handlers",
        "field_identity": field_identity,
        "selector": "READY",
        "target_name": "CommonEventHub::HandleReady",
        "target_id": target_id,
        "resolution": "exact_function_id",
        "value_kind": "lambda",
        "registration_form": "declaration_initializer_list",
        "evidence": {"file": source, "start_line": 10},
    }
    diagnostics = {
        "lambda_dispatch": {
            "assignments": [assignment],
            "call_sites": [
                {
                    "caller_id": caller_id,
                    "file": source,
                    "line": 22,
                    "expression": "it->second()",
                    "symbols": {"dispatch_table": "handlers"},
                    "field_identity": field_identity,
                    "candidate_target_ids": [target_id],
                    "candidates": [
                        {
                            "target_id": target_id,
                            "selector": "READY",
                            "evidence": assignment["evidence"],
                        }
                    ],
                }
            ],
        }
    }

    graph = build_native_dispatch_graph(
        {"repository": "/fixture", "functions": functions}, {}, diagnostics
    )

    assert graph is None


def test_reachability_overlay_accepts_native_dispatch_edges_only_for_known_functions():
    extract, call_graph = _fixture()
    graph = build_native_dispatch_graph(extract, call_graph)
    known = set(extract["functions"])

    overlay = build_semantic_reachability_overlay(graph.to_dict(), known)
    pairs = {(item["source_id"], item["target_id"]) for item in overlay["edges"]}
    assert (STUB, ENABLE_INNER) in pairs
    assert (ENABLE_INNER, ENABLE) in pairs
    assert (STUB, LIST_INNER) in pairs
    assert (LIST_INNER, LIST) in pairs
    assert overlay["candidate_edges"] == 4
    assert "native_dispatch_to_handler" in overlay["edge_kinds"]
    assert "native_dispatch_to_service" in overlay["edge_kinds"]


def test_native_dispatch_edges_are_available_to_unit_context_without_rewriting_native_graph():
    extract, call_graph = _fixture()
    graph = build_native_dispatch_graph(extract, call_graph)
    generator = UnitGenerator(call_graph, {"semantic_graph": graph.to_dict()})

    stub_unit = generator.create_unit(STUB, call_graph["functions"][STUB])
    stub_context = stub_unit["metadata"]["context_functions"]
    assert {item["id"] for item in stub_context} == {ENABLE_INNER, LIST_INNER}
    assert all(item["edge_kinds"] == [HANDLER_EDGE_KIND] for item in stub_context)

    handler_unit = generator.create_unit(
        ENABLE_INNER, call_graph["functions"][ENABLE_INNER]
    )
    handler_context = handler_unit["metadata"]["context_functions"]
    assert {item["id"] for item in handler_context} == {STUB, ENABLE}
    assert any(
        item["edge_kinds"] == [SERVICE_EDGE_KIND] for item in handler_context
    )
    assert any(
        item["edge_kinds"] == [HANDLER_EDGE_KIND] for item in handler_context
    )


def test_dispatch_graph_does_not_depend_on_function_table_name():
    extract, call_graph = _fixture()
    extract["functions"][CONSTRUCTOR]["code"] = extract["functions"][CONSTRUCTOR][
        "code"
    ].replace("baseFuncs_", "otherTable")
    extract["functions"][STUB]["code"] = extract["functions"][STUB]["code"].replace(
        "baseFuncs_", "otherTable"
    )

    graph = build_native_dispatch_graph(extract, call_graph)

    assert graph is not None
    handler_edges = [
        edge for edge in graph.edges.values() if edge.kind == HANDLER_EDGE_KIND
    ]
    assert {
        (edge.source_id, edge.target_id) for edge in handler_edges
    } == {
        (f"function:{STUB}", f"function:{ENABLE_INNER}"),
        (f"function:{STUB}", f"function:{LIST_INNER}"),
    }
    assert all(
        edge.attributes["dispatch_table"] == "otherTable"
        for edge in handler_edges
    )


def test_duplicate_handler_registrations_are_retained_in_edge_metadata():
    extract, call_graph = _fixture()
    constructor = extract["functions"][CONSTRUCTOR]
    constructor["code"] += (
        "\n    baseFuncs_[ENABLE_CODE_ALIAS] = "
        "&HealthServiceStub::EnableInner;"
    )

    graph = build_native_dispatch_graph(extract, call_graph)
    enable_edge = next(
        edge
        for edge in graph.edges.values()
        if edge.kind == HANDLER_EDGE_KIND and edge.target_id.endswith(ENABLE_INNER)
    )

    assert set(enable_edge.attributes["selectors"]) == {
        "ENABLE_CODE",
        "ENABLE_CODE_ALIAS",
    }
    assert {
        item["selector"] for item in enable_edge.attributes["registrations"]
    } == {"ENABLE_CODE", "ENABLE_CODE_ALIAS"}
