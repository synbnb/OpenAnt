"""OH-22A: OpenHarmony indirect-call diagnostics stay observation-only."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.call_graph_diagnostics import (  # noqa: E402
    build_call_graph_diagnostics,
)


SOURCE = "services/medical_sensor/src/medical_service_stub.cpp"
CONSTRUCTOR = f"{SOURCE}:MedicalSensorServiceStub::MedicalSensorServiceStub"
CALLER = f"{SOURCE}:MedicalSensorServiceStub::OnRemoteRequest"
ENABLE = f"{SOURCE}:MedicalSensorServiceStub::AfeEnableInner"
DISABLE = f"{SOURCE}:MedicalSensorServiceStub::AfeDisableInner"


def _function(name: str, code: str, start_line: int) -> dict:
    return {
        "name": name,
        "file_path": SOURCE,
        "start_line": start_line,
        "end_line": start_line + len(code.splitlines()) - 1,
        "class_name": "MedicalSensorServiceStub",
        "unit_type": "method",
        "code": code,
    }


def _extract_result() -> dict:
    constructor_code = """MedicalSensorServiceStub::MedicalSensorServiceStub()
{
    baseFuncs_[ENABLE_SENSOR] = &MedicalSensorServiceStub::AfeEnableInner;
    baseFuncs_[DISABLE_SENSOR] = &MedicalSensorServiceStub::AfeDisableInner;
}"""
    caller_code = """int32_t MedicalSensorServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply)
{
    auto itFunc = baseFuncs_.find(code);
    if (itFunc != baseFuncs_.end()) {
        auto memberFunc = itFunc->second;
        return (this->*memberFunc)(data, reply);
    }
    return -1;
}"""
    return {
        "repository": "/fixture",
        "functions": {
            CONSTRUCTOR: _function(
                "MedicalSensorServiceStub::MedicalSensorServiceStub",
                constructor_code,
                10,
            ),
            CALLER: _function(
                "MedicalSensorServiceStub::OnRemoteRequest", caller_code, 30
            ),
            ENABLE: _function(
                "MedicalSensorServiceStub::AfeEnableInner",
                "int32_t MedicalSensorServiceStub::AfeEnableInner() { return 0; }",
                50,
            ),
            DISABLE: _function(
                "MedicalSensorServiceStub::AfeDisableInner",
                "int32_t MedicalSensorServiceStub::AfeDisableInner() { return 0; }",
                60,
            ),
        },
    }


def test_member_function_dispatch_produces_bounded_candidates_without_mutating_graph():
    extract_result = _extract_result()
    native_graph = {
        "functions": extract_result["functions"],
        "call_graph": {CALLER: []},
        "reverse_call_graph": {},
    }
    before = copy.deepcopy(native_graph)

    diagnostics = build_call_graph_diagnostics(extract_result, native_graph)

    assert native_graph == before
    assert diagnostics["schema_version"] == 1
    assert diagnostics["platform"] == "openharmony"
    assert diagnostics["status"] == "complete"
    assert diagnostics["summary"] == {
        "unresolved_call_sites": 1,
        "dispatch_assignments": 2,
        "candidate_edges": 2,
        "unresolved_without_candidates": 0,
        "orphan_assignments": 0,
    }

    site = diagnostics["unresolved_call_sites"][0]
    assert site["caller_id"] == CALLER
    assert site["line"] == 36
    assert site["expression"] == "(this->*memberFunc)(data, reply)"
    assert site["ast_kind"] == "indirect_member_call"
    assert site["reason"] == "parenthesized_member_function_pointer"
    assert site["symbols"] == {
        "target_variable": "memberFunc",
        "iterator_variable": "itFunc",
        "dispatch_table": "baseFuncs_",
    }
    assert site["candidate_target_ids"] == [ENABLE, DISABLE]

    assignments = diagnostics["dispatch_assignments"]
    assert [item["selector"] for item in assignments] == [
        "ENABLE_SENSOR",
        "DISABLE_SENSOR",
    ]
    assert [item["target_id"] for item in assignments] == [ENABLE, DISABLE]
    assert all(item["table"] == "baseFuncs_" for item in assignments)
    assert all(item["resolution"] == "exact_function_id" for item in assignments)
    assert diagnostics["orphans"] == []


def test_direct_switch_calls_are_not_reported_as_unresolved_indirect_calls():
    direct = _function(
        "MedicalSensorServiceStub::OnRemoteRequest",
        """int32_t MedicalSensorServiceStub::OnRemoteRequest(uint32_t code)
{
    switch (code) {
        case ENABLE_SENSOR: return AfeEnableInner();
        default: return -1;
    }
}""",
        70,
    )
    extract_result = {
        "repository": "/fixture",
        "functions": {
            CALLER: direct,
            ENABLE: _function(
                "MedicalSensorServiceStub::AfeEnableInner",
                "int32_t MedicalSensorServiceStub::AfeEnableInner() { return 0; }",
                90,
            ),
        },
    }

    diagnostics = build_call_graph_diagnostics(extract_result, {})

    assert diagnostics["unresolved_call_sites"] == []
    assert diagnostics["dispatch_assignments"] == []
    assert diagnostics["summary"]["candidate_edges"] == 0


def test_unknown_assignment_target_is_an_orphan_not_a_candidate_edge():
    extract_result = _extract_result()
    constructor = extract_result["functions"][CONSTRUCTOR]
    constructor["code"] = constructor["code"].replace(
        "MedicalSensorServiceStub::AfeDisableInner",
        "MedicalSensorServiceStub::MissingInner",
    )

    diagnostics = build_call_graph_diagnostics(extract_result, {})

    site = diagnostics["unresolved_call_sites"][0]
    assert site["candidate_target_ids"] == [ENABLE]
    assert diagnostics["summary"]["candidate_edges"] == 1
    assert diagnostics["summary"]["orphan_assignments"] == 1
    assert diagnostics["orphans"][0]["target_name"] == (
        "MedicalSensorServiceStub::MissingInner"
    )
    assert diagnostics["orphans"][0]["reason"] == "unknown_target_function"


def test_arbitrary_table_nested_iterator_member_pointer_is_detected():
    source = "services/network/net_stub.cpp"
    constructor_id = f"{source}:NetworkStub::NetworkStub"
    caller_id = f"{source}:NetworkStub::OnRemoteRequest"
    handler_id = f"{source}:NetworkStub::HandleRequest"
    functions = {
        constructor_id: {
            "name": "NetworkStub::NetworkStub",
            "file_path": source,
            "start_line": 1,
            "class_name": "NetworkStub",
            "code": """NetworkStub::NetworkStub()
{
    requestTable_[REQUEST_CODE] = &NetworkStub::HandleRequest;
}""",
        },
        caller_id: {
            "name": "NetworkStub::OnRemoteRequest",
            "file_path": source,
            "start_line": 10,
            "class_name": "NetworkStub",
            "code": """int32_t NetworkStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply)
{
    auto index = requestTable_.find(code);
    if (index == requestTable_.end() || !index->second) {
        return -1;
    }
    return (this->*(index->second))(data, reply);
}""",
        },
        handler_id: {
            "name": "NetworkStub::HandleRequest",
            "file_path": source,
            "start_line": 25,
            "class_name": "NetworkStub",
            "code": "int32_t NetworkStub::HandleRequest(MessageParcel &, MessageParcel &) { return 0; }",
        },
    }

    diagnostics = build_call_graph_diagnostics(
        {"repository": "/fixture", "functions": functions}, {}
    )

    assert diagnostics["summary"] == {
        "unresolved_call_sites": 1,
        "dispatch_assignments": 1,
        "candidate_edges": 1,
        "unresolved_without_candidates": 0,
        "orphan_assignments": 0,
    }
    site = diagnostics["unresolved_call_sites"][0]
    assert site["symbols"] == {
        "target_variable": "index->second",
        "iterator_variable": "index",
        "dispatch_table": "requestTable_",
    }
    assert site["candidate_target_ids"] == [handler_id]
    assert diagnostics["dispatch_assignments"][0]["table"] == "requestTable_"


def test_member_function_pair_preserves_permission_metadata():
    source = "services/network/net_conn_stub.cpp"
    constructor_id = f"{source}:NetConnStub::NetConnStub"
    caller_id = f"{source}:NetConnStub::OnRemoteRequest"
    handler_id = f"{source}:NetConnStub::HandleRequest"
    functions = {
        constructor_id: {
            "name": "NetConnStub::NetConnStub",
            "file_path": source,
            "start_line": 1,
            "class_name": "NetConnStub",
            "code": """NetConnStub::NetConnStub()
{
    memberTable_[REQUEST_CODE] = {
        &NetConnStub::HandleRequest,
        {Permission::NETWORK, Permission::INTERNAL}};
}""",
        },
        caller_id: {
            "name": "NetConnStub::OnRemoteRequest",
            "file_path": source,
            "start_line": 12,
            "class_name": "NetConnStub",
            "code": """int32_t NetConnStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply)
{
    auto itFunc = memberTable_.find(code);
    auto requestFunc = itFunc->second.first;
    return (this->*requestFunc)(data, reply);
}""",
        },
        handler_id: {
            "name": "NetConnStub::HandleRequest",
            "file_path": source,
            "start_line": 28,
            "class_name": "NetConnStub",
            "code": "int32_t NetConnStub::HandleRequest(MessageParcel &, MessageParcel &) { return 0; }",
        },
    }

    diagnostics = build_call_graph_diagnostics(
        {"repository": "/fixture", "functions": functions}, {}
    )

    assert diagnostics["dispatch_assignments"]
    assignment = diagnostics["dispatch_assignments"][0]
    assert assignment["table"] == "memberTable_"
    assert assignment["target_id"] == handler_id
    assert assignment["value_kind"] == "member_function_pair"
    assert assignment["permissions"] == ["Permission::INTERNAL", "Permission::NETWORK"]
    assert diagnostics["unresolved_call_sites"][0]["candidate_target_ids"] == [handler_id]
