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
from core.platforms.openharmony.native_dispatch import (  # noqa: E402
    build_native_dispatch_graph,
)
from parsers.c.function_extractor import FunctionExtractor  # noqa: E402


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


def test_lambda_dispatch_is_projected_with_evidence_after_observation():
    source = "services/telephony/core_service_stub.cpp"
    initializer_id = f"{source}:CoreServiceStub::AddHandlerNetWorkToMap"
    caller_id = f"{source}:CoreServiceStub::OnRemoteRequest"
    handler_id = f"{source}:CoreServiceStub::OnGetNetworkState"
    functions = {
        initializer_id: {
            "name": "CoreServiceStub::AddHandlerNetWorkToMap",
            "file_path": source,
            "start_line": 1,
            "class_name": "CoreServiceStub",
            "code": """void CoreServiceStub::AddHandlerNetWorkToMap()
{
    requestTable_[GET_NETWORK_STATE] =
        [this](MessageParcel &data, MessageParcel &reply) {
            return OnGetNetworkState(data, reply);
        };
}""",
        },
        caller_id: {
            "name": "CoreServiceStub::OnRemoteRequest",
            "file_path": source,
            "start_line": 12,
            "class_name": "CoreServiceStub",
            "code": """int32_t CoreServiceStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply)
{
    auto itFunc = requestTable_.find(code);
    if (itFunc != requestTable_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return requestFunc(data, reply);
        }
    }
    return -1;
}""",
        },
        handler_id: {
            "name": "CoreServiceStub::OnGetNetworkState",
            "file_path": source,
            "start_line": 30,
            "class_name": "CoreServiceStub",
            "code": "int32_t CoreServiceStub::OnGetNetworkState(MessageParcel &, MessageParcel &) { return 0; }",
        },
    }

    extract_result = {"repository": "/fixture", "functions": functions}
    diagnostics = build_call_graph_diagnostics(extract_result, {})

    assert diagnostics["dispatch_assignments"] == []
    assert diagnostics["unresolved_call_sites"] == []
    assert diagnostics["lambda_dispatch"]["summary"] == {
        "dispatch_assignments": 1,
        "call_sites": 1,
        "candidate_edges": 1,
        "unresolved_without_candidates": 0,
        "orphan_assignments": 0,
    }
    assignment = diagnostics["lambda_dispatch"]["assignments"][0]
    assert assignment["table"] == "requestTable_"
    assert assignment["value_kind"] == "lambda"
    assert assignment["target_name"] == "CoreServiceStub::OnGetNetworkState"
    assert assignment["target_id"] == handler_id
    site = diagnostics["lambda_dispatch"]["call_sites"][0]
    assert site["caller_id"] == caller_id
    assert site["symbols"] == {
        "target_variable": "requestFunc",
        "iterator_variable": "itFunc",
        "dispatch_table": "requestTable_",
    }
    assert site["candidate_target_ids"] == [handler_id]
    graph = build_native_dispatch_graph(extract_result, {}, diagnostics)
    assert graph is not None
    edges = [
        edge for edge in graph.edges.values() if edge.kind == "native_dispatch_to_handler"
    ]
    assert {(edge.source_id, edge.target_id) for edge in edges} == {
        (f"function:{caller_id}", f"function:{handler_id}")
    }
    edge = edges[0]
    assert edge.attributes["callable_kind"] == "lambda"
    assert edge.attributes["registration_form"] == "subscript_assignment"


def test_lambda_receiver_type_and_call_arity_resolve_overloaded_target():
    source = "services/telephony/sim_file_init.cpp"
    initializer_id = f"{source}:SimFileInit::InitMemberFunc"
    functions = {
        initializer_id: {
            "name": "SimFileInit::InitMemberFunc",
            "file_path": source,
            "start_line": 1,
            "class_name": "SimFileInit",
            "parameters": ["SimFile &simFile"],
            "code": """void SimFileInit::InitMemberFunc(SimFile &simFile)
{
    simFile.memberTable_[READY] =
        [&](const Event &event) { return simFile.Process(event); };
}""",
        },
        "services/telephony/sim_file.cpp:SimFile::Process(Event)": {
            "name": "SimFile::Process",
            "file_path": "services/telephony/sim_file.cpp",
            "start_line": 20,
            "class_name": "SimFile",
            "parameters": ["const Event &event"],
            "code": "bool SimFile::Process(const Event &) { return true; }",
        },
        "services/telephony/sim_file.cpp:SimFile::Process(int)": {
            "name": "SimFile::Process",
            "file_path": "services/telephony/sim_file.cpp",
            "start_line": 30,
            "class_name": "SimFile",
            "parameters": ["int value", "int other"],
            "code": "bool SimFile::Process(int value, int other) { return value > other; }",
        },
    }

    diagnostics = build_call_graph_diagnostics(
        {"repository": "/fixture", "functions": functions}, {}
    )

    assignments = diagnostics["lambda_dispatch"]["assignments"]
    assert len(assignments) == 1
    assert assignments[0]["target_name"] == "SimFile::Process"
    assert assignments[0]["target_id"].endswith("SimFile::Process(Event)")
    assert assignments[0]["resolution"] == "exact_function_id"
    assert assignments[0]["call_argument_count"] == 1


def test_lambda_field_alias_matches_parameter_receiver_to_this_field():
    init_source = "services/telephony/sim_file_init.cpp"
    sim_source = "services/telephony/sim_file.cpp"
    initializer_id = f"{init_source}:SimFileInit::InitMemberFunc"
    caller_id = f"{sim_source}:SimFile::ProcessEvent"
    handler_id = f"{sim_source}:SimFile::ProcessReady"
    functions = {
        initializer_id: {
            "name": "SimFileInit::InitMemberFunc",
            "file_path": init_source,
            "start_line": 1,
            "class_name": "SimFileInit",
            "parameters": ["SimFile &simFile"],
            "code": """void SimFileInit::InitMemberFunc(SimFile &simFile)
{
    simFile.memberFuncMap_[READY] =
        [&](const Event &event) { return simFile.ProcessReady(event); };
}""",
        },
        caller_id: {
            "name": "SimFile::ProcessEvent",
            "file_path": sim_source,
            "start_line": 20,
            "class_name": "SimFile",
            "parameters": ["const Event &event"],
            "code": """void SimFile::ProcessEvent(const Event &event)
{
    auto itFunc = memberFuncMap_.find(event.id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        memberFunc(event);
    }
}""",
        },
        handler_id: {
            "name": "SimFile::ProcessReady",
            "file_path": sim_source,
            "start_line": 35,
            "class_name": "SimFile",
            "parameters": ["const Event &event"],
            "code": "bool SimFile::ProcessReady(const Event &) { return true; }",
        },
    }

    diagnostics = build_call_graph_diagnostics(
        {"repository": "/fixture", "functions": functions}, {}
    )

    lambda_dispatch = diagnostics["lambda_dispatch"]
    assert lambda_dispatch["summary"]["field_alias_matches"] == 1
    assignment = lambda_dispatch["assignments"][0]
    assert assignment["field_identity"] == {
        "field": "memberFuncMap_",
        "receiver": "simFile",
        "receiver_type": "SimFile",
        "receiver_kind": "parameter",
    }
    site = lambda_dispatch["call_sites"][0]
    assert site["field_identity"] == {
        "field": "memberFuncMap_",
        "receiver": "this",
        "receiver_type": "SimFile",
        "receiver_kind": "this",
    }
    assert site["candidate_target_ids"] == [handler_id]
    assert lambda_dispatch["field_alias_matches"] == [
        {
            "caller_id": caller_id,
            "call_site_line": 25,
            "registration_owner_function_id": initializer_id,
            "registration_line": 3,
            "dispatch_table": "memberFuncMap_",
            "selector": "READY",
            "target_id": handler_id,
            "target_name": "SimFile::ProcessReady",
            "reason": "same_field_receiver_type",
            "confidence": "high",
        }
    ]


def test_lambda_field_alias_does_not_cross_receiver_types():
    source = "services/telephony/other_file.cpp"
    initializer_id = f"{source}:SimFileInit::InitMemberFunc"
    caller_id = f"{source}:OtherFile::ProcessEvent"
    handler_id = f"{source}:SimFile::ProcessReady"
    functions = {
        initializer_id: {
            "name": "SimFileInit::InitMemberFunc",
            "file_path": source,
            "start_line": 1,
            "class_name": "SimFileInit",
            "parameters": ["SimFile &simFile"],
            "code": """void SimFileInit::InitMemberFunc(SimFile &simFile)
{
    simFile.memberFuncMap_[READY] =
        [&](const Event &event) { return simFile.ProcessReady(event); };
}""",
        },
        caller_id: {
            "name": "OtherFile::ProcessEvent",
            "file_path": source,
            "start_line": 20,
            "class_name": "OtherFile",
            "parameters": ["const Event &event"],
            "code": """void OtherFile::ProcessEvent(const Event &event)
{
    auto itFunc = memberFuncMap_.find(event.id);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        memberFunc(event);
    }
}""",
        },
        handler_id: {
            "name": "SimFile::ProcessReady",
            "file_path": source,
            "start_line": 35,
            "class_name": "SimFile",
            "parameters": ["const Event &event"],
            "code": "bool SimFile::ProcessReady(const Event &) { return true; }",
        },
    }

    diagnostics = build_call_graph_diagnostics(
        {"repository": "/fixture", "functions": functions}, {}
    )

    lambda_dispatch = diagnostics["lambda_dispatch"]
    site = lambda_dispatch["call_sites"][0]
    assert site["candidate_target_ids"] == []
    assert lambda_dispatch["summary"].get("field_alias_matches", 0) == 0
    assert "field_alias_matches" not in lambda_dispatch


def test_file_level_initializer_lambda_is_observed_without_new_function_unit(
    tmp_path,
):
    source = """#include <map>

struct Event {};
struct NetworkSearchHandler {
    using Func = void (*)(NetworkSearchHandler *, const Event &);
    static const std::map<int, Func> memberFuncMap_;
    void ProcessEvent(int code, const Event &event);
    void HandleEvent(const Event &event);
};

const std::map<int, NetworkSearchHandler::Func>
    NetworkSearchHandler::memberFuncMap_ = {
        {READY, [](NetworkSearchHandler *handler, const Event &event) {
            handler->HandleEvent(event);
        }}
    };

void NetworkSearchHandler::ProcessEvent(int code, const Event &event)
{
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        memberFunc(this, event);
    }
}

void NetworkSearchHandler::HandleEvent(const Event &)
{
}
"""
    source_path = tmp_path / "network_search.cpp"
    source_path.write_text(source, encoding="utf-8")

    extracted = FunctionExtractor(str(tmp_path)).extract_all(
        [source_path.name]
    )
    assert source_path.name in extracted["source_files"]
    assert "memberFuncMap_" not in extracted["functions"]

    diagnostics = build_call_graph_diagnostics(extracted, {})

    lambda_dispatch = diagnostics["lambda_dispatch"]
    assert lambda_dispatch["summary"]["dispatch_assignments"] == 1
    assert lambda_dispatch["summary"]["call_sites"] == 1
    assert lambda_dispatch["summary"]["candidate_edges"] == 1
    assert lambda_dispatch["summary"]["unresolved_without_candidates"] == 0
    assignment = lambda_dispatch["assignments"][0]
    assert assignment["registration_form"] == "file_initializer_list"
    assert assignment["table"] == "NetworkSearchHandler::memberFuncMap_"
    assert assignment["selector"] == "READY"
    assert assignment["target_name"] == "NetworkSearchHandler::HandleEvent"
    assert assignment["target_id"].endswith("NetworkSearchHandler::HandleEvent")
    site = lambda_dispatch["call_sites"][0]
    assert site["candidate_target_ids"] == [assignment["target_id"]]


def test_function_initializer_list_lambda_uses_same_observation_schema():
    source = "services/core/common_event_hub.cpp"
    initializer_id = f"{source}:CommonEventHub::InitHandlers"
    caller_id = f"{source}:CommonEventHub::OnReceive"
    handler_id = f"{source}:CommonEventHub::HandleReady"
    functions = {
        initializer_id: {
            "name": "CommonEventHub::InitHandlers",
            "file_path": source,
            "start_line": 1,
            "class_name": "CommonEventHub",
            "code": """void CommonEventHub::InitHandlers()
{
    actionHandlersMap_ = {
        {READY, [this](const Event &event) { HandleReady(event); }}
    };
}""",
        },
        caller_id: {
            "name": "CommonEventHub::OnReceive",
            "file_path": source,
            "start_line": 12,
            "class_name": "CommonEventHub",
            "code": """void CommonEventHub::OnReceive(const Event &event)
{
    auto it = actionHandlersMap_.find(event.id);
    if (it != actionHandlersMap_.end()) {
        it->second(event);
    }
}""",
        },
        handler_id: {
            "name": "CommonEventHub::HandleReady",
            "file_path": source,
            "start_line": 25,
            "class_name": "CommonEventHub",
            "code": "void CommonEventHub::HandleReady(const Event &) {}",
        },
    }

    diagnostics = build_call_graph_diagnostics(
        {"repository": "/fixture", "functions": functions}, {}
    )

    lambda_dispatch = diagnostics["lambda_dispatch"]
    assert lambda_dispatch["summary"]["dispatch_assignments"] == 1
    assert lambda_dispatch["assignments"][0]["registration_form"] == (
        "initializer_list"
    )
    assert lambda_dispatch["assignments"][0]["target_id"] == handler_id
    assert lambda_dispatch["call_sites"][0]["candidate_target_ids"] == [
        handler_id
    ]
