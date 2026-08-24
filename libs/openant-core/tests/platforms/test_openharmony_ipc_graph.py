"""Tests for deterministic OpenHarmony IDL/native IPC resolution."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.idl import OpenHarmonyIDLParser  # noqa: E402
from core.platforms.openharmony.ipc_graph import OpenHarmonyIPCResolver  # noqa: E402


def _idl(text: str):
    return OpenHarmonyIDLParser().parse_text("interfaces/IHealthService.idl", text)


def _function(name: str, code: str, line: int = 10) -> dict:
    return {
        "name": name,
        "file_path": "services/health_service.cpp",
        "start_line": line,
        "end_line": line + 5,
        "code": code,
        "unit_type": "method",
    }


def test_resolver_links_interface_transaction_stub_and_handler():
    idl = _idl(
        """
        interface OHOS.Health.IHealthService {
            int Enable([in] String sensorName);
        }
        """
    )
    functions = {
        "services.cpp:HealthServiceStub::OnRemoteRequest": _function(
            "HealthServiceStub::OnRemoteRequest",
            "switch (code) { case CMD_ENABLE: return Enable(data, reply); }",
        ),
        "services.cpp:HealthServiceProxy::Enable": _function(
            "HealthServiceProxy::Enable",
            "return remote->SendRequest(COMMAND_ENABLE, data, reply, option);",
            5,
        ),
        "services.cpp:HealthServiceStub::Enable": _function(
            "HealthServiceStub::Enable",
            "return HandleEnable(sensorName);",
            30,
        ),
        "services.cpp:OtherService::Enable": _function(
            "OtherService::Enable",
            "return 0;",
            50,
        ),
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)
    edge_kinds = {(edge.source_id, edge.target_id, edge.kind) for edge in graph.edges.values()}
    transaction = "idl:transaction:OHOS.Health.IHealthService:Enable"
    stub = "function:services.cpp:HealthServiceStub::OnRemoteRequest"
    handler = "function:services.cpp:HealthServiceStub::Enable"

    assert ("idl:interface:OHOS.Health.IHealthService", transaction, "interface_to_transaction") in edge_kinds
    assert (stub, transaction, "stub_to_transaction") in edge_kinds
    assert (
        "function:services.cpp:HealthServiceProxy::Enable",
        transaction,
        "proxy_to_transaction",
    ) in edge_kinds
    assert (transaction, handler, "transaction_to_handler") in edge_kinds
    assert not graph.orphans
    assert graph.nodes[transaction].attributes["parameters"][0]["direction"] == "in"


def test_resolver_uses_call_graph_when_handler_owner_differs_from_stub():
    """A native dispatch edge is stronger than the stub-owner heuristic."""
    idl = _idl("interface OHOS.Health.IHealthSensorService { int Enable(); }")
    stub_id = "stub.cpp:HealthSensorServiceStub::OnRemoteRequest"
    handler_id = "service.cpp:HealthSensorService::Enable"
    functions = {
        stub_id: _function(
            "HealthSensorServiceStub::OnRemoteRequest",
            "switch (code) { case CMD_ENABLE: return DispatchEnable(data, reply); }",
        ),
        handler_id: _function(
            "HealthSensorService::Enable",
            "return CheckPermission();",
            30,
        ),
    }
    call_graph = {
        "call_graph": {stub_id: [handler_id], handler_id: []},
        "reverse_call_graph": {handler_id: [stub_id], stub_id: []},
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions, call_graph=call_graph)

    transaction = "idl:transaction:OHOS.Health.IHealthSensorService:Enable"
    assert any(
        edge.source_id == transaction
        and edge.target_id == f"function:{handler_id}"
        and edge.kind == "transaction_to_handler"
        for edge in graph.edges.values()
    )
    handler_edge = next(
        edge
        for edge in graph.edges.values()
        if edge.kind == "transaction_to_handler"
    )
    assert handler_edge.evidence[0]["source"] == "call_graph"


def test_resolver_uses_call_graph_to_find_dispatch_when_interface_owner_differs():
    """Generated ZIDL stubs may use a service class unrelated to the IDL stem."""
    idl = _idl("interface OHOS.Rosen.IDisplayManagerLite { int GetCutoutInfo(); }")
    stub_id = "stub.cpp:ScreenSessionManagerLiteStub::OnRemoteRequest"
    handler_id = "stub.cpp:ScreenSessionManagerLiteStub::HandleGetCutoutInfo"
    functions = {
        stub_id: _function(
            "ScreenSessionManagerLiteStub::OnRemoteRequest",
            "switch (msgId) { case TRANS_ID_GET_CUTOUT_INFO: HandleGetCutoutInfo(data, reply); }",
        ),
        handler_id: _function(
            "ScreenSessionManagerLiteStub::HandleGetCutoutInfo",
            "return GetCutoutInfo(data.ReadUint64());",
            30,
        ),
    }
    call_graph = {
        "call_graph": {stub_id: [handler_id], handler_id: []},
        "reverse_call_graph": {handler_id: [stub_id], stub_id: []},
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions, call_graph=call_graph)

    transaction = "idl:transaction:OHOS.Rosen.IDisplayManagerLite:GetCutoutInfo"
    assert any(
        edge.source_id == f"function:{stub_id}"
        and edge.target_id == transaction
        and edge.kind == "stub_to_transaction"
        for edge in graph.edges.values()
    )
    assert any(
        edge.source_id == transaction
        and edge.target_id == f"function:{handler_id}"
        and edge.kind == "transaction_to_handler"
        for edge in graph.edges.values()
    )


def test_resolver_does_not_reuse_lite_dispatch_for_non_lite_interface():
    idl = _idl("interface OHOS.Rosen.IDisplayManager { int GetCutoutInfo(); }")
    stub_id = "dm_lite/screen_session_manager_lite_stub.cpp:ScreenSessionManagerLiteStub::OnRemoteRequest"
    handler_id = "dm_lite/screen_session_manager_lite_stub.cpp:ScreenSessionManagerLiteStub::HandleGetCutoutInfo"
    functions = {
        stub_id: _function(
            "ScreenSessionManagerLiteStub::OnRemoteRequest",
            "case TRANS_ID_GET_CUTOUT_INFO: HandleGetCutoutInfo(data, reply);",
        ),
        handler_id: _function(
            "ScreenSessionManagerLiteStub::HandleGetCutoutInfo",
            "return 0;",
            30,
        ),
    }

    graph = OpenHarmonyIPCResolver().resolve(
        idl,
        functions,
        call_graph={"call_graph": {stub_id: [handler_id]}},
    )

    assert not any(edge.kind == "stub_to_transaction" for edge in graph.edges.values())
    assert not any(edge.kind == "transaction_to_handler" for edge in graph.edges.values())


def test_resolver_uses_transaction_table_and_records_missing_methods():
    idl = _idl(
        """
        interface OHOS.Health.IHealthService {
            int Enable([in] String sensorName);
            int Reset([in] int mode);
        }
        """
    )
    functions = {
        "services.cpp:HealthServiceStub::HealthServiceStub": _function(
            "HealthServiceStub::HealthServiceStub",
            "dispatch[CMD_ENABLE] = &HealthServiceStub::HandleEnableInner;",
        ),
        "services.cpp:HealthServiceStub::HandleEnableInner": _function(
            "HealthServiceStub::HandleEnableInner",
            "return 0;",
            40,
        ),
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)
    transaction = "idl:transaction:OHOS.Health.IHealthService:Enable"
    handler = "function:services.cpp:HealthServiceStub::HandleEnableInner"
    assert any(
        edge.source_id == handler
        and edge.target_id == transaction
        for edge in graph.edges.values()
    ) is False
    assert any(
        edge.source_id == transaction and edge.target_id == handler
        for edge in graph.edges.values()
    )
    assert any(
        orphan["kind"] == "unresolved_ipc_stub"
        and orphan["attributes"]["method"] == "Reset"
        for orphan in graph.orphans
    )


def test_proxy_send_request_is_not_misclassified_as_server_dispatch():
    idl = _idl("interface OHOS.Health.IHealthService { int Enable(); }")
    functions = {
        "services.cpp:HealthServiceProxy::Enable": _function(
            "HealthServiceProxy::Enable",
            "return remote->SendRequest(CMD_ENABLE, data, reply, option);",
        )
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)

    assert any(edge.kind == "proxy_to_transaction" for edge in graph.edges.values())
    assert not any(edge.kind == "stub_to_transaction" for edge in graph.edges.values())
    assert any(orphan["kind"] == "unresolved_ipc_stub" for orphan in graph.orphans)


def test_resolver_does_not_guess_from_unrelated_same_named_method():
    idl = _idl(
        "interface OHOS.Health.IHealthService { int Enable([in] String sensorName); }"
    )
    functions = {
        "other.cpp:Unrelated::Enable": _function("Unrelated::Enable", "return 0;")
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)

    assert not any(edge.kind == "transaction_to_handler" for edge in graph.edges.values())
    assert any(orphan["kind"] == "unresolved_ipc_stub" for orphan in graph.orphans)


def test_resolver_ignores_method_names_in_comments_and_string_literals():
    idl = _idl("interface OHOS.Health.IHealthService { int Enable(); }")
    functions = {
        "services.cpp:HealthServiceStub::OnRemoteRequest": _function(
            "HealthServiceStub::OnRemoteRequest",
            '// case CMD_ENABLE: return Enable(data, reply);\n'
            'const char *text = "CMD_ENABLE Enable";\n'
            'return 0;',
        )
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)

    assert not any(edge.kind == "stub_to_transaction" for edge in graph.edges.values())
    assert any(orphan["kind"] == "unresolved_ipc_stub" for orphan in graph.orphans)


def test_resolver_serializes_auditable_orphan_result():
    idl = _idl("interface OHOS.Health.IHealthService { void Ping(); }")
    payload = OpenHarmonyIPCResolver().resolve_dict(idl, {})

    assert payload["schema_version"] == 1
    assert payload["edges"][0]["kind"] == "interface_to_transaction"
    assert payload["orphans"][0]["attributes"] == {
        "interface": "OHOS.Health.IHealthService",
        "method": "Ping",
    }


def test_resolver_preserves_ipccode_metadata_on_transaction():
    idl = _idl(
        "interface OHOS.Rosen.IDisplayManager { "
        "[ipccode 7] void GetDefaultDisplayInfo(); }"
    )

    graph = OpenHarmonyIPCResolver().resolve(idl, {})

    transaction = "idl:transaction:OHOS.Rosen.IDisplayManager:GetDefaultDisplayInfo"
    assert graph.nodes[transaction].attributes["ipc_code"] == 7
    assert graph.nodes[transaction].attributes["annotations"] == ["ipccode 7"]


def test_resolver_matches_ipccode_literal_in_native_stub_dispatch():
    idl = _idl(
        "interface OHOS.Storage.IStorageDaemon { "
        "[ipccode 7] void StartUser(); }"
    )
    stub_id = "services/storage_daemon_stub.cpp:StorageDaemonStub::OnRemoteRequest"
    functions = {
        stub_id: _function(
            "StorageDaemonStub::OnRemoteRequest",
            "switch (code) { case 7: return Dispatch(data, reply); }",
        )
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)

    transaction = "idl:transaction:OHOS.Storage.IStorageDaemon:StartUser"
    edge = next(
        edge
        for edge in graph.edges.values()
        if edge.source_id == f"function:{stub_id}"
        and edge.target_id == transaction
        and edge.kind == "stub_to_transaction"
    )
    assert edge.evidence[0]["source"] == "native"
    assert edge.evidence[0]["signal"] == "ipc_code_literal"
    assert edge.evidence[0]["ipc_code"] == 7
    assert edge.evidence[0]["matched"] == "7"


def test_resolver_matches_ipccode_literal_in_proxy_send_request():
    idl = _idl(
        "interface OHOS.Storage.IStorageDaemon { "
        "[ipccode 7] void StartUser(); }"
    )
    proxy_id = "services/storage_daemon_proxy.cpp:StorageDaemonProxy::Call"
    functions = {
        proxy_id: _function(
            "StorageDaemonProxy::Call",
            "return remote->SendRequest(7, data, reply, option);",
        )
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)

    transaction = "idl:transaction:OHOS.Storage.IStorageDaemon:StartUser"
    edge = next(
        edge
        for edge in graph.edges.values()
        if edge.source_id == f"function:{proxy_id}"
        and edge.target_id == transaction
        and edge.kind == "proxy_to_transaction"
    )
    assert edge.evidence[0]["source"] == "native"
    assert edge.evidence[0]["signal"] == "ipc_code_literal"
    assert edge.evidence[0]["ipc_code"] == 7
    assert edge.evidence[0]["matched"] == "7"


def test_resolver_rejects_mismatched_or_masked_ipccode_literals():
    idl = _idl(
        "interface OHOS.Storage.IStorageDaemon { "
        "[ipccode 7] void StartUser(); }"
    )
    functions = {
        "services/storage_daemon_stub.cpp:StorageDaemonStub::OnRemoteRequest": _function(
            "StorageDaemonStub::OnRemoteRequest",
            "switch (code) { case 8: return Dispatch(data, reply); }\n"
            'const char *text = "case 7: Dispatch";',
        ),
        "services/storage_daemon_proxy.cpp:StorageDaemonProxy::Call": _function(
            "StorageDaemonProxy::Call",
            'const char *text = "SendRequest(7, data, reply, option)";\n'
            "return 0;",
        ),
    }

    graph = OpenHarmonyIPCResolver().resolve(idl, functions)

    assert not any(edge.kind == "stub_to_transaction" for edge in graph.edges.values())
    assert not any(edge.kind == "proxy_to_transaction" for edge in graph.edges.values())


def test_resolver_keeps_overloaded_idl_methods_as_distinct_transactions():
    idl = _idl(
        """
        interface OHOS.Health.IHealthService {
            void Update([in] String name);
            void Update([in] int id);
        }
        """
    )

    graph = OpenHarmonyIPCResolver().resolve(idl, {})
    transaction_ids = sorted(
        node.id for node in graph.nodes.values() if node.kind == "ipc_transaction"
    )

    assert transaction_ids == [
        "idl:transaction:OHOS.Health.IHealthService:Update:overload:0",
        "idl:transaction:OHOS.Health.IHealthService:Update:overload:1",
    ]
