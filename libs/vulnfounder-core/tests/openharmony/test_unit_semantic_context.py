"""Integration tests for semantic IPC context functions in C/C++ Units."""

from __future__ import annotations

import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
C_PARSER_ROOT = CORE_ROOT / "parsers" / "c"
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))
if str(C_PARSER_ROOT) not in sys.path:
    sys.path.insert(0, str(C_PARSER_ROOT))

from parsers.c.unit_generator import UnitGenerator  # noqa: E402
from parsers.c.test_pipeline import CPipelineTest, ProcessingLevel  # noqa: E402
from core.platforms.openharmony.idl import OpenHarmonyIDLParser  # noqa: E402
from core.platforms.openharmony.ipc_graph import OpenHarmonyIPCResolver  # noqa: E402
from prompts.vulnerability_analysis import get_analysis_prompt  # noqa: E402


STUB_ID = "services/health_sensor_service_stub.cpp:HealthSensorServiceStub::OnRemoteRequest"
HANDLER_ID = "services/health_sensor_service_stub.cpp:HealthSensorServiceStub::EnableSensorInner"
TRANSACTION_ID = "idl:transaction:OHOS.Health.IHealthService:EnableSensor"


def _call_graph_data() -> dict:
    return {
        "repository": "/repo",
        "functions": {
            STUB_ID: {
                "name": "HealthSensorServiceStub::OnRemoteRequest",
                "file_path": "services/health_sensor_service_stub.cpp",
                "code": (
                    "int32_t HealthSensorServiceStub::OnRemoteRequest(...) {\n"
                    "    return Dispatch(code, data, reply);\n"
                    "}"
                ),
                "unit_type": "method",
            },
            HANDLER_ID: {
                "name": "HealthSensorServiceStub::EnableSensorInner",
                "file_path": "services/health_sensor_service_stub.cpp",
                "code": (
                    "int32_t HealthSensorServiceStub::EnableSensorInner(...) {\n"
                    "    auto value = data.ReadUint32();\n"
                    "    return EnableSensor(value);\n"
                    "}"
                ),
                "unit_type": "method",
            },
        },
        "call_graph": {},
        "reverse_call_graph": {},
    }


def _semantic_graph() -> dict:
    return {
        "schema_version": 1,
        "nodes": [
            {"schema_version": 1, "id": f"function:{STUB_ID}", "kind": "function", "attributes": {}},
            {"schema_version": 1, "id": TRANSACTION_ID, "kind": "ipc_transaction", "attributes": {}},
            {"schema_version": 1, "id": f"function:{HANDLER_ID}", "kind": "function", "attributes": {}},
        ],
        "edges": [
            {
                "schema_version": 1,
                "source_id": f"function:{STUB_ID}",
                "target_id": TRANSACTION_ID,
                "kind": "stub_to_transaction",
                "evidence": [{"source": "ipc_resolver", "matched": "ENABLE_SENSOR"}],
                "confidence": 0.95,
                "resolver_version": 1,
                "attributes": {},
            },
            {
                "schema_version": 1,
                "source_id": TRANSACTION_ID,
                "target_id": f"function:{HANDLER_ID}",
                "kind": "transaction_to_handler",
                "evidence": [{"source": "ipc_resolver", "matched": "EnableSensorInner"}],
                "confidence": 0.95,
                "resolver_version": 1,
                "attributes": {},
            },
        ],
        "orphans": [],
    }


def test_semantic_ipc_handler_is_inlined_as_context_function():
    generator = UnitGenerator(
        _call_graph_data(), {"semantic_graph": _semantic_graph()}
    )

    unit = generator.create_unit(STUB_ID, generator.functions[STUB_ID])
    origin = unit["code"]["primary_origin"]
    dependency_metadata = unit["code"]["dependency_metadata"]

    assert origin["semantic_context_inlined"] is True
    assert HANDLER_ID in origin["semantic_context_ids"]
    assert HANDLER_ID in dependency_metadata["semantic_context_ids"]
    assert dependency_metadata["total_semantic_context"] == 1
    assert "HealthSensorServiceStub::EnableSensorInner" in unit["code"]["primary_code"]
    assert unit["metadata"]["context_functions"][0]["id"] == HANDLER_ID
    assert unit["metadata"]["context_functions"][0]["edge_kinds"] == [
        "stub_to_transaction",
        "transaction_to_handler",
    ]


def test_semantic_context_does_not_change_native_call_graph_or_guess_without_edges():
    generator = UnitGenerator(
        _call_graph_data(), {"semantic_graph": {"schema_version": 1, "nodes": [], "edges": [], "orphans": []}}
    )

    unit = generator.create_unit(STUB_ID, generator.functions[STUB_ID])

    assert generator.call_graph == {}
    assert generator.reverse_call_graph == {}
    assert unit["code"]["primary_origin"]["semantic_context_inlined"] is False
    assert unit["metadata"]["context_functions"] == []
    assert "EnableSensorInner" not in unit["code"]["primary_code"]


def test_semantic_context_function_reaches_prompt_context_section():
    generator = UnitGenerator(
        _call_graph_data(), {"semantic_graph": _semantic_graph()}
    )
    unit = generator.create_unit(STUB_ID, generator.functions[STUB_ID])
    prompt = get_analysis_prompt(
        code=unit["code"]["primary_code"],
        language=unit["language"],
    )

    assert "HealthSensorServiceStub::OnRemoteRequest" in prompt
    assert "Context (for understanding only - do NOT analyze these for vulnerabilities):" in prompt
    assert "HealthSensorServiceStub::EnableSensorInner" in prompt


def test_resolver_output_can_feed_unit_semantic_context():
    idl = OpenHarmonyIDLParser().parse_text(
        "interfaces/IHealthService.idl",
        "interface OHOS.Health.IHealthSensorService { int EnableSensor(); }",
    )
    functions = {
        STUB_ID: {
            "name": "HealthSensorServiceStub::OnRemoteRequest",
            "file_path": "services/health_sensor_service_stub.cpp",
            "code": (
                "switch (code) { case CMD_ENABLE_SENSOR: "
                "return EnableSensorInner(data, reply); }"
            ),
            "unit_type": "method",
        },
        HANDLER_ID: {
            "name": "HealthSensorServiceStub::EnableSensorInner",
            "file_path": "services/health_sensor_service_stub.cpp",
            "code": "return EnableSensorInnerImpl(data, reply);",
            "unit_type": "method",
        },
    }
    semantic_graph = OpenHarmonyIPCResolver().resolve(idl, functions).to_dict()
    graph_data = {**_call_graph_data(), "functions": functions}

    unit = UnitGenerator(
        graph_data, {"semantic_graph": semantic_graph}
    ).create_unit(STUB_ID, functions[STUB_ID])

    assert unit["code"]["dependency_metadata"]["total_semantic_context"] == 1
    assert unit["metadata"]["context_functions"][0]["id"] == HANDLER_ID


def test_numeric_ipccode_proxy_path_reaches_unit_context():
    idl = OpenHarmonyIDLParser().parse_text(
        "interfaces/IStorageDaemon.idl",
        "interface OHOS.Storage.IStorageDaemon { "
        "[ipccode 7] void StartUser(); }",
    )
    proxy_id = "services/storage_daemon_proxy.cpp:StorageDaemonProxy::Call"
    stub_id = "services/storage_daemon_stub.cpp:StorageDaemonStub::OnRemoteRequest"
    handler_id = "services/storage_daemon_stub.cpp:StorageDaemonStub::HandleStartUser"
    functions = {
        proxy_id: {
            "name": "StorageDaemonProxy::Call",
            "file_path": "services/storage_daemon_proxy.cpp",
            "code": "return remote->SendRequest(7, data, reply, option);",
            "unit_type": "method",
        },
        stub_id: {
            "name": "StorageDaemonStub::OnRemoteRequest",
            "file_path": "services/storage_daemon_stub.cpp",
            "code": (
                "switch (code) { case CMD_START_USER: "
                "return HandleStartUser(data, reply); }"
            ),
            "unit_type": "method",
        },
        handler_id: {
            "name": "StorageDaemonStub::HandleStartUser",
            "file_path": "services/storage_daemon_stub.cpp",
            "code": "return 0;",
            "unit_type": "method",
        },
    }
    semantic_graph = OpenHarmonyIPCResolver().resolve(
        idl,
        functions,
        call_graph={"call_graph": {stub_id: [handler_id]}},
    ).to_dict()
    graph_data = {**_call_graph_data(), "functions": functions}

    unit = UnitGenerator(
        graph_data, {"semantic_graph": semantic_graph}
    ).create_unit(proxy_id, functions[proxy_id])

    assert unit["metadata"]["context_functions"][0]["id"] == handler_id
    assert unit["metadata"]["context_functions"][0]["edge_kinds"] == [
        "proxy_to_transaction",
        "transaction_to_handler",
    ]


def test_c_pipeline_collects_semantic_ipc_context_into_unit(tmp_path):
    repo = tmp_path / "openharmony_ipc"
    (repo / "interfaces").mkdir(parents=True)
    (repo / "services").mkdir()
    (repo / "bundle.json").write_text(
        '{"module":{"name":"health_sensor_service"}}', encoding="utf-8"
    )
    (repo / "BUILD.gn").write_text(
        'ohos_shared_library("health_sensor_service") {\n'
        '  sources = [ "services/health_sensor_service_stub.cpp" ]\n'
        '}\n',
        encoding="utf-8",
    )
    (repo / "interfaces" / "health_sensor.idl").write_text(
        "interface OHOS.Health.IHealthSensorService { int EnableSensor(); }\n",
        encoding="utf-8",
    )
    (repo / "services" / "health_sensor_service_stub.cpp").write_text(
        "int32_t HealthSensorServiceStub::OnRemoteRequest(uint32_t code) {\n"
        "    switch (code) {\n"
        "        case CMD_ENABLE_SENSOR: return EnableSensorInner();\n"
        "        default: return -1;\n"
        "    }\n"
        "}\n"
        "int32_t HealthSensorServiceStub::EnableSensorInner() { return 0; }\n",
        encoding="utf-8",
    )

    output = tmp_path / "out"
    pipeline = CPipelineTest(
        str(repo),
        output_dir=str(output),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True
    dataset = json.loads((output / "dataset.json").read_text(encoding="utf-8"))
    semantic_graph = json.loads(
        (output / "semantic_graph.json").read_text(encoding="utf-8")
    )

    stub_unit = next(
        unit
        for unit in dataset["units"]
        if unit["code"]["primary_origin"]["function_name"]
        == "HealthSensorServiceStub::OnRemoteRequest"
    )
    assert stub_unit["code"]["dependency_metadata"]["total_semantic_context"] == 1
    assert "EnableSensorInner" in stub_unit["code"]["primary_code"]
    assert any(
        edge["kind"] == "transaction_to_handler"
        for edge in semantic_graph["edges"]
    )


def test_c_pipeline_uses_call_graph_for_service_handler_owner(tmp_path):
    """The pipeline must pass its native call graph into IPC resolution."""
    repo = tmp_path / "openharmony_ipc_owner_split"
    (repo / "interfaces").mkdir(parents=True)
    (repo / "services").mkdir()
    (repo / "bundle.json").write_text(
        '{"module":{"name":"health_sensor_service"}}', encoding="utf-8"
    )
    (repo / "BUILD.gn").write_text(
        'ohos_shared_library("health_sensor_service") {\n'
        '  sources = [\n'
        '    "services/health_sensor_service_stub.cpp",\n'
        '    "services/health_sensor_service.cpp"\n'
        '  ]\n'
        '}\n',
        encoding="utf-8",
    )
    (repo / "interfaces" / "health_sensor.idl").write_text(
        "interface OHOS.Health.IHealthSensorService { int EnableSensor(); }\n",
        encoding="utf-8",
    )
    (repo / "services" / "health_sensor_service_stub.cpp").write_text(
        "int32_t HealthSensorServiceStub::OnRemoteRequest(uint32_t code) {\n"
        "    switch (code) {\n"
        "        case CMD_ENABLE_SENSOR: return EnableSensor();\n"
        "        default: return -1;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "services" / "health_sensor_service.cpp").write_text(
        "int32_t HealthSensorService::EnableSensor() { return 0; }\n",
        encoding="utf-8",
    )

    output = tmp_path / "out_owner_split"
    pipeline = CPipelineTest(
        str(repo),
        output_dir=str(output),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True
    semantic_graph = json.loads(
        (output / "semantic_graph.json").read_text(encoding="utf-8")
    )
    transaction = "idl:transaction:OHOS.Health.IHealthSensorService:EnableSensor"
    handler = next(
        edge
        for edge in semantic_graph["edges"]
        if edge["kind"] == "transaction_to_handler"
    )
    assert handler["source_id"] == transaction
    assert handler["evidence"][0]["source"] == "call_graph"
    assert handler["target_id"].endswith("HealthSensorService::EnableSensor")
