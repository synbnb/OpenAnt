"""OpenHarmony-native entry-point detection contracts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_C_PARSER_ROOT = Path(__file__).resolve().parents[2] / "parsers" / "c"
if str(_C_PARSER_ROOT) not in sys.path:
    sys.path.insert(0, str(_C_PARSER_ROOT))

from parsers.c.test_pipeline import CPipelineTest, ProcessingLevel
from utilities.agentic_enhancer import EntryPointDetector
from utilities.agentic_enhancer.openharmony_entry_point_detector import (
    OpenHarmonyEntryPointDetector,
    collect_hdf_registration_evidence,
)
from parsers.c.call_graph_builder import CallGraphBuilder


def _match(function: dict) -> list[dict]:
    return OpenHarmonyEntryPointDetector().detect(function)


def test_binder_on_remote_request_is_an_openharmony_entry_point():
    matches = _match(
        {
            "name": "HealthSensorServiceStub::OnRemoteRequest",
            "file_path": "services/health_sensor_service_stub.cpp",
            "start_line": 17,
            "code": "int32_t HealthSensorServiceStub::OnRemoteRequest(...) {}",
        }
    )

    assert [match["category"] for match in matches] == ["binder_ipc"]
    assert matches[0]["matched"] == "OnRemoteRequest"
    assert matches[0]["confidence"] == "high"


def test_system_ability_lifecycle_is_an_openharmony_entry_point():
    matches = _match(
        {
            "name": "MedicalSensorService::OnStart",
            "file_path": "services/medical_sensor/src/medical_service.cpp",
            "code": "void MedicalSensorService::OnStart() { SystemAbility::Publish(this); }",
        }
    )

    assert [match["category"] for match in matches] == ["system_ability_lifecycle"]
    assert matches[0]["matched"] == "OnStart"


def test_ordinary_component_start_stop_are_not_system_ability_entries():
    for method in ("OnStart", "OnStop"):
        matches = _match(
            {
                "name": f"VideoProcessingNativeBase::{method}",
                "file_path": (
                    "framework/capi/video_processing/"
                    "video_processing_native_base.cpp"
                ),
                "code": "return VIDEO_PROCESSING_SUCCESS;",
            }
        )

        assert matches == []


def test_ability_extension_start_is_not_system_ability_entry():
    matches = _match(
        {
            "name": "JsWindowExtension::OnStart",
            "file_path": "extension/window_extension/src/js_window_extension.cpp",
            "code": "return;",
        }
    )

    assert [match["category"] for match in matches] == ["ability_lifecycle"]


def test_ability_callbacks_are_classified_separately_from_system_ability():
    matches = _match(
        {
            "name": "JsUIAbility::OnNewWant",
            "file_path": "frameworks/ets/ani/ability_runtime/js_ui_ability.cpp",
            "code": "void JsUIAbility::OnNewWant(const Want &want) { Handle(want); }",
        }
    )

    assert [match["category"] for match in matches] == ["ability_lifecycle"]
    assert matches[0]["matched"] == "OnNewWant"


def test_system_ability_named_ability_takes_sa_precedence():
    matches = _match(
        {
            "name": "DeviceAuthAbility::OnStart",
            "file_path": "frameworks/src/deviceauth_sa.cpp",
            "code": "void DeviceAuthAbility::OnStart() { Publish(this); }",
        }
    )

    assert [match["category"] for match in matches] == ["system_ability_lifecycle"]


def test_unrelated_on_command_is_not_an_ability_callback():
    matches = _match(
        {
            "name": "ShellCommand::OnCommand",
            "file_path": "tools/aa/src/shell_command.cpp",
            "code": "ErrCode ShellCommand::OnCommand() { return 0; }",
        }
    )

    assert matches == []


def test_hdf_dispatch_is_an_openharmony_entry_point():
    matches = _match(
        {
            "name": "BatteryInterfaceDriverDispatch",
            "file_path": "interfaces/hdi_service/src/battery_interface_driver.cpp",
            "code": (
                "int32_t BatteryInterfaceDriverDispatch(struct HdfDeviceIoClient *client, "
                "int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply) { return 0; }"
            ),
        }
    )

    assert [match["category"] for match in matches] == ["hdf_dispatch"]
    assert matches[0]["matched"] == "BatteryInterfaceDriverDispatch"


def test_hdf_registration_marks_only_referenced_driver_callbacks(tmp_path):
    source_path = tmp_path / "sample_driver.c"
    source_path.write_text(
        """
        static int32_t SampleBind(struct HdfDeviceObject *device) { return 0; }
        static int32_t SampleInit(struct HdfDeviceObject *device) { return 0; }
        static void Helper(void) { }
        struct HdfDriverEntry g_sampleEntry = {
            .Bind = SampleBind,
            .Init = SampleInit,
        };
        HDF_INIT(g_sampleEntry);
        """,
        encoding="utf-8",
    )

    evidence = collect_hdf_registration_evidence(tmp_path, ["sample_driver.c"])
    assert evidence["sample_driver.c"][0]["callbacks"] == ["SampleBind", "SampleInit"]

    detector = EntryPointDetector(
        {
            "sample_driver.c:SampleBind": {
                "name": "SampleBind",
                "file_path": "sample_driver.c",
                "code": "return 0;",
            },
            "sample_driver.c:Helper": {
                "name": "Helper",
                "file_path": "sample_driver.c",
                "code": "return;",
            },
        },
        {},
        platform="openharmony",
        file_evidence=evidence,
    )
    entries = detector.detect_entry_points()
    assert entries == {"sample_driver.c:SampleBind"}
    assert detector.entry_point_details["sample_driver.c:SampleBind"]["platform_evidence"][0]["category"] == "hdf_registration"


def test_c_call_graph_persists_openharmony_hdf_file_evidence(tmp_path):
    source_path = tmp_path / "sample_driver.c"
    source_path.write_text(
        """
        static int32_t SampleBind(struct HdfDeviceObject *device) { return 0; }
        struct HdfDriverEntry g_sampleEntry = { .Bind = SampleBind };
        HDF_INIT(g_sampleEntry);
        """,
        encoding="utf-8",
    )

    from parsers.c.function_extractor import FunctionExtractor

    extracted = FunctionExtractor(str(tmp_path)).extract_all(["sample_driver.c"])
    graph = CallGraphBuilder(
        extracted,
        {"platform": "openharmony"},
    ).export()
    assert graph["openharmony_file_evidence"]["sample_driver.c"][0]["entry"] == "g_sampleEntry"


def test_c_pipeline_forwards_hdf_file_evidence_to_reachability(tmp_path):
    source_path = tmp_path / "sample_driver.c"
    source_path.write_text(
        """
        static int32_t SampleBind(struct HdfDeviceObject *device) { return 0; }
        static void Helper(void) { }
        struct HdfDriverEntry g_sampleEntry = { .Bind = SampleBind };
        HDF_INIT(g_sampleEntry);
        """,
        encoding="utf-8",
    )
    output_dir = tmp_path / "pipeline"
    pipeline = CPipelineTest(
        str(tmp_path),
        output_dir=str(output_dir),
        processing_level=ProcessingLevel.REACHABLE,
        skip_tests=True,
        platform="openharmony",
    )

    result = pipeline.run_full_pipeline()
    assert result["stages"]["c_parser"]["success"] is True
    assert result["stages"]["reachability_filter"]["success"] is True

    dataset = json.loads((output_dir / "dataset.json").read_text(encoding="utf-8"))
    entry_units = [unit for unit in dataset["units"] if unit.get("is_entry_point")]
    assert any("SampleBind" in unit["id"] for unit in entry_units)
    assert any(
        "platform:openharmony:hdf_registration" in unit.get("entry_point_reason", "")
        for unit in entry_units
    )


def test_interface_token_read_alone_is_not_an_entry_point():
    matches = _match(
        {
            "name": "HealthSensorServiceStub::EnableSensorInner",
            "file_path": "services/health_sensor_service_stub.cpp",
            "code": "auto token = data.ReadInterfaceToken(); return 0;",
        }
    )

    assert matches == []


def test_native_network_socket_receive_is_an_entry_point_with_evidence():
    matches = _match(
        {
            "name": "ProxyServer::AcceptLoop",
            "file_path": "services/netconnmanager/src/proxy.cpp",
            "start_line": 100,
            "code": (
                "void ProxyServer::AcceptLoop() { sockaddr_in peer{}; "
                "int fd = accept(serverFd, (sockaddr *)&peer, nullptr); "
                "recv(fd, buffer, sizeof(buffer), 0); }"
            ),
        }
    )

    assert [match["category"] for match in matches] == ["native_socket"]
    assert matches[0]["matched"] == "accept,recv"
    assert matches[0]["socket_kind"] == "network_socket"
    assert matches[0]["trust"] == "untrusted"
    assert matches[0]["socket_calls"] == [
        {"primitive": "accept", "line": 100},
        {"primitive": "recv", "line": 100},
    ]


def test_native_local_socket_accept_is_semi_trusted():
    matches = _match(
        {
            "name": "AcceptPipeSocket_",
            "file_path": "services/loopevent/socket/le_socket.c",
            "start_line": 170,
            "code": (
                "static int AcceptPipeSocket_(int serverFd) { "
                "struct sockaddr_un clientAddr; "
                "return accept(serverFd, (struct sockaddr *)&clientAddr, 0); }"
            ),
        }
    )

    assert matches[0]["socket_kind"] == "local_socket"
    assert matches[0]["trust"] == "semi_trusted"


def test_native_kernel_socket_receive_is_classified_separately():
    matches = _match(
        {
            "name": "AudioSocketThread::AudioPnpReadUeventMsg",
            "file_path": "services/audio_policy/audio_socket_thread.cpp",
            "start_line": 130,
            "code": (
                "ssize_t AudioPnpReadUeventMsg(int fd) { sockaddr_nl addr{}; "
                "msghdr msg{}; return recvmsg(fd, &msg, 0); }"
            ),
        }
    )

    assert matches[0]["socket_kind"] == "kernel_socket"
    assert matches[0]["trust"] == "semi_trusted"


def test_socket_words_in_comments_and_literals_do_not_seed_entry_point():
    matches = _match(
        {
            "name": "Helper",
            "file_path": "services/helper.cpp",
            "code": (
                '// recv(fd, buf, n, 0)\n'
                'const char *text = "accept(fd, nullptr, nullptr)";\n'
                "return read(fd, buf, n);"
            ),
        }
    )

    assert matches == []


def test_generic_detector_keeps_openharmony_patterns_disabled():
    functions = {
        "services/stub.cpp:ServiceStub::OnRemoteRequest": {
            "name": "ServiceStub::OnRemoteRequest",
            "unit_type": "method",
            "file_path": "services/stub.cpp",
            "code": "return 0;",
        }
    }

    assert EntryPointDetector(functions, {}).detect_entry_points() == set()


def test_openharmony_detector_exposes_location_and_reason():
    func_id = "services/stub.cpp:ServiceStub::OnRemoteRequest"
    functions = {
        func_id: {
            "name": "ServiceStub::OnRemoteRequest",
            "unit_type": "method",
            "file_path": "services/stub.cpp",
            "start_line": 23,
            "end_line": 37,
            "code": "int32_t ServiceStub::OnRemoteRequest(...) { return 0; }",
        }
    }

    detector = EntryPointDetector(functions, {}, platform="openharmony")
    assert detector.detect_entry_points() == {func_id}

    details = detector.entry_point_details[func_id]
    assert "platform:openharmony:binder_ipc" in details["reasons"]
    assert details["platform_evidence"] == [
        {
            "category": "binder_ipc",
            "confidence": "high",
            "evidence": "function_name:OnRemoteRequest",
            "matched": "OnRemoteRequest",
            "reason": "platform:openharmony:binder_ipc",
            "file_path": "services/stub.cpp",
            "start_line": 23,
            "end_line": 37,
        }
    ]


def test_real_ipc_fixture_detects_stub_but_not_inner_handler():
    fixture_root = Path(__file__).resolve().parents[1] / "fixtures" / "openharmony" / "ipc_service"
    stub_path = fixture_root / "services" / "health_sensor_service_stub.cpp"
    source = stub_path.read_text(encoding="utf-8")

    functions = {
        "services/health_sensor_service_stub.cpp:HealthSensorServiceStub::OnRemoteRequest": {
            "name": "HealthSensorServiceStub::OnRemoteRequest",
            "unit_type": "method",
            "file_path": "services/health_sensor_service_stub.cpp",
            "start_line": 17,
            "end_line": 31,
            "code": source,
        },
        "services/health_sensor_service_stub.cpp:HealthSensorServiceStub::EnableSensorInner": {
            "name": "HealthSensorServiceStub::EnableSensorInner",
            "unit_type": "method",
            "file_path": "services/health_sensor_service_stub.cpp",
            "start_line": 33,
            "end_line": 46,
            "code": "int32_t HealthSensorServiceStub::EnableSensorInner(...) { "
            "auto token = data.ReadInterfaceToken(); return 0; }",
        },
    }

    detector = EntryPointDetector(functions, {}, platform="openharmony")
    assert detector.detect_entry_points() == {
        "services/health_sensor_service_stub.cpp:HealthSensorServiceStub::OnRemoteRequest"
    }


def test_c_pipeline_forwards_openharmony_platform_to_reachability(tmp_path):
    fixture_root = Path(__file__).resolve().parents[1] / "fixtures" / "openharmony" / "ipc_service"
    output_dir = tmp_path / "c_pipeline"
    pipeline = CPipelineTest(
        str(fixture_root),
        output_dir=str(output_dir),
        processing_level=ProcessingLevel.REACHABLE,
        skip_tests=True,
        platform="openharmony",
    )

    result = pipeline.run_full_pipeline()

    assert result["stages"]["c_parser"]["success"] is True
    reachability = result["stages"]["reachability_filter"]
    assert reachability["success"] is True
    assert reachability["summary"]["entry_points"] >= 1

    dataset = json.loads((output_dir / "dataset.json").read_text(encoding="utf-8"))
    entry_ids = {
        unit["id"]
        for unit in dataset["units"]
        if unit.get("is_entry_point")
    }
    assert any(unit_id.endswith("HealthSensorServiceStub::OnRemoteRequest") for unit_id in entry_ids)
