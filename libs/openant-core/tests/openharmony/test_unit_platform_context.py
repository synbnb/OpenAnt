"""Contract tests for OpenHarmony unit platform context metadata."""

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

from parsers.c.test_pipeline import CPipelineTest, ProcessingLevel  # noqa: E402
from parsers.c.unit_generator import UnitGenerator  # noqa: E402


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "scope_roles"


def _call_graph_data() -> dict:
    function_id = "services/health.cpp:HealthServiceStub::OnRemoteRequest"
    return {
        "repository": "/repo",
        "functions": {
            function_id: {
                "name": "HealthServiceStub::OnRemoteRequest",
                "file_path": "services/health.cpp",
                "code": (
                    "int HealthServiceStub::OnRemoteRequest(MessageParcel &data) {\n"
                    "    if (!ReadInterfaceToken(data)) return -1;\n"
                    "    auto uid = GetCallingUid();\n"
                    "    return CheckPermission(uid) ? 0 : -1;\n"
                    "}"
                ),
                "unit_type": "method",
            }
        },
        "call_graph": {},
        "reverse_call_graph": {},
    }


def _platform_context() -> dict:
    return {
        "platform": "openharmony",
        "file_roles": {"services/health.cpp": "production"},
        "components": [
            {"name": "health_service", "manifest_path": "bundle.json"}
        ],
        "targets": [
            {
                "name": "health_service",
                "path": "services/BUILD.gn",
                "sources": ["health.cpp"],
                "role": "production",
            }
        ],
        "boundaries": ["system_ability"],
    }


def test_openharmony_unit_carries_component_target_boundary_and_guard_context():
    generator = UnitGenerator(
        _call_graph_data(), {"platform_context": _platform_context()}
    )

    unit = generator.generate_units()["units"][0]
    context = unit["platform_context"]

    assert context["platform"] == "openharmony"
    assert context["source_role"] == "production"
    assert context["component"] == ["health_service"]
    assert context["target"] == ["health_service"]
    assert context["boundary"] == ["system_ability", "binder_ipc"]
    assert context["guard"] == [
        {"kind": "interface_token", "matched": "ReadInterfaceToken"},
        {"kind": "caller_identity", "matched": "GetCallingUid"},
        {"kind": "permission_check", "matched": "CheckPermission"},
    ]
    assert {item["source"] for item in context["evidence"]} >= {
        "scope_file_role",
        "bundle_manifest",
        "gn_target",
        "native_guard_signal",
    }


def test_analyzer_output_exposes_the_same_platform_context():
    generator = UnitGenerator(
        _call_graph_data(), {"platform_context": _platform_context()}
    )

    function = generator.generate_analyzer_output()["functions"][
        "services/health.cpp:HealthServiceStub::OnRemoteRequest"
    ]

    assert function["platformContext"]["component"] == ["health_service"]
    assert function["platformContext"]["target"] == ["health_service"]


def test_generic_units_do_not_gain_openharmony_context_field():
    unit = UnitGenerator(_call_graph_data()).generate_units()["units"][0]

    assert "platform_context" not in unit


def test_comments_and_string_literals_do_not_create_native_security_signals():
    graph = _call_graph_data()
    function = next(iter(graph["functions"].values()))
    function["code"] = (
        "int Example() {\n"
        "    // CheckPermission(data); MessageParcel parcel;\n"
        "    const char *text = \"ReadInterfaceToken\";\n"
        "    return 0;\n"
        "}"
    )

    unit = UnitGenerator(
        graph, {"platform_context": _platform_context()}
    ).generate_units()["units"][0]
    context = unit["platform_context"]

    assert context["boundary"] == ["system_ability"]
    assert context["guard"] == []
    assert not any(
        item["source"] in {"native_boundary_signal", "native_guard_signal"}
        for item in context["evidence"]
    )


def test_c_pipeline_derives_context_from_openharmony_scope(tmp_path):
    pipeline = CPipelineTest(
        str(FIXTURE_ROOT),
        output_dir=str(tmp_path / "out"),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True
    dataset = json.loads((tmp_path / "out" / "dataset.json").read_text())

    enable_unit = next(
        unit
        for unit in dataset["units"]
        if unit["code"]["primary_origin"]["function_name"] == "EnableHealthSensor"
    )
    context = enable_unit["platform_context"]
    assert context["platform"] == "openharmony"
    assert context["source_role"] == "production"
    assert context["component"] == ["openant_scope_roles_fixture"]
    assert context["target"] == ["health_sensor_service"]
