"""Tests for evidence-rich disclosure context construction."""

from __future__ import annotations

import json
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))


def _function(route: str, code: str, start: int, end: int) -> dict:
    file_path, name = route.split(":", 1)
    return {
        "name": name,
        "file_path": file_path,
        "start_line": start,
        "end_line": end,
        "code": code,
        "unit_type": "method",
    }


def test_pipeline_output_contains_source_sink_and_graph_context(tmp_path: Path):
    from core import reporter

    target = "services/medical_sensor.cpp:MedicalSensorServiceClient::EnableSensor"
    init = "services/medical_sensor.cpp:MedicalSensorServiceClient::InitServiceClient"
    entry = "services/medical_sensor_stub.cpp:MedicalSensorServiceStub::OnRemoteRequest"
    handler = "services/medical_sensor_stub.cpp:MedicalSensorServiceStub::AfeEnableInner"
    downstream = "services/medical_sensor.cpp:MedicalSensorService::EnableSensor"
    functions = {
        target: _function(target, "int EnableSensor(...) { return afe->EnableSensor(...); }", 97, 114),
        init: _function(init, "int InitServiceClient() { return 0; }", 120, 130),
        entry: _function(entry, "int OnRemoteRequest(...) { dispatch(); }", 30, 80),
        handler: _function(handler, "int AfeEnableInner(...) { return EnableSensor(...); }", 90, 110),
        downstream: _function(downstream, "int EnableSensor(...) { return SaveSubscriber(...); }", 200, 230),
    }
    forward = {
        target: [init],
        entry: [],
        handler: [downstream],
    }
    reverse = {
        init: [target],
        downstream: [handler],
        target: [handler],
    }
    result = {
        "dataset": "medical_sensor",
        "metrics": {"total": 1, "vulnerable": 1},
        "results": [{
            "route_key": target,
            "unit_id": target,
            "finding": "vulnerable",
            "verdict": "vulnerable",
            "reasoning": "unchecked timing values reach a signed division",
            "attack_scenario": "Send a malformed timing pair.",
            "dataflow_summary": "caller -> client -> service -> division",
            "verification": {
                "agree": True,
                "exploit_path": {
                    "entry_point": "MedicalSensorServiceStub::OnRemoteRequest -> MedicalSensorServiceStub::AfeEnableInner (ENABLE_SENSOR)",
                    "data_flow": [
                        "Caller controls samplingPeriod and maxReportDelay.",
                        "AfeEnableInner calls MedicalSensorService::EnableSensor.",
                        "MedicalSensorService::EnableSensor reaches signed division.",
                    ],
                    "sink_reached": True,
                    "attacker_control_at_sink": "full",
                    "path_broken_at": None,
                },
            },
        }],
        "confirmed_findings": [{
            "route_key": target,
            "unit_id": target,
            "finding": "vulnerable",
            "verdict": "vulnerable",
        }],
        "code_by_route": {target: functions[target]["code"]},
    }
    (tmp_path / "results_verified.json").write_text(json.dumps(result), encoding="utf-8")
    (tmp_path / "call_graph.json").write_text(json.dumps({
        "functions": functions,
        "call_graph": forward,
        "reverse_call_graph": reverse,
        "statistics": {"function_count": len(functions), "edge_count": 3},
    }), encoding="utf-8")
    (tmp_path / "dataset_enhanced.json").write_text(json.dumps({
        "units": [{
            "id": target,
            "code": {"primary_origin": {"file_path": target.split(":", 1)[0], "start_line": 97, "end_line": 114, "function_name": target.split(":", 1)[1]}, "primary_code": functions[target]["code"]},
            "agent_context": {"include_functions": [{"id": downstream, "reason": "下游服务处理函数"}]},
        }],
        "metadata": {"agentic_enhanced": True},
    }), encoding="utf-8")
    (tmp_path / "semantic_graph.json").write_text(json.dumps({
        "edges": [{
            "source_id": f"function:{entry}",
            "target_id": f"function:{handler}",
            "kind": "native_dispatch_to_handler",
            "confidence": 0.98,
        }],
    }), encoding="utf-8")
    (tmp_path / "dispatch_recovery_diff.json").write_text(json.dumps({
        "projected_edges": [{"source_id": entry, "target_id": handler, "edge_kinds": ["native_dispatch_to_handler"], "is_new": True}],
        "summary": {"projected_edge_count": 1, "new_edge_count": 1},
    }), encoding="utf-8")

    output_path = tmp_path / "pipeline_output.json"
    reporter.build_pipeline_output(
        str(tmp_path / "results_verified.json"),
        str(output_path),
        repo_name="medical_sensor",
        language="cpp",
    )
    finding = json.loads(output_path.read_text(encoding="utf-8"))["findings"][0]

    assert finding["route_key"] == target
    assert finding["location"]["start_line"] == 97
    assert finding["location"]["end_line"] == 114
    context = finding["report_context"]
    assert context["target"]["source_location"]["route_key"] == target
    assert context["source_to_sink"]["sink_reached"] is True
    assert "MedicalSensorService::EnableSensor" in context["source_to_sink"]["ordered_steps"][1]
    routes = [node["route_key"] for node in context["call_chain"]["nodes"]]
    assert entry in routes
    assert handler in routes
    assert downstream in routes
    assert context["call_graph"]["semantic_edges"][0]["kind"] == "native_dispatch_to_handler"
    assert context["call_graph"]["projected_edges"][0]["is_new"] is True
    assert context["call_graph"]["enhanced_dataset"] is True
    assert context["provenance"]["artifacts"]


def test_context_builder_is_optional_when_scan_artifacts_are_missing(tmp_path: Path):
    from core.report_context import build_disclosure_context, load_report_context_index

    route = "services/audio.cpp:AudioService::Enable"
    index = load_report_context_index(tmp_path)
    context = build_disclosure_context(
        index,
        route,
        finding={"finding": "vulnerable"},
        full_result={"reasoning": "manual review required"},
        source_code="void Enable() {}",
    )

    assert context["target"]["source_location"]["route_key"] == route
    assert context["target"]["source_code"] == "void Enable() {}"
    assert context["call_chain"]["node_count"] == 1
    assert context["call_graph"]["native_edges"] == []
    assert context["provenance"]["artifacts"] == []


def test_historical_pipeline_is_enriched_from_sibling_artifacts(tmp_path: Path):
    from report import generator

    route = "services/audio.cpp:AudioService::Enable"
    (tmp_path / "results_verified.json").write_text(json.dumps({
        "results": [{
            "route_key": route,
            "unit_id": route,
            "finding": "vulnerable",
            "verification": {"exploit_path": {
                "entry_point": "AudioStub::OnRemoteRequest -> AudioStub::EnableInner",
                "data_flow": ["AudioStub::EnableInner calls AudioService::Enable"],
            }},
        }],
        "code_by_route": {route: "int Enable() { return 0; }"},
    }), encoding="utf-8")
    (tmp_path / "call_graph.json").write_text(json.dumps({
        "functions": {
            route: _function(route, "int Enable() { return 0; }", 10, 12),
        },
        "call_graph": {},
        "reverse_call_graph": {},
    }), encoding="utf-8")
    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline_path.write_text(json.dumps({
        "repository": {"name": "audio"},
        "findings": [{
            "id": "VULN-001",
            "route_key": route,
            "location": {"file": "services/audio.cpp", "function": "AudioService::Enable"},
        }],
    }), encoding="utf-8")

    hydrated = generator._hydrate_pipeline_findings(str(pipeline_path), json.loads(pipeline_path.read_text()))
    finding = hydrated["findings"][0]
    assert finding["report_context"]["target"]["source_location"]["start_line"] == 10
    assert finding["report_context"]["source_to_sink"]["entry_point"].startswith("AudioStub")
    assert finding["location"]["start_line"] == 10


def test_context_renderer_keeps_source_and_edges_out_of_model_rewrite():
    from report import generator

    finding = {
        "route_key": "services/audio.cpp:AudioService::Enable",
        "location": {
            "file": "services/audio.cpp",
            "function": "AudioService::Enable",
            "start_line": 10,
            "end_line": 12,
        },
        "report_context": {
            "target": {"source_location": {
                "file": "services/audio.cpp",
                "function": "AudioService::Enable",
                "start_line": 10,
                "end_line": 12,
                "route_key": "services/audio.cpp:AudioService::Enable",
            }},
            "source_to_sink": {
                "entry_point": "AudioStub::OnRemoteRequest -> AudioStub::EnableInner",
                "ordered_steps": ["caller input -> EnableInner", "EnableInner -> sink"],
                "sink_reached": True,
            },
            "assessment": {
                "defect_status": "confirmed",
                "reachability_status": "conditional",
                "impact_status": "plausible",
                "evidence_completeness": "partial",
                "boundary_type": "unix_socket",
                "missing_evidence": ["receiver registration"],
                "confidence": 0.72,
            },
            "call_chain": {"nodes": [{
                "order": 1,
                "role": "entry",
                "function": "AudioStub::OnRemoteRequest",
                "file": "services/audio_stub.cpp",
                "start_line": 20,
                "end_line": 30,
                "source_code": "int OnRemoteRequest(...) { return 0; }",
            }]},
            "call_graph": {"native_edges": [{
                "source": "services/audio_stub.cpp:AudioStub::OnRemoteRequest",
                "target": "services/audio.cpp:AudioService::Enable",
                "kind": "native_dispatch_to_handler",
            }]},
            "provenance": {"artifacts": ["call_graph.json"]},
        },
    }

    rendered = generator._render_disclosure_context(finding, language="cpp")
    assert "services/audio.cpp" in rendered
    assert "第 10-12 行" in rendered
    assert "AudioStub::OnRemoteRequest" in rendered
    assert "int OnRemoteRequest(...)" in rendered
    assert "native_dispatch_to_handler" in rendered
    assert "Sink reached" in rendered
    assert "Stage 2 Assessment" in rendered
    assert "Defect status" in rendered
    assert "receiver registration" in rendered

    localized = generator._localize_disclosure_markdown(rendered, "zh-CN")
    assert "第二阶段评估" in localized
    assert "缺陷状态" in localized
    assert "可达性状态" in localized


def test_repair_response_requires_code_and_rejects_disclosure_document():
    from report import generator

    parsed = generator._parse_repair_response(
        '{"status":"ready","patch":"if (size == 0) return ERR_INVALID_PARAM;",'
        '"rationale":"Reject empty input."}'
    )
    assert parsed["status"] == "generated"
    assert "ERR_INVALID_PARAM" in parsed["code"]

    rejected = generator._parse_repair_response(
        "# Security Disclosure: Example\n\n```cpp\nif (size == 0) return 0;\n```"
    )
    assert rejected["status"] == "unavailable"
    assert rejected["code"] == ""


def test_disclosure_uses_model_repair_patch_instead_of_manual_placeholder():
    from report import generator
    from utilities.llm import CompletionResult, PhaseBinding, TextBlock

    class RepairAdapter:
        name = "offline"
        supports_tools = False
        pricing = {"repair-model": {"input": 1.0, "output": 1.0}}

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            del model, system, max_tokens, tools
            prompt = messages[0].content[0].text
            if "minimal security patch" in prompt:
                body = json.dumps({
                    "status": "ready",
                    "patch": "if (descriptors.empty()) return ERR_INVALID_PARAM;",
                    "rationale": "Reject an empty caller-controlled container before delegation.",
                })
            else:
                body = "# Security Disclosure: test\n\n## Summary\n\nA finding was identified."
            return CompletionResult(
                content=[TextBlock(body)],
                input_tokens=2,
                output_tokens=3,
                stop_reason="end_turn",
            )

    finding = {
        "id": "VULN-001",
        "name": "Unchecked input",
        "short_name": "unchecked-input",
        "route_key": "services/audio.cpp:AudioService::Enable",
        "location": {"file": "services/audio.cpp", "function": "AudioService::Enable"},
        "cwe_id": 400,
        "cwe_name": "Uncontrolled Resource Consumption",
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "confirmed",
        "description": "Caller-controlled input reaches a delegate.",
        "suggested_fix": "[MANUAL REVIEW REQUIRED]",
        "vulnerable_code": "int Enable() { return delegate(); }",
        "vulnerable_code_section": "## Vulnerable Code\n\n```cpp\nint Enable() { return delegate(); }\n```",
        "report_context": {
            "target": {"source_location": {
                "file": "services/audio.cpp", "function": "AudioService::Enable",
                "start_line": 10, "end_line": 12,
                "route_key": "services/audio.cpp:AudioService::Enable",
            }, "source_code": "int Enable() { return delegate(); }"},
            "source_to_sink": {},
            "call_chain": {"nodes": []},
            "call_graph": {},
            "provenance": {},
        },
    }
    binding = PhaseBinding(
        phase="report", adapter=RepairAdapter(), model="repair-model", provider_name="offline"
    )
    disclosure, usage = generator.generate_disclosure(finding, "audio", binding)

    assert "if (descriptors.empty()) return ERR_INVALID_PARAM;" in disclosure
    assert "[MANUAL REVIEW REQUIRED]" not in disclosure
    assert "修复状态：`generated`" in disclosure
    assert usage["total_tokens"] == 10  # one repair call + one disclosure call


def test_hydration_recovers_revision_from_scan_record(tmp_path: Path, monkeypatch):
    from report import generator

    monkeypatch.setattr(
        generator,
        "_git_revision_metadata",
        lambda path: {"branch": "OpenHarmony-6.1-LTS", "commit_sha": "abc1234", "release_version": "OpenHarmony-6.1-LTS"},
    )
    (tmp_path / "scan.report.json").write_text(json.dumps({
        "inputs": {"repo_path": "/source/medical_sensor"},
    }), encoding="utf-8")
    pipeline = {
        "repository": {"name": "medical_sensor"},
        "findings": [],
    }
    path = tmp_path / "pipeline_output.json"
    path.write_text(json.dumps(pipeline), encoding="utf-8")

    generator._hydrate_revision_metadata(str(path), pipeline)
    assert pipeline["repository"]["commit_sha"] == "abc1234"
    assert pipeline["repository"]["release_version"] == "OpenHarmony-6.1-LTS"
    assert pipeline["revision_provenance"]["source"] == "git"
