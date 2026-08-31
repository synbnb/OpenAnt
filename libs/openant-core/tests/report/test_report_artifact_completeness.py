"""Regression tests for complete disclosure-report artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))


def test_verified_results_preserve_code_by_route(tmp_path: Path):
    from core.verifier import _write_verified_results

    route = "services/audio.cpp:AudioService::Enable"
    experiment = {
        "dataset": "audio",
        "model": "test-model",
        "timestamp": "2026-08-28T00:00:00Z",
        "metrics": {"total": 1},
        "code_by_route": {route: "int32_t AudioService::Enable() { return 0; }"},
    }
    finding = {
        "unit_id": route,
        "route_key": route,
        "finding": "vulnerable",
        "verdict": "vulnerable",
    }
    output_path = tmp_path / "results_verified.json"

    _write_verified_results(str(output_path), experiment, [finding], [finding])

    output = json.loads(output_path.read_text())
    assert output["code_by_route"][route].startswith("int32_t AudioService")


def test_pipeline_output_recovers_code_from_sibling_results_verified_input(
    tmp_path: Path,
):
    from core import reporter

    route = "services/audio.cpp:AudioService::Enable"
    code = "int32_t AudioService::Enable() { return 0; }"
    (tmp_path / "results.json").write_text(
        json.dumps(
            {
                "dataset": "audio",
                "results": [
                    {
                        "unit_id": route,
                        "route_key": route,
                        "finding": "vulnerable",
                        "verdict": "vulnerable",
                        "reasoning": "missing authorization",
                    }
                ],
                "code_by_route": {route: code},
                "confirmed_findings": [],
                "metrics": {"total": 1, "vulnerable": 1},
            }
        )
    )
    verified_path = tmp_path / "results_verified.json"
    verified_path.write_text(
        json.dumps(
            {
                "dataset": "audio",
                "results": [
                    {
                        "unit_id": route,
                        "route_key": route,
                        "finding": "vulnerable",
                        "verdict": "vulnerable",
                        "reasoning": "missing authorization",
                    }
                ],
                "confirmed_findings": [
                    {
                        "unit_id": route,
                        "route_key": route,
                        "finding": "vulnerable",
                        "verdict": "vulnerable",
                    }
                ],
                "metrics": {"total": 1, "vulnerable": 1},
            }
        )
    )
    output_path = tmp_path / "pipeline_output.json"

    reporter.build_pipeline_output(
        results_path=str(verified_path),
        output_path=str(output_path),
        repo_name="audio",
        language="cpp",
    )

    finding = json.loads(output_path.read_text())["findings"][0]
    assert code in finding["vulnerable_code_section"]
    assert finding["vulnerable_code"] == code


def test_old_pipeline_output_is_hydrated_from_sibling_artifact(tmp_path: Path):
    from report import generator

    route = "services/audio.cpp:AudioService::Enable"
    code = "int32_t AudioService::Enable() { return 0; }"
    (tmp_path / "results_verified.json").write_text(
        json.dumps({"code_by_route": {route: code}})
    )
    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline = {
        "repository": {"name": "audio", "language": "cpp"},
        "findings": [{
            "id": "VULN-001",
            "name": "Missing authorization",
            "short_name": "Missing authorization",
            "location": {"file": "services/audio.cpp", "function": "AudioService::Enable"},
            "cwe_id": 862,
            "cwe_name": "Missing Authorization",
            "stage1_verdict": "vulnerable",
            "stage2_verdict": "vulnerable",
        }],
    }
    pipeline_path.write_text(json.dumps(pipeline))

    hydrated = generator._hydrate_pipeline_findings(str(pipeline_path), pipeline)
    finding = hydrated["findings"][0]
    assert finding["vulnerable_code"] == code
    assert code in finding["vulnerable_code_section"]


def test_hydration_leaves_unavailable_source_explicit(tmp_path: Path):
    from report import generator

    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline = {
        "repository": {"name": "audio", "language": "cpp"},
        "findings": [{
            "id": "VULN-001",
            "location": {"file": "services/audio.cpp", "function": "Enable"},
        }],
    }
    pipeline_path.write_text(json.dumps(pipeline))

    # No sibling source artifact: the helper must not invent code.
    hydrated = generator._hydrate_pipeline_findings(str(pipeline_path), pipeline)
    assert "vulnerable_code" not in hydrated["findings"][0]


def test_pipeline_output_source_recovery_merges_partial_sibling_maps(tmp_path: Path):
    from core import reporter

    first = "services/audio.cpp:AudioService::Enable"
    second = "services/audio.cpp:AudioService::Disable"
    (tmp_path / "results_verified.json").write_text(
        json.dumps({"code_by_route": {first: "void Enable() {}"}})
    )
    (tmp_path / "results.json").write_text(
        json.dumps({"code_by_route": {second: "void Disable() {}"}})
    )
    recovered = reporter._load_code_by_route(
        str(tmp_path / "results_verified.json"),
        {"code_by_route": {first: "void Enable() {}"}},
    )
    assert set(recovered) == {first, second}


def test_disclosure_prompt_renders_metadata_and_final_output_sections(monkeypatch):
    from report import generator
    from utilities.llm import CompletionResult, PhaseBinding, TextBlock

    class FakeAdapter:
        name = "offline"
        supports_tools = False
        pricing = {"report-model": {"input": 1.0, "output": 1.0}}

        def __init__(self):
            self.prompt = ""

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            del model, system, max_tokens, tools
            self.prompt = messages[0].content[0].text
            return CompletionResult(
                content=[TextBlock("# Security Disclosure: fallback")],
                input_tokens=1,
                output_tokens=1,
                stop_reason="end_turn",
            )

        def validate(self, model):
            del model

    adapter = FakeAdapter()
    binding = PhaseBinding(
        phase="report",
        adapter=adapter,
        model="report-model",
        provider_name="offline",
    )
    finding = {
        "id": "VULN-001",
        "name": "Missing authorization",
        "short_name": "Missing authorization",
        "location": {"file": "services/audio.cpp", "function": "Enable"},
        "cwe_id": 862,
        "cwe_name": "Missing Authorization",
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "unverified",
        "description": "The service does not authorize the caller.",
        "impact": "A local caller can invoke the operation.",
        "suggested_fix": None,
        "steps_to_reproduce": None,
        "vulnerable_code_section": (
            "## Vulnerable Code\n\n"
            "`services/audio.cpp`:\n\n"
            "```cpp\nint Enable() { return 0; }\n```"
        ),
    }
    pipeline_data = {
        "application_type": "openharmony_component",
        "analysis_date": "2026-08-28T12:34:56+00:00",
        "repository": {"name": "audio", "commit_sha": "abc123"},
    }

    disclosure, _ = generator.generate_disclosure(
        finding,
        "audio",
        binding,
        pipeline_data=pipeline_data,
    )

    assert "{short_title}" not in adapter.prompt
    assert "{product_name}" not in adapter.prompt
    assert "{cwe_id}" not in adapter.prompt
    assert "{cwe_name}" not in adapter.prompt
    assert "{affected_versions}" not in adapter.prompt
    assert "{platform/version}" not in adapter.prompt
    assert "{date}" not in adapter.prompt
    assert "{verification_method}" not in adapter.prompt
    assert "**Product:** audio" in adapter.prompt
    assert "CWE-862 (Missing Authorization)" in adapter.prompt
    assert "## Vulnerable Code" in disclosure
    assert "## Summary" in disclosure
    assert "## Steps to Reproduce" in disclosure
    assert "## Impact" in disclosure
    assert "## Suggested Fix" in disclosure
    assert "Current scanned revision" in disclosure


def test_disclosure_replaces_model_placeholders_in_existing_sections():
    from report import generator

    finding = {
        "name": "vulnerable",
        "location": {"file": "services/audio.cpp", "function": "Enable"},
        "cwe_id": 862,
        "cwe_name": "Missing Authorization",
        "description": "The caller is not authorized.",
        "impact": "A local caller can invoke the operation.",
        "steps_to_reproduce": "[REQUIRES DYNAMIC TESTING]",
        "suggested_fix": "Add a permission check before the operation.",
    }
    model_output = """# Security Disclosure: VULNERABLE

**Product:** audio
**Type:** CWE-862 (Missing Authorization)
**Affected:** [NOT PROVIDED]
**Tested:** OpenHarmony, [NOT PROVIDED], [NOT PROVIDED].

## Summary

The caller is not authorized.

## Steps to Reproduce

[REQUIRES DYNAMIC TESTING]

## Impact

A local caller can invoke the operation.

## Suggested Fix

[REQUIRES MANUAL INPUT]
"""
    output = generator._ensure_disclosure_sections(
        model_output,
        finding,
        {
            "product_name": "audio",
            "affected_versions": "Current scanned revision (commit abc123)",
            "platform_version": "OpenHarmony",
            "analysis_date": "2026-08-28T12:34:56Z",
        },
        generator._fallback_code_section(finding),
    )

    assert "**Affected:** Current scanned revision (commit abc123)" in output
    assert "**Tested:** OpenHarmony, 2026-08-28T12:34:56Z." in output
    assert "[REQUIRES MANUAL INPUT]" not in output
    assert "Add a permission check before the operation." in output
