"""OH-16A-1 tests for the immutable OpenHarmony application baseline.

The repository-supplied threat model is useful business context, but it must not
be able to remove the minimum attacker/input assumptions that come from the
OpenHarmony platform profile.  These tests deliberately exercise the merge at
the ApplicationContext boundary and then verify the on-disk scanner artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from context.application_context import ApplicationContext, load_context, save_context
from context.openharmony_context import (
    OPENHARMONY_BASELINE_VERSION,
    build_openharmony_baseline_context,
    merge_openharmony_context,
)
from core.reporter import build_pipeline_output
from core.schemas import AnalysisMetrics, ParseResult
from core.scanner import scan_repository
from prompts.vulnerability_analysis import get_analysis_prompt
from prompts.verification_prompts import (
    format_app_context_for_verification,
    get_verification_system_prompt,
)
from report.generator import _context_provenance_header


def _ipc_profile() -> dict:
    return {
        "platform": "openharmony",
        "boundaries": ["binder_ipc", "system_ability", "idl"],
        "detection": {
            "confidence": 1.0,
            "evidence": ["bundle_manifest", "gn_target", "namespace_ohos"],
            "signals": {
                "binder_ipc": ["services/stub.cpp"],
                "system_ability": ["services/sa.cpp"],
                "idl": ["interfaces/service.idl"],
            },
        },
    }


def _hdf_profile() -> dict:
    return {
        "platform": "openharmony",
        "boundaries": ["hdf"],
        "detection": {
            "confidence": 0.9,
            "evidence": ["bundle_manifest", "gn_target"],
            "signals": {"hdf": ["driver/device.cpp"]},
        },
    }


def _repo_threat_model_context() -> ApplicationContext:
    return ApplicationContext(
        application_type="custom:service",
        purpose="A service with a deliberately narrow repository model.",
        intended_behaviors=["Accepts service requests"],
        trust_boundaries={"all_service_inputs": "trusted"},
        security_model="Only trusted system callers are expected.",
        not_a_vulnerability=[
            "IPC requests are trusted by design",
            "Parcel-derived lengths do not need independent validation",
        ],
        requires_remote_trigger=False,
        source="threat_model",
        source_sha256="repo-sha",
        threat_model_version=1,
        classification="service",
        attacker_profiles=[],
        input_sources={
            "all_service_inputs": {
                "trust": "trusted",
                "description": "Repository-declared trusted inputs",
            }
        },
        vulnerability_criteria=["Only report memory corruption after a crash."],
    )


def test_ipc_baseline_contains_local_attacker_and_untrusted_parcel():
    context = build_openharmony_baseline_context(_ipc_profile())

    assert context.application_type == "openharmony_component"
    assert context.has_openharmony_baseline()
    assert context.platform_baseline["version"] == OPENHARMONY_BASELINE_VERSION
    assert "binder_ipc" in context.platform_baseline["boundaries"]
    profile_ids = {item["id"] for item in context.attacker_profiles}
    assert "openharmony_local_ipc_caller" in profile_ids
    assert any(
        name == "openharmony_binder_parcel"
        and spec["trust"] == "untrusted"
        for name, spec in context.input_sources.items()
    )
    assert context.suppress_local_only() is False
    assert context.platform_baseline["vulnerability_criteria"]


def test_hdf_baseline_contains_device_data_boundary():
    context = build_openharmony_baseline_context(_hdf_profile())

    assert "hdf" in context.platform_baseline["boundaries"]
    assert "openharmony_device_data" in context.input_sources
    assert any(
        item["id"] == "openharmony_device_data_source"
        for item in context.attacker_profiles
    )


def test_explicit_openharmony_selection_keeps_baseline_when_profile_is_incomplete():
    context = build_openharmony_baseline_context(None, force=True)

    assert context is not None
    assert context.has_openharmony_baseline()
    assert "openharmony_local_ipc_caller" in {
        item["id"] for item in context.attacker_profiles
    }
    assert "explicit platform selection: openharmony" in context.evidence


def test_generic_context_is_unchanged_by_openharmony_merge_helper():
    context = _repo_threat_model_context()

    merged = merge_openharmony_context(
        context,
        {"platform": "generic", "boundaries": ["binder_ipc"]},
    )

    assert merged is context
    assert not merged.has_openharmony_baseline()
    assert merged.application_type == "custom:service"


def test_repository_model_cannot_remove_platform_baseline():
    merged = merge_openharmony_context(
        _repo_threat_model_context(),
        _ipc_profile(),
    )

    profile_ids = {item["id"] for item in merged.attacker_profiles}
    assert merged.application_type == "openharmony_component"
    assert "openharmony_local_ipc_caller" in profile_ids
    assert merged.input_sources["openharmony_binder_parcel"]["trust"] == "untrusted"
    assert "all_service_inputs" in merged.input_sources
    assert merged.suppress_local_only() is False
    assert merged.not_a_vulnerability == _repo_threat_model_context().not_a_vulnerability
    assert merged.repository_advisory_exclusions == merged.not_a_vulnerability
    assert merged.platform_baseline_conflicts
    assert merged.context_provenance["repository_model_applied"] is True
    assert merged.context_provenance["platform_baseline"]["applied"] is True
    assert merged.context_provenance["repository_model_sha256"] == "repo-sha"


def test_baseline_prompt_separates_mandatory_checks_from_repo_advice():
    merged = merge_openharmony_context(_repo_threat_model_context(), _ipc_profile())

    prompt = get_analysis_prompt(
        code="int OnRemoteRequest() { return 0; }",
        language="cpp",
        app_context=merged,
    )

    assert "OpenHarmony platform minimum security baseline" in prompt
    assert "mandatory" in prompt.lower()
    assert "Repository-supplied advisory exclusions" in prompt
    assert "cannot override" in prompt.lower()
    assert "IPC requests are trusted by design" in prompt


def test_stage2_prompt_keeps_openharmony_baseline_mandatory():
    merged = merge_openharmony_context(_repo_threat_model_context(), _ipc_profile())

    context_text = format_app_context_for_verification(merged)
    system_text = get_verification_system_prompt(merged)

    assert "OpenHarmony platform minimum security baseline" in context_text
    assert "cannot override" in context_text.lower()
    assert "platform minimum security baseline is mandatory" in system_text.lower()


def test_context_round_trip_preserves_baseline_and_provenance(tmp_path: Path):
    merged = merge_openharmony_context(_repo_threat_model_context(), _ipc_profile())
    path = tmp_path / "application_context.json"

    save_context(merged, path)
    restored = load_context(path)

    assert restored.platform_baseline == merged.platform_baseline
    assert restored.platform_baseline_conflicts == merged.platform_baseline_conflicts
    assert restored.repository_advisory_exclusions == merged.repository_advisory_exclusions
    assert restored.context_provenance == merged.context_provenance


def test_pipeline_output_carries_application_context_provenance(tmp_path: Path):
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps({
            "dataset": "fixture",
            "results": [],
            "metrics": {"vulnerable": 0, "safe": 0, "inconclusive": 0},
        }),
        encoding="utf-8",
    )
    output = tmp_path / "pipeline_output.json"
    provenance = {
        "repository_model_applied": True,
        "platform_baseline": {"id": "openharmony-minimum", "applied": True},
    }

    build_pipeline_output(
        results_path=str(results),
        output_path=str(output),
        application_context_provenance=provenance,
    )

    assert json.loads(output.read_text(encoding="utf-8"))["application_context_provenance"] == provenance


def test_report_header_discloses_baseline_even_without_repo_threat_model():
    header = _context_provenance_header(
        {
            "context_source": "generated",
            "application_context_provenance": {
                "platform_baseline": {
                    "applied": True,
                    "version": OPENHARMONY_BASELINE_VERSION,
                }
            },
        }
    )

    assert "OpenHarmony platform minimum baseline applied" in header
    assert "Baseline version" in header


@pytest.fixture(autouse=True)
def _stub_registry_probe(monkeypatch):
    import utilities.llm as llm_mod

    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


def test_scanner_applies_baseline_and_writes_provenance_artifacts(monkeypatch, tmp_path: Path):
    """Exercise the real scanner context/output path without any LLM calls."""
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    from core.platforms.openharmony.profile import OpenHarmonyProfileBuilder

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "OPENANT.THREATMODEL.md").write_text(
        """# Threat Model

## Machine-Readable Threat Model

```json
{
  "schema": "openant-threat-model",
  "schema_version": 1,
  "classification": "service",
  "purpose": "A service.",
  "components": [{"name": "service", "paths": ["."], "component_type": "service", "exposure": "internal"}],
  "attacker_profiles": [{"id": "repository_local", "position": "local_user", "description": "A trusted operator.", "capabilities": ["run the service"], "cannot": ["modify the service binary"], "entry_via": ["all_service_inputs"], "impact": "None."}],
  "input_sources": {
    "all_service_inputs": {"trust": "trusted", "description": "trusted"}
  },
  "vulnerability_criteria": ["Only report memory corruption after a crash."],
  "not_a_vulnerability": ["IPC requests are trusted by design"],
  "impact_statement": "Service compromise."
}
```
""",
        encoding="utf-8",
    )

    profile = OpenHarmonyProfileBuilder().build(
        str(repo),
        {
            "bundle_manifest": "bundle.json",
            "gn_target": "BUILD.gn",
            "namespace_ohos": "namespace OHOS",
        },
        boundaries=["binder_ipc", "system_ability", "idl"],
    )
    assert profile is not None
    monkeypatch.setattr(
        OpenHarmonyProfileBuilder,
        "build_from_repository",
        lambda self, repository_root: profile,
    )

    def fake_parse(*, output_dir, **kwargs):
        out = Path(output_dir)
        dataset = out / "dataset.json"
        analyzer_output = out / "analyzer.json"
        dataset.write_text('{"units": []}', encoding="utf-8")
        analyzer_output.write_text("{}", encoding="utf-8")
        return ParseResult(
            dataset_path=str(dataset),
            analyzer_output_path=str(analyzer_output),
            units_count=0,
            language="c",
            processing_level="all",
        )

    class AnalyzeResult:
        metrics = AnalysisMetrics(total=0)

    def fake_analysis(*, output_dir, **kwargs):
        result = AnalyzeResult()
        result.results_path = str(Path(output_dir) / "results.json")
        Path(result.results_path).write_text(
            '{"results": [], "metrics": {"vulnerable": 0, "safe": 0, "inconclusive": 0}}',
            encoding="utf-8",
        )
        return result

    monkeypatch.setattr(parser_adapter, "parse_repository", fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", fake_analysis)

    output_dir = tmp_path / "out"
    result = scan_repository(
        repo_path=str(repo),
        output_dir=str(output_dir),
        language="c",
        platform="openharmony",
        processing_level="all",
        generate_context=True,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )

    context_payload = json.loads((output_dir / "application_context.json").read_text())
    pipeline_payload = json.loads((output_dir / "pipeline_output.json").read_text())
    scan_payload = json.loads((output_dir / "scan.report.json").read_text())
    profile_ids = {item["id"] for item in context_payload["attacker_profiles"]}

    assert "openharmony_local_ipc_caller" in profile_ids
    assert context_payload["platform_baseline"]["version"] == OPENHARMONY_BASELINE_VERSION
    assert context_payload["context_provenance"]["repository_model_applied"] is True
    assert pipeline_payload["application_context_provenance"]["platform_baseline"]["applied"] is True
    assert scan_payload["summary"]["application_context_provenance"]["platform_baseline"]["applied"] is True
    assert result.application_context_provenance["platform_baseline"]["applied"] is True
