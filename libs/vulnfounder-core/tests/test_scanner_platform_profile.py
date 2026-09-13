"""Scanner integration tests for automatic OpenHarmony profile selection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import scanner as scanner_mod
from core.schemas import AnalysisMetrics
from core.platforms.openharmony.profile import OpenHarmonyProfileBuilder


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "openharmony" / "ipc_service"


@pytest.fixture(autouse=True)
def _stub_registry_probe(monkeypatch):
    import utilities.llm as llm_mod

    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


def _profile():
    profile = OpenHarmonyProfileBuilder().build(
        "/synthetic/openharmony",
        {
            "bundle_manifest": "bundle.json",
            "gn_target": "BUILD.gn",
            "namespace_ohos": "namespace OHOS",
        },
        components=[{"name": "synthetic_component", "subsystem": "security"}],
        languages=["c"],
    )
    assert profile is not None
    return profile


def _install_minimal_pipeline(monkeypatch, captured, platform_coverage=None):
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    import core.reporter as reporter

    class ParseResult:
        dataset_path = ""
        analyzer_output_path = ""
        units_count = 0
        language = "c"
        processing_level = "all"

    def fake_parse(*, output_dir, **kwargs):
        captured.update(kwargs)
        result = ParseResult()
        result.platform_coverage = platform_coverage
        result.dataset_path = str(Path(output_dir) / "dataset.json")
        result.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
        Path(result.dataset_path).write_text('{"units": []}', encoding="utf-8")
        Path(result.analyzer_output_path).write_text("{}", encoding="utf-8")
        return result

    class AnalyzeResult:
        results_path = ""
        metrics = AnalysisMetrics(total=0)

    def fake_analysis(*, output_dir, **kwargs):
        result = AnalyzeResult()
        result.results_path = str(Path(output_dir) / "results.json")
        Path(result.results_path).write_text("[]", encoding="utf-8")
        return result

    def fake_build_output(*, output_path, **kwargs):
        captured["build_output"] = kwargs
        Path(output_path).write_text("{}", encoding="utf-8")
        return output_path

    monkeypatch.setattr(parser_adapter, "parse_repository", fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", fake_analysis)
    monkeypatch.setattr(reporter, "build_pipeline_output", fake_build_output)


def _scan(monkeypatch, tmp_path, *, platform="auto", platform_coverage=None):
    captured = {}
    _install_minimal_pipeline(monkeypatch, captured, platform_coverage)
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform=platform,
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )
    return result, captured


def test_auto_profile_is_persisted_and_selects_openharmony(monkeypatch, tmp_path):
    profile = _profile()
    monkeypatch.setattr(
        OpenHarmonyProfileBuilder,
        "build_from_repository",
        lambda self, repository_root: profile,
    )

    result, captured = _scan(monkeypatch, tmp_path)

    profile_path = tmp_path / "out" / "platform_profile.json"
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    assert captured["platform"] == "openharmony"
    assert result.platform_selection == "openharmony"
    assert result.platform_profile == payload
    assert payload["platform"] == "openharmony"
    scan_report = json.loads((tmp_path / "out" / "scan.report.json").read_text())
    assert scan_report["summary"]["platform_profile"]["platform"] == "openharmony"
    assert scan_report["outputs"]["platform_profile_path"].endswith(
        "platform_profile.json"
    )


def test_parser_file_counts_are_synced_to_platform_profile(
    monkeypatch, tmp_path
):
    profile = _profile()
    monkeypatch.setattr(
        OpenHarmonyProfileBuilder,
        "build_from_repository",
        lambda self, repository_root: profile,
    )
    scope = {
        "platform": "openharmony",
        "source_scope": "production",
        "coverage": {
            "discovered_files": 92,
            "eligible_files": 67,
            "parsed_files": 67,
        },
    }

    result, _ = _scan(
        monkeypatch,
        tmp_path,
        platform="openharmony",
        platform_coverage=scope,
    )

    payload = json.loads(
        (tmp_path / "out" / "platform_profile.json").read_text(encoding="utf-8")
    )
    assert payload["coverage"]["discovered_files"] == 92
    assert payload["coverage"]["eligible_files"] == 67
    assert payload["coverage"]["parsed_files"] == 67
    assert result.platform_profile["coverage"] == payload["coverage"]


def test_auto_profile_is_forwarded_to_app_context_prompt(monkeypatch, tmp_path):
    from context.application_context import ApplicationContext

    profile = _profile()
    monkeypatch.setattr(
        OpenHarmonyProfileBuilder,
        "build_from_repository",
        lambda self, repository_root: profile,
    )
    captured = {}

    def fake_generate(_repo_path, _binding, **kwargs):
        captured.update(kwargs)
        return ApplicationContext(
            application_type="openharmony_component",
            purpose="fixture",
        )

    monkeypatch.setattr(scanner_mod, "generate_application_context", fake_generate)
    _install_minimal_pipeline(monkeypatch, {})

    scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="auto",
        processing_level="all",
        generate_context=True,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )

    assert captured["platform_profile"] == profile.to_dict()


def test_auto_detects_real_openharmony_fixture_before_c_parse(monkeypatch, tmp_path):
    captured = {}
    _install_minimal_pipeline(monkeypatch, captured)

    result = scanner_mod.scan_repository(
        repo_path=str(FIXTURE_ROOT),
        output_dir=str(tmp_path / "out"),
        platform="auto",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )

    payload = json.loads(
        (tmp_path / "out" / "platform_profile.json").read_text(encoding="utf-8")
    )
    assert captured["platform"] == "openharmony"
    assert result.platform_profile == payload
    assert payload["components"][0]["name"] == "openant_ipc_fixture"


def test_auto_profile_drives_real_c_parser_and_returns_scope(monkeypatch, tmp_path):
    import core.analyzer as analyzer
    import core.reporter as reporter

    class AnalyzeResult:
        results_path = ""
        metrics = AnalysisMetrics(total=0)

    def fake_analysis(*, output_dir, **kwargs):
        result = AnalyzeResult()
        result.results_path = str(Path(output_dir) / "results.json")
        Path(result.results_path).write_text("[]", encoding="utf-8")
        return result

    def fake_build_output(*, output_path, **kwargs):
        Path(output_path).write_text("{}", encoding="utf-8")
        return output_path

    monkeypatch.setattr(analyzer, "run_analysis", fake_analysis)
    monkeypatch.setattr(reporter, "build_pipeline_output", fake_build_output)

    result = scanner_mod.scan_repository(
        repo_path=str(FIXTURE_ROOT),
        output_dir=str(tmp_path / "out"),
        language="c",
        platform="auto",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )

    scan_payload = json.loads(
        (tmp_path / "out" / "scan_results.json").read_text(encoding="utf-8")
    )
    assert result.platform_selection == "openharmony"
    assert result.platform_coverage["platform"] == "openharmony"
    assert scan_payload["scope"]["platform"] == "openharmony"


def test_auto_low_confidence_keeps_generic_parser_contract(monkeypatch, tmp_path):
    monkeypatch.setattr(
        OpenHarmonyProfileBuilder,
        "build_from_repository",
        lambda self, repository_root: None,
    )

    result, captured = _scan(monkeypatch, tmp_path)

    assert "platform" not in captured
    assert result.platform_selection is None
    assert result.platform_profile is None
    assert not (tmp_path / "out" / "platform_profile.json").exists()


def test_auto_profile_failure_falls_back_without_aborting_scan(monkeypatch, tmp_path):
    def fail_detection(self, repository_root):
        raise RuntimeError("malformed profile input")

    monkeypatch.setattr(OpenHarmonyProfileBuilder, "build_from_repository", fail_detection)

    result, captured = _scan(monkeypatch, tmp_path)

    assert "platform" not in captured
    assert result.platform_selection is None
    assert result.platform_profile is None


def test_explicit_generic_does_not_probe_openharmony_profile(monkeypatch, tmp_path):
    def fail_if_called(self, repository_root):
        raise AssertionError("generic scan must not run OpenHarmony detection")

    monkeypatch.setattr(OpenHarmonyProfileBuilder, "build_from_repository", fail_if_called)

    result, captured = _scan(monkeypatch, tmp_path, platform="generic")

    assert captured["platform"] == "generic"
    assert result.platform_selection == "generic"
    assert result.platform_profile is None


def test_explicit_openharmony_without_context_keeps_report_type(monkeypatch, tmp_path):
    result, captured = _scan(monkeypatch, tmp_path, platform="openharmony")

    assert result.platform_selection == "openharmony"
    assert captured["build_output"]["application_type"] == "openharmony_component"
