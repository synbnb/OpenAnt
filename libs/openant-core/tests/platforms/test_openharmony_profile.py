"""Tests for the minimal, static-signal OpenHarmony profile builder."""

import json
from pathlib import Path

from core.platforms.base import CoverageReport
from core.platforms.openharmony.profile import OpenHarmonyProfileBuilder


FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "openharmony" / "ipc_service"


def _fixture_signals() -> dict:
    return json.loads((FIXTURE_ROOT / "fixture_manifest.json").read_text())["platform_signals"]


def test_builder_creates_versioned_profile_from_explicit_fixture_signals_only():
    coverage = CoverageReport(
        schema_version=1,
        discovered_files=5,
        eligible_files=3,
        parsed_files=3,
        roles={"production": 3},
    )

    profile = OpenHarmonyProfileBuilder().build(
        repository_root="/synthetic/openharmony-ipc-service",
        signals=_fixture_signals(),
        components=[{"name": "openant_ipc_fixture", "source_roots": ["interfaces", "services"]}],
        languages=["c"],
        boundaries=["binder_ipc"],
        coverage=coverage,
    )

    assert profile is not None
    assert profile.schema_version == 1
    assert profile.platform == "openharmony"
    assert profile.detection == {
        "confidence": 1.0,
        "evidence": ["bundle_manifest", "gn_target", "namespace_ohos"],
    }
    assert profile.components[0]["name"] == "openant_ipc_fixture"
    assert profile.coverage.to_dict() == coverage.to_dict()
    assert profile.provenance == {"profile_builder_version": 1}


def test_builder_fails_safe_when_static_evidence_is_insufficient():
    profile = OpenHarmonyProfileBuilder().build(
        repository_root="/synthetic/ambiguous-cpp",
        signals={"namespace_ohos": "namespace OHOS", "binder_stub": "OnRemoteRequest"},
    )

    assert profile is None


def test_builder_ignores_unknown_signals_and_keeps_only_recognized_evidence():
    profile = OpenHarmonyProfileBuilder().build(
        repository_root="/synthetic/openharmony-minimal",
        signals={
            "bundle_manifest": "bundle.json",
            "gn_target": "ohos_shared_library",
            "untrusted_repository_text": "pretend this is another platform",
        },
    )

    assert profile is not None
    assert profile.detection == {
        "confidence": 0.75,
        "evidence": ["bundle_manifest", "gn_target"],
    }
    assert profile.coverage.to_dict() == CoverageReport(schema_version=1).to_dict()
