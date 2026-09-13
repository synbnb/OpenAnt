"""Tests for safe OpenHarmony bundle manifest parsing and auto detection."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.platforms.openharmony.manifest import BundleManifestReader
from core.platforms.openharmony.profile import OpenHarmonyProfileBuilder


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "ipc_service"
CORPUS_MANIFEST = TESTS_ROOT / "fixtures" / "openharmony" / "corpus_manifest.json"


def test_reader_normalizes_bundle_component_and_build_contract():
    inventory = BundleManifestReader(FIXTURE_ROOT).collect()

    assert inventory.parse_failures == []
    assert len(inventory.manifests) == 1
    manifest = inventory.manifests[0]
    assert manifest.path == "bundle.json"
    assert manifest.component_name == "openant_ipc_fixture"
    assert manifest.subsystem == "security"
    assert manifest.syscaps == ("SystemCapability.Security.VulnFounderFixture",)
    assert manifest.system_types == ("standard",)
    assert manifest.build_targets == (
        "//test/openharmony/ipc_service:openant_ipc_service",
    )
    assert manifest.dependencies == ("access_token", "ipc")


def test_reader_records_malformed_manifest_as_relative_parse_failure(tmp_path):
    (tmp_path / "bundle.json").write_text("{not-json", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "bundle.json").write_text("[]", encoding="utf-8")

    inventory = BundleManifestReader(tmp_path).collect()

    assert inventory.manifests == []
    assert [failure["path"] for failure in inventory.parse_failures] == [
        "bundle.json",
        "nested/bundle.json",
    ]
    assert all("/Users/" not in json.dumps(item) for item in inventory.parse_failures)


def test_reader_flattens_group_type_build_targets(tmp_path):
    (tmp_path / "bundle.json").write_text(
        json.dumps(
            {
                "name": "@ohos/grouped",
                "component": {
                    "name": "grouped",
                    "subsystem": "communication",
                    "build": {
                        "group_type": {
                            "base_group": ["//base:client"],
                            "service_group": ["//services:daemon", "//services:config"],
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    manifest = BundleManifestReader(tmp_path).collect().manifests[0]

    assert manifest.build_targets == (
        "//base:client",
        "//services:daemon",
        "//services:config",
    )


def test_builder_auto_detects_fixture_and_exposes_component_profile():
    profile = OpenHarmonyProfileBuilder().build_from_repository(FIXTURE_ROOT)

    assert profile is not None
    assert profile.platform == "openharmony"
    assert profile.detection["confidence"] == 1.0
    assert set(profile.detection["evidence"]) == {
        "bundle_manifest",
        "gn_target",
        "namespace_ohos",
    }
    assert profile.components == [
        {
            "manifest_path": "bundle.json",
            "package_name": "@ohos/openant_ipc_fixture",
            "name": "openant_ipc_fixture",
            "subsystem": "security",
            "syscaps": ["SystemCapability.Security.VulnFounderFixture"],
            "system_types": ["standard"],
            "build_targets": [
                "//test/openharmony/ipc_service:openant_ipc_service"
            ],
            "test_targets": [],
            "inner_kits": [],
            "dependencies": ["access_token", "ipc"],
            "third_party_dependencies": [],
        }
    ]
    assert profile.provenance["manifest_paths"] == ["bundle.json"]


def test_builder_exposes_detailed_gn_metadata_in_the_profile():
    builder = OpenHarmonyProfileBuilder()
    inspection = builder.inspect_repository(FIXTURE_ROOT)
    gn = inspection["build_metadata"]["gn"]

    assert gn["files"] == ["BUILD.gn"]
    assert gn["parse_failures"] == []
    assert gn["unknown_condition_count"] == 0
    assert [target["name"] for target in gn["targets"]] == ["openant_ipc_service"]
    assert gn["targets"][0]["external_deps"] == [
        "access_token:libaccesstoken_sdk",
        "ipc:ipc_core",
    ]

    profile = builder.build_from_repository(FIXTURE_ROOT)

    assert profile is not None
    assert profile.build_metadata == inspection["build_metadata"]
    serialized = profile.to_dict()
    assert serialized["build_metadata"]["gn"]["targets"][0]["kind"] == "ohos_shared_library"


def test_builder_keeps_profile_detection_when_gn_has_an_unbalanced_target(tmp_path):
    (tmp_path / "bundle.json").write_text(
        json.dumps(
            {
                "component": {
                    "name": "broken_gn_fixture",
                    "subsystem": "security",
                    "build": {"targets": ["broken"]},
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "BUILD.gn").write_text(
        'ohos_shared_library("broken") {\n  sources = [ "broken.cpp" ]\n',
        encoding="utf-8",
    )
    (tmp_path / "service.cpp").write_text("namespace OHOS { class Service {}; }", encoding="utf-8")

    profile = OpenHarmonyProfileBuilder().build_from_repository(tmp_path)

    assert profile is not None
    assert profile.build_metadata["gn"]["targets"] == []
    assert profile.build_metadata["gn"]["parse_failures"] == [
        {"path": "BUILD.gn", "reason": "unbalanced target block: broken"}
    ]


def test_builder_fails_safe_but_keeps_low_confidence_signals(tmp_path):
    source = tmp_path / "service.cpp"
    source.write_text("namespace OHOS { class Service {}; }", encoding="utf-8")

    builder = OpenHarmonyProfileBuilder()
    inspection = builder.inspect_repository(tmp_path)

    assert inspection["confidence"] == 0.25
    assert inspection["evidence"] == ["namespace_ohos"]
    assert inspection["signals"]["namespace_ohos"] == ["service.cpp"]
    assert builder.build_from_repository(tmp_path) is None


def test_builder_includes_idl_and_sa_metadata_in_profile_build_metadata(tmp_path):
    (tmp_path / "bundle.json").write_text(
        json.dumps(
            {
                "component": {
                    "name": "wifi_contract_fixture",
                    "subsystem": "communication",
                    "build": {"targets": ["//wifi:service"]},
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "BUILD.gn").write_text(
        'ohos_shared_library("service") {\n  sources = [ "service.cpp" ]\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "service.cpp").write_text("namespace OHOS { class Service {}; }", encoding="utf-8")
    (tmp_path / "IService.idl").write_text(
        "interface OHOS.Wifi.IService {\n  void Scan([in] String bundleName);\n}\n",
        encoding="utf-8",
    )
    sa_dir = tmp_path / "sa_profile"
    sa_dir.mkdir()
    (sa_dir / "1001.json").write_text(
        json.dumps(
            {
                "process": "wifi_service",
                "systemability": {"name": 1001, "libpath": "libwifi.z.so"},
            }
        ),
        encoding="utf-8",
    )

    profile = OpenHarmonyProfileBuilder().build_from_repository(tmp_path)

    assert profile is not None
    assert profile.build_metadata["idl"]["files"] == ["IService.idl"]
    assert profile.build_metadata["idl"]["interfaces"][0]["name"] == "OHOS.Wifi.IService"
    assert profile.build_metadata["idl"]["interfaces"][0]["methods"][0]["name"] == "Scan"
    assert profile.build_metadata["sa_profiles"]["files"] == ["sa_profile/1001.json"]
    assert profile.build_metadata["sa_profiles"]["profiles"][0]["system_abilities"][0]["sa_id"] == "1001"
    assert profile.provenance["idl_paths"] == ["IService.idl"]
    assert profile.provenance["sa_profile_paths"] == ["sa_profile/1001.json"]


def test_builder_keeps_profile_when_idl_or_sa_metadata_is_malformed(tmp_path):
    (tmp_path / "bundle.json").write_text(
        json.dumps(
            {
                "component": {
                    "name": "malformed_contract_fixture",
                    "subsystem": "security",
                    "build": {"targets": ["//security:service"]},
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "BUILD.gn").write_text(
        'ohos_shared_library("service") {\n  sources = [ "service.cpp" ]\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "service.cpp").write_text("namespace OHOS { class Service {}; }", encoding="utf-8")
    (tmp_path / "Broken.idl").write_text(
        'interface OHOS.Security.IBroken {\n  void Run();\n', encoding="utf-8"
    )
    sa_dir = tmp_path / "sa_profile"
    sa_dir.mkdir()
    (sa_dir / "bad.json").write_text("{not-json", encoding="utf-8")

    profile = OpenHarmonyProfileBuilder().build_from_repository(tmp_path)

    assert profile is not None
    assert profile.build_metadata["idl"]["parse_failures"] == [
        {
            "path": "Broken.idl",
            "reason": "unbalanced interface block: OHOS.Security.IBroken",
        }
    ]
    assert profile.build_metadata["sa_profiles"]["parse_failures"][0]["path"] == "sa_profile/bad.json"


def test_external_reference_repositories_are_auto_detected_when_configured():
    configured_root = os.environ.get("OPENHARMONY_CORPUS_ROOT")
    if not configured_root:
        pytest.skip("set OPENHARMONY_CORPUS_ROOT to run the five-repository check")

    manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf-8"))
    builder = OpenHarmonyProfileBuilder()
    for repository in manifest["repositories"]:
        profile = builder.build_from_repository(Path(configured_root) / repository["name"])
        assert profile is not None, repository["name"]
        assert profile.platform == "openharmony"
        assert profile.components, repository["name"]
