"""Contract tests for the synthetic OpenHarmony Binder IPC fixture."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import pytest


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "ipc_service"
MANIFEST_PATH = FIXTURE_ROOT / "fixture_manifest.json"


@pytest.fixture(scope="module")
def fixture_manifest() -> dict:
    assert MANIFEST_PATH.is_file(), (
        "OpenHarmony IPC fixture manifest is missing: "
        f"{MANIFEST_PATH.relative_to(TESTS_ROOT.parent)}"
    )
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_ipc_fixture_is_portable_synthetic_and_complete(fixture_manifest):
    assert fixture_manifest["schema_version"] == 1
    assert fixture_manifest["fixture_id"] == "openharmony-ipc-service-v1"
    assert fixture_manifest["synthetic"] is True

    declared_files = set(fixture_manifest["files"])
    actual_files = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file() and path != MANIFEST_PATH
    }
    assert declared_files == actual_files

    for relative in declared_files:
        path = PurePosixPath(relative)
        assert not path.is_absolute()
        assert ".." not in path.parts

    serialized = json.dumps(fixture_manifest)
    assert "/Users/" not in serialized
    assert "openharmony_reference" not in serialized


def test_ipc_fixture_anchors_match_stable_source_lines(fixture_manifest):
    anchors = fixture_manifest["anchors"]
    assert anchors

    for name, anchor in anchors.items():
        relative = PurePosixPath(anchor["file"])
        assert not relative.is_absolute(), name
        assert ".." not in relative.parts, name

        source_path = FIXTURE_ROOT.joinpath(*relative.parts)
        assert source_path.is_file(), name
        lines = source_path.read_text(encoding="utf-8").splitlines()
        line_number = anchor["line"]
        assert isinstance(line_number, int) and 1 <= line_number <= len(lines), name
        assert anchor["contains"] in lines[line_number - 1], name


def test_ipc_fixture_describes_minimum_proxy_to_guarded_handler_flow(
    fixture_manifest,
):
    flow = fixture_manifest["ipc_flow"]
    assert flow["descriptor"] == "ohos.openant.fixture.IHealthSensorService"
    assert flow["transaction_code"] == "ENABLE_SENSOR"
    assert flow["proxy_method"] == "EnableSensor"
    assert flow["stub_entry"] == "OnRemoteRequest"
    assert flow["handler"] == "EnableSensorInner"
    assert flow["parcel_fields"] == ["uint32", "int64"]
    assert flow["guards"] == ["interface_token", "permission"]

    assert set(fixture_manifest["platform_signals"]) == {
        "bundle_manifest",
        "gn_target",
        "namespace_ohos",
        "message_parcel",
        "binder_stub",
        "calling_token",
        "access_token_permission",
    }
