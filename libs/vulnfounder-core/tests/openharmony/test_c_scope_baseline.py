"""Freeze the current C/C++ scanner scope before OpenHarmony classification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from parsers.c.repository_scanner import RepositoryScanner  # noqa: E402


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "scope_roles"
MANIFEST_PATH = FIXTURE_ROOT / "scope_manifest.json"
BASELINE_PATH = TESTS_ROOT / "fixtures" / "openharmony" / "c_scope_baseline.json"


@pytest.fixture(scope="module")
def scope_manifest() -> dict:
    assert MANIFEST_PATH.is_file()
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _scan(*, skip_tests: bool) -> dict:
    result = RepositoryScanner(
        str(FIXTURE_ROOT),
        {"skip_tests": skip_tests},
    ).scan()
    return {
        "files": [
            {"path": item["path"], "extension": item["extension"]}
            for item in result["files"]
        ],
        "statistics": {
            key: result["statistics"][key]
            for key in (
                "total_files",
                "directories_scanned",
                "directories_excluded",
                "test_files_skipped",
            )
        },
    }


def test_scope_manifest_is_complete_and_portable(scope_manifest):
    assert scope_manifest["schema_version"] == 1
    assert scope_manifest["fixture_id"] == "openharmony-c-scope-roles-v1"
    assert scope_manifest["synthetic"] is True

    declared_files = set(scope_manifest["files"])
    actual_files = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file() and path != MANIFEST_PATH
    }
    assert declared_files == actual_files

    role_files = [item for files in scope_manifest["roles"].values() for item in files]
    assert set(role_files) == declared_files
    assert len(role_files) == len(set(role_files))
    for relative in declared_files:
        path = Path(relative)
        assert not path.is_absolute()
        assert ".." not in path.parts

    serialized = json.dumps(scope_manifest)
    assert "/Users/" not in serialized
    assert "openharmony_reference" not in serialized


def test_default_c_scope_matches_recorded_baseline(scope_manifest):
    assert BASELINE_PATH.is_file(), (
        "OH-03A baseline is intentionally required after the RED run: "
        f"{BASELINE_PATH.relative_to(TESTS_ROOT.parent)}"
    )
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    assert baseline["schema_version"] == 1
    assert baseline["fixture_id"] == scope_manifest["fixture_id"]
    assert baseline["observations"]["skip_tests_false"] == _scan(skip_tests=False)
    assert baseline["observations"]["skip_tests_true"] == _scan(skip_tests=True)


def test_baseline_makes_current_scope_gaps_explicit(scope_manifest):
    assert BASELINE_PATH.is_file()
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    observations = baseline["observations"]
    default_paths = {item["path"] for item in observations["skip_tests_false"]["files"]}
    skip_paths = {item["path"] for item in observations["skip_tests_true"]["files"]}

    # The current scanner discovers C/C++ files by extension only. Directory
    # pruning hides tests/fuzz/vendor, while the root filename-pattern test is
    # visible unless skip_tests=True. Build metadata and .ets/.idl are ignored.
    assert default_paths == {
        "include/health_sensor_service.h",
        "services/health_sensor_service.cpp",
        "src/latest_value.c",
        "test_health_sensor.cpp",
    }
    assert skip_paths == {
        "include/health_sensor_service.h",
        "services/health_sensor_service.cpp",
        "src/latest_value.c",
    }
    assert observations["skip_tests_false"]["statistics"]["test_files_skipped"] == 0
    assert observations["skip_tests_true"]["statistics"]["test_files_skipped"] == 1
