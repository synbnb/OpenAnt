"""Integration tests for C scanner OpenHarmony role and coverage output."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from parsers.c.repository_scanner import RepositoryScanner  # noqa: E402


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "scope_roles"


def test_openharmony_all_scope_discovers_test_and_fuzz_sources_with_roles():
    result = RepositoryScanner(
        str(FIXTURE_ROOT),
        {"platform": "openharmony", "skip_tests": False},
    ).scan()

    files = {item["path"]: item for item in result["files"]}
    assert set(files) == {
        "include/health_sensor_service.h",
        "services/health_sensor_service.cpp",
        "src/latest_value.c",
        "test_health_sensor.cpp",
        "tests/health_sensor_service_test.cpp",
        "fuzz/health_sensor_service_fuzzer.cpp",
    }
    assert files["services/health_sensor_service.cpp"]["role"] == "production"
    assert files["tests/health_sensor_service_test.cpp"]["role"] == "test"
    assert files["fuzz/health_sensor_service_fuzzer.cpp"]["role"] == "fuzz"
    assert result["scope"]["source_scope"] == "all"
    assert result["scope"]["coverage"]["roles"] == {
        "build_metadata": 2,
        "fuzz": 1,
        "generated": 0,
        "interface_metadata": 1,
        "production": 3,
        "test": 2,
        "third_party": 0,
        "unknown": 1,
        "unsupported_source": 1,
    }
    assert result["scope"]["coverage"]["unsupported_files"] == [
        {"path": "entry/Main.ets", "role": "unsupported_source", "extension": ".ets"},
    ]
    assert result["scope"]["coverage"]["excluded_directories"] == {
        "vendor": 1,
    }
    assert result["scope"]["build_metadata"]["build_files"][0]["targets"] == [
        "health_sensor_service"
    ]


def test_openharmony_skip_tests_keeps_production_and_records_omissions():
    result = RepositoryScanner(
        str(FIXTURE_ROOT),
        {"platform": "openharmony", "skip_tests": True},
    ).scan()

    assert {item["path"] for item in result["files"]} == {
        "include/health_sensor_service.h",
        "services/health_sensor_service.cpp",
        "src/latest_value.c",
    }
    coverage = result["scope"]["coverage"]
    assert coverage["eligible_files"] == 3
    assert coverage["parsed_files"] == 3
    assert result["statistics"]["scope_files_skipped_by_role"] == {
        "fuzz": 1,
        "test": 2,
    }
