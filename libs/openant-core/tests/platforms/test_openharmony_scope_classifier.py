"""Contract tests for the OpenHarmony source-role and metadata classifier."""

from __future__ import annotations

import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.scope import OpenHarmonyScopeClassifier  # noqa: E402


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "scope_roles"


def test_classifier_assigns_stable_roles_to_openharmony_paths():
    classifier = OpenHarmonyScopeClassifier(FIXTURE_ROOT, source_scope="all")

    expected = {
        "services/health_sensor_service.cpp": "production",
        "include/health_sensor_service.h": "production",
        "test_health_sensor.cpp": "test",
        "tests/health_sensor_service_test.cpp": "test",
        "fuzz/health_sensor_service_fuzzer.cpp": "fuzz",
        "vendor/third_party.cpp": "third_party",
        "BUILD.gn": "build_metadata",
        "bundle.json": "build_metadata",
        "entry/Main.ets": "unsupported_source",
        "interfaces/health_sensor.idl": "interface_metadata",
    }

    assert {
        path: classifier.classify(path) for path in expected
    } == expected
    assert classifier.classify("./services//health_sensor_service.cpp") == "production"
    assert classifier.classify("src/unknown.notes") == "unknown"


def test_classifier_exposes_conservative_scope_policy():
    production = OpenHarmonyScopeClassifier(FIXTURE_ROOT, source_scope="production")
    security_tests = OpenHarmonyScopeClassifier(FIXTURE_ROOT, source_scope="security-tests")
    all_sources = OpenHarmonyScopeClassifier(FIXTURE_ROOT, source_scope="all")

    assert production.accepts("production") is True
    assert production.accepts("test") is False
    assert security_tests.accepts("production") is True
    assert security_tests.accepts("test") is True
    assert security_tests.accepts("fuzz") is True
    assert security_tests.accepts("third_party") is False
    assert all_sources.accepts("unknown") is True
    assert all_sources.accepts("third_party") is False
    assert all_sources.accepts("build_metadata") is False


def test_classifier_reads_bundle_and_gn_metadata_without_executing_them():
    classifier = OpenHarmonyScopeClassifier(FIXTURE_ROOT, source_scope="production")
    metadata = classifier.collect_build_metadata()

    assert metadata["bundle_manifests"] == [
        {
            "path": "bundle.json",
            "component": "openant_scope_roles_fixture",
            "targets": [],
        }
    ]
    assert metadata["build_files"] == [
        {
            "path": "BUILD.gn",
            "targets": ["health_sensor_service"],
            "sources": ["services/health_sensor_service.cpp"],
        }
    ]
    assert metadata["parse_failures"] == []
    serialized = json.dumps(metadata)
    assert "/Users/" not in serialized

