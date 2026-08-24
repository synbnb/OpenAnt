"""Lock the pre-adaptation OpenAnt behavior on OpenHarmony inputs."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path

import pytest

from core.parser_adapter import detect_languages
from parsers.c.call_graph_builder import CallGraphBuilder
from parsers.c.function_extractor import FunctionExtractor
from parsers.c.repository_scanner import RepositoryScanner
from parsers.c.unit_generator import UnitGenerator
from utilities.agentic_enhancer import EntryPointDetector


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_ROOT = TESTS_ROOT / "fixtures" / "openharmony"
IPC_FIXTURE_ROOT = FIXTURES_ROOT / "ipc_service"
BASELINE_PATH = FIXTURES_ROOT / "current_behavior_baseline.json"
CORPUS_MANIFEST_PATH = FIXTURES_ROOT / "corpus_manifest.json"


@pytest.fixture(scope="module")
def current_baseline() -> dict:
    assert BASELINE_PATH.is_file(), (
        "OpenHarmony current-behavior baseline is missing: "
        f"{BASELINE_PATH.relative_to(TESTS_ROOT.parent)}"
    )
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def corpus_manifest() -> dict:
    return json.loads(CORPUS_MANIFEST_PATH.read_text(encoding="utf-8"))


def _analyze_ipc_fixture() -> dict:
    scanner = RepositoryScanner(str(IPC_FIXTURE_ROOT), {"skip_tests": True})
    scan = scanner.scan()

    extracted = FunctionExtractor(str(IPC_FIXTURE_ROOT)).extract_from_scan(scan)
    builder = CallGraphBuilder(extracted)
    builder.build_call_graph()
    graph = builder.export()
    dataset = UnitGenerator(
        graph, {"dataset_name": "openharmony-ipc-baseline"}
    ).generate_units()
    entry_points = EntryPointDetector(
        extracted["functions"], graph["call_graph"]
    ).detect_entry_points()

    edges = sorted(
        (
            {"caller": caller, "callee": callee}
            for caller, callees in graph["call_graph"].items()
            for callee in callees
        ),
        key=lambda edge: (edge["caller"], edge["callee"]),
    )
    return {
        "detected_languages": detect_languages(str(IPC_FIXTURE_ROOT)),
        "scanned_files": [item["path"] for item in scan["files"]],
        "function_ids": sorted(extracted["functions"]),
        "unit_ids": sorted(unit["id"] for unit in dataset["units"]),
        "unit_types": dict(
            sorted(
                Counter(
                    function["unit_type"]
                    for function in extracted["functions"].values()
                ).items()
            )
        ),
        "call_graph_edges": edges,
        "entry_point_ids": sorted(entry_points),
    }


def test_current_baseline_is_portable_versioned_observation(current_baseline):
    assert current_baseline["schema_version"] == 1
    assert current_baseline["baseline_id"] == "openant-pre-openharmony-v1"
    assert current_baseline["mode"] == "observed_current_behavior"
    assert re.fullmatch(r"[0-9a-f]{40}", current_baseline["openant_commit"])

    serialized = json.dumps(current_baseline)
    assert "/Users/" not in serialized
    assert "openharmony_reference" not in serialized
    assert set(current_baseline["known_gaps"]) >= {
        "no_platform_profile",
        "build_metadata_not_discovered",
        "arkts_not_registered",
        "cangjie_not_registered",
        "idl_not_registered",
        "on_remote_request_not_an_entry_point",
        "no_ipc_semantic_edge",
    }


def test_external_inventory_baseline_matches_pinned_manifest(
    current_baseline, corpus_manifest
):
    corpus_by_name = {
        repository["name"]: repository
        for repository in corpus_manifest["repositories"]
    }
    observed_by_name = {
        repository["name"]: repository
        for repository in current_baseline["external_repositories"]
    }
    assert observed_by_name.keys() == corpus_by_name.keys()

    for name, observed in observed_by_name.items():
        counts = corpus_by_name[name]["source_counts"]
        detected = observed["detected_languages"]
        assert detected.get("c", 0) == counts["c"] + counts["cpp"] + counts["h"]
        assert detected.get("javascript", 0) == counts["js"] + counts["ts"]
        assert detected.get("rust", 0) == counts["rs"]
        assert observed["unsupported_source_files"] == {
            "cangjie": counts["cj"],
            "idl": counts["idl"],
            "arkts": counts["ets"],
        }
        assert observed["ignored_build_metadata"] == {
            "BUILD.gn": counts["build_gn"],
            "bundle.json": counts["bundle_json"],
            "gni": counts["gni"],
        }


def test_ipc_fixture_matches_observed_parser_and_entry_baseline(current_baseline):
    assert _analyze_ipc_fixture() == current_baseline["ipc_fixture"]

    on_remote_request = (
        "services/health_sensor_service_stub.cpp:"
        "HealthSensorServiceStub::OnRemoteRequest"
    )
    assert on_remote_request in current_baseline["ipc_fixture"]["function_ids"]
    assert on_remote_request not in current_baseline["ipc_fixture"]["entry_point_ids"]


def test_external_language_discovery_matches_observed_baseline(current_baseline):
    configured_root = os.environ.get("OPENHARMONY_CORPUS_ROOT")
    if not configured_root:
        pytest.skip(
            "set OPENHARMONY_CORPUS_ROOT to verify live language discovery"
        )

    corpus_root = Path(configured_root).resolve()
    for expected in current_baseline["external_repositories"]:
        assert detect_languages(str(corpus_root / expected["name"])) == expected[
            "detected_languages"
        ]
