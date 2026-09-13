"""Platform-neutral contracts used by future platform adapters."""

import json

import pytest

from core.platforms.base import (
    CoverageReport,
    RepositoryProfile,
    SemanticEdge,
    SemanticNode,
)
from core.schemas import ParseResult, ScanResult


def _profile() -> RepositoryProfile:
    coverage = CoverageReport(
        schema_version=1,
        discovered_files=12,
        eligible_files=10,
        parsed_files=8,
        unsupported_files=[{"path": "entry/src/main.ets", "reason": "not_registered"}],
        parse_failures=[{"path": "services/x.cpp", "reason": "syntax_error"}],
        roles={"production": 8, "test": 2},
    )
    return RepositoryProfile(
        schema_version=1,
        platform="openharmony",
        detection={"confidence": 0.98, "evidence": ["bundle.json", "BUILD.gn"]},
        repository_root="/workspace/medical_sensor",
        components=[
            {
                "name": "medical_sensor",
                "subsystem": "sensors",
                "source_roots": ["services", "interfaces"],
            }
        ],
        languages=["c", "javascript"],
        boundaries=["binder_ipc", "system_ability"],
        coverage=coverage,
        provenance={"profile_builder_version": 1, "source_hashes": {}},
    )


def test_repository_profile_and_coverage_round_trip_as_json():
    profile = _profile()

    restored = RepositoryProfile.from_dict(json.loads(json.dumps(profile.to_dict())))

    assert restored.schema_version == 1
    assert restored.platform == "openharmony"
    assert restored.coverage.parsed_files == 8
    assert restored.coverage.unsupported_files[0]["path"] == "entry/src/main.ets"
    assert restored.components[0]["name"] == "medical_sensor"


def test_repository_profile_round_trips_optional_build_metadata():
    profile = _profile()
    profile.build_metadata = {
        "gn": {
            "files": ["BUILD.gn"],
            "targets": [{"name": "medical_service", "kind": "ohos_shared_library"}],
            "unknown_condition_count": 1,
        }
    }

    restored = RepositoryProfile.from_dict(json.loads(json.dumps(profile.to_dict())))

    assert restored.build_metadata["gn"]["targets"][0]["name"] == "medical_service"
    assert restored.to_dict()["build_metadata"]["gn"]["unknown_condition_count"] == 1


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload["detection"].update({"confidence": 1.01}), "confidence"),
        (lambda payload: payload["coverage"].update({"parsed_files": 11}), "parsed_files"),
        (lambda payload: payload.update({"languages": "c"}), "languages"),
        (lambda payload: payload.update({"platform": ""}), "platform"),
    ],
)
def test_repository_profile_rejects_invalid_schema_content(mutate, message):
    payload = _profile().to_dict()
    mutate(payload)

    with pytest.raises(ValueError, match=message):
        RepositoryProfile.from_dict(payload)


def test_coverage_rejects_negative_and_non_monotonic_counts():
    with pytest.raises(ValueError, match="discovered_files"):
        CoverageReport.from_dict({"schema_version": 1, "discovered_files": -1})

    with pytest.raises(ValueError, match="eligible_files"):
        CoverageReport.from_dict(
            {"schema_version": 1, "discovered_files": 2, "eligible_files": 3}
        )


def test_semantic_nodes_and_non_syntactic_edges_preserve_evidence():
    node = SemanticNode(
        schema_version=1,
        id="tx:health:enable_sensor",
        kind="ipc_transaction",
        attributes={"code": 1},
    )
    edge = SemanticEdge(
        schema_version=1,
        source_id="proxy:health:enable_sensor",
        target_id=node.id,
        kind="proxy_to_transaction",
        evidence=[{"file": "proxy.cpp", "line": 42, "role": "send_request"}],
        confidence=0.9,
        resolver_version=1,
    )

    restored_node = SemanticNode.from_dict(json.loads(json.dumps(node.to_dict())))
    restored_edge = SemanticEdge.from_dict(json.loads(json.dumps(edge.to_dict())))

    assert restored_node.attributes == {"code": 1}
    assert restored_edge.evidence[0]["role"] == "send_request"
    assert restored_edge.confidence == 0.9


@pytest.mark.parametrize(
    ("contract", "payload"),
    [
        (RepositoryProfile, {"platform": "openharmony"}),
        (CoverageReport, {"parsed_files": 1}),
        (SemanticNode, {"id": "node", "kind": "function"}),
        (SemanticEdge, {"source_id": "a", "target_id": "b", "kind": "calls"}),
    ],
)
def test_platform_contracts_reject_missing_schema_version(contract, payload):
    with pytest.raises(ValueError, match="schema_version"):
        contract.from_dict(payload)


def test_generic_results_stay_unchanged_until_platform_data_is_explicitly_attached():
    legacy_parse = ParseResult(dataset_path="/out/dataset.json", language="c")
    legacy_scan = ScanResult(output_dir="/out", language="c")

    assert "platform_profile" not in legacy_parse.to_dict()
    assert "platform_coverage" not in legacy_scan.to_dict()

    profile = _profile()
    platform_parse = ParseResult(
        dataset_path="/out/dataset.json",
        language="c",
        platform_profile=profile.to_dict(),
    )
    platform_scan = ScanResult(
        output_dir="/out",
        language="c",
        platform_profile=profile.to_dict(),
        platform_coverage=profile.coverage.to_dict(),
    )

    parse_payload = json.loads(json.dumps(platform_parse.to_dict()))
    scan_payload = json.loads(json.dumps(platform_scan.to_dict()))
    assert parse_payload["platform_profile"]["platform"] == "openharmony"
    assert scan_payload["platform_coverage"]["parsed_files"] == 8
