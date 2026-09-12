from __future__ import annotations

import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[1]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.call_graph_facts import (  # noqa: E402
    build_effective_call_graph,
    refresh_effective_call_graph,
    synchronize_dataset_dependencies,
)
from core.call_graph_gap_report import build_call_graph_gap_report  # noqa: E402
from core.scanner import _gap_priority_sources  # noqa: E402
from utilities.agentic_enhancer.repository_index import (  # noqa: E402
    load_index_from_file,
)


def _native():
    return {
        "functions": {"main": {"name": "main"}, "caller": {}, "target": {}, "other": {}},
        "call_graph": {"main": ["caller"], "caller": []},
        "reverse_call_graph": {"caller": ["main"]},
    }


def test_resolved_callsite_edge_missing_is_repaired_without_mutating_native():
    native = _native()
    ledger = {
        "call_sites": [
            {
                "site_id": "site-dp12",
                "caller_id": "caller",
                "binding_status": "resolved",
                "candidate_target_ids": ["target"],
                "candidate_completeness": "complete",
                "binding_basis": "qualified_name_and_arity",
                "binding_evidence": {
                    "binding_rule": "qualified_name_and_arity",
                    "qualified_callee": "Target::target",
                    "target_id": "target",
                    "signature_match": True,
                },
                "linked_target_ids": [],
                "graph_status": "edge_missing",
                "file": "sp_thread_socket.cpp",
                "line_start": 378,
                "expression": "controlCallCmd.GetResult(vec)",
            }
        ]
    }

    effective = build_effective_call_graph(native, ledger=ledger)

    assert native["call_graph"]["caller"] == []
    assert effective["call_graph"]["caller"] == ["target"]
    assert effective["reverse_call_graph"]["target"] == ["caller"]
    assert effective["summary"]["resolved_edge_missing_repaired"] == 1
    assert effective["summary"]["confirmed_added"] == 1
    assert effective["summary"]["resolved_edge_missing_unrepaired"] == 0


def test_native_edge_is_enriched_with_matching_ledger_source_span():
    ledger = {
        "call_sites": [
            {
                "site_id": "native-site",
                "caller_id": "caller",
                "candidate_target_ids": ["target"],
                "linked_target_ids": ["target"],
                "binding_status": "resolved",
                "graph_status": "linked",
                "file": "example.cpp",
                "line_start": 42,
                "line_end": 42,
                "expression": "target()",
            }
        ]
    }
    native = _native()
    native["call_graph"]["caller"] = ["target"]
    effective = build_effective_call_graph(native, ledger=ledger)
    edge = next(
        item
        for item in effective["edge_facts"]
        if item["caller_id"] == "main" and item["callee_id"] == "caller"
    )
    assert edge["evidence"] == [] or edge["evidence"] == {}
    enriched = next(
        item
        for item in effective["edge_facts"]
        if item["caller_id"] == "caller" and item["callee_id"] == "target"
    )
    assert enriched["evidence"][0]["file"] == "example.cpp"
    assert enriched["evidence"][0]["line_start"] == 42
    assert enriched["attributes"]["ledger_callsite_count"] == 1


def test_single_unknown_candidate_is_not_promoted_to_strict_edge():
    ledger = {
        "call_sites": [
            {
                "site_id": "member-unknown",
                "caller_id": "caller",
                "binding_status": "resolved",
                "candidate_target_ids": ["target"],
                "candidate_completeness": "unknown",
                "binding_basis": "member_name_and_arity",
                "binding_evidence": {},
                "graph_status": "edge_missing",
            }
        ]
    }

    effective = build_effective_call_graph(_native(), ledger=ledger)

    assert "target" not in effective["call_graph"].get("caller", [])
    assert effective["summary"]["candidate_edges"] == 1
    assert effective["summary"]["resolved_edge_missing_unrepaired"] == 1


def test_partial_and_unvalidated_overlay_stay_candidates():
    overlay = {
        "edges": [
            {
                "source": "caller",
                "target": "other",
                "resolver": "llm",
                "attributes": {"reachability_tier": "candidate"},
            }
        ]
    }
    ledger = {
        "call_sites": [
            {
                "site_id": "ambiguous",
                "caller_id": "caller",
                "binding_status": "resolved",
                "candidate_target_ids": ["target", "other"],
                "graph_status": "edge_missing",
            }
        ]
    }
    effective = build_effective_call_graph(_native(), ledger=ledger, semantic_overlays=[overlay])

    assert "other" not in effective["call_graph"].get("caller", [])
    assert effective["summary"]["candidate_edges"] >= 2
    assert effective["summary"]["resolved_edge_missing_unrepaired"] == 1


def test_refresh_writes_effective_graph_and_keeps_native_file(tmp_path):
    native_path = tmp_path / "call_graph.json"
    native_path.write_text(json.dumps(_native()), encoding="utf-8")
    (tmp_path / "callsite_ledger.json").write_text(
        json.dumps(
            {
                "call_sites": [
                    {
                        "site_id": "site-dp17",
                        "caller_id": "caller",
                        "binding_status": "resolved",
                        "candidate_target_ids": ["target"],
                        "candidate_completeness": "complete",
                        "binding_basis": "qualified_name_and_arity",
                        "binding_evidence": {
                            "binding_rule": "qualified_name_and_arity",
                            "qualified_callee": "Target::target",
                            "target_id": "target",
                            "signature_match": True,
                        },
                        "graph_status": "edge_missing",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = refresh_effective_call_graph(tmp_path)

    assert result is not None
    assert (tmp_path / "effective_call_graph.json").is_file()
    assert json.loads(native_path.read_text(encoding="utf-8"))["call_graph"]["caller"] == []
    assert json.loads(
        (tmp_path / "effective_call_graph.json").read_text(encoding="utf-8")
    )["call_graph"]["caller"] == ["target"]
    effective_payload = json.loads(
        (tmp_path / "effective_call_graph.json").read_text(encoding="utf-8")
    )
    assert effective_payload["graph_version"]
    assert effective_payload["provenance"]["source_revision"] == "unknown"


def test_repository_index_consumes_effective_edges(tmp_path):
    analyzer_path = tmp_path / "analyzer_output.json"
    analyzer_path.write_text(
        json.dumps({"functions": _native()["functions"], "call_graph": {}, "reverse_call_graph": {}}),
        encoding="utf-8",
    )
    (tmp_path / "effective_call_graph.json").write_text(
        json.dumps(
            {
                "functions": _native()["functions"],
                "call_graph": {"caller": ["target"]},
                "reverse_call_graph": {"target": ["caller"]},
            }
        ),
        encoding="utf-8",
    )

    index = load_index_from_file(str(analyzer_path))

    assert index.get_call_graph_context("caller")["callees"] == ["target"]
    assert index.get_call_graph_context("target")["callers"] == ["caller"]


def test_dataset_dependencies_are_synchronized_from_effective_graph(tmp_path):
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(
        json.dumps(
            {
                "units": [
                    {"id": "caller", "metadata": {"direct_calls": []}},
                    {"id": "target", "metadata": {}},
                ]
            }
        ),
        encoding="utf-8",
    )
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        json.dumps(
            {
                "call_graph": {"caller": ["target"]},
                "reverse_call_graph": {"target": ["caller"]},
            }
        ),
        encoding="utf-8",
    )

    summary = synchronize_dataset_dependencies(dataset_path, [graph_path])
    units = json.loads(dataset_path.read_text(encoding="utf-8"))["units"]

    assert summary["units_updated"] == 2
    assert units[0]["metadata"]["direct_calls"] == ["target"]
    assert units[1]["metadata"]["direct_callers"] == ["caller"]
    assert "effective_call_graphs" in json.loads(
        dataset_path.read_text(encoding="utf-8")
    )["metadata"]


def test_clang_sidecar_is_projected_only_when_marked_strict(tmp_path):
    (tmp_path / "call_graph.json").write_text(json.dumps(_native()), encoding="utf-8")
    (tmp_path / "clang_semantic_overlay.json").write_text(
        json.dumps(
            {
                "edges": [
                    {
                        "source_id": "function:caller",
                        "target_id": "function:target",
                            "attributes": {
                                "resolver": "clang",
                                "binding_status": "resolved",
                                "reachability_tier": "strict",
                                "build_status": "compile_database",
                                "evidence_quality": "semantic_binding_validated",
                            "validation_record": {
                                "id": "clang:test",
                                "status": "accepted",
                                "validator": "test",
                            },
                        },
                        "evidence": [{"kind": "call_site", "text": "caller()"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    effective = refresh_effective_call_graph(tmp_path)

    assert effective["call_graph"]["caller"] == ["target"]
    assert effective["summary"]["confirmed_added"] == 1


def test_clang_candidate_build_is_not_promoted_by_validation_record():
    overlay = {
        "edges": [
            {
                "source": "caller",
                "target": "target",
                "resolver": "clang",
                "evidence": [{"kind": "call_site", "text": "caller()"}],
                "attributes": {
                    "resolver": "clang",
                    "binding_status": "resolved",
                    "reachability_tier": "candidate",
                    "build_status": "reconstructed_candidate",
                    "evidence_quality": "semantic_binding_validated",
                    "validation_record": {
                        "id": "clang:candidate",
                        "status": "accepted",
                        "validator": "test",
                    },
                },
            }
        ]
    }

    effective = build_effective_call_graph(_native(), semantic_overlays=[overlay])

    assert "target" not in effective["call_graph"].get("caller", [])
    assert effective["summary"]["candidate_edges"] == 1
    assert effective["candidate_facts"][0]["repair_reason"] == (
        "semantic_overlay_candidate_tier"
    )


def test_clang_strict_tier_without_build_status_is_not_admitted():
    overlay = {
        "edges": [
            {
                "source": "caller",
                "target": "target",
                "resolver": "clang",
                "evidence": [{"kind": "call_site", "text": "caller()"}],
                "attributes": {
                    "resolver": "clang",
                    "binding_status": "resolved",
                    "reachability_tier": "strict",
                    "evidence_quality": "semantic_binding_validated",
                    "validation_record": {
                        "id": "clang:missing-build-status",
                        "status": "accepted",
                        "validator": "test",
                    },
                },
            }
        ]
    }

    effective = build_effective_call_graph(_native(), semantic_overlays=[overlay])

    assert "target" not in effective["call_graph"].get("caller", [])
    assert effective["candidate_facts"][0]["repair_reason"] == (
        "build_context_incomplete_or_manual"
    )


def test_clang_overlay_build_config_mismatch_is_not_admitted():
    overlay = {
        "build_config_id": "old-config",
        "edges": [
            {
                "source": "caller",
                "target": "target",
                "resolver": "clang",
                "evidence": [{"kind": "call_site", "text": "caller()"}],
                "attributes": {
                    "resolver": "clang",
                    "binding_status": "resolved",
                    "reachability_tier": "strict",
                    "build_status": "compile_database",
                    "evidence_quality": "semantic_binding_validated",
                    "validation_record": {
                        "id": "clang:old-config",
                        "status": "accepted",
                        "validator": "test",
                    },
                },
            }
        ],
    }

    effective = build_effective_call_graph(
        _native(), semantic_overlays=[overlay], build_config_id="new-config"
    )

    assert "target" not in effective["call_graph"].get("caller", [])
    assert effective["candidate_facts"][0]["repair_reason"] == (
        "overlay_build_config_mismatch"
    )


def test_validated_flag_without_validation_record_stays_candidate():
    overlay = {
        "edges": [
            {
                "source": "caller",
                "target": "target",
                "resolver": "llm",
                "evidence": [{"kind": "call_site", "text": "caller()"}],
                "attributes": {
                    "validated": True,
                    "reachability_tier": "strict",
                    "evidence_quality": "relation_supported",
                },
            }
        ]
    }

    effective = build_effective_call_graph(_native(), semantic_overlays=[overlay])

    assert "target" not in effective["call_graph"].get("caller", [])
    assert effective["summary"]["candidate_edges"] == 1
    assert effective["candidate_facts"][0]["repair_reason"] == (
        "validation_record_missing_or_untrusted"
    )


def test_strict_overlay_revision_mismatch_is_not_admitted():
    overlay = {
        "source_revision": "old-revision",
        "edges": [
            {
                "source": "caller",
                "target": "target",
                "resolver": "clang",
                "evidence": [{"kind": "call_site", "text": "caller()"}],
                "attributes": {
                    "reachability_tier": "strict",
                    "build_status": "compile_database",
                    "evidence_quality": "semantic_binding_validated",
                    "validation_record": {
                        "id": "clang:old",
                        "status": "accepted",
                        "validator": "test",
                    },
                },
            }
        ],
    }

    effective = build_effective_call_graph(
        _native(), semantic_overlays=[overlay], source_revision="new-revision"
    )

    assert "target" not in effective["call_graph"].get("caller", [])
    assert effective["candidate_facts"][0]["repair_reason"] == (
        "overlay_source_revision_mismatch"
    )


def test_clang_overlay_with_unknown_build_context_stays_candidate():
    overlay = {
        "edges": [
            {
                "source": "caller",
                "target": "target",
                "resolver": "clang",
                "evidence": [{"kind": "call_site", "text": "target()"}],
                "attributes": {
                    "evidence_quality": "semantic_binding_validated",
                    "build_status": "unknown",
                    "validation_record": {
                        "id": "clang:unknown-build",
                        "status": "accepted",
                        "validator": "test",
                    },
                },
            }
        ]
    }
    effective = build_effective_call_graph(_native(), semantic_overlays=[overlay])

    assert effective["call_graph"].get("caller", []) == []
    assert effective["candidate_facts"][0]["repair_reason"] == (
        "build_context_incomplete_or_manual"
    )


def test_graph_version_is_stable_when_native_adjacency_order_changes():
    first = build_effective_call_graph(
        {
            **_native(),
            "call_graph": {"main": ["caller"], "caller": []},
        },
        source_revision="rev",
        build_config_id="cfg",
    )
    second = build_effective_call_graph(
        {
            **_native(),
            "call_graph": {"caller": [], "main": ["caller"]},
        },
        source_revision="rev",
        build_config_id="cfg",
    )

    assert first["graph_version"] == second["graph_version"]
    assert first["provenance"]["input_fingerprint"] == second["provenance"][
        "input_fingerprint"
    ]


def test_gap_report_counts_one_site_not_each_candidate(tmp_path):
    native = _native()
    native_path = tmp_path / "call_graph.json"
    native_path.write_text(json.dumps(native), encoding="utf-8")
    ledger = {
        "call_sites": [
            {
                "site_id": "site-many",
                "caller_id": "caller",
                "binding_status": "partial",
                "candidate_target_ids": ["target", "other"],
                "candidate_completeness": "unknown",
                "graph_status": "edge_missing",
                "file": "a.cpp",
                "line_start": 12,
                "expression": "handler(data)",
            }
        ]
    }
    (tmp_path / "callsite_ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    effective = build_effective_call_graph(native, ledger=ledger)
    effective_path = tmp_path / "effective_call_graph.json"
    effective_path.write_text(json.dumps(effective), encoding="utf-8")

    report = build_call_graph_gap_report([effective_path])

    assert report["summary"]["candidate_fact_records"] == 2
    assert report["summary"]["unique_gap_sites"] == 1
    assert report["summary"]["candidate_callsite_groups"] == 1
    assert report["sites"][0]["candidate_target_count"] == 2
    assert report["sites"][0]["candidate_record_count"] == 2
    assert report["summary"]["reason_site_counts"]["edge_missing"] == 1
    assert report["summary"]["unrepaired_reason_site_counts"]["edge_missing"] == 1
    assert report["summary"]["unrepaired_source_file_counts"] == {"a.cpp": 1}


def test_gap_priority_sources_use_highest_yield_files_first():
    report = {
        "summary": {
            "unrepaired_source_file_counts": {
                "low.cpp": 1,
                "hot.cpp": 9,
                "middle.cpp": 3,
            }
        },
        "sites": [
            {"file": "low.cpp", "ledger_unrepaired": True},
            {"file": "hot.cpp", "ledger_unrepaired": True},
            {"file": "middle.cpp", "ledger_unrepaired": True},
        ],
    }

    assert _gap_priority_sources(report) == ["hot.cpp", "middle.cpp", "low.cpp"]


def test_effective_graph_keeps_declaration_only_overlay_node():
    overlay = {
        "nodes": [
            {
                "id": "function:external.hpp:External::run",
                "kind": "symbol",
                "attributes": {"declaration_only": True},
            }
        ],
        "edges": [
            {
                "source": "caller",
                "target": "function:external.hpp:External::run",
                "resolver": "clang",
                "evidence": [{"kind": "call_site", "text": "run()"}],
                "attributes": {
                    "reachability_tier": "strict",
                    "build_status": "compile_database",
                    "evidence_quality": "semantic_binding_validated",
                    "validation_record": {
                        "id": "clang:external",
                        "status": "accepted",
                        "validator": "test",
                    },
                },
            }
        ],
    }
    effective = build_effective_call_graph(_native(), semantic_overlays=[overlay])

    assert "external.hpp:External::run" in effective["nodes"]
    assert effective["external_nodes"]["external.hpp:External::run"]["declaration_only"] is True
    assert effective["call_graph"]["caller"] == ["external.hpp:External::run"]
