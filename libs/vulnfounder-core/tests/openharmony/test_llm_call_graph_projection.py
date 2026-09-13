"""Tests for the isolated LLM call-graph recovery projection boundary."""

from __future__ import annotations

import copy
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.graph import SemanticGraph  # noqa: E402
from core.platforms.openharmony.llm_call_graph_projection import (  # noqa: E402
    EDGE_KIND,
    project_recovery_overlay,
)


SOURCE = "services/network/net_stub.cpp"
CALLER = f"{SOURCE}:NetStub::OnRemoteRequest"
TARGET = f"{SOURCE}:NetStub::HandleRequest"
OTHER = f"{SOURCE}:NetStub::OtherRequest"
SITE = "native:12:abc123"


def _functions() -> dict[str, dict]:
    return {
        CALLER: {
            "name": "NetStub::OnRemoteRequest",
            "file_path": SOURCE,
            "start_line": 10,
            "end_line": 20,
            "class_name": "NetStub",
            "unit_type": "function",
            "code": "int32_t NetStub::OnRemoteRequest() { return (this->*requestFunc)(data, reply); }",
        },
        TARGET: {
            "name": "NetStub::HandleRequest",
            "file_path": SOURCE,
            "start_line": 30,
            "end_line": 35,
            "class_name": "NetStub",
            "unit_type": "function",
            "code": "int32_t NetStub::HandleRequest(MessageParcel &data) { return 0; }",
        },
        OTHER: {
            "name": "NetStub::OtherRequest",
            "file_path": SOURCE,
            "start_line": 40,
            "end_line": 45,
            "class_name": "NetStub",
            "unit_type": "function",
            "code": "int32_t NetStub::OtherRequest(MessageParcel &data) { return 0; }",
        },
    }


def _proposal(target_id: str = TARGET, *, confidence: str = "high", evidence=None) -> dict:
    return {
        "site_id": SITE,
        "decision": "add_edge",
        "target_id": target_id,
        "confidence": confidence,
        "reason": "The member-function pointer resolves to the indexed handler.",
        "evidence": evidence
        or [
            {
                "kind": "call_site",
                "file": SOURCE,
                "start_line": 12,
                "end_line": 12,
                "text": "(this->*requestFunc)(data, reply)",
            },
            {
                "kind": "target",
                "function_id": TARGET,
                "file": SOURCE,
                "start_line": 30,
                "end_line": 35,
                "text": "NetStub::HandleRequest(MessageParcel &data)",
            },
        ],
    }


def _report(
    *proposals: dict,
    retrieval_ids=None,
    candidate_ids=None,
    candidate_completeness="complete",
) -> dict:
    if retrieval_ids is None:
        retrieval_ids = [TARGET]
    if candidate_ids is None:
        candidate_ids = [TARGET]
    return {
        "schema_version": 1,
        "task": "openharmony_call_edge_recovery",
        "status": "complete",
        "worklist": [
            {
                "site_id": SITE,
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 12,
                "expression": "(this->*requestFunc)(data, reply)",
                "candidate_target_ids": candidate_ids,
                "candidate_completeness": candidate_completeness,
                "retrieval_candidates": [
                    {"function_id": item} for item in retrieval_ids
                ],
            }
        ],
        "validation": {"accepted": list(proposals), "kept_unresolved": [], "rejected": []},
    }


def test_projects_only_source_backed_high_confidence_edge_and_does_not_mutate_inputs():
    report = _report(_proposal())
    functions = _functions()
    before = copy.deepcopy((report, functions))

    overlay = project_recovery_overlay(report, functions)

    assert (report, functions) == before
    assert overlay["status"] == "complete"
    assert overlay["summary"] == {
        "accepted_input": 1,
        "projected_edges": 1,
        "rejected": 0,
        "duplicate_edges": 0,
        "strict_edges": 0,
        "candidate_edges": 1,
        "evidence_quality_counts": {"reference_validated": 1},
        "edge_limit": 1000,
        "minimum_confidence": "high",
    }
    assert overlay["edges"][0]["source_id"] == f"function:{CALLER}"
    assert overlay["edges"][0]["target_id"] == f"function:{TARGET}"
    assert overlay["edges"][0]["kind"] == EDGE_KIND
    assert overlay["edges"][0]["attributes"]["site_id"] == SITE
    assert overlay["edges"][0]["attributes"]["reachability_tier"] == "candidate"

    # Extra envelope fields must not make the semantic graph unreadable.
    graph = SemanticGraph.from_dict(overlay)
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1


def test_candidate_less_residual_can_project_bounded_retrieval_target():
    """Unknown-indirect sites may use only their local retrieval shortlist."""
    report = _report(
        _proposal(),
        retrieval_ids=[TARGET],
        candidate_ids=[],
    )

    overlay = project_recovery_overlay(report, _functions())

    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["edges"][0]["target_id"] == f"function:{TARGET}"


def test_incomplete_parser_candidates_are_hints_not_a_hard_whitelist():
    evidence = _proposal(target_id=OTHER)["evidence"]
    evidence[1]["function_id"] = OTHER
    evidence[1]["text"] = "NetStub::OtherRequest(MessageParcel &data)"
    report = _report(
        _proposal(target_id=OTHER, evidence=evidence),
        retrieval_ids=[TARGET, OTHER],
        candidate_ids=[TARGET],
        candidate_completeness="unknown",
    )

    overlay = project_recovery_overlay(report, _functions())

    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["edges"][0]["target_id"] == f"function:{OTHER}"


def test_projects_wrapped_parser_registration_when_model_quotes_first_line():
    """A two-line table write remains valid source evidence at projection."""
    report = _report(_proposal())
    report["worklist"][0]["candidate_registrations"] = [
        {
            "target_id": TARGET,
            "target_name": "NetStub::HandleRequest",
            "registration_evidence": {
                "file": SOURCE,
                "start_line": 24,
                "end_line": 25,
                "text": "memberFuncMap_[REQUEST] = {\n    &NetStub::HandleRequest};",
            },
        }
    ]
    report["validation"]["accepted"][0]["evidence"] = [
        {
            "kind": "call_site",
            "file": SOURCE,
            "start_line": 12,
            "end_line": 12,
            "text": "(this->*requestFunc)(data, reply)",
        },
        {
            "kind": "registration",
            "file": SOURCE,
            "start_line": 24,
            "end_line": 24,
            "text": "memberFuncMap_[REQUEST] = {",
        },
    ]

    overlay = project_recovery_overlay(report, _functions())

    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["summary"]["rejected"] == 0
    assert overlay["summary"]["strict_edges"] == 1
    assert overlay["summary"]["candidate_edges"] == 0
    assert overlay["edges"][0]["attributes"]["evidence_quality"] == (
        "relation_supported"
    )
    assert overlay["edges"][0]["attributes"]["reachability_tier"] == "strict"


def test_type_evidence_requires_target_owner_before_strict_admission():
    evidence = _proposal()["evidence"]
    evidence[1] = {
        "kind": "type",
        "file": SOURCE,
        "start_line": 30,
        "end_line": 35,
        "text": "OtherStub::HandleRequest handler",
    }
    overlay = project_recovery_overlay(
        _report(_proposal(evidence=evidence)), _functions()
    )

    assert overlay["summary"]["projected_edges"] == 0
    assert overlay["summary"]["rejected"] == 1
    assert overlay["rejected"][0]["reason"] == (
        "target_or_registration_evidence_not_source_backed"
    )


def test_type_evidence_with_target_owner_is_strict():
    evidence = _proposal()["evidence"]
    evidence[1] = {
        "kind": "type",
        "file": SOURCE,
        "start_line": 30,
        "end_line": 35,
        "text": "NetStub::HandleRequest handler",
    }
    overlay = project_recovery_overlay(
        _report(_proposal(evidence=evidence)), _functions()
    )

    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["summary"]["strict_edges"] == 1
    assert overlay["edges"][0]["attributes"]["evidence_quality"] == (
        "type_supported"
    )


def test_rejects_low_confidence_unknown_candidate_and_unbacked_evidence():
    low = _proposal(confidence="medium")
    unknown = _proposal(target_id=OTHER)
    bad_evidence = _proposal(
        evidence=[
            {
                "kind": "call_site",
                "file": SOURCE,
                "start_line": 12,
                "end_line": 12,
                "text": "handler call",
            },
            {
                "kind": "target",
                "function_id": TARGET,
                "file": SOURCE,
                "start_line": 30,
                "end_line": 35,
                "text": "NetStub::HandleRequest(...)",
            },
        ]
    )

    overlay = project_recovery_overlay(
        _report(
            low,
            unknown,
            bad_evidence,
            retrieval_ids=[TARGET, OTHER],
            candidate_ids=[TARGET],
        ),
        _functions(),
    )

    assert overlay["edges"] == []
    assert overlay["summary"]["projected_edges"] == 0
    assert overlay["summary"]["rejected"] == 3
    assert {item["reason"] for item in overlay["rejected"]} == {
        "confidence_below_projection_threshold",
        "target_not_in_site_candidates",
        "call_site_evidence_not_source_backed",
    }


def test_duplicate_pair_is_projected_once_and_is_reported():
    overlay = project_recovery_overlay(_report(_proposal(), _proposal()), _functions())

    assert len(overlay["edges"]) == 1
    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["summary"]["duplicate_edges"] == 1
    assert overlay["summary"]["rejected"] == 1
    assert overlay["rejected"][0]["reason"] == "duplicate_edge"
    assert overlay["edges"][0]["attributes"]["site_ids"] == [SITE]
    assert len(overlay["edges"][0]["attributes"]["site_evidence"]) == 1


def test_missing_validation_block_is_invalid_and_emits_no_edges():
    overlay = project_recovery_overlay(
        {"schema_version": 1, "task": "openharmony_call_edge_recovery"},
        _functions(),
    )

    assert overlay["status"] == "invalid"
    assert overlay["edges"] == []
    assert overlay["rejected"][0]["reason"] == "missing_validation_block"
