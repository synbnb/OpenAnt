"""TDD contract for OpenHarmony candidate-edge review.

The direct-dispatch residual in ``MedicalSensorServiceStub::OnRemoteRequest``
has one call site but several runtime targets selected by an IPC transaction
code.  The candidate-review protocol must therefore preserve all candidate
targets in the bounded context and allow one decision per confirmed edge.
"""

from __future__ import annotations

import json

from core.platforms.openharmony.llm_call_graph_recovery import (
    build_recovery_prompt,
    build_recovery_worklist,
    parse_recovery_response,
    validate_recovery_proposals,
)


SOURCE = "services/medical_sensor/src/medical_service_stub.cpp"
CALLER = f"{SOURCE}:MedicalSensorServiceStub::OnRemoteRequest"
HANDLERS = [
    f"{SOURCE}:MedicalSensorServiceStub::AfeEnableInner",
    f"{SOURCE}:MedicalSensorServiceStub::AfeDisableInner",
    f"{SOURCE}:MedicalSensorServiceStub::GetAfeStateInner",
    f"{SOURCE}:MedicalSensorServiceStub::RunCommandInner",
    f"{SOURCE}:MedicalSensorServiceStub::GetAllSensorsInner",
    f"{SOURCE}:MedicalSensorServiceStub::CreateDataChannelInner",
    f"{SOURCE}:MedicalSensorServiceStub::DestroyDataChannelInner",
    f"{SOURCE}:MedicalSensorServiceStub::AfeSetOptionInner",
]


def _functions() -> dict[str, dict]:
    functions = {
        CALLER: {
            "name": "MedicalSensorServiceStub::OnRemoteRequest",
            "file_path": SOURCE,
            "start_line": 54,
            "end_line": 74,
            "class_name": "MedicalSensorServiceStub",
            "code": "return (this->*memberFunc)(data, reply);",
            "is_entry_point": True,
        }
    }
    for index, function_id in enumerate(HANDLERS):
        functions[function_id] = {
            "name": function_id.rsplit("::", 1)[-1],
            "file_path": SOURCE,
            "start_line": 75 + index * 10,
            "end_line": 82 + index * 10,
            "class_name": "MedicalSensorServiceStub",
            "code": "return ERR_OK;",
        }
    return functions


def _diagnostics() -> dict:
    return {
        "unresolved_call_sites": [
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 68,
                "expression": "return (this->*memberFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"target_variable": "memberFunc"},
                "candidate_target_ids": HANDLERS,
                "candidate_completeness": "complete",
            }
        ]
    }


def test_candidate_review_keeps_all_runtime_targets_in_shortlist():
    worklist = build_recovery_worklist(
        _diagnostics(),
        _functions(),
        include_candidate_sites=True,
        max_sites=-1,
        max_shortlist=2,
    )

    assert len(worklist) == 1
    item = worklist[0]
    assert item["candidate_count"] == len(HANDLERS)
    assert set(item["candidate_target_ids"]) == set(HANDLERS)
    assert {candidate["function_id"] for candidate in item["retrieval_candidates"]} == set(
        HANDLERS
    )


def test_candidate_prompt_allows_multiple_edges_and_requires_candidate_membership():
    worklist = build_recovery_worklist(
        _diagnostics(),
        _functions(),
        include_candidate_sites=True,
        max_sites=-1,
        max_shortlist=2,
    )
    prompt = build_recovery_prompt(worklist)

    assert "一个或多个 decision" in prompt
    assert "candidate_target_ids" in prompt
    assert "retrieval_candidates" in prompt


def test_candidate_review_accepts_multiple_edges_and_rejects_non_candidate_target():
    functions = _functions()
    non_candidate_id = (
        f"{SOURCE}:MedicalSensorServiceStub::NotRegistered"
    )
    functions[non_candidate_id] = {
        "name": "NotRegistered",
        "file_path": SOURCE,
        "start_line": 160,
        "end_line": 165,
        "class_name": "MedicalSensorServiceStub",
        "code": "return ERR_OK;",
    }
    worklist = build_recovery_worklist(
        _diagnostics(),
        functions,
        include_candidate_sites=True,
        max_sites=-1,
        max_shortlist=2,
    )
    site_id = worklist[0]["site_id"]
    evidence = lambda target: [
        {
            "kind": "call_site",
            "file": SOURCE,
            "start_line": 68,
            "end_line": 68,
            "text": "(this->*memberFunc)(data, reply)",
        },
        {
            "kind": "registration",
            "function_id": target,
            "file": SOURCE,
            "start_line": 39,
            "end_line": 46,
            "text": "baseFuncs_[code] = &MedicalSensorServiceStub::handler",
        },
    ]
    response = {
        "schema_version": 1,
        "decisions": [
            {
                "site_id": site_id,
                "decision": "add_edge",
                "target_id": target,
                "confidence": "high",
                "reason": "The dispatch table registers this handler.",
                "evidence": evidence(target),
            }
            for target in HANDLERS[:2]
        ]
        + [
            {
                "site_id": site_id,
                "decision": "add_edge",
                "target_id": non_candidate_id,
                "confidence": "high",
                "reason": "not actually registered",
                "evidence": evidence(HANDLERS[0]),
            }
        ],
    }
    errors: list[str] = []
    parsed = parse_recovery_response(
        json.dumps(response),
        valid_site_ids={site_id},
        valid_function_ids=set(functions),
        on_error=errors.append,
    )

    # The unknown function ID would be rejected by the strict parser; this
    # target is known to the function index but absent from the registration
    # candidates, so it must survive parsing and be rejected by validation.
    assert len(parsed) == 3
    validated = validate_recovery_proposals(parsed, worklist, functions)
    assert [item["target_id"] for item in validated["accepted"]] == HANDLERS[:2]
    assert all(
        item["evidence_status"] == "source_references_verified"
        for item in validated["accepted"]
    )
    assert all(
        item["reachability_tier"] == "candidate"
        for item in validated["accepted"]
    )
    assert len(validated["rejected"]) == 1
    assert validated["rejected"][0]["rejection_reason"] == (
        "target_not_in_candidate_targets"
    )
