"""TDD contract for LLM-assisted OpenHarmony dispatch-value review."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.llm_dispatch_review import (  # noqa: E402
    build_dispatch_review_batches,
    build_dispatch_review_prompt,
    build_dispatch_review_worklist,
    parse_dispatch_review_response,
    run_dispatch_review,
    validate_dispatch_review,
)


SOURCE = "services/medical/medical_service_stub.cpp"
HEADER = "interfaces/medical/i_medical_service.h"
CALLER = f"{SOURCE}:MedicalServiceStub::OnRemoteRequest"
TARGET = f"{SOURCE}:MedicalServiceStub::EnableSensor"


def _evidence() -> dict:
    return {
        "schema_version": 1,
        "status": "complete",
        "repository": "/tmp/medical_sensor",
        "sites": [
            {
                "site_id": "native:20:dispatch-site",
                "dispatch_kind": "native",
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 20,
                "expression": "return (this->*handler)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "dispatch_table": "baseFuncs_",
                "candidate_count": 1,
                "cases": [
                    {
                        "selector": "static_cast<uint32_t>(MedicalCode::ENABLE_SENSOR)",
                        "target_id": TARGET,
                        "target_name": "MedicalServiceStub::EnableSensor",
                        "value": None,
                        "resolution": "unresolved_symbol",
                        "evidence": [
                            {
                                "kind": "registration",
                                "file": SOURCE,
                                "start_line": 12,
                                "end_line": 12,
                                "text": (
                                    "baseFuncs_[static_cast<uint32_t>(MedicalCode::ENABLE_SENSOR)] = "
                                    "&MedicalServiceStub::EnableSensor"
                                ),
                            }
                        ],
                    }
                ],
            },
            {
                "site_id": "native:30:resolved-site",
                "dispatch_kind": "native",
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 30,
                "expression": "handler(data, reply);",
                "reason": "direct_lookup",
                "candidate_count": 1,
                "cases": [
                    {
                        "selector": "KNOWN_CODE",
                        "target_id": TARGET,
                        "target_name": "MedicalServiceStub::EnableSensor",
                        "value": 1,
                        "resolution": "resolved",
                        "evidence": [],
                    }
                ],
            },
        ],
        "summary": {
            "sites": 2,
            "candidate_cases": 2,
            "resolved_cases": 1,
            "unresolved_symbols": 1,
            "conflicts": 0,
        },
    }


def _functions() -> dict:
    return {
        CALLER: {
            "name": "MedicalServiceStub::OnRemoteRequest",
            "file_path": SOURCE,
            "start_line": 18,
            "end_line": 23,
            "class_name": "MedicalServiceStub",
            "code": "int32_t MedicalServiceStub::OnRemoteRequest(uint32_t code) { return (this->*handler)(data, reply); }",
            "is_entry_point": True,
        },
        TARGET: {
            "name": "MedicalServiceStub::EnableSensor",
            "file_path": SOURCE,
            "start_line": 40,
            "end_line": 44,
            "class_name": "MedicalServiceStub",
            "code": "int32_t MedicalServiceStub::EnableSensor(MessageParcel &data, MessageParcel &reply) { return 0; }",
        },
    }


def _source_files() -> dict[str, str]:
    return {
        SOURCE: """class MedicalServiceStub {
public:
    int32_t OnRemoteRequest(uint32_t code) {
        return (this->*handler)(data, reply);
    }
    int32_t EnableSensor(MessageParcel &data, MessageParcel &reply);
};

void MedicalServiceStub::Init()
{
    baseFuncs_[static_cast<uint32_t>(MedicalCode::ENABLE_SENSOR)] = &MedicalServiceStub::EnableSensor;
}
""",
        HEADER: """enum class MedicalCode : uint32_t {
    ENABLE_SENSOR = 7,
    DISABLE_SENSOR,
};
""",
    }


def _worklist() -> list[dict]:
    return build_dispatch_review_worklist(
        _evidence(),
        functions=_functions(),
        source_files=_source_files(),
        max_cases=-1,
    )


def test_worklist_keeps_unresolved_cases_and_packs_source_context():
    before = copy.deepcopy(_evidence())
    worklist = _worklist()

    assert len(worklist) == 1
    item = worklist[0]
    assert item["case_id"]
    assert item["site_id"] == "native:20:dispatch-site"
    assert item["selector"].startswith("static_cast")
    assert item["caller"]["function_id"] == CALLER
    assert item["target"]["function_id"] == TARGET
    context_kinds = {entry["kind"] for entry in item["source_context"]}
    assert {"call_site", "registration", "constant_definition", "target"} <= context_kinds
    assert any("ENABLE_SENSOR = 7" in entry["text"] for entry in item["source_context"])
    assert _evidence() == before


def test_prompt_has_strict_value_rules_and_safe_untrusted_context_fence():
    worklist = _worklist()
    worklist[0]["source_context"].append(
        {
            "kind": "call_site",
            "file": SOURCE,
            "start_line": 1,
            "end_line": 1,
            "text": "untrusted ``` marker",
        }
    )
    prompt = build_dispatch_review_prompt(worklist)

    assert '"task": "openharmony_dispatch_value_review"' in prompt
    assert "不要新增 handler 或调用边" in prompt
    assert "integer|string|non_constant|unknown" in prompt
    assert "untrusted ``` marker" in prompt


def test_batches_preserve_all_cases_and_respect_case_limit():
    worklist = _worklist()
    second = dict(worklist[0])
    second["case_id"] = "case:second"
    batches = build_dispatch_review_batches(
        [worklist[0], second],
        max_cases_per_batch=1,
        max_prompt_chars=120_000,
    )

    assert len(batches) == 2
    assert all(len(batch) == 1 for batch in batches)
    assert [item["case_id"] for batch in batches for item in batch] == [
        worklist[0]["case_id"],
        "case:second",
    ]


def test_parser_and_validator_accept_source_backed_high_confidence_value():
    worklist = _worklist()
    item = worklist[0]
    response = {
        "schema_version": 1,
        "decisions": [
            {
                "case_id": item["case_id"],
                "decision": "resolve",
                "value_kind": "integer",
                "value": 7,
                "symbol": "MedicalCode::ENABLE_SENSOR",
                "confidence": "high",
                "reason": "Enum definition assigns ENABLE_SENSOR the value 7.",
                "evidence": [
                    {
                        "kind": "registration",
                        "file": SOURCE,
                        "start_line": 12,
                        "end_line": 12,
                        "text": "baseFuncs_[static_cast<uint32_t>(MedicalCode::ENABLE_SENSOR)] = &MedicalServiceStub::EnableSensor;",
                    },
                    {
                        "kind": "constant_definition",
                        "file": HEADER,
                        "start_line": 2,
                        "end_line": 2,
                        "text": "ENABLE_SENSOR = 7,",
                    },
                ],
            }
        ],
    }
    errors: list[str] = []
    parsed = parse_dispatch_review_response(
        json.dumps(response),
        valid_case_ids={item["case_id"]},
        on_error=errors.append,
    )
    validated = validate_dispatch_review(parsed, worklist)

    assert errors == []
    assert len(validated["accepted"]) == 1
    accepted = validated["accepted"][0]
    assert accepted["value"] == 7
    assert accepted["resolution_status"] == "llm_verified"
    assert validated["advisory"] == []
    assert validated["kept_unresolved"] == []
    assert validated["rejected"] == []


def test_unknown_case_and_untrusted_evidence_are_rejected():
    worklist = _worklist()
    response = {
        "schema_version": 1,
        "decisions": [
            {
                "case_id": "missing-case",
                "decision": "resolve",
                "value_kind": "integer",
                "value": 99,
                "symbol": "UNKNOWN",
                "confidence": "high",
                "reason": "hallucinated",
                "evidence": [],
            },
            {
                "case_id": worklist[0]["case_id"],
                "decision": "resolve",
                "value_kind": "integer",
                "value": 99,
                "symbol": "MedicalCode::ENABLE_SENSOR",
                "confidence": "high",
                "reason": "not backed by the supplied source",
                "evidence": [
                    {
                        "kind": "constant_definition",
                        "file": "other.cpp",
                        "start_line": 1,
                        "end_line": 1,
                        "text": "ENABLE_SENSOR = 99",
                    }
                ],
            },
        ],
    }
    errors: list[str] = []
    parsed = parse_dispatch_review_response(
        json.dumps(response),
        valid_case_ids={worklist[0]["case_id"]},
        on_error=errors.append,
    )
    validated = validate_dispatch_review(parsed, worklist)

    assert any("unknown case_id" in error for error in errors)
    assert len(validated["rejected"]) == 1
    assert validated["rejected"][0]["rejection_reason"] == "evidence_not_in_context"


def test_runner_retries_malformed_response_without_mutating_evidence():
    evidence = _evidence()
    before = copy.deepcopy(evidence)
    worklist = _worklist()
    responses: list[str] = []

    def completion(prompt: str) -> str:
        responses.append(prompt)
        if len(responses) == 1:
            return "not-json"
        marker = '"case_id": "'
        start = prompt.rindex(marker) + len(marker)
        case_id = prompt[start : prompt.index('"', start)]
        return json.dumps(
            {
                "schema_version": 1,
                "decisions": [
                    {
                        "case_id": case_id,
                        "decision": "keep_unresolved",
                        "value_kind": "unknown",
                        "value": None,
                        "symbol": "",
                        "confidence": "medium",
                        "reason": "The model declines to guess.",
                        "evidence": [],
                    }
                ],
            }
        )

    report = run_dispatch_review(
        evidence,
        functions=_functions(),
        source_files=_source_files(),
        completion=completion,
        max_cases=-1,
        max_retries=1,
        retry_backoff_seconds=0,
    )

    assert evidence == before
    assert report["status"] == "complete"
    assert report["summary"]["attempts"] == 2
    assert report["summary"]["accepted"] == 0
    assert report["summary"]["kept_unresolved"] == 1
    assert report["errors"]


def test_empty_worklist_does_not_call_model():
    calls: list[str] = []

    def completion(_prompt: str) -> str:
        calls.append("called")
        raise AssertionError("empty worklist must not call the model")

    report = run_dispatch_review(
        {"sites": []},
        completion=completion,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "no_cases"
    assert report["summary"]["llm_calls"] == 0
    assert calls == []
