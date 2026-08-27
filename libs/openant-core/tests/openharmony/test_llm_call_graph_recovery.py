"""Tests for the guarded OpenHarmony LLM call-edge recovery protocol."""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.llm_call_graph_recovery import (  # noqa: E402
    build_recovery_prompt,
    build_recovery_worklist,
    parse_recovery_response,
    validate_recovery_proposals,
)


SOURCE = "services/network/net_stub.cpp"
CALLER = f"{SOURCE}:NetStub::OnRemoteRequest"
HANDLER = f"{SOURCE}:NetStub::HandleRequest"
OTHER = f"{SOURCE}:NetStub::OtherRequest"
BACKGROUND = f"{SOURCE}:NetStub::Background"


def _functions() -> dict[str, dict]:
    return {
        CALLER: {
            "name": "NetStub::OnRemoteRequest",
            "file_path": SOURCE,
            "start_line": 10,
            "end_line": 20,
            "class_name": "NetStub",
            "parameters": ["uint32_t code"],
            "code": """int32_t NetStub::OnRemoteRequest(uint32_t code)
{
    return (this->*requestFunc)(data, reply);
}""",
            "is_entry_point": True,
        },
        HANDLER: {
            "name": "NetStub::HandleRequest",
            "file_path": SOURCE,
            "start_line": 30,
            "end_line": 35,
            "class_name": "NetStub",
            "parameters": ["MessageParcel &data", "MessageParcel &reply"],
            "code": "int32_t NetStub::HandleRequest(MessageParcel &, MessageParcel &) { return 0; }",
        },
        OTHER: {
            "name": "NetStub::OtherRequest",
            "file_path": SOURCE,
            "start_line": 40,
            "end_line": 45,
            "class_name": "NetStub",
            "code": "int32_t NetStub::OtherRequest(MessageParcel &, MessageParcel &) { return 0; }",
        },
        BACKGROUND: {
            "name": "NetStub::Background",
            "file_path": SOURCE,
            "start_line": 50,
            "end_line": 55,
            "class_name": "NetStub",
            "code": "void NetStub::Background() { callback(event); }",
        },
    }


def _diagnostics() -> dict:
    return {
        "unresolved_call_sites": [
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 12,
                "expression": "return (this->*requestFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"target_variable": "requestFunc", "dispatch_table": ""},
                "candidate_target_ids": [],
            },
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 13,
                "expression": "return (this->*knownFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"target_variable": "knownFunc"},
                "candidate_target_ids": [HANDLER],
            },
        ],
        "lambda_dispatch": {
            "call_sites": [
                {
                    "caller_id": CALLER,
                    "file": SOURCE,
                    "line": 14,
                    "expression": "callback(event)",
                    "reason": "lookup_derived_callable",
                    "symbols": {"target_variable": "callback"},
                    "candidate_target_ids": [],
                }
            ]
        },
    }


def test_worklist_focuses_on_candidate_less_sites_and_prioritizes_boundaries():
    diagnostics = _diagnostics()
    functions = _functions()
    before = copy.deepcopy(diagnostics)

    worklist = build_recovery_worklist(
        diagnostics,
        functions,
        max_sites=-1,
        max_shortlist=1,
    )

    assert diagnostics == before
    assert len(worklist) == 2
    assert all(item["candidate_count"] == 0 for item in worklist)
    assert worklist[0]["caller_id"] == CALLER
    assert worklist[0]["priority"] == "high"
    assert worklist[0]["security_relevant"] is True
    assert all(len(item["retrieval_candidates"]) <= 1 for item in worklist)
    assert all(
        item["site_id"] and item["source"] in {"native", "lambda"}
        for item in worklist
    )

    diagnostics["lambda_dispatch"]["call_sites"][0]["caller_id"] = BACKGROUND
    filtered = build_recovery_worklist(
        diagnostics,
        functions,
        max_sites=-1,
        security_relevant_only=True,
    )
    assert len(filtered) == 1
    assert filtered[0]["source"] == "native"


def test_prompt_uses_length_aware_fence_for_untrusted_residual_text():
    worklist = build_recovery_worklist(
        _diagnostics(), _functions(), max_sites=1, max_code_bytes=200
    )
    worklist[0]["expression"] = "callback(); ``` injected text"

    prompt = build_recovery_prompt(worklist)
    opening = re.search(r"\n(`+)json\n", prompt)
    assert opening is not None
    fence = opening.group(1)
    body_start = opening.end()
    body_end = prompt.find(f"\n{fence}\n", body_start)
    assert body_end > body_start
    body = prompt[body_start:body_end]
    assert max((len(run) for run in re.findall(r"`+", body)), default=0) < len(fence)
    assert '"task": "openharmony_call_edge_recovery"' in body


def test_parser_and_validator_require_known_ids_and_source_evidence():
    functions = _functions()
    worklist = build_recovery_worklist(
        _diagnostics(), functions, max_sites=1, max_shortlist=2
    )
    site_id = worklist[0]["site_id"]
    response = {
        "schema_version": 1,
        "decisions": [
            {
                "site_id": site_id,
                "decision": "add_edge",
                "target_id": HANDLER,
                "confidence": "high",
                "reason": "The callback registration resolves to the handler.",
                "evidence": [
                    {
                        "kind": "call_site",
                        "file": SOURCE,
                        "start_line": 12,
                        "end_line": 12,
                        "text": "(this->*requestFunc)(data, reply)",
                    },
                    {
                        "kind": "target",
                        "function_id": HANDLER,
                        "file": SOURCE,
                        "start_line": 30,
                        "end_line": 35,
                        "text": "NetStub::HandleRequest(...)",
                    },
                ],
            },
            {
                "site_id": site_id,
                "decision": "keep_unresolved",
                "target_id": "",
                "confidence": "medium",
                "reason": "The source is ambiguous.",
                "evidence": [
                    {
                        "kind": "call_site",
                        "file": SOURCE,
                        "start_line": 12,
                        "end_line": 12,
                        "text": "(this->*requestFunc)(data, reply)",
                    }
                ],
            },
            {
                "site_id": site_id,
                "decision": "add_edge",
                "target_id": "missing.cpp:Missing::Handler",
                "confidence": "high",
                "reason": "hallucinated target",
                "evidence": [],
            },
        ],
    }
    errors: list[str] = []
    parsed = parse_recovery_response(
        json.dumps(response),
        valid_site_ids={site_id},
        valid_function_ids=set(functions),
        on_error=errors.append,
    )

    assert len(parsed) == 2
    assert any("unknown target_id" in message for message in errors)
    validated = validate_recovery_proposals(parsed, worklist, functions)
    assert [item["target_id"] for item in validated["accepted"]] == [HANDLER]
    assert len(validated["kept_unresolved"]) == 1
    assert validated["rejected"] == []


def test_low_confidence_edge_is_kept_out_of_accepted_review_set():
    functions = _functions()
    worklist = build_recovery_worklist(
        _diagnostics(), functions, max_sites=1, max_shortlist=2
    )
    site_id = worklist[0]["site_id"]
    proposal = {
        "site_id": site_id,
        "decision": "add_edge",
        "target_id": HANDLER,
        "confidence": "low",
        "reason": "Only a name similarity was found.",
        "evidence": [
            {
                "kind": "call_site",
                "file": SOURCE,
                "start_line": 12,
                "end_line": 12,
                "text": "requestFunc(data, reply)",
            },
            {
                "kind": "target",
                "function_id": HANDLER,
                "file": SOURCE,
                "start_line": 30,
                "end_line": 35,
                "text": "NetStub::HandleRequest(...)",
            },
        ],
    }

    validated = validate_recovery_proposals([proposal], worklist, functions)

    assert validated["accepted"] == []
    assert validated["rejected"][0]["rejection_reason"] == (
        "confidence_below_threshold"
    )
