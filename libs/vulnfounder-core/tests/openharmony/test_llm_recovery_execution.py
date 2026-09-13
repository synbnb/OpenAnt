"""Tests for the isolated OpenHarmony LLM recovery execution wrapper."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.llm_call_graph_recovery import (  # noqa: E402
    run_recovery_review,
)


SOURCE = "services/network/net_stub.cpp"
CALLER = f"{SOURCE}:NetStub::OnRemoteRequest"
TARGET = f"{SOURCE}:NetStub::HandleRequest"


def _functions() -> dict[str, dict]:
    return {
        CALLER: {
            "name": "NetStub::OnRemoteRequest",
            "file_path": SOURCE,
            "start_line": 10,
            "end_line": 20,
            "class_name": "NetStub",
            "code": "int32_t NetStub::OnRemoteRequest() { return (this->*handler)(data); }",
        },
        TARGET: {
            "name": "NetStub::HandleRequest",
            "file_path": SOURCE,
            "start_line": 30,
            "end_line": 35,
            "class_name": "NetStub",
            "code": "int32_t NetStub::HandleRequest(MessageParcel &data) { return 0; }",
        },
    }


def _diagnostics() -> dict:
    return {
        "unresolved_call_sites": [
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 12,
                "expression": "return (this->*handler)(data);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"target_variable": "handler"},
                "candidate_target_ids": [],
            }
        ]
    }


def _valid_response(site_id: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "decisions": [
                {
                    "site_id": site_id,
                    "decision": "add_edge",
                    "target_id": TARGET,
                    "confidence": "high",
                    "reason": "The member-function pointer is resolved to the indexed handler.",
                    "evidence": [
                        {
                            "kind": "call_site",
                            "file": SOURCE,
                            "start_line": 12,
                            "end_line": 12,
                            "text": "(this->*handler)(data)",
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
            ],
        }
    )


def test_empty_worklist_skips_model_without_side_effects():
    calls: list[str] = []

    def completion(_prompt: str) -> str:
        calls.append("called")
        raise AssertionError("empty worklist must not invoke the model")

    diagnostics = {"unresolved_call_sites": []}
    report = run_recovery_review(
        diagnostics,
        {},
        completion=completion,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "no_sites"
    assert report["summary"]["worklist_sites"] == 0
    assert report["summary"]["llm_calls"] == 0
    assert report["summary"]["attempts"] == 0
    assert calls == []


def test_review_runner_passes_registration_context_to_completion(tmp_path: Path):
    source = tmp_path / SOURCE
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            [
                "void NetStub::Initialize() {",
                "    requestTable[1] = &NetStub::HandleRequest;",
                "}",
                "int32_t NetStub::OnRemoteRequest(uint32_t code) {",
                "    return (this->*requestFunc)(data, reply);",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    diagnostics = {
        "repository": str(tmp_path),
        "unresolved_call_sites": [
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 5,
                "expression": "return (this->*requestFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"dispatch_table": "requestTable"},
                "candidate_target_ids": [TARGET],
            }
        ],
    }
    prompts: list[str] = []

    def completion(prompt: str) -> str:
        prompts.append(prompt)
        marker = '"site_id": "'
        start = prompt.rindex(marker) + len(marker)
        site_id = prompt[start : prompt.index('"', start)]
        return json.dumps(
            {
                "schema_version": 1,
                "decisions": [
                    {
                        "site_id": site_id,
                        "decision": "keep_unresolved",
                        "target_id": "",
                        "confidence": "low",
                        "reason": "test keeps the advisory edge unresolved",
                        "evidence": [
                            {
                                "kind": "call_site",
                                "file": SOURCE,
                                "start_line": 5,
                                "end_line": 5,
                                "text": "(this->*requestFunc)(data, reply)",
                            }
                        ],
                    }
                ],
            }
        )

    report = run_recovery_review(
        diagnostics,
        _functions(),
        completion=completion,
        include_candidate_sites=True,
        max_retries=0,
        retry_backoff_seconds=0,
    )

    assert report["status"] == "complete"
    assert report["worklist"][0]["registration_context"]["status"] == "found"
    assert "requestTable[1] = &NetStub::HandleRequest;" in prompts[0]


def test_malformed_first_response_is_retried_and_known_edge_is_accepted():
    diagnostics = _diagnostics()
    before = copy.deepcopy(diagnostics)
    responses: list[str] = []

    def completion(prompt: str) -> str:
        responses.append(prompt)
        if len(responses) == 1:
            return "not-json"
        # The execution wrapper must build the site ID from the same worklist
        # it supplied to the model; the test obtains it from the prompt-free
        # callback contract by returning a response after inspecting the
        # serialized site marker embedded in the prompt.
        marker = '"site_id": "'
        start = prompt.rindex(marker) + len(marker)
        site_id = prompt[start : prompt.index('"', start)]
        return _valid_response(site_id)

    report = run_recovery_review(
        diagnostics,
        _functions(),
        completion=completion,
        max_retries=2,
        retry_backoff_seconds=0,
        max_shortlist=2,
    )

    assert diagnostics == before
    assert report["status"] == "complete"
    assert report["summary"]["attempts"] == 2
    assert report["summary"]["llm_calls"] == 2
    assert report["summary"]["retry_count"] == 1
    assert report["summary"]["accepted"] == 1
    assert report["validation"]["accepted"][0]["target_id"] == TARGET
    assert report["errors"]
    assert "上一轮响应未通过严格 JSON 校验" in responses[1]
    assert [item["status"] for item in report["response_diagnostics"]] == [
        "invalid",
        "valid",
    ]
    assert report["response_diagnostics"][0]["response"]["response_chars"] == len(
        "not-json"
    )
    assert "response" in report["errors"][0]


def test_transport_failures_stop_after_retry_budget_and_keep_graph_advisory():
    diagnostics = _diagnostics()
    before = copy.deepcopy(diagnostics)
    calls: list[str] = []

    def completion(_prompt: str) -> str:
        calls.append("called")
        raise TimeoutError("provider timed out")

    report = run_recovery_review(
        diagnostics,
        _functions(),
        completion=completion,
        max_retries=2,
        retry_backoff_seconds=0,
    )

    assert diagnostics == before
    assert report["status"] == "failed"
    assert report["summary"]["attempts"] == 3
    assert report["summary"]["llm_calls"] == 3
    assert report["summary"]["retry_count"] == 2
    assert report["summary"]["accepted"] == 0
    assert len(calls) == 3
    assert all(error["type"] == "TimeoutError" for error in report["errors"])
