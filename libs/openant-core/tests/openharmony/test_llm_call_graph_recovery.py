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
    classify_recovery_site,
    parse_recovery_response,
    run_recovery_review,
    validate_recovery_proposals,
)
from core.platforms.openharmony.llm_call_graph_recovery import (  # noqa: E402
    _partition_worklist,
)


SOURCE = "services/network/net_stub.cpp"
CALLER = f"{SOURCE}:NetStub::OnRemoteRequest"
HANDLER = f"{SOURCE}:NetStub::HandleRequest"
OTHER = f"{SOURCE}:NetStub::OtherRequest"
BACKGROUND = f"{SOURCE}:NetStub::Background"
CALLER_ALIAS = f"{SOURCE}:OHOS.NetStub"


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
        CALLER_ALIAS: {
            "name": "OHOS.NetStub",
            "file_path": SOURCE,
            "start_line": 10,
            "end_line": 20,
            "class_name": "NetStub",
            "code": "int32_t OHOS::NetStub::OnRemoteRequest(uint32_t code) { return 0; }",
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


def test_worklist_can_attach_cross_function_registration_context(tmp_path: Path):
    source = tmp_path / SOURCE
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            [
                "void NetStub::Initialize() {",
                "    requestTable[1] = &NetStub::HandleRequest;",
                "}",
                "int32_t NetStub::OnRemoteRequest(uint32_t code)",
                "{",
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
                "line": 6,
                "expression": "return (this->*requestFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"dispatch_table": "requestTable", "target_variable": "requestFunc"},
                "candidate_target_ids": [HANDLER],
            }
        ],
    }

    worklist = build_recovery_worklist(
        diagnostics,
        _functions(),
        max_sites=-1,
        include_candidate_sites=True,
        include_registration_context=True,
        registration_context_max_chars=4_000,
    )

    assert len(worklist) == 1
    context = worklist[0]["registration_context"]
    assert context["status"] == "found"
    combined = "\n".join(item["text"] for item in context["snippets"])
    assert "requestTable[1] = &NetStub::HandleRequest;" in combined
    prompt = build_recovery_prompt(worklist)
    assert '"registration_context"' in prompt
    assert '"line_numbered_text"' in prompt
    assert "requestTable[1] = &NetStub::HandleRequest;" in prompt


def test_worklist_preserves_parser_registration_evidence_for_candidate_review():
    diagnostics = _diagnostics()
    diagnostics["unresolved_call_sites"][1]["candidates"] = [
        {
            "target_id": HANDLER,
            "target_name": "NetStub::HandleRequest",
            "selector": "REQUEST_HANDLE",
            "value_kind": "member_function_pointer",
            "registration_owner_function_id": CALLER,
            "owner_class": "NetStub",
            "evidence": {
                "file": SOURCE,
                "start_line": 18,
                "end_line": 18,
                "text": "memberFuncMap_[REQUEST_HANDLE] = &NetStub::HandleRequest",
            },
        }
    ]

    worklist = build_recovery_worklist(
        diagnostics,
        _functions(),
        max_sites=-1,
        include_candidate_sites=True,
    )

    candidate_item = next(
        item for item in worklist if item["candidate_target_ids"]
    )
    registrations = candidate_item["candidate_registrations"]
    assert registrations == [
        {
            "target_id": HANDLER,
            "target_name": "NetStub::HandleRequest",
            "selector": "REQUEST_HANDLE",
            "value_kind": "member_function_pointer",
            "registration_form": "",
            "owner_class": "NetStub",
            "registration_owner_function_id": CALLER,
            "permissions": [],
            "registration_evidence": {
                "file": SOURCE,
                "start_line": 18,
                "end_line": 18,
                "text": "memberFuncMap_[REQUEST_HANDLE] = &NetStub::HandleRequest",
            },
        }
    ]
    prompt = build_recovery_prompt([candidate_item])
    assert "candidate_registrations" in prompt
    assert "REQUEST_HANDLE" in prompt


def test_registration_context_is_opt_in_for_direct_worklist_call():
    worklist = build_recovery_worklist(
        _diagnostics(),
        _functions(),
        max_sites=1,
    )

    assert "registration_context" not in worklist[0]


def test_worklist_attaches_bounded_known_graph_neighbors():
    diagnostics = _diagnostics()
    call_graph = {
        CALLER: [HANDLER, OTHER, BACKGROUND],
        BACKGROUND: [CALLER],
    }
    worklist = build_recovery_worklist(
        diagnostics,
        _functions(),
        max_sites=1,
        call_graph=call_graph,
        graph_context_neighbors=2,
        graph_context_code_bytes=40,
    )

    graph_context = worklist[0]["graph_context"]
    assert [item["function_id"] for item in graph_context["direct_callees"]] == [
        BACKGROUND,
        HANDLER,
    ]
    assert [item["function_id"] for item in graph_context["direct_callers"]] == [
        BACKGROUND,
    ]
    assert all(len(item["code"]) <= 40 for item in graph_context["direct_callees"])
    prompt = build_recovery_prompt(worklist)
    assert "graph_context" in prompt
    assert HANDLER in prompt


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


def test_parser_rejects_multiline_evidence_text():
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
                "decision": "keep_unresolved",
                "target_id": "",
                "confidence": "low",
                "reason": "The source is ambiguous.",
                "evidence": [
                    {
                        "kind": "call_site",
                        "file": SOURCE,
                        "start_line": 12,
                        "end_line": 13,
                        "text": "line one\nline two",
                    }
                ],
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

    assert parsed == []
    assert any("evidence.text must be single-line" in message for message in errors)


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


def test_worklist_deduplicates_same_source_span_and_keeps_all_callers():
    diagnostics = {
        "unresolved_call_sites": [
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 12,
                "expression": "return (this->*requestFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"target_variable": "requestFunc"},
                "candidate_target_ids": [],
            },
            {
                "caller_id": CALLER_ALIAS,
                "file": SOURCE,
                "line": 12,
                "expression": "return (this->*requestFunc)(data, reply);",
                "reason": "same_span_from_second_parser",
                "symbols": {
                    "target_variable": "requestFunc",
                    "dispatch_table": "handlers_",
                },
                "candidate_target_ids": [],
            },
        ]
    }

    first = build_recovery_worklist(diagnostics, _functions(), max_sites=-1)
    reversed_diagnostics = {
        "unresolved_call_sites": list(reversed(diagnostics["unresolved_call_sites"]))
    }
    second = build_recovery_worklist(
        reversed_diagnostics, _functions(), max_sites=-1
    )

    assert len(first) == 1
    assert first[0]["duplicate_count"] == 2
    assert set(first[0]["caller_ids"]) == {CALLER, CALLER_ALIAS}
    assert first[0]["symbols"]["dispatch_table"] == "handlers_"
    assert first[0]["site_id"] == second[0]["site_id"]


def test_site_classification_separates_local_template_and_external_calls():
    local = classify_recovery_site(
        {
            "expression": "iter->second(args)",
            "reason": "lookup_derived_callable",
            "symbols": {"dispatch_table": "handlers_"},
        },
        {
            "name": "AudioEngine::Invoke",
            "code": "void *handle = dlsym(nullptr, \"unrelated\"); auto it = handlers_.find(cmd); if (it != handlers_.end()) it->second(args);",
        },
    )
    template = classify_recovery_site(
        {
            "expression": "(modulePtr.get()->*(_moduleFunc))(args...)",
            "reason": "parenthesized_member_function_pointer",
        },
        {
            "name": "TelRilCallback::Execute",
            "code": "template<typename ModuleFuncType> return (modulePtr.get()->*(_moduleFunc))(args...);",
        },
    )
    callback = classify_recovery_site(
        {
            "expression": "(*cacheCallback)(event)",
            "reason": "parenthesized_function_pointer",
        },
        {
            "name": "TaiheAudioCallback::SafeJsCallbackWork",
            "code": "std::shared_ptr<taihe::callback<void(Event)>> cacheCallback; (*cacheCallback)(event);",
        },
    )
    dynamic = classify_recovery_site(
        {
            "expression": "(*initParam)(processName)",
            "reason": "parenthesized_function_pointer",
        },
        {
            "name": "InitDebugParams",
            "code": 'void *handle = dlopen(path, RTLD_LAZY); dlsym(handle, "InitEnvironmentParam");',
        },
    )
    external_interface = classify_recovery_site(
        {
            "expression": "(rilInterface->*(_func))(slotId, serial)",
            "reason": "parenthesized_member_function_pointer",
        },
        {
            "name": "TelRilBase::Execute",
            "code": "return (rilInterface->*(_func))(slotId, serial);",
        },
    )

    assert local["kind"] == "local_dispatch"
    assert local["analysis_route"] == "deterministic"
    assert template["kind"] == "template_dispatch"
    assert template["analysis_route"] == "deterministic"
    assert callback["kind"] == "external_callback"
    assert callback["analysis_route"] == "external_boundary"
    assert callback["llm_eligible"] is False
    assert dynamic["kind"] == "external_dynamic_symbol"
    assert dynamic["analysis_route"] == "external_boundary"
    assert dynamic["llm_eligible"] is False
    assert external_interface["kind"] == "external_interface"
    assert external_interface["analysis_route"] == "external_boundary"
    assert external_interface["llm_eligible"] is False


def test_partition_splits_large_candidate_site_without_prompt_truncation():
    candidates = [
        {
            "function_id": f"{SOURCE}:NetStub::Handler{index}",
            "name": f"NetStub::Handler{index}",
            "file_path": SOURCE,
            "start_line": index + 100,
            "end_line": index + 110,
            "class_name": "NetStub",
            "code": "int32_t Handler(MessageParcel &, MessageParcel &) { return 0; }",
        }
        for index in range(60)
    ]
    item = {
        "site_id": "native:12:large",
        "source": "native",
        "caller_id": CALLER,
        "caller_ids": [CALLER],
        "caller": _functions()[CALLER],
        "file": SOURCE,
        "line": 12,
        "expression": "return (this->*requestFunc)(data, reply);",
        "reason": "parenthesized_member_function_pointer",
        "symbols": {"target_variable": "requestFunc"},
        "candidate_target_ids": [candidate["function_id"] for candidate in candidates],
        "candidate_count": len(candidates),
        "retrieval_candidates": candidates,
    }

    batches = _partition_worklist(
        [item],
        max_prompt_chars=80_000,
        max_sites_per_request=6,
        max_candidates_per_request=24,
    )

    assert len(batches) == 3
    assert sum(len(batch[0]["candidate_target_ids"]) for batch in batches) == 60
    assert all(
        len(build_recovery_prompt(batch, max_prompt_chars=80_000)) <= 80_000
        for batch in batches
    )


def test_item_level_invalid_decision_keeps_valid_subset_without_retry():
    functions = _functions()
    diagnostics = _diagnostics()
    worklist = build_recovery_worklist(diagnostics, functions, max_sites=1)
    site_id = worklist[0]["site_id"]
    calls = []

    def completion(_prompt: str) -> str:
        calls.append(1)
        return json.dumps(
            {
                "schema_version": 1,
                "decisions": [
                    {
                        "site_id": site_id,
                        "decision": "keep_unresolved",
                        "target_id": "",
                        "confidence": "medium",
                        "reason": "The callback target is not proven.",
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
                        "site_id": "unknown:1:site",
                        "decision": "keep_unresolved",
                        "target_id": "",
                        "confidence": "low",
                        "reason": "Unknown site should be ignored.",
                        "evidence": [
                            {
                                "kind": "call_site",
                                "file": SOURCE,
                                "start_line": 12,
                                "end_line": 12,
                                "text": "unknown()",
                            }
                        ],
                    },
                ],
            }
        )

    result = run_recovery_review(
        diagnostics,
        functions,
        completion=completion,
        max_sites=1,
        max_retries=2,
    )

    assert calls == [1]
    assert result["status"] == "partial"
    assert result["summary"]["retry_count"] == 0
    assert result["summary"]["kept_unresolved"] == 1


def test_run_batches_keep_all_candidate_edges_and_never_send_truncated_json():
    functions = _functions()
    candidates = []
    for index in range(30):
        target_id = f"{SOURCE}:NetStub::GeneratedHandler{index}"
        functions[target_id] = {
            "name": f"NetStub::GeneratedHandler{index}",
            "file_path": SOURCE,
            "start_line": 100 + index,
            "end_line": 105 + index,
            "class_name": "NetStub",
            "code": "int32_t GeneratedHandler(MessageParcel &, MessageParcel &) { return 0; }",
        }
        candidates.append(
            {
                "target_id": target_id,
                "target_name": f"NetStub::GeneratedHandler{index}",
                "selector": f"REQUEST_{index}",
                "value_kind": "member_function_pointer",
                "evidence": {
                    "file": SOURCE,
                    "start_line": 20 + index,
                    "end_line": 20 + index,
                    "text": f"requestTable[REQUEST_{index}] = &GeneratedHandler{index};",
                },
            }
        )
    diagnostics = {
        "unresolved_call_sites": [
            {
                "caller_id": CALLER,
                "file": SOURCE,
                "line": 12,
                "expression": "return (this->*requestFunc)(data, reply);",
                "reason": "parenthesized_member_function_pointer",
                "symbols": {"target_variable": "requestFunc"},
                "candidate_target_ids": [item["target_id"] for item in candidates],
                "candidates": candidates,
            }
        ]
    }
    calls = []

    def completion(prompt: str) -> str:
        calls.append(prompt)
        opening = re.search(r"\n(`+)json\n", prompt)
        assert opening is not None
        fence = opening.group(1)
        body_start = opening.end()
        body_end = prompt.find(f"\n{fence}\n", body_start)
        assert body_end > body_start
        payload = json.loads(prompt[body_start:body_end])
        decisions = []
        for site in payload["sites"]:
            for candidate in site.get("candidate_registrations", []):
                evidence = candidate["registration_evidence"]
                decisions.append(
                    {
                        "site_id": site["site_id"],
                        "decision": "add_edge",
                        "target_id": candidate["target_id"],
                        "confidence": "high",
                        "reason": "The parser supplied a source-backed registration.",
                        "evidence": [
                            {
                                "kind": "call_site",
                                "file": site["file"],
                                "start_line": site["line"],
                                "end_line": site["line"],
                                "text": site["expression"],
                            },
                            {
                                "kind": "registration",
                                "file": evidence["file"],
                                "start_line": evidence["start_line"],
                                "end_line": evidence["end_line"],
                                "text": evidence["text"].splitlines()[0],
                            },
                        ],
                    }
                )
        return json.dumps({"schema_version": 1, "decisions": decisions})

    result = run_recovery_review(
        diagnostics,
        functions,
        completion=completion,
        include_candidate_sites=True,
        max_sites=-1,
        max_candidates_per_request=10,
        max_prompt_chars=20_000,
        max_retries=0,
    )

    assert result["status"] == "complete"
    assert len(calls) == 3
    assert result["summary"]["request_batches"] == 3
    assert result["summary"]["accepted"] == 30
    assert result["summary"]["unreviewed_sites"] == 0
