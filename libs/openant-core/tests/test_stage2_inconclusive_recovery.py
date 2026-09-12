"""Offline regression tests for Stage-2 inconclusive evidence recovery."""

import json

from core.verifier import (
    _count_final_findings,
    _count_verification_outcomes,
    select_stage2_candidates,
)
from prompts.verification_prompts import get_verification_prompt
from utilities.llm import PhaseBinding, PhaseRegistry, TextBlock, ToolUseBlock
from utilities.llm.adapter import CompletionResult


def test_stage2_candidate_selection_includes_inconclusive_but_not_clean_units():
    results = [
        {"route_key": "v", "finding": "vulnerable"},
        {"route_key": "b", "finding": "bypassable"},
        {"route_key": "i", "finding": "inconclusive"},
        {"route_key": "p", "finding": "protected"},
        {"route_key": "s", "finding": "safe"},
        {"route_key": "e", "verdict": "ERROR"},
    ]

    selected = select_stage2_candidates(results)
    assert [r["route_key"] for r in selected] == ["v", "b", "i"]

    # Callers that explicitly retain the legacy high-risk-only policy can
    # still disable the additional evidence-recovery class.
    selected_legacy = select_stage2_candidates(results, include_inconclusive=False)
    assert [r["route_key"] for r in selected_legacy] == ["v", "b"]


def test_inconclusive_outcomes_are_counted_without_being_folded_into_safe():
    results = [
        {
            "route_key": "promoted",
            "finding": "vulnerable",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": False,
                "correct_finding": "vulnerable",
            },
        },
        {
            "route_key": "resolved",
            "finding": "protected",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": False,
                "correct_finding": "protected",
            },
        },
        {
            "route_key": "still-uncertain",
            "finding": "inconclusive",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": True,
                "correct_finding": "inconclusive",
            },
        },
        {
            "route_key": "incomplete",
            "finding": "inconclusive",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": False,
                "correct_finding": "inconclusive",
                "incomplete": True,
            },
        },
    ]

    counts = _count_verification_outcomes(results)
    assert counts["inconclusive_input"] == 4
    assert counts["inconclusive_promoted"] == 1
    assert counts["inconclusive_resolved"] == 1
    assert counts["inconclusive_remaining"] == 2
    assert counts["confirmed_vulnerabilities"] == 1
    assert counts["disagreed"] == 1  # only inconclusive -> protected
    assert counts["needs_review"] == 2

    final = _count_final_findings(results)
    assert final == {
        "vulnerable": 1,
        "bypassable": 0,
        "inconclusive": 2,
        "protected": 1,
        "safe": 0,
        "errors": 0,
    }


def test_final_counts_prioritize_verification_errors_over_stage1_finding():
    """A failed Stage-2 call must not remain counted as a finding."""
    from core.verifier import _count_final_findings

    assert _count_final_findings([{
        "route_key": "broken:unit",
        "finding": "inconclusive",
        "error": "LLMResponseError: timeout",
    }]) == {
        "vulnerable": 0,
        "bypassable": 0,
        "inconclusive": 0,
        "protected": 0,
        "safe": 0,
        "errors": 1,
    }


def test_inconclusive_verification_prompt_requests_downstream_evidence_recovery():
    prompt = get_verification_prompt(
        code="int f(const std::vector<void*> &items) { return delegate(items); }",
        finding="inconclusive",
        attack_vector="malformed input",
        reasoning="The downstream implementation was not included.",
    )

    assert "evidence-recovery review" in prompt
    assert "unresolved callee" in prompt
    assert "parameter forwarding" in prompt
    assert "first downstream use" in prompt
    assert "return INCONCLUSIVE" in prompt


class _PromotionAdapter:
    """A no-network adapter that promotes an inconclusive result."""

    name = "test"
    supports_tools = True
    pricing = {"test-model": {"input": 0.0, "output": 0.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[ToolUseBlock(
                id="finish-1",
                name="finish",
                input={
                    "agree": False,
                    "correct_finding": "vulnerable",
                    "exploit_path": {
                        "entry_point": "f",
                        "data_flow": ["f -> downstream -> front()"],
                        "sink_reached": True,
                        "attacker_control_at_sink": "partial",
                        "path_broken_at": None,
                    },
                    "explanation": "Recovered a concrete downstream path.",
                },
            )],
            input_tokens=2,
            output_tokens=2,
            stop_reason="tool_use",
        )


def test_run_verification_sends_inconclusive_to_finding_verifier(tmp_path):
    """The standard verifier path must not discard an inconclusive candidate."""
    route = "src/service.cpp:Service::f"
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps({
        "results": [
            {
                "route_key": route,
                "unit_id": route,
                "finding": "inconclusive",
                "reasoning": "The downstream implementation was not included.",
                "attack_vector": None,
            },
            {
                "route_key": "src/clean.cpp:Clean::f",
                "unit_id": "src/clean.cpp:Clean::f",
                "finding": "safe",
                "reasoning": "No security-sensitive behavior.",
            },
        ],
        "code_by_route": {route: "int Service::f() { return delegate(); }"},
    }))
    analyzer_path = tmp_path / "analyzer_output.json"
    analyzer_path.write_text(json.dumps({
        "functions": {
            route: {"name": "Service::f", "code": "int Service::f() {}", "filePath": "src/service.cpp"}
        }
    }))

    binding = PhaseBinding(
        phase="verify",
        adapter=_PromotionAdapter(),
        model="test-model",
        provider_name="test",
    )
    registry = PhaseRegistry({"verify": binding}, "test-config")

    from core.verifier import run_verification

    output_dir = tmp_path / "verify"
    result = run_verification(
        results_path=str(results_path),
        output_dir=str(output_dir),
        analyzer_output_path=str(analyzer_path),
        registry=registry,
        workers=1,
    )

    assert result.findings_input == 1
    assert result.findings_verified == 1
    assert result.inconclusive_input == 1
    assert result.inconclusive_promoted == 1
    assert result.inconclusive_resolved == 0
    assert result.inconclusive_remaining == 0
    assert result.final_counts["vulnerable"] == 1
    assert result.final_counts["safe"] == 1

    written = json.loads((output_dir / "results_verified.json").read_text())
    promoted = next(r for r in written["results"] if r["route_key"] == route)
    assert promoted["finding"] == "vulnerable"
    assert promoted["verification"]["stage1_finding"] == "inconclusive"
    assert written["review_findings"] == []


def test_report_keeps_inconclusive_promotion_disclosure_eligible(tmp_path):
    """A Stage-2 promotion must not be mislabeled as a rejected finding."""
    from core.reporter import build_pipeline_output

    route = "src/service.cpp:Service::f"
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps({
        "results": [{
            "route_key": route,
            "unit_id": route,
            "finding": "vulnerable",
            "verdict": "VULNERABLE",
            "reasoning": "Recovered a downstream null dereference.",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": False,
                "correct_finding": "vulnerable",
                "exploit_path": {
                    "sink_reached": True,
                    "attacker_control_at_sink": "partial",
                    "path_broken_at": None,
                },
            },
        }],
        "confirmed_findings": [{
            "route_key": route,
            "unit_id": route,
            "finding": "vulnerable",
            "verdict": "VULNERABLE",
            "reasoning": "Recovered a downstream null dereference.",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": False,
                "correct_finding": "vulnerable",
                "exploit_path": {
                    "sink_reached": True,
                    "attacker_control_at_sink": "partial",
                    "path_broken_at": None,
                },
            },
        }],
        "code_by_route": {route: "int Service::f() { return delegate(); }"},
        "metrics": {"total": 1, "vulnerable": 1},
    }))
    output_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(str(results_path), str(output_path), language="cpp")
    data = json.loads(output_path.read_text())

    assert len(data["findings"]) == 1
    assert data["findings"][0]["stage2_verdict"] == "confirmed"


def test_stage2_prompt_exposes_route_and_non_binder_recovery_tools():
    prompt = get_verification_prompt(
        code="int handle(const char *msg) { return dispatch(msg); }",
        finding="inconclusive",
        attack_vector="socket message",
        reasoning="The receiver was not included in Stage 1.",
        files_included="services/socket.cpp",
        route="services/socket.cpp:Service::handle",
    )

    assert "Target route: services/socket.cpp:Service::handle" in prompt
    assert "Files included in Stage-1 context: services/socket.cpp" in prompt
    assert "Unix/TCP/UDP Socket" in prompt
    assert "get_static_dependencies" in prompt
    assert "assessment.missing_evidence" in prompt


def test_stage2_prompt_requires_boundary_specific_route_evidence_for_socket_cli_and_events():
    """Stage 2 must distinguish an inbound route from a generic API mention."""
    prompt = get_verification_prompt(
        code="int handle(int argc, char **argv) { return dispatch(argv[1]); }",
        finding="inconclusive",
        attack_vector="command or socket input",
        reasoning="The original context omitted the receiver details.",
        route="src/handler.cpp:Service::handle",
    )

    assert "boundary_type" in prompt
    assert "direction" in prompt
    assert "registration/listener" in prompt
    assert "source-backed" in prompt
    assert "CLI" in prompt or "argc/argv" in prompt
    assert "event callback" in prompt or "callback" in prompt
    assert "outbound" in prompt


def test_stage2_parser_normalizes_boundary_route_evidence_aliases():
    """Aliases from different models must converge on auditable route fields."""
    from utilities.finding_verifier import FindingVerifier

    verifier = FindingVerifier.__new__(FindingVerifier)
    parsed = verifier._parse_finish_result({
        "agree": False,
        "correct_finding": "vulnerable",
        "assessment": {
            "defect_status": "confirmed",
            "reachability_status": "conditional",
            "impact_status": "plausible",
            "evidence_completeness": "partial",
            "boundary_type": "event callback",
            "direction": "receive",
            "source_evidence_status": "source-backed",
            "registration_evidence": ["RegisterCallback at event.cpp:12"],
            "input_relation": "confirmed",
            "missing_evidence": ["deployment ACL"],
        },
        "exploit_path": {
            "entry_point": "event.cpp:RegisterCallback",
            "data_flow": ["event -> callback -> sink"],
            "sink_reached": True,
            "attacker_control_at_sink": "partial",
        },
        "explanation": "The callback route is source-backed but deployment is conditional.",
    }, "inconclusive", 1, 2)

    assert parsed.assessment["boundary_type"] == "callback"
    assert parsed.assessment["direction"] == "inbound"
    assert parsed.assessment["source_evidence_status"] == "confirmed"
    assert parsed.assessment["input_relation"] == "confirmed"
    assert parsed.assessment["registration_evidence"] == ["RegisterCallback at event.cpp:12"]


def test_stage2_parser_normalizes_composite_socket_and_event_labels():
    from utilities.finding_verifier import FindingVerifier

    verifier = FindingVerifier.__new__(FindingVerifier)
    for raw, expected in (
        ("local Unix SOCK_SEQPACKET service socket", "unix_socket"),
        ("tcp/udp_loopback_socket", "tcp_udp_socket"),
        ("tcp/udp", "tcp_udp_socket"),
        ("event callback / device-facing event ingestion", "callback"),
        ("local inbound socket / IPC message boundary", "socket"),
    ):
        parsed = verifier._parse_finish_result({
            "agree": True,
            "correct_finding": "inconclusive",
            "assessment": {"boundary_type": raw},
            "explanation": "route label only",
        }, "inconclusive", 1, 1)
        assert parsed.assessment["boundary_type"] == expected


def test_stage2_parser_accepts_flattened_assessment_and_bounds_finish_data():
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.finding_verifier import FindingVerifier

    verifier = FindingVerifier.__new__(FindingVerifier)
    parsed = verifier._parse_finish_result({
        "agree": "false",
        "correct_finding": "INCONCLUSIVE",
        "defect_status": "confirmed",
        "reachability_status": "conditional",
        "impact_status": "plausible",
        "evidence_completeness": "partial",
        "boundary_type": "unix_socket",
        "missing_evidence": ["receiver"] * 30,
        "confidence": 0.8,
        "exploit_path": {
            "entry_point": "accept",
            "data_flow": ["x"] * 30,
            "sink_reached": "true",
            "attacker_control_at_sink": "partial",
        },
        "explanation": {"not": "a string"},
    }, "vulnerable", 1, 2)

    assert parsed.agree is False
    assert parsed.correct_finding == "inconclusive"
    assert parsed.incomplete is False
    assert parsed.assessment["boundary_type"] == "unix_socket"
    assert len(parsed.assessment["missing_evidence"]) == 12
    assert len(parsed.exploit_path.data_flow) == 24
    assert parsed.exploit_path.sink_reached is True
    assert parsed.explanation.startswith("{")

    malformed = verifier._parse_finish_result({
        "agree": True,
        "correct_finding": "not-a-verdict",
        "explanation": "malformed verdict",
    }, "vulnerable", 1, 2)
    assert malformed.agree is False
    assert malformed.incomplete is True
    assert malformed.correct_finding == "vulnerable"


def test_repository_index_exposes_native_graph_to_static_dependency_tool():
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.agentic_enhancer.tools import ToolExecutor

    target = "src/service.cpp:Service::handle"
    callee = "src/service.cpp:Service::delegate"
    caller = "src/stub.cpp:Stub::OnRequest"
    index = RepositoryIndex({
        "functions": {
            target: {"name": "Service::handle", "code": "return delegate();"},
            callee: {"name": "Service::delegate", "code": "return 0;"},
            caller: {"name": "Stub::OnRequest", "code": "return handle();"},
        },
        "call_graph": {f"function:{target}": [f"function:{callee}"]},
        "reverse_call_graph": {target: [caller]},
    })
    executor = ToolExecutor(index)
    executor.set_unit_context(index.call_graph[target], index.reverse_call_graph[target], target)
    result = executor.execute("get_static_dependencies", {})
    assert result["target_route"] == target
    assert result["dependencies"]["resolved"][0]["id"] == callee
    assert result["callers"]["resolved"][0]["id"] == caller


def test_repository_index_accepts_python_camelcase_graph_keys():
    from utilities.agentic_enhancer.repository_index import RepositoryIndex

    target = "src/service.py:handle"
    callee = "src/service.py:delegate"
    caller = "src/stub.py:on_request"
    index = RepositoryIndex({
        "functions": {
            target: {"name": "handle", "code": "return delegate()"},
            callee: {"name": "delegate", "code": "return 0"},
            caller: {"name": "on_request", "code": "return handle()"},
        },
        "callGraph": {target: [callee]},
        "reverseCallGraph": {target: [caller]},
    })

    assert index.get_call_graph_context(target) == {
        "function_id": target,
        "callees": [callee],
        "callers": [caller],
    }


def test_unverified_stage2_agreement_is_not_reported_as_completed_agreement(tmp_path):
    """agree=True + correct_finding=inconclusive must stay explicitly unverified."""
    from core.reporter import build_pipeline_output

    route = "src/socket.cpp:Service::handle"
    write = {
        "results": [{
            "route_key": route,
            "unit_id": route,
            "finding": "inconclusive",
            "verdict": "INCONCLUSIVE",
            "reasoning": "The receiver is outside the first context.",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": True,
                "correct_finding": "inconclusive",
                "assessment": {
                    "defect_status": "confirmed",
                    "reachability_status": "unknown",
                    "impact_status": "plausible",
                    "evidence_completeness": "partial",
                    "boundary_type": "unix_socket",
                    "missing_evidence": ["receiver implementation"],
                },
            },
        }],
        "confirmed_findings": [],
        "review_findings": [{
            "route_key": route,
            "unit_id": route,
            "finding": "inconclusive",
            "verification": {
                "stage1_finding": "inconclusive",
                "agree": True,
                "correct_finding": "inconclusive",
                "assessment": {
                    "defect_status": "confirmed",
                    "reachability_status": "unknown",
                    "impact_status": "plausible",
                    "evidence_completeness": "partial",
                    "boundary_type": "unix_socket",
                    "missing_evidence": ["receiver implementation"],
                },
            },
        }],
        "code_by_route": {route: "int handle(const char *msg) { return dispatch(msg); }"},
        "metrics": {"total": 1, "inconclusive": 1},
    }
    results_path = tmp_path / "results_verified.json"
    results_path.write_text(json.dumps(write), encoding="utf-8")
    output_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(str(results_path), str(output_path), language="cpp")
    data = json.loads(output_path.read_text(encoding="utf-8"))
    finding = data["findings"][0]
    assert finding["stage2_verdict"] == "unverified"
    assert finding["review_status"] == "needs_review"
    assert finding["verification_assessment"]["boundary_type"] == "unix_socket"
    assert finding["report_context"]["assessment"]["missing_evidence"] == ["receiver implementation"]


def test_review_candidates_are_not_removed_by_confirmed_caller_callee_dedup(tmp_path):
    from core.reporter import build_pipeline_output

    caller = "src/stub.cpp:Stub::OnRequest"
    callee = "src/service.cpp:Service::handle"
    common = {"cwe_id": 400, "cwe_name": "Resource Consumption"}
    payload = {
        "results": [
            {"route_key": caller, "unit_id": caller, "finding": "vulnerable", "vulnerabilities": [common]},
            {"route_key": callee, "unit_id": callee, "finding": "inconclusive", "vulnerabilities": [common],
             "verification": {"agree": True, "correct_finding": "inconclusive"}},
        ],
        "confirmed_findings": [
            {"route_key": caller, "unit_id": caller, "finding": "vulnerable", "cwe_id": 400}
        ],
        "review_findings": [
            {"route_key": callee, "unit_id": callee, "finding": "inconclusive", "cwe_id": 400,
             "verification": {"agree": True, "correct_finding": "inconclusive"}}
        ],
        "code_by_route": {caller: "void OnRequest() {}", callee: "void handle() {}"},
        "metrics": {"total": 2, "vulnerable": 1, "inconclusive": 1},
    }
    results_path = tmp_path / "results_verified.json"
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "call_graph.json").write_text(json.dumps({
        "reverse_call_graph": {callee: [caller]},
    }), encoding="utf-8")
    output_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(str(results_path), str(output_path), language="cpp")
    findings = json.loads(output_path.read_text(encoding="utf-8"))["findings"]
    assert {item["route_key"] for item in findings} == {caller, callee}


def test_reporter_preserves_flattened_assessment_from_legacy_artifact(tmp_path):
    """Legacy resumed results may store Stage-2 assessment beside verification."""
    from core.reporter import build_pipeline_output

    route = "src/socket.cpp:Service::handle"
    payload = {
        "results": [{
            "route_key": route,
            "unit_id": route,
            "finding": "inconclusive",
            "verdict": "INCONCLUSIVE",
            "verification": {
                "agree": False,
                "incomplete": True,
            },
            "verification_assessment": {
                "defect_status": "confirmed",
                "reachability_status": "conditional",
                "impact_status": "plausible",
                "evidence_completeness": "partial",
                "boundary_type": "unix_socket",
                "missing_evidence": ["receiver registration"],
            },
        }],
        "confirmed_findings": [],
        "review_findings": [{
            "route_key": route,
            "unit_id": route,
            "finding": "inconclusive",
            "verdict": "INCONCLUSIVE",
            "verification": {
                "agree": False,
                "incomplete": True,
            },
            "verification_assessment": {
                "defect_status": "confirmed",
                "reachability_status": "conditional",
                "impact_status": "plausible",
                "evidence_completeness": "partial",
                "boundary_type": "unix_socket",
                "missing_evidence": ["receiver registration"],
            },
        }],
        "code_by_route": {route: "int handle(const char *msg) { return dispatch(msg); }"},
        "metrics": {"total": 1, "inconclusive": 1},
    }
    results_path = tmp_path / "results_verified.json"
    results_path.write_text(json.dumps(payload), encoding="utf-8")
    output_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(str(results_path), str(output_path), language="cpp")
    finding = json.loads(output_path.read_text(encoding="utf-8"))["findings"][0]
    assert finding["review_status"] == "needs_review"
    assert finding["verification_assessment"]["boundary_type"] == "unix_socket"
