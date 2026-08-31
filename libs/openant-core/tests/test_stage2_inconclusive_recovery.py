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
