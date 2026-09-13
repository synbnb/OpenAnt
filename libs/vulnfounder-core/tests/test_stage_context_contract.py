from core.attack_chain_context import stage_context_from_unit
from prompts.verification_prompts import (
    format_stage1_context_for_verification,
    get_verification_prompt,
)
from utilities.finding_verifier import FindingVerifier


def test_stage_context_separates_structural_path_from_stage2_dataflow():
    context = stage_context_from_unit({
        "reachability_context": {
            "status": "path_found",
            "generic_entry_path_found": True,
            "top_level_entry": "socket.cpp:HandleMsg",
            "entry_path_ids": [["socket.cpp:HandleMsg", "sink.cpp:Sink"]],
            "attack_chain_context": {
                "status": "incomplete",
                "complete": False,
                "missing_evidence": ["source_to_sink_dataflow_not_traced"],
            },
        }
    })

    assert context["stage1"]["status"] == "strict"
    assert context["stage1"]["analysis_allowed"] is True
    assert context["stage1"]["parameter_dataflow_is_stage1_gate"] is False
    assert context["stage1"]["top_level_entry"] == "socket.cpp:HandleMsg"
    assert context["stage2"]["parameter_dataflow_status"] == "incomplete"
    assert context["stage2"]["parameter_dataflow_complete"] is False
    assert "source_to_sink_dataflow_not_traced" in context["stage2"]["missing_evidence"]


def test_unknown_structural_path_does_not_turn_off_stage1_analysis():
    context = stage_context_from_unit({
        "reachability_context": {"status": "unknown"},
    })

    assert context["stage1"]["status"] == "unknown"
    assert context["stage1"]["analysis_allowed"] is True
    assert "external_or_structural_entry_path_not_proven" in context["stage1"]["missing_evidence"]
    assert context["stage2"]["parameter_dataflow_status"] == "not_evaluated"


def test_stage1_prompt_labels_dataflow_as_stage2_work():
    rendered = format_stage1_context_for_verification({
        "stage1": {
            "status": "strict",
            "top_level_entry": "socket.cpp:HandleMsg",
            "generic_entry_path_found": True,
        },
        "stage2": {
            "parameter_dataflow_status": "not_evaluated",
            "missing_evidence": ["source_to_sink_dataflow_not_traced"],
        },
    })
    assert "Stage-1 Context Handoff" in rendered
    assert "Stage-2 owns the" in rendered
    assert "source_to_sink_dataflow_not_traced" in rendered


def test_stage2_prompt_receives_stage1_context_without_treating_it_as_proof():
    prompt = get_verification_prompt(
        code="void Sink(const char *cmd) { popen(cmd, \"r\"); }",
        finding="inconclusive",
        attack_vector="socket payload",
        reasoning="The local sink is visible but the parameter flow is not traced.",
        route="sink.cpp:Sink",
        stage1_context={
            "stage1": {
                "status": "strict",
                "top_level_entry": "socket.cpp:HandleMsg",
                "generic_entry_path_found": True,
            },
            "stage2": {
                "parameter_dataflow_status": "not_evaluated",
            },
        },
    )
    assert "Stage-1 Context Handoff" in prompt
    assert "Stage-2 parameter data-flow status: not_evaluated" in prompt
    assert "Treat parameter source-to-sink tracing as a primary Stage-2 task" in prompt
    assert "not proof" in prompt


def test_stage2_assessment_accepts_explicit_parameter_dataflow_status():
    assessment = FindingVerifier._parse_assessment({
        "parameter_dataflow_status": "partial",
        "missing_evidence": ["state write/read ordering"],
    })
    assert assessment["parameter_dataflow_status"] == "partial"
