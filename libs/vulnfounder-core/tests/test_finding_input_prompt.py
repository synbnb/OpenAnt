from __future__ import annotations

from utilities.openharmony_dynamic.finding_input import FindingInput


def test_dynamic_prompt_view_keeps_route_facts_but_omits_attack_narrative():
    finding = FindingInput(
        finding_id="T-PROMPT-01",
        unit_id="unit",
        vuln_class="command_injection",
        description="完整漏洞推理：popen('sh -c ...')",
        source_paths=["service.cpp"],
        evidence_lines=[[10, 20]],
        sink="Service::Handle",
        candidate_attack_chains=[["recv", "Service::Handle"]],
        analysis_context={
            "stage1_reasoning": "reasoning with shell ; and payload",
            "stage1_attack_scenario": "attack scenario echo hack",
            "source_evidence": ["service.cpp:10-20"],
            "candidate_entry_path_ids": [["recv", "Service::Handle"]],
            "stage1_finding": {
                "function_analyzed": "Service::Handle",
                "file": "service.cpp",
                "line_start": 10,
                "line_end": 20,
                "vulnerability_categories": ["command_injection"],
                "reasoning": "omit this prose",
                "attack_scenario": "omit this payload",
            },
        },
    )

    prompt = finding.to_prompt_dict()
    assert prompt["sink"] == "Service::Handle"
    assert prompt["analysis_context"]["source_evidence"] == ["service.cpp:10-20"]
    assert "stage1_reasoning" not in prompt["analysis_context"]
    assert "stage1_attack_scenario" not in prompt["analysis_context"]
    assert "reasoning" not in prompt["analysis_context"]["stage1_finding"]
    assert "attack_scenario" not in prompt["analysis_context"]["stage1_finding"]
    # Persistence still keeps the complete finding for audit/Stage 2.
    persisted = finding.to_dict()
    assert persisted["description"].startswith("完整漏洞推理")
    assert "stage1_attack_scenario" in persisted["analysis_context"]
