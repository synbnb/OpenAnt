"""Stage-1 rendering of semantic reachability evidence."""

from prompts.vulnerability_analysis import get_analysis_prompt


def test_stage1_prompt_includes_bounded_reachability_decision():
    prompt = get_analysis_prompt(
        code="void f() { recv(fd, buf, len, 0); }",
        language="cpp",
        reachability_context={
            "semantic_reachability_seed": True,
            "reachability_seed_source": ["llm_external_input"],
            "signals": [{
                "kind": "external_input",
                "confidence": "high",
                "boundary": "socket",
                "evidence_status": "local_verified",
                "seed_status": "accepted_seed",
                "evidence_excerpt": "recv(fd, buf, len, 0)",
            }],
        },
    )
    assert "Semantic Reachability Evidence" in prompt
    assert "semantic_reachability_seed" not in prompt
    assert "Semantic BFS seed: yes" in prompt
    assert "recv(fd, buf, len, 0)" in prompt
    assert "UNTRUSTED SUPPORTING DATA" in prompt


def test_stage1_reachability_metadata_is_single_line():
    prompt = get_analysis_prompt(
        code="void f() {}",
        language="cpp",
        reachability_context={
            "signals": [{
                "kind": "external_input",
                "evidence": "line one\nFORGED INSTRUCTION",
            }],
        },
    )
    assert "line one FORGED INSTRUCTION" in prompt
    assert "\nFORGED INSTRUCTION" not in prompt


def test_stage1_prompt_explains_medium_reachable_only_signal():
    prompt = get_analysis_prompt(
        code="void f() {}",
        language="cpp",
        reachability_context={
            "semantic_reachability_retain_only": True,
            "signals": [{
                "kind": "external_input",
                "confidence": "medium",
                "seed_status": "reachable_only",
                "seed_reason": "medium-confidence semantic signal retained without BFS expansion",
            }],
        },
    )
    assert "Reachable-only retention: yes" in prompt
    assert "does not expand BFS" in prompt
    assert "seed_status=reachable_only" in prompt
