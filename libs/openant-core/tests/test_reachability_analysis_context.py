"""Stage-1 rendering of semantic reachability evidence."""

from prompts.vulnerability_analysis import get_analysis_prompt
from core.analysis_core import _reachability_context_for_unit


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


def test_stage1_context_merges_post_enhancement_data_flow_candidate():
    projected = _reachability_context_for_unit({
        "id": "sink.cpp:Sink",
        "llm_context": {"data_flow": {
            "inputs": ["UDP payload"],
            "tainted_variables": ["cmd"],
            "security_relevant_flows": ["payload -> cmd"],
        }},
        "reachability_context": {
            "status": "path_found",
            "entry_path_ids": [["socket.cpp:Handle", "sink.cpp:Sink"]],
            "entry_paths": [],
            "attack_chain_context": {
                "status": "not_evaluated",
                "complete": None,
                "callsite_contexts": [],
                "missing_evidence": ["target_callsite_not_selected"],
            },
        },
    })
    chain = projected["entry_context"]["attack_chain_context"]
    assert chain["status"] == "incomplete"
    assert chain["complete"] is False
    assert chain["callsite_contexts"][0]["source"] == "UDP payload"
    assert "source_to_sink_dataflow_not_traced" in chain["missing_evidence"]


def test_stage1_context_projects_primary_structural_route():
    projected = _reachability_context_for_unit({
        "id": "sink.cpp:Sink",
        "reachability_context": {
            "status": "candidate_path_found",
            "stage1_context_status": "candidate",
            "primary_entry_path_kind": "candidate",
            "primary_entry_path_ids": [["socket.cpp:Handle", "sink.cpp:Sink"]],
            "primary_entry_path": [{
                "id": "socket.cpp:Handle", "file": "socket.cpp",
                "line_start": 10, "source_excerpt": "recv(fd, buf, len, 0);",
            }, {
                "id": "sink.cpp:Sink", "file": "sink.cpp",
                "line_start": 20, "source_excerpt": "popen(cmd, \"r\");",
            }],
            "primary_entry_path_edge_statuses": ["candidate"],
            "primary_top_level_entry": "socket.cpp:Handle",
            "primary_entry_path_source_complete": True,
            "primary_entry_path_validation": {"valid": True, "issues": []},
            "entry_path_ids": [],
            "entry_paths": [],
        },
    })
    entry = projected["entry_context"]
    assert entry["primary_entry_path_kind"] == "candidate"
    assert entry["primary_top_level_entry"] == "socket.cpp:Handle"
    assert entry["primary_entry_path_ids"] == [["socket.cpp:Handle", "sink.cpp:Sink"]]
    assert entry["primary_entry_path_edge_statuses"] == ["candidate"]
    assert entry["primary_entry_path_validation"]["valid"] is True


def test_stage1_context_projects_full_primary_source_bundle():
    projected = _reachability_context_for_unit({
        "id": "sink.cpp:Sink",
        "reachability_context": {
            "status": "path_found",
            "primary_entry_path_kind": "strict",
            "primary_entry_path_source_complete": True,
            "primary_entry_path_full_source_complete": True,
            "primary_path_source_bundle": {
                "schema_version": 2,
                "kind": "strict",
                "order": "entry_to_target",
                "source_complete": True,
                "nodes": [{
                    "order": 1,
                    "id": "socket.cpp:Handle",
                    "file": "socket.cpp",
                    "line_start": 10,
                    "source": "void Handle() { recv(fd, buf, len, 0); }",
                }, {
                    "order": 2,
                    "id": "sink.cpp:Sink",
                    "file": "sink.cpp",
                    "line_start": 20,
                    "source": "void Sink() { popen(cmd, \"r\"); }",
                }],
                "edges": [{"caller": "socket.cpp:Handle",
                           "callee": "sink.cpp:Sink", "status": "native"}],
            },
        },
    })
    bundle = projected["entry_context"]["primary_path_source_bundle"]
    assert bundle["source_complete"] is True
    assert bundle["nodes"][0]["source"].startswith("void Handle")
    assert bundle["nodes"][1]["source"].startswith("void Sink")
