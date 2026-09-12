from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.platforms.openharmony.analysis_feedback import build_analysis_feedback


def test_feedback_keeps_candidate_refs_separate_from_graph_mutation():
    dataset = {
        "metadata": {"reachability_context": {"graph_versions": ["g1"]}},
        "units": [
            {
                "id": "f",
                "code": {"primary_origin": {"file": "a.cpp", "start_line": 4}},
                "agent_context": {
                    "include_functions": [{"id": "g", "reason": "downstream"}],
                    "additional_callers": [{"name": "entry", "reason": "socket"}],
                    "security_classification": "vulnerable_internal",
                    "confidence": "high",
                },
                "reachability_context": {
                    "top_level_entry": "entry",
                    "entry_path_ids": [["entry", "f"]],
                    "path_count": 1,
                    "upstream_complete": True,
                },
            }
        ],
    }
    result = {"results": [{"unit_id": "f", "finding": "inconclusive"}]}
    payload = build_analysis_feedback(dataset, results=result, graph_versions=["g1"])
    assert payload["summary"]["strict_graph_mutated"] is False
    assert payload["summary"]["candidate_facts"] == 2
    assert any(f["kind"] == "entry_path_observation" for f in payload["facts"])
    assert any(f["kind"] == "stage1_observation" for f in payload["facts"])
    assert all(f.get("admission") == "not_validated_no_graph_promotion"
               for f in payload["facts"] if f["status"] == "candidate")


def test_feedback_deduplicates_pending_task_projection():
    payload = build_analysis_feedback(
        {"units": []},
        gap_tasks={"tasks": [
            {"task_id": "gap:s1", "site_key": "s1", "status": "pending",
             "kind": "semantic_compile_context", "candidate_targets": ["g"]},
            {"task_id": "gap:s2", "site_key": "s2", "status": "resolved",
             "kind": "direct_symbol_binding"},
        ]},
    )
    assert payload["summary"]["pending_gap_tasks"] == 1
    assert payload["pending_gap_tasks"][0]["task_id"] == "gap:s1"
