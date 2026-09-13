import json

from core.platforms.openharmony.gap_tasks import build_gap_tasks


def test_gap_tasks_are_grouped_by_unrepaired_call_site():
    report = {
        "sites": [
            {
                "site_key": "site-a",
                "site_id": "site-a",
                "ledger_edge_missing": True,
                "ledger_unrepaired": True,
                "caller_id": "a.cpp:A::run",
                "file": "a.cpp",
                "line_start": 10,
                "candidate_targets": [],
                "reason_codes": ["edge_missing", "binding_incomplete"],
            },
            {
                "site_key": "site-a",
                "site_id": "site-a",
                "ledger_edge_missing": True,
                "ledger_unrepaired": True,
                "candidate_targets": ["a.cpp:B::run"],
                "reason_codes": ["candidate_set_incomplete_or_unknown"],
            },
            {
                "site_key": "candidate-only",
                "ledger_edge_missing": False,
                "ledger_unrepaired": False,
                "candidate_targets": ["x.cpp:X::f"],
            },
        ]
    }
    payload = build_gap_tasks(report, repository="repo", graph_versions=["g1"])
    assert payload["summary"]["tasks"] == 1
    assert payload["summary"]["pending"] == 1
    task = payload["tasks"][0]
    assert task["site_key"] == "site-a"
    assert task["candidate_targets"] == ["a.cpp:B::run"]
    assert task["status"] == "pending"
    assert payload["provenance"]["graph_versions"] == ["g1"]


def test_gap_task_marks_repaired_site_resolved_and_is_json_safe():
    payload = build_gap_tasks({
        "sites": [{
            "site_key": "site-b",
            "ledger_edge_missing": True,
            "ledger_unrepaired": False,
            "candidate_targets": ["b.cpp:B::f"],
            "candidate_completeness": ["complete"],
            "reason_codes": ["edge_missing"],
        }]
    })
    assert payload["tasks"][0]["status"] == "resolved"
    json.dumps(payload)
