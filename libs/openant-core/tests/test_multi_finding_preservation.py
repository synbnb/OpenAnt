"""Regression tests for preserving more than one issue per analysis context.

The scanner still exposes the historical single ``finding`` field as the
primary verdict.  These tests cover the additive ``findings`` collection used
to keep target and context findings separate instead of silently overwriting
one of them.
"""

import json

from core.reporter import build_pipeline_output

from core.analysis_core import parse_response
from core.finding_records import ensure_primary_record, normalize_findings
from report.generator import _compact_for_summary, _render_disclosure_context
from prompts.vulnerability_analysis import get_analysis_prompt
from utilities.finding_verifier import (
    FindingVerifier,
    VerificationResult,
    _VERIFY_JSON_SCHEMA,
)


def _verifier_without_init():
    # _parse_finish_result only translates model output and does not require
    # repository state.  Bypass the expensive constructor for this unit test.
    return FindingVerifier.__new__(FindingVerifier)


def test_stage1_keeps_primary_and_context_findings_separately():
    response = json.dumps({
        "finding": "vulnerable",
        "findings": [
            {
                "finding_id": "target-1",
                "finding": "VULNERABLE",
                "scope": "target",
                "relation": "primary",
                "target_match": True,
                "file": "src/service.cpp",
                "line_start": 10,
                "line_end": 14,
                "reasoning": "target defect",
            },
            {
                "finding_id": "context-1",
                "finding": "vulnerable",
                "scope": "context",
                "relation": "context_risk",
                "target_match": False,
                "file": "src/parser.cpp",
                "line_start": 20,
                "line_end": 24,
                "reasoning": "neighboring defect",
            },
        ],
    })

    result = parse_response(response)

    assert result["finding"] == "vulnerable"
    assert result["primary_finding_id"] == "target-1"
    assert len(result["findings"]) == 2
    assert result["findings"][0]["finding"] == "vulnerable"
    assert result["findings"][1]["scope"] == "context"
    assert result["findings"][1]["target_match"] is False


def test_stage1_nested_only_response_gets_legacy_primary_projection():
    result = parse_response(json.dumps({
        "findings": [{
            "finding": "vulnerable",
            "scope": "target",
            "relation": "primary",
            "target_match": True,
        }]
    }))

    assert result["finding"] == "vulnerable"
    assert result["verdict"] == "VULNERABLE"
    assert result["primary_finding_id"] == result["findings"][0]["finding_id"]


def test_context_only_inventory_cannot_replace_legacy_target_verdict():
    records = normalize_findings([{
        "finding": "vulnerable",
        "scope": "context",
        "target_match": False,
        "relation": "context_risk",
    }])
    records = ensure_primary_record(records, "inconclusive")

    assert any(item["scope"] == "context" for item in records)
    assert any(
        item["scope"] == "target" and item["finding"] == "inconclusive"
        for item in records
    )


def test_stage1_prompt_requires_independent_finding_inventory():
    prompt = get_analysis_prompt(code="int f() { return 0; }", language="cpp")

    assert '"findings"' in prompt
    assert "target_match" in prompt
    assert "independent" in prompt.lower()


def test_stage2_finish_preserves_independent_findings():
    verifier = _verifier_without_init()
    parsed = verifier._parse_finish_result(
        {
            "agree": True,
            "correct_finding": "vulnerable",
            "explanation": "two independently located issues",
            "findings": [
                {
                    "finding_id": "target-1",
                    "finding": "vulnerable",
                    "scope": "target",
                    "relation": "primary",
                    "target_match": True,
                    "file": "src/service.cpp",
                    "line_start": 10,
                    "line_end": 14,
                    "vulnerability_categories": ["OOB"],
                    "evidence": ["service.cpp:10"],
                },
                {
                    "finding_id": "context-1",
                    "finding": "inconclusive",
                    "scope": "context",
                    "relation": "context_risk",
                    "target_match": False,
                    "file": "src/parser.cpp",
                    "line_start": 20,
                    "line_end": 24,
                    "missing_evidence": ["socket ACL"],
                },
            ],
        },
        "vulnerable",
        1,
        10,
    )

    assert isinstance(parsed, VerificationResult)
    records = parsed.to_dict()["findings"]
    assert len(records) == 2
    assert records[0]["target_match"] is True
    assert records[1]["scope"] == "context"
    assert records[1]["finding"] == "inconclusive"


def test_stage2_legacy_finish_gets_a_primary_finding_record():
    verifier = _verifier_without_init()
    parsed = verifier._parse_finish_result(
        {
            "agree": True,
            "correct_finding": "vulnerable",
            "explanation": "legacy verifier response",
        },
        "vulnerable",
        1,
        10,
    )

    records = parsed.to_dict()["findings"]
    assert len(records) == 1
    assert records[0]["scope"] == "target"
    assert records[0]["relation"] == "primary"
    assert records[0]["target_match"] is True


def test_stage2_incomplete_exit_still_preserves_target_record():
    result = VerificationResult(
        agree=False,
        correct_finding="vulnerable",
        explanation="no tool call",
        iterations=1,
        total_tokens=0,
        incomplete=True,
    )
    records = result.to_dict()["findings"]
    assert len(records) == 1
    assert records[0]["scope"] == "target"
    assert records[0]["finding"] == "vulnerable"


def test_verifier_schema_declares_findings_collection():
    assert '"findings"' in _VERIFY_JSON_SCHEMA
    assert "target_match" in _VERIFY_JSON_SCHEMA


def test_report_keeps_context_findings_without_promoting_them(tmp_path):
    results_path = tmp_path / "results.json"
    output_path = tmp_path / "pipeline_output.json"
    results_path.write_text(json.dumps({
        "code_by_route": {"src/service.cpp:Target": "int Target() {}"},
        "confirmed_findings": [{
            "route_key": "src/service.cpp:Target",
            "unit_id": "src/service.cpp:Target",
            "finding": "vulnerable",
            "verification": {
                "agree": True,
                "correct_finding": "vulnerable",
                "findings": [
                    {
                        "finding": "vulnerable",
                        "scope": "target",
                        "relation": "primary",
                        "target_match": True,
                        "file": "src/service.cpp",
                        "line_start": 1,
                    },
                    {
                        "finding": "vulnerable",
                        "scope": "context",
                        "relation": "context_risk",
                        "target_match": False,
                        "file": "src/parser.cpp",
                        "line_start": 2,
                    },
                ],
            },
        }],
    }), encoding="utf-8")

    build_pipeline_output(
        results_path=str(results_path),
        output_path=str(output_path),
        language="cpp",
        repo_name="test/repo",
    )
    output = json.loads(output_path.read_text(encoding="utf-8"))
    finding = output["findings"][0]
    assert len(finding["independent_findings"]) == 2
    assert len(finding["context_findings"]) == 1
    assert finding["context_findings"][0]["target_match"] is False
    assert output["pipeline_stats"]["independent_issue_count"] == 2
    assert output["pipeline_stats"]["target_issue_count"] == 1
    assert output["pipeline_stats"]["context_issue_count"] == 1


def test_report_summary_and_disclosure_render_inventory():
    pipeline = {
        "findings": [{
            "id": "VULN-001",
            "stage1_verdict": "vulnerable",
            "stage2_verdict": "confirmed",
            "independent_findings": [{
                "finding": "vulnerable",
                "scope": "target",
                "relation": "primary",
                "target_match": True,
                "function_analyzed": "Target",
                "file": "src/service.cpp",
                "line_start": 10,
                "line_end": 14,
                "vulnerability_categories": ["COMMAND_INJECTION"],
            }, {
                "finding": "inconclusive",
                "scope": "context",
                "relation": "context_risk",
                "target_match": False,
                "function_analyzed": "Neighbor",
                "file": "src/parser.cpp",
                "line_start": 20,
                "line_end": 24,
            }],
        }]
    }
    compact = _compact_for_summary(pipeline)
    assert len(compact["findings"][0]["independent_findings"]) == 2
    context = _render_disclosure_context(
        {
            "report_context": {},
            "independent_findings": pipeline["findings"][0]["independent_findings"],
        },
        locale="zh-CN",
    )
    assert "独立问题清单" in context
    assert "src/parser.cpp:20-24" in context
