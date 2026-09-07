"""Tests for the optional OpenHarmony LLM call-edge recovery stage.

The stage is deliberately exercised with a local fake reviewer.  These tests
pin the orchestration contract without making a real API request:

* the CLI flag is opt-in and defaults to false;
* ``cmd_scan`` forwards the flag to ``scan_repository``;
* an OpenHarmony scan writes an advisory recovery artifact and a step report;
* a generic scan records a safe skip instead of sending OpenHarmony prompts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import scanner as scanner_mod
from core.schemas import AnalysisMetrics, ScanResult
from openant import cli


@pytest.fixture(autouse=True)
def _offline_registry_probe(monkeypatch):
    import utilities.llm as llm_mod

    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


def test_cli_flag_is_opt_in_and_forwarded(monkeypatch, tmp_path):
    parser = cli.build_parser()
    assert parser.parse_args(["scan", "/repo"]).llm_call_graph_recovery is False
    assert parser.parse_args(["scan", "/repo"]).llm_call_graph_iterative_recovery is False
    assert parser.parse_args(["scan", "/repo"]).llm_call_graph_candidate_review is False

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n", encoding="utf-8")
    args = parser.parse_args(
        [
            "scan",
            str(repo),
            "--llm-call-graph-recovery",
            "--no-context",
            "--no-enhance",
            "--no-report",
        ]
    )
    captured = {}

    def fake_scan_repository(**kwargs):
        captured.update(kwargs)
        return ScanResult(output_dir=kwargs["output_dir"])

    monkeypatch.setattr(scanner_mod, "scan_repository", fake_scan_repository)

    assert cli.cmd_scan(args) == 0
    assert captured["llm_call_graph_recovery"] is True


def test_cli_iterative_recovery_flag_is_opt_in_and_forwarded(monkeypatch, tmp_path):
    parser = cli.build_parser()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n", encoding="utf-8")
    args = parser.parse_args(
        [
            "scan",
            str(repo),
            "--llm-call-graph-iterative-recovery",
            "--no-context",
            "--no-enhance",
            "--no-report",
        ]
    )
    captured = {}

    def fake_scan_repository(**kwargs):
        captured.update(kwargs)
        return ScanResult(output_dir=kwargs["output_dir"])

    monkeypatch.setattr(scanner_mod, "scan_repository", fake_scan_repository)

    assert cli.cmd_scan(args) == 0
    assert captured["llm_call_graph_iterative_recovery"] is True


def test_iterative_summary_normalizer_handles_aggregate_wrappers():
    """Historical aggregate reports must not hide nested review counters."""
    aggregate = {
        "summary": {
            "worklist_sites": 6,
            "sites_reviewed": 6,
            "attempts": 0,
            "parsed_decisions": 0,
            "accepted": 0,
            "kept_unresolved": 0,
            "rejected": 0,
            "unreviewed_sites": 0,
            "llm_calls": 5,
            "accepted_decisions": 0,
        },
        "reports": [{
            "report": {
                "rounds": [
                    {"review": {"summary": {
                        "attempts": 1, "parsed_decisions": 2,
                        "accepted": 0, "kept_unresolved": 2, "rejected": 0,
                    }}},
                    {"review": {"summary": {
                        "attempts": 4, "parsed_decisions": 4,
                        "accepted": 0, "kept_unresolved": 4, "rejected": 0,
                    }}},
                ]
            }
        }],
    }

    normalized = scanner_mod._normalise_call_graph_review_summary(
        aggregate, iterative=True
    )
    assert normalized["attempts"] == 5
    assert normalized["parsed_decisions"] == 6
    assert normalized["kept_unresolved"] == 6


def test_cli_candidate_review_flag_is_opt_in_and_forwarded(monkeypatch, tmp_path):
    parser = cli.build_parser()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n", encoding="utf-8")
    args = parser.parse_args(
        [
            "scan",
            str(repo),
            "--llm-call-graph-candidate-review",
            "--no-context",
            "--no-enhance",
            "--no-report",
        ]
    )
    captured = {}

    def fake_scan_repository(**kwargs):
        captured.update(kwargs)
        return ScanResult(output_dir=kwargs["output_dir"])

    monkeypatch.setattr(scanner_mod, "scan_repository", fake_scan_repository)

    assert cli.cmd_scan(args) == 0
    assert captured["llm_call_graph_candidate_review"] is True


def test_cli_dispatch_code_evidence_flag_is_opt_in_and_forwarded(
    monkeypatch, tmp_path
):
    parser = cli.build_parser()
    assert parser.parse_args(["scan", "/repo"]).openharmony_dispatch_code_evidence is False
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n", encoding="utf-8")
    args = parser.parse_args(
        [
            "scan",
            str(repo),
            "--openharmony-dispatch-code-evidence",
            "--no-context",
            "--no-enhance",
            "--no-report",
        ]
    )
    captured = {}

    def fake_scan_repository(**kwargs):
        captured.update(kwargs)
        return ScanResult(output_dir=kwargs["output_dir"])

    monkeypatch.setattr(scanner_mod, "scan_repository", fake_scan_repository)

    assert cli.cmd_scan(args) == 0
    assert captured["openharmony_dispatch_code_evidence"] is True


def _install_minimal_pipeline(
    monkeypatch, tmp_path, *, candidate_site=False, mark_entry_point=False
):
    """Install cheap parser/analyzer/report stubs with OH residual artifacts."""
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    import core.reporter as reporter

    def fake_parse(*, output_dir, **kwargs):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        functions = {
            "entry.cpp:entry": {
                "name": "entry",
                "file_path": "entry.cpp",
                "start_line": 1,
                "end_line": 8,
                "is_entry_point": mark_entry_point,
                "unit_type": "main" if mark_entry_point else "function",
                "code": "void entry() { callback(); }",
            },
            "entry.cpp:target": {
                "name": "target",
                "file_path": "entry.cpp",
                "start_line": 10,
                "end_line": 14,
                "code": "void target() {}",
            },
        }
        (out / "dataset.json").write_text(
            json.dumps({"units": [{"id": key} for key in functions]}),
            encoding="utf-8",
        )
        (out / "analyzer.json").write_text(
            json.dumps({"functions": functions}), encoding="utf-8"
        )
        (out / "call_graph.json").write_text(
            json.dumps(
                {
                    "functions": functions,
                    "call_graph": {key: [] for key in functions},
                    "reverse_call_graph": {},
                }
            ),
            encoding="utf-8",
        )
        residual = {
            "unresolved_call_sites": [
                {
                    "caller_id": "entry.cpp:entry",
                    "file": "entry.cpp",
                    "line": 2,
                    "expression": "callback()",
                    "candidate_target_ids": (
                        ["entry.cpp:target"] if candidate_site else []
                    ),
                }
            ],
            "lambda_dispatch": {"call_sites": []},
        }
        (out / "call_graph_residuals.json").write_text(
            json.dumps(residual),
            encoding="utf-8",
        )

        class ParseResult:
            dataset_path = str(out / "dataset.json")
            analyzer_output_path = str(out / "analyzer.json")
            units_count = len(functions)
            language = "c"
            processing_level = "all"

        return ParseResult()

    class AnalyzeResult:
        metrics = AnalysisMetrics(total=2, safe=2)

    def fake_analysis(*, output_dir, **kwargs):
        result = AnalyzeResult()
        result.results_path = str(Path(output_dir) / "results.json")
        Path(result.results_path).write_text("[]", encoding="utf-8")
        return result

    def fake_build_output(*, output_path, **kwargs):
        Path(output_path).write_text("{}", encoding="utf-8")
        return output_path

    monkeypatch.setattr(parser_adapter, "parse_repository", fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", fake_analysis)
    monkeypatch.setattr(reporter, "build_pipeline_output", fake_build_output)


def test_openharmony_stage_writes_advisory_artifact_without_graph_mutation(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(monkeypatch, tmp_path)
    calls = []

    def fake_review(diagnostics, functions, **kwargs):
        calls.append((diagnostics, functions, kwargs))
        return {
            "schema_version": 1,
            "task": "openharmony_call_edge_recovery",
            "status": "complete",
            "summary": {
                "worklist_sites": 1,
                "attempts": 1,
                "llm_calls": 1,
                "retry_count": 0,
                "parsed_decisions": 1,
                "accepted": 0,
                "kept_unresolved": 1,
                "rejected": 0,
                "unreviewed_sites": 0,
            },
            "worklist": [],
            "decisions": [],
            "validation": {
                "accepted": [],
                "kept_unresolved": [],
                "rejected": [],
            },
            "errors": [],
        }

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    monkeypatch.setattr(recovery, "run_recovery_review", fake_review)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_recovery=True,
    )

    artifact = tmp_path / "out" / "llm_call_graph_recovery.json"
    report = tmp_path / "out" / "llm-call-graph-recovery.report.json"
    assert artifact.exists()
    assert report.exists()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert payload["summary"]["accepted"] == 0
    assert result.llm_call_graph_recovery_path == str(artifact)
    assert len(calls) == 1
    assert calls[0][0]["unresolved_call_sites"]
    assert "entry.cpp:entry" in calls[0][1]


def test_generic_scan_skips_openharmony_stage_without_model_call(monkeypatch, tmp_path):
    _install_minimal_pipeline(monkeypatch, tmp_path)
    called = False

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("generic scan must not call the OH recovery stage")

    monkeypatch.setattr(recovery, "run_recovery_review", fail_if_called)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="generic",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_recovery=True,
    )

    assert called is False
    assert result.skipped_step_reasons["llm-call-graph-recovery"] == "unsupported_platform"
    report = tmp_path / "out" / "llm-call-graph-recovery.report.json"
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "skipped"


def test_recovery_partial_status_is_preserved_in_step_report(monkeypatch, tmp_path):
    _install_minimal_pipeline(monkeypatch, tmp_path)

    def partial_review(*args, **kwargs):
        return {
            "schema_version": 1,
            "task": "openharmony_call_edge_recovery",
            "status": "partial",
            "summary": {
                "worklist_sites": 1,
                "attempts": 1,
                "llm_calls": 1,
                "retry_count": 0,
                "parsed_decisions": 0,
                "accepted": 0,
                "kept_unresolved": 1,
                "rejected": 0,
                "unreviewed_sites": 0,
            },
            "worklist": [],
            "decisions": [],
            "validation": {"accepted": [], "kept_unresolved": [], "rejected": []},
            "errors": ["one site exceeded the review budget"],
        }

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    monkeypatch.setattr(recovery, "run_recovery_review", partial_review)

    scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_recovery=True,
    )

    report = json.loads(
        (tmp_path / "out" / "llm-call-graph-recovery.report.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["status"] == "partial"


def test_candidate_review_writes_separate_artifact_and_includes_candidates(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(monkeypatch, tmp_path, candidate_site=True)
    calls = []

    def fake_review(diagnostics, functions, **kwargs):
        calls.append((diagnostics, functions, kwargs))
        assert kwargs["include_candidate_sites"] is True
        assert diagnostics["unresolved_call_sites"][0]["candidate_target_ids"] == [
            "entry.cpp:target"
        ]
        return {
            "schema_version": 1,
            "task": "openharmony_call_edge_recovery",
            "status": "complete",
            "summary": {
                "worklist_sites": 1,
                "attempts": 1,
                "llm_calls": 1,
                "retry_count": 0,
                "parsed_decisions": 0,
                "accepted": 0,
                "kept_unresolved": 1,
                "rejected": 0,
                "unreviewed_sites": 1,
            },
            "worklist": [],
            "decisions": [],
            "validation": {
                "accepted": [],
                "kept_unresolved": [],
                "rejected": [],
            },
            "errors": [],
        }

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    monkeypatch.setattr(recovery, "run_recovery_review", fake_review)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_candidate_review=True,
    )

    artifact = tmp_path / "out" / "llm_call_graph_candidate_review.json"
    report = tmp_path / "out" / "llm-call-graph-candidate-review.report.json"
    assert artifact.exists()
    assert report.exists()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert result.llm_call_graph_candidate_review_path == str(artifact)
    assert result.llm_call_graph_recovery_path is None
    assert len(calls) == 1


def test_candidate_review_partial_status_is_preserved_in_step_report(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(monkeypatch, tmp_path, candidate_site=True)

    def partial_review(*args, **kwargs):
        return {
            "schema_version": 1,
            "task": "openharmony_call_edge_recovery",
            "status": "partial",
            "summary": {
                "worklist_sites": 1,
                "attempts": 1,
                "llm_calls": 1,
                "parsed_decisions": 0,
                "accepted": 0,
                "kept_unresolved": 1,
                "rejected": 0,
                "unreviewed_sites": 1,
            },
            "worklist": [],
            "decisions": [],
            "validation": {"accepted": [], "kept_unresolved": [], "rejected": []},
            "errors": ["one candidate site exceeded the review budget"],
        }

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    monkeypatch.setattr(recovery, "run_recovery_review", partial_review)

    scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_candidate_review=True,
    )

    report = json.loads(
        (tmp_path / "out" / "llm-call-graph-candidate-review.report.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["status"] == "partial"


def test_generic_scan_skips_candidate_review_without_model_call(monkeypatch, tmp_path):
    _install_minimal_pipeline(monkeypatch, tmp_path)
    called = False

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("generic scan must not call candidate review")

    monkeypatch.setattr(recovery, "run_recovery_review", fail_if_called)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="generic",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_candidate_review=True,
    )

    assert called is False
    assert result.llm_call_graph_candidate_review_path is None
    assert result.skipped_step_reasons["llm-call-graph-candidate-review"] == (
        "unsupported_platform"
    )
    report = tmp_path / "out" / "llm-call-graph-candidate-review.report.json"
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "skipped"


def test_dispatch_code_evidence_writes_separate_artifact(monkeypatch, tmp_path):
    _install_minimal_pipeline(monkeypatch, tmp_path, candidate_site=True)
    calls = []

    import core.platforms.openharmony.dispatch_code_evidence as evidence

    def fake_evidence(diagnostics, repository, **kwargs):
        calls.append((diagnostics, repository, kwargs))
        assert diagnostics["unresolved_call_sites"][0]["candidate_target_ids"] == [
            "entry.cpp:target"
        ]
        return {
            "schema_version": 1,
            "platform": "openharmony",
            "status": "complete",
            "summary": {
                "sites": 1,
                "candidate_cases": 1,
                "resolved_cases": 1,
                "unresolved_symbols": 0,
                "conflicts": 0,
                "files_scanned": 2,
                "definitions": 1,
            },
            "sites": [],
            "errors": [],
        }

    monkeypatch.setattr(evidence, "build_dispatch_code_evidence", fake_evidence)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        openharmony_dispatch_code_evidence=True,
    )

    artifact = tmp_path / "out" / "openharmony_dispatch_code_evidence.json"
    report = tmp_path / "out" / "openharmony-dispatch-code-evidence.report.json"
    assert artifact.exists()
    assert report.exists()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["status"] == "complete"
    assert payload["summary"]["resolved_cases"] == 1
    assert result.openharmony_dispatch_code_evidence_path == str(artifact)
    assert len(calls) == 1
    assert calls[0][1] == str(tmp_path)


def test_cli_projection_flag_is_opt_in_and_forwarded(monkeypatch, tmp_path):
    parser = cli.build_parser()
    assert parser.parse_args(["scan", "/repo"]).llm_call_graph_projection is False
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n", encoding="utf-8")
    args = parser.parse_args(
        [
            "scan",
            str(repo),
            "--llm-call-graph-projection",
            "--no-context",
            "--no-enhance",
            "--no-report",
        ]
    )
    captured = {}

    def fake_scan_repository(**kwargs):
        captured.update(kwargs)
        return ScanResult(output_dir=kwargs["output_dir"])

    monkeypatch.setattr(scanner_mod, "scan_repository", fake_scan_repository)

    assert cli.cmd_scan(args) == 0
    assert captured["llm_call_graph_projection"] is True


def test_generic_scan_skips_dispatch_code_evidence_without_source_read(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(monkeypatch, tmp_path)
    called = False

    import core.platforms.openharmony.dispatch_code_evidence as evidence

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("generic scan must not build OH code evidence")

    monkeypatch.setattr(evidence, "build_dispatch_code_evidence", fail_if_called)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="generic",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        openharmony_dispatch_code_evidence=True,
    )

    assert called is False
    assert result.openharmony_dispatch_code_evidence_path is None
    assert result.skipped_step_reasons["openharmony-dispatch-code-evidence"] == (
        "unsupported_platform"
    )
    report = tmp_path / "out" / "openharmony-dispatch-code-evidence.report.json"
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "skipped"


def _accepted_projection_report():
    return {
        "schema_version": 1,
        "task": "openharmony_call_edge_recovery",
        "status": "complete",
        "worklist": [
            {
                "site_id": "native:2:callback",
                "caller_id": "entry.cpp:entry",
                "file": "entry.cpp",
                "line": 2,
                "expression": "callback()",
                "candidate_target_ids": ["entry.cpp:target"],
                "retrieval_candidates": [
                    {"function_id": "entry.cpp:target"},
                ],
            },
        ],
        "validation": {
            "accepted": [
                {
                    "site_id": "native:2:callback",
                    "decision": "add_edge",
                    "target_id": "entry.cpp:target",
                    "confidence": "high",
                    "reason": "The callback resolves to the indexed target.",
                    "evidence": [
                        {
                            "kind": "call_site",
                            "file": "entry.cpp",
                            "start_line": 2,
                            "end_line": 2,
                            "text": "callback()",
                        },
                        {
                            "kind": "target",
                            "function_id": "entry.cpp:target",
                            "file": "entry.cpp",
                            "start_line": 10,
                            "end_line": 14,
                            "text": "target()",
                        },
                    ],
                },
            ],
            "kept_unresolved": [],
            "rejected": [],
        },
    }


def _accepted_iterative_recovery_report():
    nested = _accepted_projection_report()
    return {
        "schema_version": 1,
        "task": "openharmony_iterative_call_edge_recovery",
        "status": "complete",
        "entry_point_ids": ["entry.cpp:entry"],
        "rounds": [
            {
                "round": 0,
                "frontier_function_ids": ["entry.cpp:entry"],
                "site_ids": ["native:2:callback"],
                "review_status": "complete",
                "review": nested,
                "overlay": {
                    "schema_version": 1,
                    "nodes": [],
                    "edges": [],
                    "orphans": [],
                },
            }
        ],
        "graph": {
            "schema_version": 1,
            "nodes": [],
            "edges": [],
            "orphans": [],
        },
        "errors": [],
        "summary": {
            "entry_points": 1,
            "worklist_sites": 1,
            "rounds": 1,
            "sites_scheduled": 1,
            "sites_reviewed": 1,
            "unreviewed_sites": 0,
            "accepted_decisions": 1,
            "projected_edges": 1,
            "duplicate_edges": 0,
            "llm_calls": 1,
            "retry_count": 0,
            "failed_rounds": 0,
            "termination_reason": "frontier_exhausted",
        },
    }


def test_projection_stage_writes_overlay_without_mutating_native_graph(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(monkeypatch, tmp_path)

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    monkeypatch.setattr(
        recovery,
        "run_recovery_review",
        lambda *args, **kwargs: _accepted_projection_report(),
    )

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_recovery=True,
        llm_call_graph_projection=True,
    )

    output = tmp_path / "out"
    overlay_path = output / "llm_call_graph_overlay.json"
    assert overlay_path.exists()
    overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert overlay["status"] == "complete"
    assert overlay["summary"]["accepted_input"] == 1
    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["edges"][0]["kind"] == "llm_confirmed_indirect_call"
    assert result.llm_call_graph_overlay_path == str(overlay_path)
    assert json.loads((output / "call_graph.json").read_text(encoding="utf-8"))["call_graph"] == {
        "entry.cpp:entry": [],
        "entry.cpp:target": [],
    }
    scan_report = json.loads((output / "scan.report.json").read_text(encoding="utf-8"))
    assert scan_report["outputs"]["llm_call_graph_overlay_path"] == str(overlay_path)
    assert (output / "llm-call-graph-projection.report.json").exists()


def test_iterative_recovery_writes_rounds_and_projection_revalidates_each_round(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(monkeypatch, tmp_path, mark_entry_point=True)
    calls = []

    import core.platforms.openharmony.llm_call_graph_rounds as rounds

    def fake_iterative(diagnostics, functions, **kwargs):
        calls.append((diagnostics, functions, kwargs))
        assert kwargs["call_graph"] == {
            "entry.cpp:entry": [],
            "entry.cpp:target": [],
        }
        return _accepted_iterative_recovery_report()

    monkeypatch.setattr(rounds, "run_iterative_recovery_review", fake_iterative)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_iterative_recovery=True,
        llm_call_graph_projection=True,
    )

    output = tmp_path / "out"
    rounds_path = output / "llm_call_graph_recovery_rounds.json"
    assert rounds_path.exists()
    rounds_payload = json.loads(rounds_path.read_text(encoding="utf-8"))
    assert rounds_payload["task"] == "openharmony_iterative_call_edge_recovery"
    assert rounds_payload["mode"] == "iterative"
    assert result.llm_call_graph_rounds_path == str(rounds_path)
    assert result.llm_call_graph_recovery_path is None
    assert len(calls) == 1

    overlay = json.loads(
        (output / "llm_call_graph_overlay.json").read_text(encoding="utf-8")
    )
    assert overlay["summary"]["projected_edges"] == 1
    assert overlay["edges"][0]["target_id"] == "function:entry.cpp:target"
    recovery_report = json.loads(
        (output / "llm-call-graph-recovery.report.json").read_text(encoding="utf-8")
    )
    assert recovery_report["summary"]["attempts"] == 1
    assert recovery_report["summary"]["parsed_decisions"] == 1
    assert recovery_report["summary"]["accepted"] == 1
    assert recovery_report["summary"]["kept_unresolved"] == 0
    scan_report = json.loads((output / "scan.report.json").read_text(encoding="utf-8"))
    assert scan_report["outputs"]["llm_call_graph_rounds_path"] == str(rounds_path)


def test_generic_iterative_recovery_is_safe_skip(monkeypatch, tmp_path):
    _install_minimal_pipeline(monkeypatch, tmp_path)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="generic",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_iterative_recovery=True,
    )

    assert result.llm_call_graph_rounds_path is None
    assert result.skipped_step_reasons["llm-call-graph-recovery"] == (
        "unsupported_platform"
    )


def test_projection_stage_expands_reachable_dataset_only_when_requested(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(
        monkeypatch,
        tmp_path,
        mark_entry_point=True,
    )

    import core.platforms.openharmony.llm_call_graph_recovery as recovery

    monkeypatch.setattr(
        recovery,
        "run_recovery_review",
        lambda *args, **kwargs: _accepted_projection_report(),
    )

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="reachable",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_recovery=True,
        llm_call_graph_projection=True,
    )

    output = tmp_path / "out"
    dataset = json.loads((output / "dataset.json").read_text(encoding="utf-8"))
    assert {unit["id"] for unit in dataset["units"]} == {
        "entry.cpp:entry",
        "entry.cpp:target",
    }
    metadata = dataset["metadata"]["reachability_filter"]
    assert metadata["native_reachable_units"] == 1
    assert metadata["semantic_reachable_added"] == 1
    assert metadata["semantic_overlay"]["edges_added"] == 1
    assert result.units_count == 2


def test_projection_without_review_artifacts_keeps_baseline_reachability(
    monkeypatch, tmp_path
):
    _install_minimal_pipeline(
        monkeypatch,
        tmp_path,
        mark_entry_point=True,
    )

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="openharmony",
        processing_level="reachable",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_projection=True,
    )

    output = tmp_path / "out"
    dataset = json.loads((output / "dataset.json").read_text(encoding="utf-8"))
    assert {unit["id"] for unit in dataset["units"]} == {"entry.cpp:entry"}
    overlay = json.loads(
        (output / "llm_call_graph_overlay.json").read_text(encoding="utf-8")
    )
    assert overlay["status"] == "no_artifacts"
    assert overlay["summary"]["projected_edges"] == 0
    assert result.skipped_step_reasons["llm-call-graph-projection"] == (
        "no_artifacts"
    )


def test_generic_projection_is_safe_skip_without_overlay(monkeypatch, tmp_path):
    _install_minimal_pipeline(monkeypatch, tmp_path)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        platform="generic",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_call_graph_projection=True,
    )

    assert result.llm_call_graph_overlay_path is None
    assert result.skipped_step_reasons["llm-call-graph-projection"] == (
        "unsupported_platform"
    )
    report = tmp_path / "out" / "llm-call-graph-projection.report.json"
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "skipped"
