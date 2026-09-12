"""Small real-source tests for the bounded Clang batch extractor."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from core.platforms.openharmony.clang_batch_extractor import (
    _build_definition_loading_plan,
    _run_definition_loading,
    extract_clang_semantic_overlay,
)


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_batch_extractor_binds_direct_call(tmp_path):
    source = tmp_path / "sample.cpp"
    source.write_text("void target() {}\nvoid caller() { target(); }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": "sample.cpp",
                    "arguments": [
                        "clang++",
                        "-std=c++17",
                        "-c",
                        "sample.cpp",
                        "-o",
                        "sample.o",
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    functions = {
        "sample.cpp:target": {
            "name": "target",
            "file_path": "sample.cpp",
            "start_line": 1,
            "end_line": 1,
            "code": "void target() {}",
        },
        "sample.cpp:caller": {
            "name": "caller",
            "file_path": "sample.cpp",
            "start_line": 2,
            "end_line": 2,
            "code": "void caller() { target(); }",
        },
    }

    result = extract_clang_semantic_overlay(tmp_path, functions, source_revision="rev")

    assert result["status"] == "complete"
    assert result["summary"]["projected_edges"] == 1
    edge = result["edges"][0]
    assert edge["source_id"] == "function:sample.cpp:caller"
    assert edge["target_id"] == "function:sample.cpp:target"
    assert "target" in edge["evidence"][1]["text"]
    assert result["batch_summary"]["files_succeeded"] == 1


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_batch_extractor_prioritizes_gap_source_before_file_budget(tmp_path):
    sources = []
    for name in ("first.cpp", "second.cpp", "gap.cpp"):
        path = tmp_path / name
        path.write_text("void {}() {{}}\n".format(name.removesuffix(".cpp")), encoding="utf-8")
        sources.append(path)
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([
            {
                "directory": str(tmp_path),
                "file": path.name,
                "arguments": ["clang++", "-std=c++17", "-c", path.name],
            }
            for path in sources
        ]),
        encoding="utf-8",
    )

    result = extract_clang_semantic_overlay(
        tmp_path,
        {},
        source_revision="rev",
        auto_context=False,
        max_files=1,
        priority_sources=["gap.cpp"],
    )

    summary = result.get("batch_summary", result["summary"])
    assert summary["files_attempted"] == 1
    assert summary["priority_sources_requested"] == 1
    assert summary["priority_sources_matched"] == 1
    assert summary["priority_files_selected"] == 1
    assert summary["non_priority_files_selected"] == 0
    assert result["file_results"][0]["file"].endswith("/gap.cpp")


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_batch_extractor_preserves_unindexed_user_caller_as_symbol(tmp_path):
    source = tmp_path / "sample.cpp"
    source.write_text("void target() {}\nvoid omittedCaller() { target(); }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([{
            "directory": str(tmp_path),
            "file": "sample.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "sample.cpp"],
        }]),
        encoding="utf-8",
    )
    result = extract_clang_semantic_overlay(
        tmp_path,
        {
            "sample.cpp:target": {
                "name": "target", "file_path": "sample.cpp",
                "start_line": 1, "end_line": 1, "code": "void target() {}",
            }
        },
        source_revision="rev",
    )
    assert result["batch_summary"]["caller_not_in_index"] >= 1
    assert result["batch_summary"]["caller_symbols_added"] >= 1
    symbol_nodes = [
        node for node in result["nodes"]
        if node["attributes"].get("index_status") == "caller_not_in_function_index"
    ]
    assert symbol_nodes
    assert result["unindexed_calls"]
    assert result["unindexed_calls"][0]["caller_symbol_status"] == "declaration_only"
    assert symbol_nodes[0]["attributes"]["definition_resolution"] == "none"
    assert symbol_nodes[0]["attributes"]["definition_candidates"] == []


def test_definition_loading_plan_schedules_only_unique_candidates(tmp_path):
    dep = tmp_path / "definition.cpp"
    dep.write_text("void External::run() {}\n", encoding="utf-8")
    plan = _build_definition_loading_plan(
        {
            "external.hpp:External::run": {
                "name": "External::run",
                "definition_resolution": "unique_candidate",
                "definition_candidates": ["definition.cpp:External::run"],
            },
            "ambiguous.hpp:External::run": {
                "name": "External::run",
                "definition_resolution": "ambiguous_candidates",
                "definition_candidates": ["a.cpp:External::run", "b.cpp:External::run"],
            },
        },
        {
            "definition.cpp:External::run": {
                "name": "External::run", "file_path": "definition.cpp",
                "start_line": 1, "end_line": 1,
            }
        },
        [{
            "directory": str(tmp_path),
            "file": "definition.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "definition.cpp"],
        }],
        repository=tmp_path,
        selected_sources=[],
        max_files=1,
    )
    by_symbol = {item["symbol_id"]: item for item in plan}
    assert by_symbol["external.hpp:External::run"]["status"] == "scheduled"
    assert by_symbol["ambiguous.hpp:External::run"]["status"] == "ambiguous_definition"


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_definition_loading_executes_scheduled_translation_unit(tmp_path):
    source = tmp_path / "definition.cpp"
    source.write_text("void target() {}\n", encoding="utf-8")
    entry = {
        "directory": str(tmp_path),
        "file": "definition.cpp",
        "arguments": ["clang++", "-std=c++17", "-c", "definition.cpp"],
    }
    plan = [{
        "symbol_id": "external.hpp:External::run",
        "symbol_name": "External::run",
        "definition_resolution": "unique_candidate",
        "definition_candidates": ["definition.cpp:target"],
        "definition_id": "definition.cpp:target",
        "status": "scheduled",
        "compile_entry": entry,
        "working_directory": str(tmp_path),
        "source_path": str(source),
    }]
    base = {
        "summary": {
            "files_executed": 0,
            "files_succeeded": 0,
            "definition_files_executed": 0,
            "definition_files_reused": 0,
            "definition_files_succeeded": 0,
            "definition_files_failed": 0,
            "call_sites": 0,
            "bound_calls": 0,
            "ambiguous_calls": 0,
            "caller_not_in_index": 0,
            "caller_symbols_added": 0,
        },
        "diagnostics": [],
    }
    functions = {
        "definition.cpp:target": {
            "name": "target", "file_path": "definition.cpp",
            "start_line": 1, "end_line": 1, "code": "void target() {}",
        }
    }
    raw_edges, raw_symbols, raw_unindexed, file_results = [], {}, [], []
    checkpoint = {"files": {}}
    _run_definition_loading(
        plan=plan,
        functions=functions,
        source_revision="rev",
        effective_build_status="manual_rebuild",
        timeout_seconds=30,
        base=base,
        raw_edges=raw_edges,
        raw_symbols=raw_symbols,
        raw_unindexed_calls=raw_unindexed,
        file_results=file_results,
        checkpoint=checkpoint,
        resolved_checkpoint=tmp_path / "checkpoint.json",
    )
    assert plan[0]["status"] == "loaded"
    assert base["summary"]["definition_files_succeeded"] == 1
    assert file_results[0]["source_kind"] == "definition_load"
    assert checkpoint["files"]


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_batch_extractor_keeps_virtual_member_dispatch_candidate_only(tmp_path):
    source = tmp_path / "virtual.cpp"
    source.write_text(
        "struct Base { virtual void run(); };\n"
        "struct Derived : Base { void run() override; };\n"
        "void caller(Base *value) { value->run(); }\n"
        "void Base::run() {}\n"
        "void Derived::run() {}\n",
        encoding="utf-8",
    )
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([{
            "directory": str(tmp_path),
            "file": "virtual.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "virtual.cpp"],
        }]),
        encoding="utf-8",
    )
    functions = {
        "virtual.cpp:caller": {
            "name": "caller", "file_path": "virtual.cpp",
            "start_line": 3, "end_line": 3,
            "code": "void caller(Base *value) { value->run(); }",
        },
        "virtual.cpp:Base::run": {
            "name": "Base::run", "file_path": "virtual.cpp",
            "start_line": 4, "end_line": 4,
            "code": "void Base::run() {}",
        },
    }
    result = extract_clang_semantic_overlay(
        tmp_path, functions, source_revision="rev", build_status="compile_database"
    )

    assert result["summary"]["projected_edges"] == 1
    edge = result["edges"][0]
    assert edge["attributes"]["dispatch_kind"] == "virtual"
    assert edge["attributes"]["candidate_completeness"] == "unknown"
    assert edge["attributes"]["reachability_tier"] == "candidate"


def test_batch_extractor_reports_missing_compile_database(tmp_path):
    result = extract_clang_semantic_overlay(tmp_path, {}, source_revision="rev")

    assert result["status"] == "no_compile_commands"
    assert result["summary"]["files_attempted"] == 0
    assert result["clang_context"]["status"] == "context_unavailable"


def test_batch_extractor_persists_context_report_for_auto_discovery(tmp_path):
    context_dir = tmp_path / "context"
    result = extract_clang_semantic_overlay(
        tmp_path,
        {},
        source_revision="rev",
        context_output_dir=context_dir,
    )

    assert result["clang_context_report"] == str(
        (context_dir / "clang_context.json").resolve()
    )
    assert (context_dir / "clang_context.json").is_file()


def test_batch_extractor_marks_gn_reconstruction_as_candidate(tmp_path):
    source = tmp_path / "sample.cpp"
    source.write_text("void target() {}\nvoid caller() { target(); }\n", encoding="utf-8")
    (tmp_path / "BUILD.gn").write_text(
        'executable("sample") {\n  sources = [ "sample.cpp" ]\n}\n',
        encoding="utf-8",
    )
    functions = {
        "sample.cpp:target": {
            "name": "target",
            "file_path": "sample.cpp",
            "start_line": 1,
            "end_line": 1,
            "code": "void target() {}",
        },
        "sample.cpp:caller": {
            "name": "caller",
            "file_path": "sample.cpp",
            "start_line": 2,
            "end_line": 2,
            "code": "void caller() { target(); }",
        },
    }

    result = extract_clang_semantic_overlay(
        tmp_path,
        functions,
        context_output_dir=tmp_path / "context",
    )

    assert result["clang_context"]["status"] == "reconstructed_candidate"
    assert result["build_status"] == "reconstructed_candidate"
    assert result["status"] == "complete"
    assert result["summary"]["projected_edges"] == 1
    assert result["edges"][0]["attributes"]["reachability_tier"] == "candidate"


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_batch_extractor_resumes_successful_units(tmp_path):
    source = tmp_path / "sample.cpp"
    source.write_text("void target() {}\nvoid caller() { target(); }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([{
            "directory": str(tmp_path),
            "file": "sample.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "sample.cpp"],
        }]),
        encoding="utf-8",
    )
    functions = {
        "sample.cpp:target": {
            "name": "target", "file_path": "sample.cpp",
            "start_line": 1, "end_line": 1, "code": "void target() {}",
        },
        "sample.cpp:caller": {
            "name": "caller", "file_path": "sample.cpp",
            "start_line": 2, "end_line": 2, "code": "void caller() { target(); }",
        },
    }
    context_dir = tmp_path / "context"
    first = extract_clang_semantic_overlay(
        tmp_path, functions, context_output_dir=context_dir, batch_size=1,
    )
    second = extract_clang_semantic_overlay(
        tmp_path, functions, context_output_dir=context_dir, batch_size=1,
    )
    assert first["batch_summary"]["files_executed"] == 1
    assert first["batch_summary"]["files_reused"] == 0
    assert second["batch_summary"]["files_executed"] == 0
    assert second["batch_summary"]["files_reused"] == 1
    assert second["file_results"][0]["status"] == "reused"
    assert Path(second["checkpoint_path"]).is_file()
    assert Path(second["dependency_gap_report"]).is_file()


def test_dependency_gap_report_extracts_missing_headers_and_external_deps(tmp_path):
    source = tmp_path / "broken.cpp"
    source.write_text("#include <missing_header.h>\n", encoding="utf-8")
    context_dir = tmp_path / "context"
    context_dir.mkdir()
    # The helper is exercised through the public extractor so the persisted
    # artifact has the same shape as a real failed translation unit.
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([{
            "directory": str(tmp_path),
            "file": "broken.cpp",
            "arguments": ["clang++", "-c", "broken.cpp"],
        }]),
        encoding="utf-8",
    )
    result = extract_clang_semantic_overlay(
        tmp_path,
        {},
        context_output_dir=context_dir,
        auto_context=False,
    )
    report = json.loads(Path(result["dependency_gap_report"]).read_text(encoding="utf-8"))
    assert report["summary"]["failed_translation_units"] == 1
    assert any(item["header"] == "missing_header.h" for item in report["missing_headers"])


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_missing_header_retries_with_local_dependency_root(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    deps = tmp_path / "deps"
    repo.mkdir()
    (deps / "component" / "include").mkdir(parents=True)
    (deps / "component" / "include" / "dep_header.h").write_text(
        "#define DEP_VALUE 7\n", encoding="utf-8"
    )
    source = repo / "sample.cpp"
    source.write_text(
        '#include "dep_header.h"\nint value() { return DEP_VALUE; }\n',
        encoding="utf-8",
    )
    (repo / "compile_commands.json").write_text(
        json.dumps([{
            "directory": str(repo),
            "file": "sample.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "sample.cpp"],
        }]),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENANT_SOURCE_ROOTS", str(deps))
    context_dir = tmp_path / "context"
    result = extract_clang_semantic_overlay(
        repo,
        {
            "sample.cpp:value": {
                "name": "value", "file_path": "sample.cpp",
                "start_line": 2, "end_line": 2,
                "code": "int value() { return DEP_VALUE; }",
            }
        },
        context_output_dir=context_dir,
        auto_context=False,
        dependency_retry_attempts=1,
    )
    summary = result.get("batch_summary", result.get("summary", {}))
    assert summary["dependency_retry_attempts"] == 1
    assert summary["files_recovered_by_dependency_retry"] == 1
    assert summary["files_failed"] == 0
    assert result["file_results"][0]["status"] == "succeeded_after_dependency_retry"
    assert Path(result["dependency_retry_compile_commands"]).is_file()
    report = json.loads(Path(result["dependency_gap_report"]).read_text(encoding="utf-8"))
    assert report["dependency_retry_history"][0]["status"] == "recovered"


@pytest.mark.skipif(shutil.which("clang++") is None, reason="clang++ is unavailable")
def test_dependency_retry_can_follow_new_missing_header_across_rounds(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    deps = tmp_path / "deps"
    repo.mkdir()
    (deps / "first" / "include").mkdir(parents=True)
    (deps / "second" / "include").mkdir(parents=True)
    (deps / "first" / "include" / "first.h").write_text(
        '#include "second.h"\n#define FIRST_VALUE SECOND_VALUE\n', encoding="utf-8"
    )
    (deps / "second" / "include" / "second.h").write_text(
        "#define SECOND_VALUE 11\n", encoding="utf-8"
    )
    source = repo / "sample.cpp"
    source.write_text(
        '#include "first.h"\nint value() { return FIRST_VALUE; }\n', encoding="utf-8"
    )
    (repo / "compile_commands.json").write_text(
        json.dumps([{
            "directory": str(repo),
            "file": "sample.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "sample.cpp"],
        }]),
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENANT_SOURCE_ROOTS", str(deps))
    result = extract_clang_semantic_overlay(
        repo,
        {},
        context_output_dir=tmp_path / "context",
        auto_context=False,
        dependency_retry_attempts=2,
    )
    summary = result.get("summary", {})
    assert summary["dependency_retry_attempts"] == 2
    assert summary["files_recovered_by_dependency_retry"] == 1
    assert summary["files_failed"] == 0
    assert [item["attempt"] for item in result["dependency_retry_history"]] == [1, 2]
