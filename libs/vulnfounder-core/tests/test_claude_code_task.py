"""Tests for the Claude Code dynamic-test task package."""

import json
from pathlib import Path


def _pipeline(path: Path) -> None:
    data = {
        "repository": {"name": "fixture", "language": "c"},
        "application_type": "openharmony_system_service",
        "findings": [
            {
                "id": "OH-001",
                "name": "confirmed candidate",
                "stage1_verdict": "vulnerable",
                "stage2_verdict": "confirmed",
                "location": {"file": "src/service.cpp", "function": "Service::OnRemoteRequest"},
                "cwe_id": 20,
                "cwe_name": "Improper Input Validation",
            },
            {
                "id": "OH-002",
                "name": "rejected finding",
                "stage1_verdict": "vulnerable",
                "stage2_verdict": "rejected",
                "location": {"file": "src/other.cpp", "function": "Other"},
                "cwe_id": 20,
                "cwe_name": "Improper Input Validation",
            },
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_create_claude_code_task_contains_candidates_source_and_tools(tmp_path):
    repo = tmp_path / "source"
    (repo / "src").mkdir(parents=True)
    (repo / "src/service.cpp").write_text("int Service::OnRemoteRequest() {}\n", encoding="utf-8")
    scan = tmp_path / "scan"
    scan.mkdir()
    pipeline = scan / "pipeline_output.json"
    _pipeline(pipeline)
    (scan / "dataset.json").write_text('{"units": []}\n', encoding="utf-8")
    (scan / "dynamic_test_results.json").write_text('{"results": []}\n', encoding="utf-8")

    from utilities.dynamic_tester.claude_code import create_claude_code_task

    manifest = create_claude_code_task(
        str(pipeline), output_dir=str(tmp_path / "runs"), repo_path=str(repo)
    )

    task = Path(manifest["task_workspace"])
    tools = Path(manifest["public_tool_library"])
    assert task.is_dir()
    assert (task / "CLAUDE.md").is_file()
    assert (task / "TASK.md").is_file()
    assert (task / ".claude/skills/vulnfounder-openharmony-dynamic/SKILL.md").is_file()
    # Existing task runners may still use the old path during the migration
    # window; the generated package deliberately keeps a compatibility copy.
    assert (task / ".claude/skills/openant-openharmony-dynamic/SKILL.md").is_file()
    assert (task / "context/pipeline_output.json").is_file()
    assert (task / "context/static_artifacts/dataset.json").is_file()
    assert not (task / "context/static_artifacts/dynamic_test_results.json").exists()
    assert (task / "results/summary.json").is_file()
    assert (task / "source_code").is_symlink()
    assert (task / "source_code").resolve() == repo.resolve()
    assert tools.parent == task.parent
    assert (tools / "README.zh-CN.md").is_file()
    assert (tools / "toolchain-manifest.json").is_file()
    assert manifest["candidate_count"] == 1

    candidates = json.loads((task / "context/candidate_manifest.json").read_text())
    assert [item["id"] for item in candidates["candidates"]] == ["OH-001"]
    assert "claude --dangerously-skip-permissions" in manifest["launch_command"]


def test_core_dynamic_test_claude_code_mode_does_not_require_docker(tmp_path, monkeypatch):
    repo = tmp_path / "source"
    repo.mkdir()
    pipeline = tmp_path / "pipeline_output.json"
    _pipeline(pipeline)

    # If the implementation accidentally checks Docker before dispatching the
    # mode, this test fails even on a machine without Docker installed.
    monkeypatch.setattr("shutil.which", lambda name: None)
    from core.dynamic_tester import run_tests

    result = run_tests(
        str(pipeline),
        output_dir=str(tmp_path / "runs"),
        repo_path=str(repo),
        mode="claude-code",
    )

    assert result.mode == "claude-code"
    assert result.findings_tested == 1
    assert Path(result.task_workspace).is_dir()
    assert Path(result.task_manifest_path).is_file()
    assert result.launch_command.startswith("cd ")


def test_task_generation_excludes_output_directory_inside_scan(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    scan = tmp_path / "scan"
    scan.mkdir()
    pipeline = scan / "pipeline_output.json"
    _pipeline(pipeline)
    (scan / "dataset.json").write_text('{"units": []}\n', encoding="utf-8")

    output = scan / "task-runs"
    from utilities.dynamic_tester.claude_code import create_claude_code_task

    manifest = create_claude_code_task(
        str(pipeline), output_dir=str(output), repo_path=str(repo)
    )

    static_root = Path(manifest["task_workspace"]) / "context/static_artifacts"
    copied = {path.relative_to(static_root).as_posix() for path in static_root.rglob("*") if path.is_file()}
    assert "dataset.json" in copied
    assert not any(path.startswith("task-runs/") for path in copied)


def test_task_generation_with_scan_directory_output_keeps_static_artifacts(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    scan = tmp_path / "scan"
    scan.mkdir()
    pipeline = scan / "pipeline_output.json"
    _pipeline(pipeline)
    (scan / "dataset.json").write_text('{"units": []}\n', encoding="utf-8")

    from utilities.dynamic_tester.claude_code import create_claude_code_task

    manifest = create_claude_code_task(
        str(pipeline), output_dir=str(scan), repo_path=str(repo)
    )
    static_root = Path(manifest["task_workspace"]) / "context/static_artifacts"
    copied = {path.relative_to(static_root).as_posix() for path in static_root.rglob("*") if path.is_file()}
    assert "dataset.json" in copied
    assert not any(path.startswith("run-") for path in copied)
