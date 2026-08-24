"""Generate a Claude Code task workspace for OpenHarmony dynamic testing.

This mode deliberately does not execute Claude Code or Docker.  It prepares a
reviewable workspace containing the static candidates, source repository link,
project-local OpenHarmony tools and a Claude Code skill.  The operator can then
run Claude Code in the generated ``task`` directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shlex
import shutil
from datetime import datetime, timezone
from pathlib import Path

from core.verdict_taxonomy import DYNAMIC_TESTABLE
from utilities.file_io import normalize_results, read_json, write_json


TASK_SCHEMA_VERSION = "openant.claude-code.dynamic.v1"
_ARTIFACT_SUFFIXES = frozenset({
    ".json", ".jsonl", ".md", ".yaml", ".yml", ".txt", ".log",
})
_SKIP_ARTIFACT_DIRS = frozenset({
    ".git", ".venv", "venv", "__pycache__", "claude-code-runs",
    "dynamic_test_checkpoints",
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_root() -> Path:
    # .../OpenAnt/libs/openant-core/utilities/dynamic_tester/claude_code.py
    return Path(__file__).resolve().parents[4]


def _template_dir() -> Path:
    return Path(__file__).resolve().parent / "templates" / "claude_code"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _link_or_record(link_path: Path, target: Path) -> dict:
    """Create a relative link; record a readable fallback if links are unavailable."""
    link_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        relative = os.path.relpath(target, link_path.parent)
        link_path.symlink_to(relative)
        return {"path": str(link_path), "target": str(target), "kind": "symlink"}
    except (OSError, NotImplementedError):
        marker = link_path.with_name(link_path.name + ".path")
        marker.write_text(str(target) + "\n", encoding="utf-8")
        return {"path": str(marker), "target": str(target), "kind": "path_file"}


def _resolve_source(repo_path: str | None, pipeline: dict) -> Path:
    candidate = repo_path
    if not candidate:
        repository = pipeline.get("repository")
        if isinstance(repository, dict):
            for key in ("repo_path", "path", "source_path", "url"):
                value = repository.get(key)
                if isinstance(value, str) and value and Path(value).expanduser().is_dir():
                    candidate = value
                    break
    if not candidate:
        raise ValueError(
            "Claude Code mode requires --repo-path so the task can expose the "
            "real source repository"
        )
    source = Path(candidate).expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"source repository is not a directory: {source}")
    return source


def _candidate_manifest(pipeline: dict, pipeline_path: Path, source: Path) -> dict:
    findings = pipeline.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    normalized = []
    for finding in findings:
        if isinstance(finding, dict):
            normalized.append(finding)
    candidates = [
        finding for finding in normalized
        if finding.get("stage2_verdict") in DYNAMIC_TESTABLE
    ]
    summary = []
    for finding in normalized:
        summary.append({
            "id": str(finding.get("id", "")),
            "name": finding.get("name", ""),
            "stage1_verdict": finding.get("stage1_verdict"),
            "stage2_verdict": finding.get("stage2_verdict"),
            "dynamic_testable": finding.get("stage2_verdict") in DYNAMIC_TESTABLE,
            "location": finding.get("location"),
        })
    return {
        "schema_version": TASK_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "source_pipeline_output": str(pipeline_path),
        "source_pipeline_sha256": _sha256(pipeline_path),
        "source_code_path": str(source),
        "selection": {
            "dynamic_testable_stage2_verdicts": sorted(DYNAMIC_TESTABLE),
            "rule": "only findings whose stage2_verdict is in DYNAMIC_TESTABLE are candidates",
        },
        "repository": pipeline.get("repository", {}),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "all_findings_summary": summary,
    }


def _copy_static_artifacts(
    pipeline_path: Path,
    destination: Path,
    excluded_dirs: tuple[Path, ...] = (),
) -> list[dict]:
    """Copy readable pre-dynamic artifacts next to pipeline_output.json."""
    source_dir = pipeline_path.parent.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    for root, dirs, files in os.walk(source_dir, followlinks=False):
        root_path = Path(root)
        root_resolved = root_path.resolve()
        if any(
            root_resolved == excluded or excluded in root_resolved.parents
            for excluded in excluded_dirs
        ):
            dirs[:] = []
            continue
        relative_root = root_path.relative_to(source_dir)
        filtered_dirs = []
        for name in dirs:
            child = root_path / name
            child_resolved = child.resolve()
            if name in _SKIP_ARTIFACT_DIRS:
                continue
            # A Web run stores Claude task directories as run-*/ below the
            # scan output directory. Do not feed previous task packages back
            # into the next package as static evidence. Restrict this to the
            # source root so a source repository's legitimate nested run-
            # directory is not silently omitted.
            if root_path == source_dir and name.startswith("run-"):
                continue
            if any(
                child_resolved == excluded or excluded in child_resolved.parents
                for excluded in excluded_dirs
            ):
                continue
            filtered_dirs.append(name)
        dirs[:] = filtered_dirs
        for name in files:
            original = root_path / name
            if original.is_symlink() or original.suffix.lower() not in _ARTIFACT_SUFFIXES:
                continue
            # Do not feed a previous dynamic run back to Claude as if it were
            # a pre-dynamic candidate. The current task has its own results/
            # directory and should start from static-stage evidence.
            if "dynamic_test" in name.lower() or "dynamic-test" in name.lower():
                continue
            if original.resolve() == pipeline_path.resolve():
                # It is copied separately to a stable top-level path below.
                continue
            relative = relative_root / name
            copied = destination / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, copied)
            manifest.append({
                "source": str(original),
                "workspace": str(copied),
                "relative_path": str(relative),
                "size_bytes": copied.stat().st_size,
                "sha256": _sha256(copied),
            })
    return manifest


def _toolchain_root() -> Path:
    override = os.environ.get("OPENANT_DYNAMIC_TOOLCHAIN", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return (
        _project_root()
        / "libs/openant-core/utilities/dynamic_tester/toolchains"
        / "commandline-tools-mac-arm64-6.1.0.860/command-line-tools"
    )


def _build_public_tool_library(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "bin").mkdir(exist_ok=True)
    (destination / "docs").mkdir(exist_ok=True)
    template = _template_dir() / "PUBLIC_TOOLS_README.zh-CN.md"
    shutil.copyfile(template, destination / "README.zh-CN.md")

    root = _toolchain_root()
    tools = {
        "hdc": root / "sdk/default/openharmony/toolchains/hdc",
        "hvigorw": root / "hvigor/bin/hvigorw",
        "node": root / "tool/node/bin/node",
        "hap-sign-tool.jar": root / "sdk/default/openharmony/toolchains/lib/hap-sign-tool.jar",
    }
    host_java = shutil.which("java")
    if host_java:
        tools["java"] = Path(host_java).resolve()
    entries = []
    for name, target in tools.items():
        entry = {
            "name": name,
            "target": str(target),
            "exists": target.exists(),
        }
        if target.exists():
            entry.update(_link_or_record(destination / "bin" / name, target))
        entries.append(entry)

    manifest = {
        "schema_version": TASK_SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "toolchain_root": str(root),
        "toolchain_root_exists": root.is_dir(),
        "platform": "macOS ARM64 (project-provided toolchain)",
        "tools": entries,
        "host_commands": {
            "java": "required for hap-sign-tool.jar",
            "sh": "required by hvigorw",
            "claude": "provided by the operator, not copied into this library",
        },
        "secrets_policy": "no private key, keystore password, API key or signing profile is copied here",
    }
    write_json(destination / "toolchain-manifest.json", manifest)
    return manifest


def _write_task_description(task_dir: Path, manifest: dict) -> None:
    source = manifest["source_code"]
    pipeline = manifest["pipeline_output"]
    launch = manifest["launch_command"]
    text = f"""# Claude Code 动态测试任务

## 任务身份

- 任务包版本：`{manifest['schema_version']}`
- 生成时间：`{manifest['generated_at']}`
- 模式：`claude-code`（不使用 Docker）
- 候选数：`{manifest['candidate_count']}`
- 设备：由 Claude Code 根据用户提供的开发板序列号执行预检

## 已提供的上下文

- 真实源码：`{source['link']}`，绝对路径：`{source['path']}`
- 完整静态产物：`{pipeline['workspace']}`
- 候选清单：`context/candidate_manifest.json`
- 其他静态产物：`context/static_artifacts/`
- 动态测试 Skill：`.claude/skills/openant-openharmony-dynamic/SKILL.md`
- 公开工具库：`../openharmony-public-tools/`

## 执行要求

请先阅读 `CLAUDE.md` 和 Skill，再逐个候选验证。不要直接相信 finding；先查源码和构建配置。所有命令、日志、源码引用和结论都必须写入 `results/`。

推荐启动命令（本任务包不会自动启动 Claude Code）：

```bash
{launch}
```

完成后，`results/summary.json` 应汇总每个候选的状态和限制。没有足够协议或设备证据时，使用 `REQUIRES_PROTOCOL_REVIEW`、`BLOCKED` 或 `INCONCLUSIVE`，不要为了得到 `CONFIRMED` 而猜测。
"""
    _write_text(task_dir / "TASK.md", text)


def create_claude_code_task(
    pipeline_output_path: str,
    output_dir: str | None = None,
    repo_path: str | None = None,
) -> dict:
    """Create a Claude Code task workspace and return its manifest."""
    pipeline_path = Path(pipeline_output_path).expanduser().resolve()
    if not pipeline_path.is_file():
        raise FileNotFoundError(f"pipeline_output.json not found: {pipeline_path}")
    pipeline = read_json(pipeline_path)
    if not isinstance(pipeline, dict):
        raise ValueError("pipeline_output.json must contain a JSON object")
    if "findings" in pipeline:
        normalize_results(pipeline, "findings")
    source = _resolve_source(repo_path, pipeline)

    parent = Path(output_dir).expanduser().resolve() if output_dir else pipeline_path.parent / "claude-code-runs"
    parent.mkdir(parents=True, exist_ok=True)
    run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    run_root = parent / run_id
    task_dir = run_root / "task"
    tools_dir = run_root / "openharmony-public-tools"
    context_dir = task_dir / "context"
    results_dir = task_dir / "results"
    task_dir.mkdir(parents=True)
    context_dir.mkdir()
    results_dir.mkdir()
    (task_dir / ".claude/skills/openant-openharmony-dynamic").mkdir(parents=True)

    # Keep the input JSON immutable in the task package.  The candidate manifest
    # is a filtered, auditable view; the complete file remains available too.
    pipeline_workspace = context_dir / "pipeline_output.json"
    shutil.copy2(pipeline_path, pipeline_workspace)
    candidate_manifest = _candidate_manifest(pipeline, pipeline_path, source)
    write_json(context_dir / "candidate_manifest.json", candidate_manifest)
    # The Web server passes the scan output directory itself as ``output_dir``.
    # Excluding that directory would prune every static artifact. Exclude only
    # the current run in that case; a distinct parent still needs exclusion to
    # avoid copying older Claude runs into the new task.
    excluded_dirs = (run_root,)
    if parent != pipeline_path.parent.resolve():
        excluded_dirs = (parent, run_root)
    artifact_manifest = _copy_static_artifacts(
        pipeline_path,
        context_dir / "static_artifacts",
        excluded_dirs=excluded_dirs,
    )
    write_json(context_dir / "artifact_manifest.json", {
        "schema_version": TASK_SCHEMA_VERSION,
        "source_directory": str(pipeline_path.parent),
        "files": artifact_manifest,
    })

    source_link = _link_or_record(task_dir / "source_code", source)
    source_metadata = {
        "path": str(source),
        "link": source_link.get("path", str(task_dir / "source_code")),
        "kind": source_link["kind"],
        "note": "The link exposes the real source repository; Claude Code should not modify it.",
    }
    write_json(context_dir / "source_code.json", source_metadata)

    tools_manifest = _build_public_tool_library(tools_dir)
    for filename in ("CLAUDE.md",):
        shutil.copyfile(_template_dir() / filename, task_dir / filename)
    shutil.copyfile(
        _template_dir() / "SKILL.md",
        task_dir / ".claude/skills/openant-openharmony-dynamic/SKILL.md",
    )

    launch_command = "cd " + shlex.quote(str(task_dir)) + " && claude --dangerously-skip-permissions"
    manifest = {
        "schema_version": TASK_SCHEMA_VERSION,
        "mode": "claude-code",
        "run_id": run_id,
        "generated_at": _utc_now(),
        "run_root": str(run_root),
        "task_workspace": str(task_dir),
        "public_tool_library": str(tools_dir),
        "launch_command": launch_command,
        "source_code": source_metadata,
        "pipeline_output": {
            "source": str(pipeline_path),
            "workspace": str(pipeline_workspace),
            "sha256": _sha256(pipeline_workspace),
        },
        "candidate_count": candidate_manifest["candidate_count"],
        "candidate_manifest": str(context_dir / "candidate_manifest.json"),
        "artifact_manifest": str(context_dir / "artifact_manifest.json"),
        "toolchain_manifest": str(tools_dir / "toolchain-manifest.json"),
        "tools": tools_manifest,
        "results_workspace": str(results_dir),
        "execution": {
            "docker": False,
            "claude_code_invoked_by_openant": False,
            "operator_must_start_command": True,
        },
    }
    write_json(task_dir / "task_manifest.json", manifest)
    write_json(results_dir / "summary.json", {
        "schema_version": TASK_SCHEMA_VERSION,
        "run_id": run_id,
        "status": "not_started",
        "candidate_count": candidate_manifest["candidate_count"],
        "candidates": [
            {"candidate_id": str(item.get("id", "")), "status": "not_started"}
            for item in candidate_manifest["candidates"]
        ],
    })
    _write_task_description(task_dir, manifest)
    return manifest
