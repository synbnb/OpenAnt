"""
Dynamic testing wrapper.

Runs Docker-isolated exploit tests against confirmed vulnerabilities.
Wraps ``utilities.dynamic_tester.run_dynamic_tests()``.
"""

import json
import os
import shutil
import sys

from core.schemas import DynamicTestStepResult, UsageInfo
from core.observability import print_chinese_log
from core.verdict_taxonomy import DYNAMIC_TESTABLE
from core import tracking
from utilities.file_io import normalize_results, read_json, write_json


def run_tests(
    pipeline_output_path: str,
    output_dir: str,
    max_retries: int = 3,
    repo_path: str | None = None,
    registry=None,
    llm_config_name: str | None = None,
    mode: str = "docker",
) -> DynamicTestStepResult:
    """Run dynamic exploit tests or prepare a Claude Code task workspace.

    ``docker`` preserves the existing isolated executor. ``claude-code`` does
    not call an LLM or Docker from OpenAnt; it creates a task workspace that
    the operator can open with Claude Code.

    Args:
        pipeline_output_path: Path to ``pipeline_output.json``.
        output_dir: Directory for test results.
        max_retries: Max retries per finding on error (default 3).
        registry: Pre-built PhaseRegistry passed down by the scanner.
            Standalone callers omit this and pay one config-load.
        llm_config_name: Name of the llm-config when registry is None.
        mode: ``docker`` (default) or ``claude-code``.

    Returns:
        DynamicTestStepResult with counts and paths.

    Raises:
        RuntimeError: If Docker is not available.
        FileNotFoundError: If pipeline_output_path doesn't exist.
    """
    if mode not in {"docker", "claude-code"}:
        raise ValueError(f"unsupported dynamic-test mode: {mode!r}; choose docker or claude-code")

    # Both modes need the static input, but Claude Code mode deliberately does
    # not require Docker or an OpenAnt LLM configuration.
    if not os.path.exists(pipeline_output_path):
        raise FileNotFoundError(
            f"pipeline_output.json not found: {pipeline_output_path}"
        )

    if mode == "claude-code":
        from utilities.dynamic_tester.claude_code import create_claude_code_task

        task = create_claude_code_task(
            pipeline_output_path=pipeline_output_path,
            output_dir=output_dir,
            repo_path=repo_path,
        )
        print_chinese_log(
            f"动态验证任务：Claude Code 工作目录已创建为 {task['task_workspace']}，"
            f"候选条目数={task['candidate_count']}；该模式只准备上下文和工具，不在 OpenAnt 内执行 Docker。",
            category="动态验证",
        )
        task_workspace = task["task_workspace"]
        return DynamicTestStepResult(
            results_json_path=task["candidate_manifest"],
            results_md_path=os.path.join(task_workspace, "TASK.md"),
            mode="claude-code",
            task_workspace=task_workspace,
            public_tool_library=task["public_tool_library"],
            task_manifest_path=os.path.join(task_workspace, "task_manifest.json"),
            candidate_manifest=task["candidate_manifest"],
            launch_command=task["launch_command"],
            findings_tested=task["candidate_count"],
        )

    # Check Docker availability for the existing executor only.
    if not shutil.which("docker"):
        raise RuntimeError(
            "Docker is required for dynamic testing but was not found. "
            "Install Docker and ensure it is running."
        )

    os.makedirs(output_dir, exist_ok=True)

    # Check how many findings to test
    pipeline_data = read_json(pipeline_output_path)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load
    # (presence-guarded) so the testability filter's `f.get(...)` is safe.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")
    findings = pipeline_data.get("findings", [])
    testable = [
        f for f in findings
        if f.get("stage2_verdict") in DYNAMIC_TESTABLE
    ]

    print(f"[Dynamic Test] {len(testable)} testable findings "
          f"(out of {len(findings)} total)", file=sys.stderr)
    print_chinese_log(
        f"动态验证筛选：从 {len(findings)} 个汇总问题中只选出 {len(testable)} 个"
        "满足第二阶段验证条件的条目，避免对未经确认的结果执行载荷。",
        category="动态验证",
    )

    if not testable:
        results_path = os.path.join(output_dir, "dynamic_test_results.json")
        write_json(results_path, {"findings_tested": 0, "results": []})
        print_chinese_log(
            f"动态验证自动结束：没有可测试条目，已写入 {results_path}，未调用运行时执行器。",
            category="动态验证",
        )

        return DynamicTestStepResult(
            results_json_path=results_path,
            findings_tested=0,
            usage=tracking.get_usage(),
        )

    # Import and run
    from utilities.dynamic_tester import run_dynamic_tests

    print(f"[Dynamic Test] Running with max_retries={max_retries}...",
          file=sys.stderr)
    print_chinese_log(
        f"动态验证执行：开始运行 {len(testable)} 个载荷，单条最多重试 {max_retries} 次；"
        "失败、阻塞和未复现会分别记录，不会直接当作安全。",
        category="动态验证",
    )

    results = run_dynamic_tests(
        pipeline_output_path,
        output_dir,
        max_retries=max_retries,
        repo_path=repo_path,
        registry=registry,
        llm_config_name=llm_config_name,
    )

    # Count outcomes
    confirmed = 0
    not_reproduced = 0
    blocked = 0
    inconclusive = 0
    errors = 0

    for r in results:
        status = r.get("status", "") if isinstance(r, dict) else getattr(r, "status", "")
        if status == "CONFIRMED":
            confirmed += 1
        elif status == "NOT_REPRODUCED":
            not_reproduced += 1
        elif status == "BLOCKED":
            blocked += 1
        elif status == "INCONCLUSIVE":
            inconclusive += 1
        elif status == "ERROR":
            errors += 1

    results_json_path = os.path.join(output_dir, "dynamic_test_results.json")
    results_md_path = os.path.join(output_dir, "dynamic_test_results.md")

    # Check which output files exist (dynamic_tester may write them itself)
    if not os.path.exists(results_md_path):
        results_md_path = None

    tracking.log_usage("Dynamic Test")

    print(f"\n[Dynamic Test] Results: {confirmed} confirmed, "
          f"{not_reproduced} not reproduced, {blocked} blocked, "
          f"{inconclusive} inconclusive, {errors} errors", file=sys.stderr)
    print_chinese_log(
        f"动态验证结果：确认={confirmed}，未复现={not_reproduced}，阻塞={blocked}，"
        f"待定={inconclusive}，错误={errors}；结果文件={results_json_path}。",
        category="动态验证",
    )

    return DynamicTestStepResult(
        results_json_path=results_json_path,
        results_md_path=results_md_path,
        findings_tested=len(testable),
        confirmed=confirmed,
        not_reproduced=not_reproduced,
        blocked=blocked,
        inconclusive=inconclusive,
        errors=errors,
        usage=tracking.get_usage(),
    )
