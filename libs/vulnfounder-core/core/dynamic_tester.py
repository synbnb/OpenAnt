"""动态验证模式的统一编排入口。

保留 Docker 隔离执行和 Claude Code 任务包，同时提供显式设备序列号、预算和
状态变更授权约束下的 OpenHarmony 真机 Agentic Loop。
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
    device_serial: str | None = None,
    device_hdc_path: str | None = None,
    dynamic_device_max_rounds: int = 16,
    dynamic_device_max_commands: int = 512,
    dynamic_device_max_wall_seconds: int = 20 * 60,
    dynamic_device_command_timeout_seconds: int = 30,
    dynamic_device_allow_state_change: bool = False,
    dynamic_device_canary_path: str = "/data/local/tmp/vulnfounder-canary",
    dynamic_device_carrier_root: str | None = None,
    dynamic_device_carrier_id: str | None = None,
    dynamic_device_carrier_bundle: str = "com.security.research.trigger",
    dynamic_device_carrier_ability: str = "EntryAbility",
    dynamic_device_execute_carrier: bool = False,
    dynamic_device_service_liveness_samples: int = 4,
    dynamic_device_service_liveness_interval_seconds: float = 0.5,
    dynamic_device_service_observation_delay_seconds: float = 0.8,
) -> DynamicTestStepResult:
    """Run dynamic exploit tests or prepare a Claude Code task workspace.

    ``docker`` preserves the existing isolated executor. ``claude-code`` does
    not call an LLM or Docker from VulnFounder; it creates a task workspace that
    the operator can open with Claude Code. ``openharmony-device`` executes a
    bounded, auditable Agentic Loop against an explicitly selected OpenHarmony
    development board and writes PoC/Exp evidence artifacts. Device state
    changes are disabled unless explicitly enabled.

    Args:
        pipeline_output_path: Path to ``pipeline_output.json``.
        output_dir: Directory for test results.
        max_retries: Max retries per finding on error (default 3).
        registry: Pre-built PhaseRegistry passed down by the scanner.
            Standalone callers omit this and pay one config-load.
        llm_config_name: Name of the llm-config when registry is None.
        mode: ``docker`` (default), ``claude-code`` or ``openharmony-device``.
        device_serial: Explicit HDC target serial for ``openharmony-device``.

    Returns:
        DynamicTestStepResult with counts and paths.

    Raises:
        RuntimeError: If Docker is not available.
        FileNotFoundError: If pipeline_output_path doesn't exist.
    """
    if mode not in {"docker", "claude-code", "openharmony-device"}:
        raise ValueError(
            f"unsupported dynamic-test mode: {mode!r}; "
            "choose docker, claude-code, or openharmony-device"
        )

    # Both modes need the static input, but Claude Code mode deliberately does
    # not require Docker or an VulnFounder LLM configuration.
    if not os.path.exists(pipeline_output_path):
        raise FileNotFoundError(
            f"pipeline_output.json not found: {pipeline_output_path}"
        )

    if mode == "openharmony-device":
        if not device_serial:
            raise ValueError(
                "openharmony-device mode requires --device/"
                "dynamic_device_serial; never implicitly select a board"
            )
        from utilities.dynamic_tester import materialize_dynamic_results, run_openharmony_device

        # Standalone CLI callers may not have a scanner-created registry. If a
        # local config exists, construct the dynamic-test binding so the device
        # Agentic Loop can use tools; if credentials/configuration are absent,
        # keep the read-only preflight usable and record a deterministic
        # BLOCKED/INCONCLUSIVE result instead of failing before collecting it.
        if registry is None:
            try:
                from utilities.llm import build_phase_registry, load_config_file, resolve_llm_config
                config_file = load_config_file()
                if config_file.llm_providers or config_file.llm_configs:
                    registry = build_phase_registry(
                        config_file,
                        resolve_llm_config(config_file, llm_config_name),
                    )
            except Exception:
                registry = None

        os.makedirs(output_dir, exist_ok=True)
        binding = registry.get("dynamic_test") if registry is not None else None

        def _device_event(stage: str, summary_text: str, _details: dict) -> None:
            # Keep Web/job logs readable; the complete task tree, command
            # output and model trace are written to the device run artifacts.
            print_chinese_log(
                f"真机 Agent[{stage}] {summary_text}",
                category="动态验证",
            )

        summary = run_openharmony_device(
            pipeline_output_path=pipeline_output_path,
            output_dir=output_dir,
            serial=device_serial,
            hdc_path=device_hdc_path,
            binding=binding,
            repo_path=repo_path,
            max_rounds=dynamic_device_max_rounds,
            max_commands=dynamic_device_max_commands,
            max_wall_seconds=dynamic_device_max_wall_seconds,
            command_timeout_seconds=dynamic_device_command_timeout_seconds,
            allow_state_change=dynamic_device_allow_state_change,
            canary_path=dynamic_device_canary_path,
            carrier_root=dynamic_device_carrier_root,
            carrier_id=dynamic_device_carrier_id,
            carrier_bundle=dynamic_device_carrier_bundle,
            carrier_ability=dynamic_device_carrier_ability,
            execute_carrier=dynamic_device_execute_carrier,
            service_liveness_samples=dynamic_device_service_liveness_samples,
            service_liveness_interval_seconds=dynamic_device_service_liveness_interval_seconds,
            service_observation_delay_seconds=dynamic_device_service_observation_delay_seconds,
            event_callback=_device_event,
        )
        pipeline_data = read_json(pipeline_output_path)
        repository = pipeline_data.get("repository", {})
        repository_name = repository.get("name", "unknown") if isinstance(repository, dict) else "unknown"
        results_json_path, results_md_path, results = materialize_dynamic_results(
            summary, output_dir, repository_name
        )
        counts: dict[str, int] = {}
        for item in results:
            counts[item.status] = counts.get(item.status, 0) + 1
        print_chinese_log(
            f"OpenHarmony 真机动态验证完成：设备={device_serial}，候选={len(results)}，"
            f"确认={counts.get('CONFIRMED', 0)}，阻塞={counts.get('BLOCKED', 0)}，"
            f"待定={counts.get('INCONCLUSIVE', 0)}；证据目录={summary.get('run_dir')}",
            category="动态验证",
        )
        return DynamicTestStepResult(
            results_json_path=results_json_path,
            results_md_path=results_md_path,
            mode="openharmony-device",
            task_workspace=summary.get("run_dir"),
            task_manifest_path=summary.get("manifest"),
            candidate_manifest=summary.get("decisions"),
            findings_tested=len(results),
            confirmed=counts.get("CONFIRMED", 0),
            not_reproduced=counts.get("NOT_REPRODUCED", 0),
            blocked=counts.get("BLOCKED", 0),
            inconclusive=counts.get("INCONCLUSIVE", 0),
            errors=counts.get("ERROR", 0),
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
            f"候选条目数={task['candidate_count']}；该模式只准备上下文和工具，不在 VulnFounder 内执行 Docker。",
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
