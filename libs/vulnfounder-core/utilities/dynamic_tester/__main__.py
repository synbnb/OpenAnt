"""CLI entry point for Docker, Claude Code or OpenHarmony 真机动态验证。"""

import argparse
import os
import sys

from utilities.dynamic_tester import run_dynamic_tests


def main():
    parser = argparse.ArgumentParser(
        description="Dynamic vulnerability testing using Docker, Claude Code or an OpenHarmony device",
    )
    parser.add_argument(
        "pipeline_output",
        help="Path to pipeline_output.json from the static analysis pipeline",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for results (default: same as input file)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retries per finding on ERROR status (default: 3)",
    )
    parser.add_argument(
        "--llm-config",
        default=None,
        help="Named VulnFounder LLM configuration used by the Agentic Loop",
    )
    parser.add_argument(
        "--repo-path",
        default=None,
        help="Source repository path (required by claude-code mode)",
    )
    parser.add_argument(
        "--mode",
        choices=["docker", "claude-code", "openharmony-device"],
        default="docker",
        help="Execution mode: docker (default), claude-code, or openharmony-device",
    )
    parser.add_argument("--device", default=None, help="Explicit HDC device serial (required by openharmony-device)")
    parser.add_argument("--hdc", default=None, help="HDC executable path (optional; otherwise project toolchain/PATH)")
    parser.add_argument("--max-rounds", type=int, default=16, help="Agentic loop maximum rounds for openharmony-device")
    parser.add_argument("--max-commands", type=int, default=512, help="Maximum device commands for openharmony-device")
    parser.add_argument("--device-timeout", type=int, default=30, help="Per-device-command timeout in seconds")
    parser.add_argument("--device-wall-timeout", type=int, default=1200, help="Total device run timeout in seconds")
    parser.add_argument("--allow-state-change", action="store_true", help="Explicitly allow state-changing device commands")
    parser.add_argument("--canary-path", default="/data/local/tmp/vulnfounder-canary", help="Safe canary root on the device")
    parser.add_argument("--carrier-root", default=None, help="Reviewed HAP carrier root; each finding must have <id>/manifest.txt and entry-default-signed.hap")
    parser.add_argument("--carrier-id", default=None, help="Only execute the reviewed carrier for this finding ID")
    parser.add_argument("--carrier-bundle", default="com.security.research.trigger", help="Reviewed carrier bundle name")
    parser.add_argument("--carrier-ability", default="EntryAbility", help="Reviewed carrier Ability name")
    parser.add_argument("--execute-carrier", action="store_true", help="Explicitly execute reviewed HAP carriers; requires --allow-state-change")
    parser.add_argument(
        "--service-liveness-samples",
        type=int,
        default=4,
        help="观察 service_crash 载体的 PID 采样次数（1-8，默认 4）",
    )
    parser.add_argument(
        "--service-liveness-interval",
        type=float,
        default=0.5,
        help="service_crash PID 采样间隔秒数（0-5，默认 0.5）",
    )
    parser.add_argument(
        "--service-observation-delay",
        type=float,
        default=0.8,
        help="载体发送后延迟日志采样的等待秒数（0-5，默认 0.8）",
    )

    args = parser.parse_args()

    if args.mode == "claude-code":
        from core.dynamic_tester import run_tests

        result = run_tests(
            args.pipeline_output,
            args.output_dir,
            max_retries=args.max_retries,
            repo_path=args.repo_path,
            llm_config_name=args.llm_config,
            mode="claude-code",
        )
        print("Claude Code task prepared")
        print(f"  Task workspace: {result.task_workspace}")
        print(f"  Public tools:   {result.public_tool_library}")
        print(f"  Candidates:     {result.findings_tested}")
        print(f"  Launch:         {result.launch_command}")
        return

    if args.mode == "openharmony-device":
        from core.dynamic_tester import run_tests

        if not args.device:
            parser.error("--mode openharmony-device requires --device SERIAL")
        result = run_tests(
            args.pipeline_output,
            args.output_dir or os.path.dirname(os.path.abspath(args.pipeline_output)),
            max_retries=args.max_retries,
            repo_path=args.repo_path,
            llm_config_name=args.llm_config,
            mode="openharmony-device",
            device_serial=args.device,
            device_hdc_path=args.hdc,
            dynamic_device_max_rounds=args.max_rounds,
            dynamic_device_max_commands=args.max_commands,
            dynamic_device_max_wall_seconds=args.device_wall_timeout,
            dynamic_device_command_timeout_seconds=args.device_timeout,
            dynamic_device_allow_state_change=args.allow_state_change,
            dynamic_device_canary_path=args.canary_path,
            dynamic_device_carrier_root=args.carrier_root,
            dynamic_device_carrier_id=args.carrier_id,
            dynamic_device_carrier_bundle=args.carrier_bundle,
            dynamic_device_carrier_ability=args.carrier_ability,
            dynamic_device_execute_carrier=args.execute_carrier,
            dynamic_device_service_liveness_samples=args.service_liveness_samples,
            dynamic_device_service_liveness_interval_seconds=args.service_liveness_interval,
            dynamic_device_service_observation_delay_seconds=args.service_observation_delay,
        )
        print("OpenHarmony device dynamic test completed")
        print(f"  Results:  {result.results_json_path}")
        print(f"  Evidence: {result.task_workspace}")
        print(f"  Candidates: {result.findings_tested}")
        print(f"  Confirmed: {result.confirmed}")
        print(f"  Blocked: {result.blocked}")
        print(f"  Inconclusive: {result.inconclusive}")
        return

    results = run_dynamic_tests(
        args.pipeline_output, args.output_dir,
        max_retries=args.max_retries,
        repo_path=args.repo_path,
    )

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n" + "=" * 50)
    print("DYNAMIC TEST SUMMARY")
    print("=" * 50)
    for status in ["CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"]:
        if status in counts:
            print(f"  {status}: {counts[status]}")
    print(f"  TOTAL: {len(results)}")
    print("=" * 50)


if __name__ == "__main__":
    main()
