"""CLI entry point for Docker testing or Claude Code task preparation."""

import argparse
import sys

from utilities.dynamic_tester import run_dynamic_tests


def main():
    parser = argparse.ArgumentParser(
        description="Dynamic vulnerability testing using Docker or Claude Code",
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
        "--repo-path",
        default=None,
        help="Source repository path (required by claude-code mode)",
    )
    parser.add_argument(
        "--mode",
        choices=["docker", "claude-code"],
        default="docker",
        help="Execution mode: docker (default) or claude-code",
    )

    args = parser.parse_args()

    if args.mode == "claude-code":
        from core.dynamic_tester import run_tests

        result = run_tests(
            args.pipeline_output,
            args.output_dir,
            max_retries=args.max_retries,
            repo_path=args.repo_path,
            mode="claude-code",
        )
        print("Claude Code task prepared")
        print(f"  Task workspace: {result.task_workspace}")
        print(f"  Public tools:   {result.public_tool_library}")
        print(f"  Candidates:     {result.findings_tested}")
        print(f"  Launch:         {result.launch_command}")
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
