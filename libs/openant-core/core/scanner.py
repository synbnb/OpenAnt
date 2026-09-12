"""
All-in-one scanner orchestrator.

Runs the full pipeline:

    Parse → App Context → Enhance → Detect → Verify
        → Build pipeline_output → Dynamic Test → Report

This is the implementation behind ``open-ant scan <path>``.

Each step:
 1. Writes its own ``{step}.report.json`` via ``step_context``.
 2. Can be individually skipped with ``--no-{step}`` flags.
 3. Feeds its outputs into the next step.

On completion, a final ``scan.report.json`` aggregates all step reports.
"""

import json
import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from core.schemas import (
    ScanResult, AnalysisMetrics, UsageInfo, StepReport,
)
from core.observability import print_chinese_log
from core.step_report import step_context
from core import tracking
from utilities.file_io import read_json, write_json

# Import app context generator (optional)
try:
    from context.application_context import (
        generate_application_context,
        save_context,
    )
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False


def _print_chinese_log(message: str) -> None:
    """Emit a user-facing Chinese explanation without replacing raw logs.

    The Web UI streams stderr line-by-line.  Existing English progress output is
    intentionally left untouched for compatibility and troubleshooting; these
    additive lines explain the decision behind each operation in Chinese.
    ``flush=True`` is important here because the Web server forwards the line as
    soon as it arrives rather than waiting for the whole scan to finish.
    """
    print_chinese_log(message)


def _source_revision_for_graph(repo_path: str, requested: str | None) -> str:
    """Resolve the source identity used by derived graph artifacts.

    The caller-provided revision remains authoritative.  For local scans that
    do not pass one, capture the checkout HEAD so a resumed scan cannot
    silently reuse an effective graph from another checkout.  Non-Git source
    directories receive the explicit ``unknown`` marker rather than a null
    provenance field.
    """
    if requested:
        return str(requested)
    try:
        completed = subprocess.run(
            ["git", "-C", repo_path, "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    revision = (completed.stdout or "").strip()
    return revision if completed.returncode == 0 and revision else "unknown"


def _build_config_id(
    *,
    platform: str,
    effective_platform: str,
    language: str,
    languages: list[str] | None,
    processing_level: str,
    skip_tests: bool,
    library_mode: bool,
) -> str:
    payload = {
        "platform": platform,
        "effective_platform": effective_platform,
        "language": language,
        "languages": list(languages or []),
        "processing_level": processing_level,
        "skip_tests": bool(skip_tests),
        "library_mode": bool(library_mode),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "openant-build:" + hashlib.sha256(encoded).hexdigest()[:20]


def _run_clang_semantic_batch(
    *,
    repo_path: str,
    output_dir: str,
    source_revision: str,
    graph_build_config_id: str,
    compile_commands: str | None,
    build_status: str,
    max_files: int,
    timeout_seconds: int,
    auto_context: bool,
    batch_size: int,
    force_recompute: bool,
    dependency_retry_attempts: int,
    dependency_retry_low_trust: bool,
    definition_load_max_files: int,
    priority_sources: list[str] | None = None,
) -> list[str]:
    """Run the bounded Clang fact extractor for each parsed graph.

    This is explicitly opt-in because a real OpenHarmony compilation database
    is not always present.  Every graph gets an artifact, including a
    ``no_compile_commands`` result, so missing build context is observable.
    """
    from core.platforms.openharmony.clang_batch_extractor import (
        extract_clang_semantic_overlay,
    )

    overlays: list[str] = []
    for _language, graph_dir in resolve_call_graph_dirs(output_dir).items():
        native_path = os.path.join(graph_dir, "call_graph.json")
        try:
            native = read_json(native_path)
        except (OSError, json.JSONDecodeError, TypeError):
            continue
        functions = native.get("functions", {}) if isinstance(native, Mapping) else {}
        if not isinstance(functions, Mapping):
            functions = {}
        artifact = extract_clang_semantic_overlay(
            repo_path,
            functions,
            compile_commands=compile_commands,
            source_revision=source_revision,
            build_status=build_status,
            max_files=max_files,
            timeout_seconds=timeout_seconds,
            auto_context=auto_context,
            context_output_dir=graph_dir,
            batch_size=batch_size,
            force_recompute=force_recompute,
            dependency_retry_attempts=dependency_retry_attempts,
            dependency_retry_low_trust=dependency_retry_low_trust,
            definition_load_max_files=definition_load_max_files,
            priority_sources=priority_sources,
        )
        artifact["build_config_id"] = graph_build_config_id
        artifact["source_revision"] = source_revision
        artifact["graph_directory"] = graph_dir
        path = os.path.join(graph_dir, "clang_semantic_overlay.json")
        write_json(path, artifact, indent=2)
        overlays.append(path)
    return overlays


def _gap_priority_sources(report: Mapping[str, Any] | None) -> list[str]:
    """Extract unique source files for unresolved ledger sites.

    This is deliberately a scheduling hint for the bounded Clang pass. It
    consumes only the immutable pre-Clang snapshot and never turns a gap into
    an accepted edge. If the report has no site-level file, the extractor
    retains its normal compilation-database order.
    """
    if not isinstance(report, Mapping):
        return []
    sites = report.get("sites")
    if not isinstance(sites, list):
        return []
    values: list[str] = []
    # Prefer sites still unrepaired after the native graph. If that field is
    # absent in an older report, fall back to all edge-missing sites.
    selected = [
        item for item in sites
        if isinstance(item, Mapping) and bool(item.get("ledger_unrepaired"))
    ]
    if not selected:
        selected = [
            item for item in sites
            if isinstance(item, Mapping) and bool(item.get("ledger_edge_missing"))
        ]
    # The gap report already aggregates source-file frequencies. Prefer files
    # with the largest number of unresolved sites so a small Clang budget
    # attacks the highest-yield translation units first; retain a stable
    # lexical fallback for older reports without that summary.
    source_counts = report.get("summary", {})
    source_counts = (
        source_counts.get("unrepaired_source_file_counts", {})
        if isinstance(source_counts, Mapping)
        else {}
    )
    if isinstance(source_counts, Mapping) and source_counts:
        ordered_files = [
            str(path) for path, _count in sorted(
                source_counts.items(),
                key=lambda item: (-int(item[1] or 0), str(item[0])),
            )
            if str(path) and str(path) != "<unknown>"
        ]
        for value in ordered_files:
            if value not in values:
                values.append(value)
    for item in selected:
        value = item.get("file") or item.get("source_file")
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        if value not in values:
            values.append(value)
    return values


def _write_call_graph_gap_report(
    *,
    output_dir: str,
    effective_graphs: list[Mapping[str, Any]],
    repo_path: str,
    source_revision: str,
    build_config_id: str,
    filename: str = "call_graph_gap_report.json",
) -> tuple[str | None, dict[str, Any]]:
    """Write the P1 per-site gap aggregation after each graph refresh."""
    if not effective_graphs:
        return None, {}
    from core.call_graph_gap_report import write_call_graph_gap_report

    graph_paths = [
        item.get("path")
        for item in effective_graphs
        if isinstance(item, Mapping) and item.get("path")
    ]
    report_path = os.path.join(output_dir, filename)
    report = write_call_graph_gap_report(
        report_path,
        graph_paths,
        repository=repo_path,
        source_revision=source_revision,
        build_config_id=build_config_id,
    )
    return report_path, report


def _write_openharmony_gap_tasks(
    *,
    result: ScanResult,
    output_dir: str,
    repo_path: str,
    source_revision: str,
    build_config_id: str,
    effective_platform: str,
    effective_graphs: list[Mapping[str, Any]] | None = None,
    gap_report: Mapping[str, Any] | None = None,
) -> tuple[str | None, dict[str, Any]]:
    """Refresh the gap report and emit the P3 scheduling queue.

    This is intentionally deterministic and runs after optional projection, so
    task status reflects the effective graph version actually consumed by
    enhancement and Stage 1.
    """
    if effective_platform != "openharmony":
        return None, {}
    try:
        from core.call_graph_facts import refresh_effective_call_graphs
        from core.platforms.openharmony.gap_tasks import write_gap_tasks

        # Always refresh once here. ``effective_graphs`` captured before the
        # optional projection may otherwise hide newly accepted overlay edges.
        graphs = refresh_effective_call_graphs(
            output_dir,
            source_revision=source_revision,
            build_config_id=build_config_id,
            include_persisted_overlays=True,
        )
        refreshed_gap_path, refreshed_gap = _write_call_graph_gap_report(
            output_dir=output_dir,
            effective_graphs=graphs,
            repo_path=repo_path,
            source_revision=source_revision,
            build_config_id=build_config_id,
        )
        graph_versions: list[str] = []
        for item in graphs or []:
            path = item.get("path") if isinstance(item, Mapping) else None
            if not path:
                continue
            try:
                payload = read_json(path)
            except Exception:
                continue
            version = payload.get("graph_version") if isinstance(payload, Mapping) else None
            if version:
                graph_versions.append(str(version))
        report = refreshed_gap if isinstance(refreshed_gap, Mapping) else gap_report
        tasks_path = os.path.join(output_dir, "call_graph_gap_tasks.json")
        tasks = write_gap_tasks(
            tasks_path,
            report,
            repository=repo_path,
            source_revision=source_revision,
            build_config_id=build_config_id,
            graph_versions=graph_versions,
        )
        result.call_graph_gap_report_path = refreshed_gap_path or result.call_graph_gap_report_path
        result.effective_call_graph_paths = [
            str(item.get("path"))
            for item in graphs
            if isinstance(item, Mapping) and item.get("path")
        ]
        result.call_graph_gap_tasks_path = tasks_path
        return tasks_path, tasks
    except Exception as exc:
        print(f"  WARNING: OpenHarmony gap task generation failed: {exc}", file=sys.stderr)
        _print_chinese_log(f"P3 缺口任务队列生成失败（{exc}），保留已有调用图和缺口报告。")
        return None, {"status": "failed", "error": str(exc)[:500]}


def _write_openharmony_analysis_feedback(
    *,
    result: ScanResult,
    output_dir: str,
    dataset_path: str,
    results_path: str | None,
    gap_tasks_path: str | None,
    repo_path: str,
    source_revision: str,
    build_config_id: str,
    effective_platform: str,
) -> tuple[str | None, dict[str, Any]]:
    """Persist P3 facts learned by enhancement/Stage 1/Stage 2.

    This is intentionally run after the optional verification step, so the
    artifact can describe the exact Stage 1 result that was consumed by Stage 2.
    It is an audit/next-work queue, not a hidden graph mutation.
    """
    if effective_platform != "openharmony":
        return None, {}
    try:
        from core.platforms.openharmony.analysis_feedback import write_analysis_feedback

        dataset = read_json(dataset_path)
        results = read_json(results_path) if results_path and os.path.exists(results_path) else None
        gap_tasks = read_json(gap_tasks_path) if gap_tasks_path and os.path.exists(gap_tasks_path) else None
        graph_versions: list[str] = []
        for path in result.effective_call_graph_paths:
            try:
                graph = read_json(path)
            except Exception:
                continue
            if isinstance(graph, Mapping) and graph.get("graph_version"):
                graph_versions.append(str(graph["graph_version"]))
        output_path = os.path.join(output_dir, "analysis_feedback.json")
        payload = write_analysis_feedback(
            output_path,
            dataset,
            results=results,
            gap_tasks=gap_tasks,
            repository=repo_path,
            source_revision=source_revision,
            build_config_id=build_config_id,
            graph_versions=graph_versions,
        )
        result.analysis_feedback_path = output_path
        return output_path, payload
    except Exception as exc:
        print(f"  WARNING: OpenHarmony analysis feedback failed: {exc}", file=sys.stderr)
        _print_chinese_log(f"P3 分析反馈产物生成失败（{exc}），不改变当前分析结果。")
        return None, {"status": "failed", "error": str(exc)[:500]}


def _write_clang_p1_acceptance_report(
    *,
    output_dir: str,
    overlay_paths: list[str],
    pre_clang_gap_report_path: str | None,
    repo_path: str,
    source_revision: str,
) -> tuple[str | None, dict[str, Any]]:
    """Correlate Clang batch facts with the pre-Clang unresolved-site ledger.

    The report is intentionally diagnostic.  It does not alter the effective
    graph or dataset.  The gap report must be the snapshot taken before the
    Clang overlay is projected; otherwise repaired sites would disappear from
    the comparison input.
    """
    if not overlay_paths or not pre_clang_gap_report_path:
        return None, {}
    gap_path = Path(pre_clang_gap_report_path)
    if not gap_path.is_file():
        return None, {}
    from core.platforms.openharmony.clang_p1_validation import (
        build_clang_batch_acceptance_report,
    )

    graph_reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for overlay_path in overlay_paths:
        batch_path = Path(overlay_path)
        graph_dir = batch_path.parent
        ledger_path = graph_dir / "callsite_ledger.json"
        if not ledger_path.is_file():
            ledger_path = graph_dir / "call_graph_residuals.json"
        if not ledger_path.is_file():
            errors.append({
                "overlay": str(batch_path),
                "reason": "callsite_ledger_missing",
            })
            continue
        try:
            graph_reports.append(
                build_clang_batch_acceptance_report(
                    ledger_path,
                    gap_path,
                    batch_path,
                    source_revision=source_revision,
                )
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            errors.append({
                "overlay": str(batch_path),
                "reason": str(exc)[:500],
            })

    if not graph_reports and errors:
        return None, {"errors": errors}
    outcome_counts: dict[str, int] = {}
    total_unresolved = 0
    total_in_scope = 0
    total_unindexed = 0
    for item in graph_reports:
        scope = item.get("scope", {})
        if isinstance(scope, Mapping):
            total_unresolved += int(scope.get("unresolved_input_sites", 0) or 0)
            total_in_scope += int(scope.get("unresolved_sites_in_batch_scope", 0) or 0)
        unindexed = item.get("unindexed_callers", {})
        if isinstance(unindexed, Mapping):
            total_unindexed += int(unindexed.get("count", 0) or 0)
        outcomes = item.get("unresolved_site_outcomes", {})
        counts = outcomes.get("counts", {}) if isinstance(outcomes, Mapping) else {}
        if isinstance(counts, Mapping):
            for key, value in counts.items():
                try:
                    outcome_counts[str(key)] = outcome_counts.get(str(key), 0) + int(value or 0)
                except (TypeError, ValueError):
                    continue
    report = {
        "schema_version": 1,
        "report_type": "openharmony_clang_p1_acceptance",
        "repository": repo_path,
        "source_revision": source_revision,
        "comparison_input": {
            "gap_report": str(gap_path),
            "gap_snapshot": "pre_clang_projection",
        },
        "graphs": graph_reports,
        "errors": errors,
        "summary": {
            "graphs": len(graph_reports),
            "unresolved_input_sites": total_unresolved,
            "unresolved_sites_in_batch_scope": total_in_scope,
            "semantic_fact_observed_candidate_only": outcome_counts.get(
                "semantic_fact_observed_candidate_only", 0
            ),
            "in_batch_scope_not_matched": outcome_counts.get(
                "in_batch_scope_not_matched", 0
            ),
            "outside_batch_scope": outcome_counts.get("outside_batch_scope", 0),
            "unindexed_callers": total_unindexed,
            "errors": len(errors),
        },
        "interpretation": (
            "该报告只说明 Clang 批次对原始未决站点观察到了哪些语义事实；"
            "它不改变有效图，也不把 candidate-only 事实提升为产品 strict 证据。"
        ),
    }
    report_path = os.path.join(output_dir, "clang_p1_acceptance_report.json")
    write_json(report_path, report, indent=2)
    return report_path, report


_CALL_GRAPH_REVIEW_COUNTERS = (
    "attempts",
    "parsed_decisions",
    "accepted",
    "kept_unresolved",
    "rejected",
)


def _counter_value(summary, key: str) -> int:
    """Read a report counter without allowing malformed JSON to break a scan."""
    if not isinstance(summary, Mapping):
        return 0
    try:
        return max(0, int(summary.get(key, 0) or 0))
    except (TypeError, ValueError):
        return 0


def _iterative_review_counters(report):
    """Collect one-shot review counters nested inside an iterative report.

    Iterative recovery originally exposed only BFS counters at the report root
    (for example ``sites_scheduled`` and ``accepted_decisions``).  Each round
    still contains the complete one-shot review result, so use those nested
    summaries as the source of truth when normalising the stage report.  The
    validation-list fallback keeps older test and production artifacts useful
    even if a round did not persist a nested summary.
    """
    totals = {key: 0 for key in _CALL_GRAPH_REVIEW_COUNTERS}
    present = set()
    if not isinstance(report, Mapping):
        return totals, present

    # A stage aggregate wraps one iterative report per language under
    # ``reports[*].report``. A per-language report stores ``rounds`` at its
    # own root. Normalize both shapes so historical and current artifacts use
    # the same counter source.
    report_sources = []
    if isinstance(report.get("rounds"), list):
        report_sources.append(report)
    children = report.get("reports")
    if isinstance(children, list):
        report_sources.extend(
            item.get("report")
            for item in children
            if isinstance(item, Mapping) and isinstance(item.get("report"), Mapping)
        )

    for report_source in report_sources:
        rounds = report_source.get("rounds", [])
        if not isinstance(rounds, list):
            continue
        for round_item in rounds:
            if not isinstance(round_item, Mapping):
                continue
            review = round_item.get("review")
            if not isinstance(review, Mapping):
                review = {}
            nested = review.get("summary")
            if isinstance(nested, Mapping):
                for key in _CALL_GRAPH_REVIEW_COUNTERS:
                    if key in nested:
                        totals[key] += _counter_value(nested, key)
                        present.add(key)
                continue

            # Early iterative artifacts persisted the validation lists but not
            # ``review.summary``. Recover the decision counters from those
            # lists.
            validation = review.get("validation")
            if not isinstance(validation, Mapping):
                continue
            list_keys = {
                "accepted": "accepted",
                "kept_unresolved": "kept_unresolved",
                "rejected": "rejected",
            }
            parsed = 0
            for counter, list_name in list_keys.items():
                values = validation.get(list_name)
                if isinstance(values, list):
                    count = len(values)
                    totals[counter] += count
                    present.add(counter)
                    parsed += count
            if parsed or any(name in validation for name in list_keys.values()):
                totals["parsed_decisions"] += parsed
                present.add("parsed_decisions")

    return totals, present


def _normalise_call_graph_review_summary(report, *, iterative: bool):
    """Return a backwards-compatible, truthful summary for an optional stage."""
    raw = report.get("summary", {}) if isinstance(report, Mapping) else {}
    if not isinstance(raw, Mapping):
        return {}
    normalized = dict(raw)
    if not iterative:
        return normalized

    nested, nested_present = _iterative_review_counters(report)
    for key in _CALL_GRAPH_REVIEW_COUNTERS:
        if key in nested_present:
            normalized[key] = nested[key]

    # Compatibility with iterative artifacts written before review counters
    # were added.  Canonical BFS counters remain authoritative for aliases;
    # a nested counter, when available, always wins over a stale zero.
    if "attempts" not in nested_present and _counter_value(raw, "attempts") == 0:
        normalized["attempts"] = _counter_value(raw, "llm_calls")
    if "accepted" not in nested_present and _counter_value(raw, "accepted") == 0:
        normalized["accepted"] = _counter_value(raw, "accepted_decisions")
    if "parsed_decisions" not in nested_present and _counter_value(raw, "parsed_decisions") == 0:
        parsed = (
            _counter_value(normalized, "accepted")
            + _counter_value(normalized, "kept_unresolved")
            + _counter_value(normalized, "rejected")
        )
        if parsed == 0:
            parsed = _counter_value(raw, "accepted_decisions")
        normalized["parsed_decisions"] = parsed
    if "kept_unresolved" not in nested_present and _counter_value(raw, "kept_unresolved") == 0:
        worklist = _counter_value(raw, "worklist_sites")
        accepted = _counter_value(normalized, "accepted")
        rejected = _counter_value(normalized, "rejected")
        unreviewed = _counter_value(raw, "unreviewed_sites")
        normalized["kept_unresolved"] = max(
            0,
            worklist - accepted - rejected - unreviewed,
        )
    return normalized



def resolve_call_graph_dirs(output_dir: str) -> dict[str | None, str]:
    """Directories holding a usable ``call_graph.json``, keyed by language.

    Multi-language runs write one per language under ``<run>/<lang>/`` and
    record them in ``call_graphs.json``; single-language runs keep the legacy
    flat layout. Both are resolved here so the re-filter does not need to know
    which shape it is looking at.

    Entries are validated against the filesystem rather than trusted from the
    index — a stale index would otherwise point the filter at a graph that no
    longer exists.

    Returns:
        ``{language: dir}``, or ``{None: run_dir}`` for the legacy layout, or
        ``{}`` when no call graph exists anywhere.
    """
    index_path = os.path.join(output_dir, "call_graphs.json")
    if os.path.exists(index_path):
        try:
            index = read_json(index_path)
        except (json.JSONDecodeError, OSError):
            index = {}
        dirs: dict[str | None, str] = {}
        for language, rel in (index or {}).items():
            candidate = os.path.join(output_dir, rel)
            if os.path.isfile(candidate):
                dirs[language] = os.path.dirname(candidate)
        return dirs

    if os.path.isfile(os.path.join(output_dir, "call_graph.json")):
        return {None: output_dir}
    return {}



def scope_entry_points_to_units(entry_point_ids, units: list[dict]) -> set:
    """Restrict reachability seed ids to those present in *units*.

    ``apply_reachability_filter`` unions ``extra_entry_points`` into its seed
    set BEFORE evaluating the empty-seed safety net. Passing the whole run's
    promoted entry-point or semantic seed ids to a single language's filter
    therefore hands it seeds that do
    not exist in that language's call graph: the seed set is non-empty, so the
    "no entry points — pass everything through rather than black out" guard
    never fires, BFS reaches nothing, and every unit of that language is
    dropped from the scan while it still reports success.

    Scoping per partition restores the guard: a language with no promoted or
    semantic-seed units of its own gets an EMPTY seed set, which is exactly the
    condition the safety net is written to detect.
    """
    if not entry_point_ids:
        return set()
    unit_ids = {u.get("id") for u in units if u.get("id")}
    return {eid for eid in entry_point_ids if eid in unit_ids}


def partition_units_by_language(units: list[dict]) -> dict[str | None, list[dict]]:
    """Group units by their ``language`` stamp.

    Units from a legacy single-language dataset carry no stamp and group under
    ``None``. The partition is lossless: every input unit lands in exactly one
    bucket, so re-filtering per language cannot silently drop units.
    """
    parts: dict[str | None, list[dict]] = {}
    for unit in units:
        parts.setdefault(unit.get("language"), []).append(unit)
    return parts


def _sync_platform_profile_file_counts(
    result: ScanResult,
    output_dir: str,
) -> None:
    """Copy parser file-count coverage into the persisted platform profile.

    OpenHarmony profile detection runs before parsing, so its initial
    ``CoverageReport`` necessarily starts at zero.  The platform-aware C
    parser later reports the authoritative file counts in
    ``platform_coverage.coverage``.  Keep this synchronization deliberately
    narrow: only the three file-count fields are updated here; the profile's
    detection evidence and build metadata remain unchanged.
    """
    profile = result.platform_profile
    scope = result.platform_coverage
    if not isinstance(profile, dict) or not isinstance(scope, dict):
        return

    coverage = scope.get("coverage")
    if not isinstance(coverage, dict):
        return

    counts: dict[str, int] = {}
    for field in ("discovered_files", "eligible_files", "parsed_files"):
        value = coverage.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return
        counts[field] = value

    profile_coverage = profile.setdefault("coverage", {})
    if not isinstance(profile_coverage, dict):
        return
    profile_coverage.update(counts)
    write_json(os.path.join(output_dir, "platform_profile.json"), profile)


def scan_repository(
    repo_path: str,
    output_dir: str,
    language: str = "auto",
    platform: str = "auto",
    languages: list[str] | None = None,
    excluded_languages: dict[str, str] | None = None,
    strict_languages: bool = False,
    processing_level: str = "reachable",
    verify: bool = False,
    generate_context: bool = True,
    generate_report: bool = True,
    skip_tests: bool = True,
    limit: int | None = None,
    llm_config_name: str | None = None,
    enhance: bool = True,
    enhance_mode: str = "agentic",
    dynamic_test: bool = False,
    dynamic_test_mode: str = "docker",
    workers: int = 8,
    backoff_seconds: int = 30,
    repo_name: str | None = None,
    repo_url: str | None = None,
    commit_sha: str | None = None,
    diff_manifest: str | None = None,
    llm_reachability: bool = False,
    llm_reachability_max_code_bytes: int = 1500,
    stop_after: str | None = None,
    llm_call_graph_recovery: bool = False,
    llm_call_graph_iterative_recovery: bool = False,
    llm_call_graph_candidate_review: bool = False,
    llm_call_graph_projection: bool = False,
    openharmony_dispatch_code_evidence: bool = False,
    clang_semantic: bool = False,
    clang_compile_commands: str | None = None,
    clang_build_status: str = "compile_database",
    clang_max_files: int = 128,
    clang_timeout_seconds: int = 30,
    clang_auto_context: bool = True,
    clang_batch_size: int = 16,
    clang_force_recompute: bool = False,
    clang_dependency_retry_attempts: int = 1,
    clang_dependency_retry_low_trust: bool = False,
    clang_definition_load_max_files: int = 16,
    library_mode: bool = False,
    scope_manifest: str | None = None,
) -> ScanResult:
    """Scan a repository for vulnerabilities.

    Orchestrates the full OpenAnt pipeline:

    1. **Parse** repository into a dataset
    2. **App Context** — generate application context (optional)
    3. **Enhance** — add security context via agentic/single-shot LLM (optional)
    4. **Detect** — Stage 1 vulnerability detection
    5. **Verify** — Stage 2 attacker simulation (optional)
    6. **Build pipeline_output.json** — bridge format for reports + dynamic tests
    7. **LLM call-edge recovery** — advisory OpenHarmony residual review,
       either one-shot or entry-driven iterative (optional)
    8. **LLM candidate-edge review** — separate advisory candidate review (optional)
    9. **Dispatch-code evidence** — deterministic OpenHarmony selector-value extraction (optional)
    10. **Dynamic Test** — Docker-isolated testing or Claude Code task preparation (optional, off by default)
    11. **Report** — summary + disclosure documents (optional, merges dynamic test results)

    Args:
        repo_path: Path to the repository to scan.
        output_dir: Directory for all output files.
        language: ``"auto"``, ``"python"``, ``"javascript"``, ``"go"``, or ``"c"``.
        platform: ``"auto"``, ``"generic"``, or ``"openharmony"``. Auto mode
            promotes to OpenHarmony only when the local profile reaches its
            confidence threshold; the effective C parser mode is then recorded
            in the result and ``platform_profile.json``.
        languages: Optional explicit list of languages to parse. With more than
            one entry the parse fans out per language into ``<output_dir>/<lang>/``
            and the datasets are merged; every later stage still runs ONCE over
            the merged dataset. Omitted or single-element means the unchanged
            single-language path.
        strict_languages: If True, abort when any selected language fails to
            parse instead of continuing with the survivors.
        processing_level: ``"all"``, ``"reachable"``, ``"codeql"``, or ``"exploitable"``.
        verify: If True, run Stage 2 attacker simulation after detection.
        generate_context: If True, generate application context (reduces FP).
        generate_report: If True, generate summary + disclosure reports.
        skip_tests: If True, exclude test files from parsing (default: True).
        limit: Max number of units to analyze.
        enhance: If True, run agentic/single-shot context enhancement.
        enhance_mode: ``"agentic"`` (thorough) or ``"single-shot"`` (fast).
        dynamic_test: If True, run dynamic testing or prepare a Claude Code task.
        dynamic_test_mode: ``"docker"`` (default) or ``"claude-code"``. Claude
            Code mode prepares a task workspace and does not require Docker.
        llm_call_graph_recovery: If True, review OpenHarmony residual indirect
            call sites with the advisory LLM executor.  The resulting artifact
            is never projected into the persisted call graph in this stage.
        llm_call_graph_iterative_recovery: If True, run the entry-driven,
            bounded multi-round residual review and write
            ``llm_call_graph_recovery_rounds.json``.  This explicitly opts into
            the iterative path; it does not change the legacy one-shot mode.
        llm_call_graph_candidate_review: If True, run a separate OpenHarmony
            review over residual sites that already have deterministic
            candidate targets.  This is opt-in and writes an advisory artifact
            without changing the persisted call graph.
        llm_call_graph_projection: If True, project validated high-confidence
            decisions from the OpenHarmony recovery/candidate artifacts into
            an independent semantic overlay.  For non-``all`` scans the
            overlay is additionally used by a promote-only reachable re-filter;
            the native call graph remains unchanged.
        openharmony_dispatch_code_evidence: If True, extract integer values
            for OpenHarmony dispatch selectors from source/header constants.
            This deterministic evidence pass is opt-in and does not modify the
            persisted call graph.
        clang_semantic: If True, run a bounded Clang AST pass. The context
            resolver reuses a compilation database or Ninja export when
            available, otherwise reconstructs candidate commands from BUILD.gn
            and records the provenance and missing dependencies.
        clang_compile_commands: Optional path to ``compile_commands.json``.
        clang_build_status: Provenance label for the compilation context;
            ``compile_database``/``complete`` are strict for that concrete
            configuration, while ``manual_rebuild``/
            ``reconstructed_candidate``/``unknown`` remain candidate facts.
        clang_max_files: Maximum translation units processed by Clang.
        clang_timeout_seconds: Per-translation-unit Clang timeout.
        clang_auto_context: If True, discover an existing compile database,
            export one from an existing Ninja build directory with the
            read-only ``ninja -t compdb`` command, or reconstruct candidate
            commands from bounded BUILD.gn metadata.
        clang_batch_size: Number of translation units represented by one
            resumable Clang batch (checkpointing still occurs after each unit).
        clang_force_recompute: Ignore an existing Clang checkpoint and rerun
            selected translation units.
        clang_dependency_retry_attempts: Number of bounded local include-root
            retry rounds for missing-header failures.
        clang_dependency_retry_low_trust: Also try paths under test/mock
            directories; results remain candidate-only.
        clang_definition_load_max_files: Maximum additional translation units
            loaded for unique declaration-to-definition candidates.
        workers: Number of parallel workers for LLM steps (default: 8).
        backoff_seconds: Seconds to wait when rate-limited (default: 30).

    Returns:
        ScanResult with paths to all generated files and metrics.
    """
    if stop_after not in (
        None,
        "effective-call-graph",
        "llm-reachability",
        "openharmony-gap-tasks",
    ):
        raise ValueError(
            f"Unsupported stop_after stage: {stop_after!r}; "
            "expected None, 'effective-call-graph', 'llm-reachability', "
            "or 'openharmony-gap-tasks'"
        )
    if stop_after == "llm-reachability" and not llm_reachability:
        raise ValueError(
            "stop_after='llm-reachability' requires llm_reachability=True"
        )
    requested_repo_path = os.path.abspath(repo_path)
    repo_path = requested_repo_path
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Socket-guided scanning is an explicit, user-confirmed narrowing of the
    # normal repository input.  Validation is deliberately performed before
    # any parser or model work; an unconfirmed/foreign manifest must fail
    # closed rather than silently falling back to a different tree.
    applied_scope_manifest: dict[str, Any] | None = None
    applied_scope_path: str | None = None
    applied_scope_root: str | None = None
    if scope_manifest:
        from core.socket_scope import load_selected_scope

        scan_root, applied_scope_manifest = load_selected_scope(
            requested_repo_path, scope_manifest
        )
        repo_path = str(scan_root)
        applied_scope_path = os.path.abspath(scope_manifest)
        applied_scope_root = repo_path
        write_json(
            os.path.join(output_dir, "scan_scope_applied.json"),
            {
                "schema_version": 1,
                "requested_repository": requested_repo_path,
                "scan_repository": repo_path,
                "manifest_path": applied_scope_path,
                "manifest": applied_scope_manifest,
                "mode": "confirmed_socket_scope",
            },
        )
        _print_chinese_log(
            f"Socket 引导范围已确认：原仓库={requested_repo_path}，"
            f"本次扫描根目录={repo_path}。完整仓库扫描仍可通过不提供 --scope-manifest 保留。"
        )

    _print_chinese_log(
        f"扫描准备完成：目标源码目录为 {repo_path}，本次所有阶段产物写入 {output_dir}。"
    )
    _print_chinese_log(
        f"运行参数已接收：平台={platform}，语言={languages or language}，"
        f"处理范围={processing_level}，跳过测试代码={skip_tests}，"
        f"库模式={library_mode}。"
    )

    if dynamic_test_mode not in {"docker", "claude-code"}:
        raise ValueError(
            f"Unsupported dynamic test mode: {dynamic_test_mode!r}; "
            "choose docker or claude-code"
        )

    # Reset tracking
    tracking.reset_tracking()

    # Model initialization is deliberately skipped for the independent graph
    # checkpoint.  That checkpoint is meant to validate parser/ledger/Clang
    # facts on a machine that has no model credentials or network access.
    registry = None
    if stop_after != "effective-call-graph":
        # Build the registry once at scan start. Sub-steps reuse it, so a
        # single --llm-config controls every phase without each step
        # re-reading the config file or silently switching providers.
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            probe_registry_or_raise,
            resolve_llm_config,
        )
        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
        print(f"[Scan] LLM config: {registry.config_name}", file=sys.stderr)
        _print_chinese_log(
            f"模型配置已解析为“{registry.config_name}”。扫描开始前会先做一次最小连通性探测，"
            "后续各阶段复用同一套阶段绑定，避免中途悄悄切换模型。"
        )
        probe_registry_or_raise(registry)
        _print_chinese_log("模型连通性探测通过，已允许进入源码解析和后续分析阶段。")
    else:
        _print_chinese_log(
            "有效调用图独立检查点：跳过模型配置和联网探测，只运行源码解析、台账与有效图生成。"
        )

    if platform not in {"auto", "generic", "openharmony"}:
        raise ValueError(f"Unsupported platform: {platform}")

    graph_source_revision = _source_revision_for_graph(repo_path, commit_sha)

    # Platform detection is an additive, fail-safe layer.  Explicit generic
    # scans never inspect OpenHarmony metadata; auto scans only promote to the
    # platform-aware C path when the profile builder reaches its confidence
    # threshold.  A detector failure therefore cannot turn a generic scan into
    # a failed scan or silently change its parser argv.
    effective_platform = platform
    platform_profile = None
    platform_profile_path = None
    _print_chinese_log(
        f"平台决策：请求模式为“{platform}”。auto 会先检查 OpenHarmony 特征，"
        "generic 不读取 OpenHarmony 元数据，openharmony 则强制使用平台适配路径。"
    )
    if platform in {"auto", "openharmony"}:
        try:
            from core.platforms.openharmony.profile import OpenHarmonyProfileBuilder

            detected_profile = OpenHarmonyProfileBuilder().build_from_repository(repo_path)
        except Exception as exc:
            detected_profile = None
            print(
                f"[Scan] OpenHarmony profile detection unavailable: {exc}; "
                "continuing with the requested platform mode.",
                file=sys.stderr,
            )
            _print_chinese_log(
                f"平台画像检测未完成（{exc}），扫描将继续沿用请求的平台模式，"
                "不会因为画像失败而改变为另一种解析器。"
            )
        if detected_profile is not None:
            platform_profile = detected_profile.to_dict()
            platform_profile_path = os.path.join(output_dir, "platform_profile.json")
            write_json(platform_profile_path, platform_profile)
            if platform == "auto":
                effective_platform = "openharmony"
            print(
                f"[Scan] OpenHarmony profile: {platform_profile_path} "
                f"(confidence={detected_profile.detection['confidence']:.2f})",
                file=sys.stderr,
            )
            _print_chinese_log(
                f"平台画像已生成：{platform_profile_path}；检测置信度为 "
                f"{detected_profile.detection['confidence']:.2f}，有效平台确定为 OpenHarmony。"
            )
        elif platform == "auto":
            _print_chinese_log(
                "auto 模式未得到可用的 OpenHarmony 画像，因此保留 auto 请求并使用通用解析路径。"
            )
        elif platform == "openharmony":
            _print_chinese_log(
                "显式 OpenHarmony 模式未生成完整画像，但仍强制使用 OpenHarmony 解析器；"
                "缺失的画像字段不会被模型或规则臆造。"
            )
    elif platform == "generic":
        _print_chinese_log("已明确选择 generic：本次不会应用 OpenHarmony 专用入口和调用图规则。")

    platform_kwargs = (
        {"platform": effective_platform} if effective_platform != "auto" else {}
    )
    result = ScanResult(
        output_dir=output_dir,
        platform_profile=platform_profile,
        platform_selection=(
            effective_platform if effective_platform != "auto" else None
        ),
        scope_manifest_path=applied_scope_path,
        scope_root=applied_scope_root,
    )
    collected_step_reports: list[dict] = []

    # Count total steps for progress display
    total_steps = _count_steps(
        generate_context, enhance, verify, generate_report, dynamic_test,
        llm_reachability=llm_reachability,
        stop_after=stop_after,
        llm_call_graph_recovery=llm_call_graph_recovery,
        llm_call_graph_iterative_recovery=llm_call_graph_iterative_recovery,
        llm_call_graph_candidate_review=llm_call_graph_candidate_review,
        llm_call_graph_projection=llm_call_graph_projection,
        openharmony_dispatch_code_evidence=openharmony_dispatch_code_evidence,
        openharmony_gap_tasks=(effective_platform == "openharmony"),
    )
    step_num = 0

    def _step_label(name: str) -> str:
        nonlocal step_num
        step_num += 1
        return f"[{step_num}/{total_steps}] {name}"

    _print_chinese_log(
        f"流程计划：本次共计 {total_steps} 个阶段；必要阶段始终执行，"
        "可选阶段会依据开关、候选数量和运行环境决定执行或跳过。"
    )
    _print_chinese_log(
        "阶段开关："
        f"上下文={'开启' if generate_context else '关闭'}，"
        f"增强={'开启' if enhance else '关闭'}，"
        f"验证={'开启' if verify else '关闭'}，"
        f"LLM 可达性={'开启' if llm_reachability else '关闭'}，"
        f"动态测试={'开启' if dynamic_test else '关闭'}，"
        f"报告={'开启' if generate_report else '关闭'}。"
    )

    _print_banner(repo_path, output_dir, language, processing_level,
                  verify, generate_context, enhance, enhance_mode,
                  generate_report, dynamic_test, workers, backoff_seconds,
                  stop_after=stop_after,
                  llm_call_graph_recovery=llm_call_graph_recovery,
                  llm_call_graph_iterative_recovery=llm_call_graph_iterative_recovery,
                  llm_call_graph_candidate_review=llm_call_graph_candidate_review,
                  llm_call_graph_projection=llm_call_graph_projection,
                  openharmony_dispatch_code_evidence=openharmony_dispatch_code_evidence,
                  clang_semantic=clang_semantic)

    # ---------------------------------------------------------------
    # Step 1: Parse
    # ---------------------------------------------------------------
    from core.parser_adapter import parse_repository
    from core.schemas import ParseResult

    # When LLM reachability is enabled the stage must see ALL units so it can
    # identify entry points the structural pass would miss.  Parse with "all"
    # here; the structural filter is re-applied after LLM signals are merged.
    projection_requires_full_dataset = (
        effective_platform == "openharmony"
        and llm_call_graph_projection
        and processing_level != "all"
    )
    effective_parse_level = (
        "all"
        if (
            (llm_reachability or projection_requires_full_dataset)
            and processing_level != "all"
        )
        else processing_level
    )
    graph_build_config_id = _build_config_id(
        platform=platform,
        effective_platform=effective_platform,
        language=language,
        languages=languages,
        processing_level=effective_parse_level,
        skip_tests=skip_tests,
        library_mode=library_mode,
    )

    print(_step_label("Parsing repository..."), file=sys.stderr)
    _print_chinese_log(
        "阶段 1/解析：正在扫描源码文件，提取函数单元、入口标记、原生调用图和"
        "平台相关注册信息，后续漏洞分析只消费这里生成的结构化数据。"
    )
    _print_chinese_log(
        f"解析参数决策：实际语言={languages or language}，请求范围={processing_level}，"
        f"实际首轮解析范围={effective_parse_level}，测试目录过滤={'开启' if skip_tests else '关闭'}。"
    )
    if effective_parse_level != processing_level:
        reasons = []
        if llm_reachability:
            reasons.append("LLM reachability")
        if projection_requires_full_dataset:
            reasons.append("LLM call-edge projection")
        print(
            "  [" + " + ".join(reasons) + "] parsing all units; "
            "structural filter runs after semantic signals",
            file=sys.stderr,
        )
        _print_chinese_log(
            "解析范围被临时提升为 all："
            f"{ '、'.join(reasons) }需要先看到完整单元集合，"
            "待语义信号合并后再按原始范围做安全的可达性筛选，避免入口被过早裁剪。"
        )

    with step_context("parse", output_dir, inputs={
        "repo_path": repo_path,
        "language": language,
        "processing_level": effective_parse_level,
        "skip_tests": skip_tests,
        "platform": platform,
        "effective_platform": effective_platform,
    }) as ctx:
        if languages and len(languages) > 1:
            # Fan out per language, then merge into the single dataset every
            # later stage consumes. Post-parse stages are unchanged and still
            # run ONCE — the merge is what makes that possible.
            from core.dataset_merge import (
                merge_analyzer_outputs,
                merge_datasets,
                write_call_graph_index,
            )
            from core.parser_adapter import (
                _maybe_apply_diff_filter,
                parse_repository_multi,
            )

            outcomes = parse_repository_multi(
                repo_path=repo_path,
                run_dir=output_dir,
                languages=languages,
                processing_level=effective_parse_level,
                skip_tests=skip_tests,
                library_mode=library_mode,
                strict=strict_languages,
                **platform_kwargs,
            )
            _dataset_path = os.path.join(output_dir, "dataset.json")
            _analyzer_path = os.path.join(output_dir, "analyzer_output.json")
            _merge_stats = merge_datasets(outcomes, _dataset_path)
            merge_analyzer_outputs(outcomes, _analyzer_path)
            write_call_graph_index(
                outcomes, os.path.join(output_dir, "call_graphs.json")
            )

            _failed = [o for o in outcomes if not o.ok]
            parse_result = ParseResult(
                dataset_path=_dataset_path,
                analyzer_output_path=(
                    _analyzer_path if os.path.exists(_analyzer_path) else None
                ),
                units_count=_merge_stats.total_units,
                # Scalar stays the PRIMARY language: it is serialized into JSON
                # the Go CLI unmarshals.
                language=_merge_stats.languages[0] if _merge_stats.languages else language,
                processing_level=effective_parse_level,
                languages=_merge_stats.languages,
                language_stats=_merge_stats.units_per_language,
                per_language={o.language: o.to_dict() for o in outcomes},
                parse_errors=[o.to_dict() for o in _failed],
            )
            # Applied once against the MERGED dataset, not per language.
            _maybe_apply_diff_filter(parse_result, output_dir, diff_manifest)
            _print_chinese_log(
                f"解析策略：选中了 {len(languages)} 种语言，先分别解析再合并 dataset.json、"
                "analyzer_output.json 和各语言调用图；后续 LLM/检测阶段只运行一次。"
            )
        else:
            _print_chinese_log(
                "解析策略：使用单语言解析路径，直接在本次扫描目录生成 dataset.json 和调用图产物。"
            )
            parse_result = parse_repository(
                repo_path=repo_path,
                output_dir=output_dir,
                language=(languages[0] if languages else language),
                processing_level=effective_parse_level,
                skip_tests=skip_tests,
                diff_manifest=diff_manifest,
                library_mode=library_mode,
                **platform_kwargs,
            )

        # Build the audited effective graph immediately after parsing.  This
        # is a deterministic, additive step: call_graph.json and the parser's
        # call-site ledger remain immutable inputs, while later reachability,
        # enhancement and reporting can consume effective_call_graph.json.
        clang_overlay_paths: list[str] = []
        clang_definition_loading_report_paths: list[str] = []
        clang_p1_acceptance_report_path: str | None = None
        pre_clang_gap_report_path: str | None = None
        pre_clang_gap_report: dict[str, Any] = {}
        call_graph_gap_report_path: str | None = None
        call_graph_gap_report: dict[str, Any] = {}
        try:
            from core.call_graph_facts import refresh_effective_call_graphs
            from core.call_graph_facts import synchronize_dataset_dependencies

            # Do not replay a stale projection artifact when a scan directory
            # is resumed. New semantic overlays enter only after their own
            # validation stage below.
            effective_graphs = refresh_effective_call_graphs(
                output_dir,
                source_revision=graph_source_revision,
                build_config_id=graph_build_config_id,
                include_persisted_overlays=False,
            )
            dependency_sync = synchronize_dataset_dependencies(
                parse_result.dataset_path,
                [item.get("path") for item in effective_graphs if item.get("path")],
            )
            if effective_graphs:
                _print_chinese_log(
                    "调用事实库：已生成有效调用图，保留原生 call_graph.json；"
                    f"图目录={len(effective_graphs)}，"
                    f"已同步 {dependency_sync.get('units_updated', 0)} 个单元的调用依赖，"
                    "后续可达性将优先使用 effective_call_graph.json。"
                )
            else:
                _print_chinese_log(
                    "调用事实库：本次解析未发现可生成的调用图，保留原解析结果并记录降级。"
                )
        except Exception as exc:
            effective_graphs = []
            dependency_sync = {}
            print(f"  WARNING: effective call graph generation failed: {exc}", file=sys.stderr)
            _print_chinese_log(
                f"调用事实库生成失败（{exc}），后续按原生 call_graph.json 降级；"
                "该失败不会被当作图完整。"
            )

        # Keep an immutable before-Clang snapshot.  The normal gap report is
        # regenerated after semantic overlays are projected, so using only
        # that later file would hide sites that Clang repaired.
        if clang_semantic and effective_platform == "openharmony":
            try:
                pre_clang_gap_report_path, pre_clang_gap_report = _write_call_graph_gap_report(
                    output_dir=output_dir,
                    effective_graphs=effective_graphs,
                    repo_path=repo_path,
                    source_revision=graph_source_revision,
                    build_config_id=graph_build_config_id,
                    filename="call_graph_gap_report.pre_clang.json",
                )
            except Exception as exc:
                print(f"  WARNING: pre-Clang gap report failed: {exc}", file=sys.stderr)
                _print_chinese_log(f"Clang 前调用图缺口快照失败（{exc}），本轮只保留批处理产物。")

        # P1: use a real compilation database when explicitly requested.  The
        # extractor writes one auditable artifact per graph directory, then a
        # second deterministic refresh consumes only validated Clang facts.
        if clang_semantic and effective_platform == "openharmony":
            try:
                from core.call_graph_facts import (
                    refresh_effective_call_graphs,
                    synchronize_dataset_dependencies,
                )
                priority_sources = _gap_priority_sources(pre_clang_gap_report)
                if priority_sources:
                    _print_chinese_log(
                        "P1 Clang 调度：根据 Clang 前调用图缺口，"
                        f"优先处理 {len(priority_sources)} 个源文件；"
                        "该排序只影响有限预算分配，不改变事实准入。"
                    )
                clang_overlay_paths = _run_clang_semantic_batch(
                    repo_path=repo_path,
                    output_dir=output_dir,
                    source_revision=graph_source_revision,
                    graph_build_config_id=graph_build_config_id,
                    compile_commands=clang_compile_commands,
                    build_status=clang_build_status,
                    max_files=clang_max_files,
                    timeout_seconds=clang_timeout_seconds,
                    auto_context=clang_auto_context,
                    batch_size=clang_batch_size,
                    force_recompute=clang_force_recompute,
                    dependency_retry_attempts=clang_dependency_retry_attempts,
                    dependency_retry_low_trust=clang_dependency_retry_low_trust,
                    definition_load_max_files=clang_definition_load_max_files,
                    priority_sources=priority_sources,
                )
                clang_definition_loading_report_paths = [
                    str(Path(path).parent / "clang_definition_loading_report.json")
                    for path in clang_overlay_paths
                    if (Path(path).parent / "clang_definition_loading_report.json").is_file()
                ]
                clang_p1_acceptance_report_path, clang_p1_acceptance_report = (
                    _write_clang_p1_acceptance_report(
                        output_dir=output_dir,
                        overlay_paths=clang_overlay_paths,
                        pre_clang_gap_report_path=pre_clang_gap_report_path,
                        repo_path=repo_path,
                        source_revision=graph_source_revision,
                    )
                )
                if clang_p1_acceptance_report:
                    p1_summary = clang_p1_acceptance_report.get("summary", {})
                    _print_chinese_log(
                        "P1 Clang 未决站点对照："
                        f"本批次范围内={p1_summary.get('unresolved_sites_in_batch_scope', 0)}，"
                        f"观察到 candidate 事实={p1_summary.get('semantic_fact_observed_candidate_only', 0)}，"
                        f"未匹配={p1_summary.get('in_batch_scope_not_matched', 0)}，"
                        f"caller 未入索引={p1_summary.get('unindexed_callers', 0)}。"
                    )
                effective_graphs = refresh_effective_call_graphs(
                    output_dir,
                    source_revision=graph_source_revision,
                    build_config_id=graph_build_config_id,
                    include_persisted_overlays=True,
                )
                dependency_sync = synchronize_dataset_dependencies(
                    parse_result.dataset_path,
                    [item.get("path") for item in effective_graphs if item.get("path")],
                )
                _print_chinese_log(
                    "P1 Clang 批处理：已保存每个调用图目录的 clang_semantic_overlay.json，"
                    f"并重新生成有效图；图目录={len(effective_graphs)}。"
                )
            except Exception as exc:
                print(f"  WARNING: Clang semantic batch failed: {exc}", file=sys.stderr)
                _print_chinese_log(
                    f"P1 Clang 批处理失败（{exc}），保留原有效图和失败诊断，"
                    "不会把缺少编译上下文解释成解析成功。"
                )

        try:
            call_graph_gap_report_path, call_graph_gap_report = _write_call_graph_gap_report(
                output_dir=output_dir,
                effective_graphs=effective_graphs,
                repo_path=repo_path,
                source_revision=graph_source_revision,
                build_config_id=graph_build_config_id,
            )
            if call_graph_gap_report:
                gap_summary = call_graph_gap_report.get("summary", {})
                _print_chinese_log(
                    "调用图缺口汇总：按调用点去重后，"
                    f"未决站点={gap_summary.get('unrepaired_edge_missing_sites', gap_summary.get('unique_gap_sites', 0))}，"
                    f"候选记录={gap_summary.get('candidate_fact_records', 0)}；"
                    "候选数量不会被当作缺边数量。"
                )
        except Exception as exc:
            print(f"  WARNING: call graph gap report failed: {exc}", file=sys.stderr)
            _print_chinese_log(f"调用图缺口汇总失败（{exc}），不影响有效图生成。")

        ctx.summary = {
            "total_units": parse_result.units_count,
            "language": parse_result.language,
            "processing_level": parse_result.processing_level,
            "effective_call_graphs": effective_graphs,
            "dependency_sync": dependency_sync,
            "clang_semantic_overlays": clang_overlay_paths,
            "clang_definition_loading_reports": clang_definition_loading_report_paths,
            "clang_p1_acceptance_report": clang_p1_acceptance_report_path,
            "call_graph_gap_report": call_graph_gap_report_path,
        }
        # If the parse step generated a diff_stats report, attach it.
        _diff_report = os.path.join(output_dir, "diff_filter.report.json")
        if os.path.exists(_diff_report):
            try:
                ctx.summary["diff_stats"] = read_json(_diff_report)
            except (json.JSONDecodeError, OSError):
                pass
        ctx.outputs = {
            "dataset_path": parse_result.dataset_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
            "effective_call_graphs": effective_graphs,
            "dependency_sync": dependency_sync,
            "clang_semantic_overlays": clang_overlay_paths,
            "clang_definition_loading_reports": clang_definition_loading_report_paths,
            "clang_p1_acceptance_report": clang_p1_acceptance_report_path,
            "call_graph_gap_report": call_graph_gap_report_path,
        }

    result.dataset_path = parse_result.dataset_path
    result.analyzer_output_path = parse_result.analyzer_output_path
    result.units_count = parse_result.units_count
    result.language = parse_result.language
    # getattr with defaults: `parse_repository` is duck-typed by callers and
    # test stubs that predate these fields. Attribute access would turn a
    # missing optional field into an AttributeError mid-scan.
    result.languages = getattr(parse_result, "languages", []) or []
    result.language_stats = getattr(parse_result, "language_stats", {}) or {}
    result.per_language = getattr(parse_result, "per_language", {}) or {}
    result.parse_errors = getattr(parse_result, "parse_errors", []) or []
    result.platform_coverage = getattr(parse_result, "platform_coverage", None)
    result.effective_call_graph_paths = [
        str(item.get("path"))
        for item in (effective_graphs or [])
        if isinstance(item, Mapping) and item.get("path")
    ]
    result.call_graph_gap_report_path = call_graph_gap_report_path
    result.clang_semantic_overlay_paths = list(clang_overlay_paths)
    result.clang_p1_acceptance_report_path = clang_p1_acceptance_report_path
    result.clang_definition_loading_report_paths = list(
        clang_definition_loading_report_paths
    )
    _sync_platform_profile_file_counts(result, output_dir)
    result.excluded_languages = dict(excluded_languages or {})
    collected_step_reports.append(_load_step_report(output_dir, "parse"))

    print(f"  Parsed: {parse_result.units_count} units ({parse_result.language})",
          file=sys.stderr)
    graph_dirs_after_parse = resolve_call_graph_dirs(output_dir)
    graph_hint = (
        f"发现 {len(graph_dirs_after_parse)} 个调用图目录"
        if graph_dirs_after_parse
        else "未发现可供后续可达性复核使用的 call_graph.json"
    )
    _print_chinese_log(
        f"解析结果：生成 {parse_result.units_count} 个函数单元，主语言为 {parse_result.language}；"
        f"{graph_hint}。解析器错误数={len(getattr(parse_result, 'parse_errors', []) or [])}。"
    )
    print(file=sys.stderr)

    # The graph-facts checkpoint is intentionally independent of LLM stages.
    # It lets parser/Clang/ledger work be inspected and benchmarked without
    # paying for context enhancement or vulnerability analysis.
    if stop_after == "effective-call-graph":
        downstream_steps = (
            "app-context",
            "llm-reachability",
            "llm-call-graph-recovery",
            "llm-call-graph-candidate-review",
            "llm-call-graph-projection",
            "openharmony-dispatch-code-evidence",
            "openharmony-gap-tasks",
            "enhance",
            "analyze",
            "verify",
            "build-output",
            "dynamic-test",
            "report",
        )
        for downstream_step in downstream_steps:
            _record_skip(result, downstream_step, "stop_after_effective_call_graph")
        result.step_reports = collected_step_reports
        _print_chinese_log(
            "有效调用图阶段已完成：根据 --stop-after effective-call-graph "
            "主动结束本次扫描；未执行上下文增强、漏洞分析、验证、动态测试和报告阶段。"
        )
        return result

    # Active dataset path — may be updated by enhance step
    active_dataset_path = parse_result.dataset_path
    # Projection/reachability integration may run after the optional LLM
    # reachability stage, which rewrites dataset.json to its filtered view.
    # Preserve the parser's complete unit set so the later additive BFS can
    # restore units reachable only through a recovered edge. This sidecar is
    # created only for the explicit OpenHarmony projection flag and does not
    # alter the legacy dataset layout.
    unfiltered_dataset_path: str | None = None
    if projection_requires_full_dataset and active_dataset_path:
        unfiltered_dataset_path = os.path.join(
            output_dir, "dataset_unfiltered.json"
        )
        try:
            shutil.copyfile(active_dataset_path, unfiltered_dataset_path)
            _print_chinese_log(
                "解析产物保护：已保存未过滤的完整 dataset 副本，"
                "供后续调用图语义投影在需要时重新进行增量 BFS。"
            )
        except (OSError, shutil.Error) as exc:
            print(
                f"  [Warning] Could not preserve unfiltered dataset for "
                f"LLM overlay reachability: {exc}",
                file=sys.stderr,
            )
            _print_chinese_log(
                f"解析产物保护失败（{exc}），后续仍会继续，但调用图投影无法恢复被过滤单元。"
            )
            unfiltered_dataset_path = None

    # ---------------------------------------------------------------
    # Step 2: Application Context (optional)
    # ---------------------------------------------------------------
    app_context_path: str | None = None
    if generate_context and HAS_APP_CONTEXT:
        print(_step_label("Generating application context..."), file=sys.stderr)
        _print_chinese_log(
            "阶段 2/应用上下文：正在整理仓库说明、目录结构、平台画像和安全边界，"
            "生成攻击者画像、外部输入源、信任边界及漏洞判定标准，供后续模型减少误报。"
        )

        with step_context("app-context", output_dir, inputs={
            "repo_path": repo_path,
        }) as ctx:
            # A threat model committed to the scanned repo is authoritative and
            # short-circuits generation. Loaded OUTSIDE the try below on
            # purpose: a malformed one must abort the scan rather than degrade
            # into a default context, because silently applying the wrong
            # security model to every finding is worse than failing loudly.
            from context.threat_model import load_threat_model

            threat_model_ctx = load_threat_model(Path(repo_path))

            if threat_model_ctx is not None:
                _print_chinese_log(
                    "上下文决策：仓库提供了 OPENANT.THREATMODEL.md，优先使用该人工安全模型；"
                    "同时保留 OpenHarmony 平台最低安全基线，不允许仓库模型删除平台约束。"
                )
                # A repository threat model supplies useful business context,
                # but it cannot delete the OpenHarmony platform minimum.  The
                # merge is deterministic and leaves its provenance on the
                # serialized ApplicationContext and ScanResult.
                from context.openharmony_context import merge_openharmony_context

                threat_model_ctx = merge_openharmony_context(
                    threat_model_ctx,
                    platform_profile,
                    force=effective_platform == "openharmony",
                )
                app_context_path = os.path.join(output_dir, "application_context.json")
                save_context(threat_model_ctx, Path(app_context_path))
                result.app_context_path = app_context_path
                result.context_source = "threat_model"
                result.application_context_provenance = dict(
                    threat_model_ctx.context_provenance
                )
                # R5: carry the file's provenance (sha over raw bytes) and the
                # previously discarded permissive-model warnings onto the result
                # so both land in scan.report.json / pipeline_output.json rather
                # than reaching only stderr (which CI discards).
                result.threat_model_sha256 = threat_model_ctx.source_sha256
                result.threat_model_warnings = list(
                    threat_model_ctx.permissive_warnings
                )
                ctx.summary = {
                    "application_type": threat_model_ctx.application_type,
                    "context_source": "threat_model",
                    "application_context_provenance": threat_model_ctx.context_provenance,
                }
                ctx.outputs = {"app_context_path": app_context_path}
                print(
                    "  Using repo-supplied threat model: "
                    f"{threat_model_ctx.application_type}",
                    file=sys.stderr,
                )
                _print_chinese_log(
                    f"上下文结果：已加载仓库安全模型，应用类型为 {threat_model_ctx.application_type}，"
                    "并记录来源哈希和合并 provenance，便于复核。"
                )
            else:
                _print_chinese_log(
                    "上下文决策：未发现仓库自带安全模型，调用应用上下文生成器；"
                    "若存在 OpenHarmony 画像，会把平台输入源和信任边界作为额外约束传入。"
                )
                try:
                    # Forward the already detected profile to the app-context
                    # prompt. Explicit OpenHarmony selection still supplies a
                    # minimal platform marker when detection is incomplete.
                    app_context_profile = platform_profile
                    if (
                        app_context_profile is None
                        and effective_platform == "openharmony"
                    ):
                        app_context_profile = {"platform": "openharmony"}
                    generator_kwargs = (
                        {"platform_profile": app_context_profile}
                        if app_context_profile is not None
                        else {}
                    )
                    context = generate_application_context(
                        Path(repo_path),
                        registry.get("app_context"),
                        **generator_kwargs,
                    )
                    if context is not None:
                        # ``generate_application_context`` is duck-typed by
                        # older integrations/tests.  Only the real
                        # ApplicationContext can carry the additive baseline
                        # fields; a legacy stub must keep the old path alive.
                        from context.application_context import ApplicationContext

                        if isinstance(context, ApplicationContext):
                            from context.openharmony_context import merge_openharmony_context

                            context = merge_openharmony_context(
                                context,
                                platform_profile,
                                force=effective_platform == "openharmony",
                            )
                    app_context_path = os.path.join(
                        output_dir, "application_context.json"
                    )
                    save_context(context, Path(app_context_path))
                    result.app_context_path = app_context_path
                    result.context_source = "generated"
                    result.application_context_provenance = dict(
                        getattr(context, "context_provenance", {}) or {}
                    )
                    ctx.summary = {
                        "application_type": context.application_type,
                        "context_source": "generated",
                        "application_context_provenance": result.application_context_provenance,
                    }
                    ctx.outputs = {"app_context_path": app_context_path}
                    print(f"  App type: {context.application_type}", file=sys.stderr)
                    _print_chinese_log(
                        f"上下文结果：生成应用类型为 {context.application_type}，"
                        f"上下文文件已写入 {app_context_path}。"
                    )
                except Exception as e:
                    print(f"  WARNING: App context generation failed: {e}",
                          file=sys.stderr)
                    print("  Continuing without app context.", file=sys.stderr)
                    _print_chinese_log(
                        f"上下文生成失败（{e}），按降级策略继续扫描；后续模型将缺少专用应用上下文，"
                        "该降级原因会写入阶段报告。"
                    )
                    ctx.status = "skipped"
                    ctx.summary = {"skipped": True, "reason": str(e)}
                    # Record the crash like the enhance/verify/dynamic-test
                    # handlers do — otherwise the degraded scan (default threat
                    # model) is absent from result.skipped_steps / scan.report.json
                    # / pipeline_output.json and the summary claims "No steps were
                    # skipped" (only the per-step report + stderr carried it).
                    _record_skip(result, "app-context", "failed")

        collected_step_reports.append(_load_step_report(output_dir, "app-context"))
    elif generate_context:
        print(_step_label("Skipping application context (module not available)."),
              file=sys.stderr)
        _print_chinese_log(
            "上下文阶段跳过：当前 Python 环境没有应用上下文模块，"
            "不会伪造默认上下文，后续阶段按无上下文模式继续。"
        )
        _record_skip(result, "app-context", "module_unavailable")
    else:
        print(_step_label("Skipping application context (--no-context)."),
              file=sys.stderr)
        _print_chinese_log(
            "上下文阶段跳过：运行参数显式关闭 --no-context；"
            "后续漏洞判定不会使用应用上下文提供的攻击者和信任边界信息。"
        )
        # Skipping is a legitimate operator choice, but doing it silently while
        # the repo ships a threat model means the scan runs under a different
        # security model than the repository declares, invisibly.
        if (Path(repo_path) / "OPENANT.THREATMODEL.md").exists():
            print(
                "  NOTE: this repository ships an OPENANT.THREATMODEL.md, which "
                "--no-context discards. The scan will NOT use its attacker "
                "profiles or vulnerability criteria.",
                file=sys.stderr,
            )
            _print_chinese_log(
                "重要提示：仓库虽然提供了 OPENANT.THREATMODEL.md，但本次 --no-context 已明确丢弃它；"
                "结果不能按该模型解释。"
            )
        _record_skip(result, "app-context", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 2.5: LLM Reachability review (optional, opt-in)
    # ---------------------------------------------------------------
    # Runs after parse + app-context and before enhance/analyze. Because parse
    # was done with processing_level="all" (when filtering is requested), the
    # LLM sees every unit in the codebase and can identify entry points the
    # structural heuristics would miss. After signals are applied, the
    # structural reachability filter is re-run with LLM entry points and
    # high-confidence semantic seeds as extra BFS roots; medium-confidence
    # targets are retained without becoming roots, so the final dataset
    # honours the user's requested processing_level. Threading app_context into
    # the prompt helps
    # the model reason about expected entry points (e.g. "this is a web_app,
    # look for HTTP handlers").
    if llm_reachability:
        from core.llm_reachability import (
            analyze_reachability,
            apply_signals,
            signals_to_json,
        )

        llm_reach_binding = registry.get("llm_reach")
        print(_step_label("Running LLM reachability review..."), file=sys.stderr)
        _print_chinese_log(
            "阶段 2.5/LLM 可达性复核：将把完整函数集合交给语义复核，"
            f"使用 {llm_reach_binding.provider_name}/{llm_reach_binding.model}，"
            f"每个函数最多提供 {llm_reachability_max_code_bytes} 字节代码；"
            "目的是真正补足结构规则可能漏掉的入口和外部输入点。"
        )
        _print_chinese_log(
            "可达性安全边界：LLM 只产生入口/输入信号和审计证据；"
            "有具体证据的 external_input/入站 cross_process high 信号作为 BFS 语义种子，"
            "medium 信号进入独立 candidate BFS，但不会升级为 strict 入口；"
            "证据、边界和方向只用于审计，原生调用图不被直接改写。"
        )

        with step_context("llm-reachability", output_dir, inputs={
            "dataset_path": active_dataset_path,
            "model": llm_reach_binding.model,
            "provider": llm_reach_binding.provider_name,
        }) as ctx:
            try:
                dataset = read_json(active_dataset_path)
            except Exception as exc:
                # Broaden beyond (OSError, json.JSONDecodeError): read_json opens
                # strict UTF-8, so a bad-encoding dataset raises UnicodeDecodeError
                # (a ValueError) which previously escaped and aborted the whole
                # scan. NOTE: this guards only the dataset READ. The stage's LLM
                # call (analyze_reachability, below) is NOT wrapped here, so a
                # provider error there still aborts the scan — a separate gap
                # tracked as a follow-up (wrap the whole stage body like
                # enhance/verify do).
                print(f"  WARNING: failed to load dataset: {exc}", file=sys.stderr)
                _print_chinese_log(
                    f"可达性阶段无法读取 dataset.json（{exc}），本阶段已跳过，"
                    "不会用不完整数据猜测入口；该失败原因会保留在阶段报告。"
                )
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(exc)}
                # Record the crash so the degraded reachability pass (no
                # LLM-promoted entry points -> potential missed vulns) is
                # visible in the artifacts, not only on CI-discarded stderr.
                _record_skip(result, "llm-reachability", "failed")
                dataset = None

            if dataset is not None:
                _print_chinese_log(
                    f"可达性输入：已加载 {len(dataset.get('units', []))} 个函数单元，"
                    "未使用 --limit 截断可达性复核，确保模型能看到潜在遗漏入口。"
                )
                app_ctx_payload = None
                if app_context_path and os.path.exists(app_context_path):
                    try:
                        app_ctx_payload = read_json(app_context_path)
                    except Exception as exc:
                        # Broad like the dataset load above: this optional
                        # app-context read must never abort the scan. read_json
                        # opens strict UTF-8, so a bad-encoding self-written file
                        # raises UnicodeDecodeError (not OSError/JSONDecodeError);
                        # a missing payload just means the reachability prompt
                        # runs without the extra app-context hint. Warn (like the
                        # dataset-load sibling) so this recall-affecting
                        # degradation is visible, not silent.
                        print(
                            f"  WARNING: could not read app context for "
                            f"reachability ({exc}); continuing without the "
                            f"app-context hint.",
                            file=sys.stderr,
                        )
                        _print_chinese_log(
                            f"可达性上下文读取失败（{exc}），已降级为仅使用源码和函数索引，"
                            "不会阻塞整次扫描。"
                        )
                        app_ctx_payload = None
                    else:
                        _print_chinese_log(
                            "可达性上下文：已附带 application_context.json，"
                            "模型会结合应用类型、外部输入源和信任边界判断入口。"
                        )
                else:
                    _print_chinese_log(
                        "可达性上下文：没有可用的 application_context.json，"
                        "本阶段仅依据函数代码、索引和平台信息判断，不补造安全背景。"
                    )

                # --limit governs the analyze stage, not how many units the
                # LLM reachability pass reviews — it must see the full
                # codebase to find missed entry points.
                signals = analyze_reachability(
                    dataset=dataset,
                    app_context=app_ctx_payload,
                    binding=llm_reach_binding,
                    max_code_bytes=llm_reachability_max_code_bytes,
                )
                summary = apply_signals(dataset, signals)

                # Persist both the raw/normalized signals and the local seed
                # decisions. Downstream stages must not infer semantic seeds
                # solely from ``is_entry_point`` because external-input and
                # cross-process signals intentionally keep that flag
                # false.
                signals_path = os.path.join(output_dir, "llm_reachability.json")
                write_json(
                    signals_path,
                    {
                        "signals": signals_to_json(signals),
                        "summary": summary,
                    },
                    indent=2,
                )

                reachability_metadata = dict(dataset.get("metadata") or {})
                reachability_metadata["llm_reachability"] = summary
                dataset["metadata"] = reachability_metadata

                pre_filter_count = len(dataset.get("units", []))
                post_filter_count = pre_filter_count
                refilter_supported = False

                # Re-apply the structural reachability filter using LLM
                # entry points and accepted high-confidence semantic seeds as
                # additional BFS roots. Medium-confidence semantic units are
                # passed separately into a candidate-only BFS over accepted
                # edges; the parser keeps strict and candidate evidence
                # distinct.
                # Only possible when the parser persisted call_graph.json.
                # Which parsers do so is determined by PROBING THE FILESYSTEM
                # below, not by a hardcoded language list — an earlier comment
                # here claimed only Python and Zig persist it, which is wrong
                # (JavaScript writes a fully-formed call_graph.json too). Keep
                # this probe-based: parsers gain and lose the behaviour over
                # time, and a stale list here would silently skip re-filtering
                # for a language that actually supports it.
                if processing_level != "all":
                    cg_dirs = resolve_call_graph_dirs(output_dir)
                    if cg_dirs:
                        from core.parser_adapter import apply_reachability_filter

                        llm_promoted_ids = {
                            u["id"] for u in dataset.get("units", [])
                            if u.get("is_entry_point") and u.get("id")
                        }
                        semantic_seed_ids = {
                            str(unit_id)
                            for unit_id in summary.get("semantic_seed_ids", [])
                            if unit_id
                        }
                        semantic_retain_only_ids = {
                            str(unit.get("id"))
                            for unit in dataset.get("units", [])
                            if (
                                unit.get("semantic_reachability_retain_only") is True
                                or unit.get("reachability_retain_only") is True
                            )
                            and unit.get("id")
                        }
                        semantic_candidate_seed_ids = {
                            str(unit.get("id"))
                            for unit in dataset.get("units", [])
                            if unit.get("semantic_reachability_candidate_seed") is True
                            and unit.get("id")
                        }
                        partitions = partition_units_by_language(
                            dataset.get("units", [])
                        )
                        kept: list[dict] = []
                        unfilterable: dict[str, int] = {}
                        # Per-language reachability_filter stats, aggregated back
                        # onto the rebuilt dataset below. Without this the rebuild
                        # at `dataset = {**dataset, "units": kept}` carried the
                        # ORIGINAL (pre-LLM) metadata, so the reporter rendered
                        # "reachability filtering not applied" on a scan that DID
                        # prune via the LLM-seeded re-filter.
                        refilter_by_language: dict[str, dict] = {}

                        for lang, lang_units in partitions.items():
                            lang_dir = cg_dirs.get(lang)
                            if lang_dir is None and None in cg_dirs:
                                # Legacy flat layout: one graph covers everything.
                                lang_dir = cg_dirs[None]
                            if lang_dir is None:
                                # This language's parser persisted no call graph,
                                # so its units pass through unfiltered — the
                                # pre-existing behaviour, now scoped per language
                                # instead of disabling the filter for the whole
                                # scan just because the primary lacked a graph.
                                unfilterable[lang or "unknown"] = len(lang_units)
                                kept.extend(lang_units)
                                continue

                            # Deep-copy metadata: the shallow {**dataset} copy
                            # shares the nested metadata dict across every
                            # per-language call, so each filter's stats
                            # overwrote the previous language's.
                            lang_dataset = {
                                **dataset,
                                "units": lang_units,
                                "metadata": dict(dataset.get("metadata") or {}),
                            }
                            filtered = apply_reachability_filter(
                                lang_dataset,
                                lang_dir,
                                processing_level,
                                extra_entry_points=scope_entry_points_to_units(
                                    llm_promoted_ids, lang_units
                                ),
                                extra_reachability_seeds=scope_entry_points_to_units(
                                    semantic_seed_ids, lang_units
                                ),
                                extra_retain_only_units=scope_entry_points_to_units(
                                    semantic_retain_only_ids, lang_units
                                ),
                                extra_candidate_reachability_seeds=scope_entry_points_to_units(
                                    semantic_candidate_seed_ids, lang_units
                                ),
                                library_mode=library_mode,
                                platform=effective_platform,
                            )
                            kept.extend(filtered.get("units", []))
                            _rf = (filtered.get("metadata") or {}).get(
                                "reachability_filter"
                            )
                            if _rf:
                                refilter_by_language[lang or "unknown"] = _rf

                        # Rebuild the dataset, aggregating the per-language filter
                        # stats into metadata so the reporter reads a real record
                        # instead of the stale pre-LLM one. Unfilterable languages
                        # (no call graph) are folded in as pass-throughs so the
                        # aggregate reconciles with len(kept).
                        _new_md = dict(dataset.get("metadata") or {})
                        # Only stamp a record when a real per-language filter ran.
                        # If every language was unfilterable (no call graph), the
                        # units passed through untouched, so leaving no record —
                        # the honest "not applied" signal — is correct; a "0%
                        # reduction" record would falsely claim filtering happened.
                        if refilter_by_language:
                            _per_lang = dict(refilter_by_language)
                            _unfiltered = 0
                            for _lang, _cnt in unfilterable.items():
                                _unfiltered += _cnt
                                _per_lang[_lang] = {
                                    "original_units": _cnt,
                                    "entry_points": 0,
                                    "entry_point_labels": 0,
                                    "semantic_seed_count": 0,
                                    "semantic_seed_ids": [],
                                    "semantic_retain_only_count": 0,
                                    "semantic_retain_only_ids": [],
                                    "semantic_candidate_seed_count": 0,
                                    "semantic_candidate_seed_ids": [],
                                    "candidate_reachable_units": _cnt,
                                    "candidate_reachable_added": _cnt,
                                    "candidate_reachable_ids": [],
                                    "strict_path_coverage_count": 0,
                                    "strict_path_coverage_ids": [],
                                    "candidate_path_coverage_count": 0,
                                    "candidate_path_coverage_ids": [],
                                    "fallback_only_count": _cnt,
                                    "fallback_only_ids": [],
                                    "final_analysis_count": _cnt,
                                    "fallback_triggered": True,
                                    "fallback_reason": "unfiltered_no_call_graph",
                                    "reachability_evidence": "unfiltered_no_call_graph",
                                    "reachable_only_count": 0,
                                    "reachable_only_ids": [],
                                    "reachable_units": _cnt,
                                    "filtered_out": 0,
                                    "reduction_percentage": 0,
                                    "unfilterable": True,
                                }
                            _orig = sum(
                                r.get("original_units", 0) for r in _per_lang.values()
                            )
                            _reach = sum(
                                r.get("reachable_units", 0) for r in _per_lang.values()
                            )
                            _agg = {
                                "original_units": _orig,
                                "entry_points": sum(
                                    r.get("entry_points", 0) for r in _per_lang.values()
                                ),
                                "entry_point_labels": sum(
                                    r.get("entry_point_labels", r.get("entry_points", 0))
                                    for r in _per_lang.values()
                                ),
                                "semantic_seed_count": sum(
                                    r.get("semantic_seed_count", 0)
                                    for r in _per_lang.values()
                                ),
                                "semantic_seed_ids": sorted({
                                    str(seed_id)
                                    for r in _per_lang.values()
                                    for seed_id in (r.get("semantic_seed_ids", []) or [])
                                    if seed_id
                                }),
                                "semantic_retain_only_count": sum(
                                    r.get("semantic_retain_only_count", 0)
                                    for r in _per_lang.values()
                                ),
                                "semantic_retain_only_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (
                                        r.get("semantic_retain_only_ids", []) or []
                                    )
                                    if unit_id
                                }),
                                "semantic_candidate_seed_count": sum(
                                    r.get("semantic_candidate_seed_count", 0)
                                    for r in _per_lang.values()
                                ),
                                "semantic_candidate_seed_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (
                                        r.get("semantic_candidate_seed_ids", []) or []
                                    )
                                    if unit_id
                                }),
                                "candidate_reachable_units": sum(
                                    r.get("candidate_reachable_units", 0)
                                    for r in _per_lang.values()
                                ),
                                "candidate_reachable_added": sum(
                                    r.get("candidate_reachable_added", 0)
                                    for r in _per_lang.values()
                                ),
                                "candidate_reachable_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (
                                        r.get("candidate_reachable_ids", []) or []
                                    )
                                    if unit_id
                                }),
                                "strict_path_coverage_count": sum(
                                    r.get("strict_path_coverage_count", 0)
                                    for r in _per_lang.values()
                                ),
                                "strict_path_coverage_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (r.get("strict_path_coverage_ids", []) or [])
                                    if unit_id
                                }),
                                "candidate_path_coverage_count": sum(
                                    r.get("candidate_path_coverage_count", 0)
                                    for r in _per_lang.values()
                                ),
                                "candidate_path_coverage_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (r.get("candidate_path_coverage_ids", []) or [])
                                    if unit_id
                                }),
                                "fallback_only_count": sum(
                                    r.get("fallback_only_count", 0)
                                    for r in _per_lang.values()
                                ),
                                "fallback_only_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (r.get("fallback_only_ids", []) or [])
                                    if unit_id
                                }),
                                "final_analysis_count": sum(
                                    r.get("final_analysis_count", r.get("reachable_units", 0))
                                    for r in _per_lang.values()
                                ),
                                "fallback_triggered": any(
                                    bool(r.get("fallback_triggered"))
                                    for r in _per_lang.values()
                                ),
                                "fallback_reason": "; ".join(
                                    f"{lang}: {reason}"
                                    for lang, r in _per_lang.items()
                                    if (reason := r.get("fallback_reason"))
                                ),
                                "reachability_evidence": (
                                    "mixed_filtered_and_unfiltered"
                                    if _unfiltered
                                    else "accepted_or_candidate_path"
                                ),
                                "reachable_only_count": sum(
                                    r.get(
                                        "reachable_only_count",
                                        r.get("semantic_retain_only_count", 0),
                                    )
                                    for r in _per_lang.values()
                                ),
                                "reachable_only_ids": sorted({
                                    str(unit_id)
                                    for r in _per_lang.values()
                                    for unit_id in (
                                        r.get(
                                            "reachable_only_ids",
                                            r.get("semantic_retain_only_ids", []),
                                        )
                                        or []
                                    )
                                    if unit_id
                                }),
                                "reachable_units": _reach,
                                "filtered_out": _orig - _reach,
                                # Units that flowed through unfiltered (no call
                                # graph for their language) — folded into the
                                # totals above but surfaced explicitly so the
                                # record never silently claims they were filtered.
                                "unfiltered_units": _unfiltered,
                                "reduction_percentage": (
                                    round((1 - _reach / _orig) * 100, 1)
                                    if _orig
                                    else 0
                                ),
                                "per_language": _per_lang,
                            }
                            # Lift any per-language advisory (e.g. an empty-seed
                            # blackout — a language that flowed through unfiltered
                            # because it had no real entry points) to the top
                            # level, where the reporter reads it (reporter.py:505).
                            # Without this the record reads "filter applied, N%
                            # reduction" while hiding that a language blacked out —
                            # the exact fidelity gap this record exists to close.
                            _warnings = [
                                f"{_lang}: {_r['warning']}"
                                for _lang, _r in _per_lang.items()
                                if _r.get("warning")
                            ]
                            if _warnings:
                                _agg["warning"] = "; ".join(_warnings)
                            _new_md["reachability_filter"] = _agg
                        else:
                            # No real filter ran (every language unfilterable):
                            # honour the "not applied" contract by clearing any
                            # record inherited from an upstream merge, so a stale
                            # record can never misdescribe the passed-through units.
                            _new_md.pop("reachability_filter", None)
                        dataset = {**dataset, "units": kept, "metadata": _new_md}
                        post_filter_count = len(kept)
                        result.units_count = post_filter_count
                        refilter_supported = True

                        for lang, count in unfilterable.items():
                            print(
                                f"\n  WARNING: {lang} persisted no call_graph.json; "
                                f"{count} unit(s) skip post-LLM re-filtering and "
                                f"flow to downstream stages unfiltered.",
                                file=sys.stderr,
                            )
                            _print_chinese_log(
                                f"可达性筛选降级：{lang} 没有 call_graph.json，"
                                f"{count} 个单元不做结构裁剪并全部传给下游，避免误删。"
                            )
                    else:
                        # Parser doesn't persist call_graph.json — the full
                        # unfiltered dataset will flow to downstream stages.
                        # Warn loudly so the cost impact is visible.
                        print(
                            f"\n  WARNING: --llm-reachability with "
                            f"--level {processing_level}: "
                            f"{parse_result.language} does not yet support "
                            f"post-LLM re-filtering (call_graph.json not found). "
                            f"Downstream stages will process all "
                            f"{pre_filter_count} units instead of the filtered "
                            f"subset — this may significantly increase cost.",
                            file=sys.stderr,
                        )
                        _print_chinese_log(
                            f"可达性筛选降级：{parse_result.language} 没有 call_graph.json，"
                            f"{pre_filter_count} 个单元全部保留；这是保召回的安全选择，但会增加模型成本。"
                        )

                # Persist final dataset so downstream stages see promoted
                # entry points, per-unit signals, and the applied filter.
                write_json(active_dataset_path, dataset, indent=2)

                ctx.summary = {
                    "units_reviewed": pre_filter_count,
                    "signals_added": summary["signals_applied"],
                    "entry_points_promoted": summary["entry_points_promoted"],
                    "semantic_seed_count": len(summary.get("semantic_seed_ids", [])),
                    "semantic_seed_ids": summary.get("semantic_seed_ids", []),
                    "semantic_retain_only_count": len(
                        summary.get("semantic_retain_only_ids", [])
                    ),
                    "semantic_retain_only_ids": summary.get(
                        "semantic_retain_only_ids", []
                    ),
                    "reachable_only_ids": summary.get("reachable_only_ids", []),
                    "reachable_only_count": len(
                        summary.get("reachable_only_ids", [])
                    ),
                    "semantic_candidate_seed_count": len(
                        summary.get("semantic_candidate_seed_ids", [])
                    ),
                    "semantic_candidate_seed_ids": summary.get(
                        "semantic_candidate_seed_ids", []
                    ),
                    "candidate_seed_count": len(
                        summary.get("semantic_candidate_seed_ids", [])
                    ),
                    "candidate_reachable_added": (
                        (dataset.get("metadata", {}).get("reachability_filter", {}) or {})
                        .get("candidate_reachable_added", 0)
                    ),
                    "seed_counts": summary.get("seed_counts", {}),
                    "retained_only_counts": summary.get(
                        "retained_only_counts", {}
                    ),
                    "seed_rejected_counts": summary.get("rejected_counts", {}),
                    "seed_review_only": summary.get("review_only", 0),
                    "retained_only": summary.get("retained_only", 0),
                    "units_touched": summary["units_touched"],
                    "post_filter_units": post_filter_count,
                    "refilter_supported": refilter_supported,
                }
                ctx.outputs = {"signals_path": signals_path}

                print(
                    f"  LLM reachability: {summary['signals_applied']} signals, "
                    f"{summary['entry_points_promoted']} new entry points, "
                    f"{len(summary.get('semantic_seed_ids', []))} semantic seeds, "
                    f"{len(summary.get('semantic_candidate_seed_ids', []))} medium candidate seeds",
                    file=sys.stderr,
                )
                _print_chinese_log(
                    f"可达性结果：模型应用 {summary['signals_applied']} 条信号，"
                    f"提升 {summary['entry_points_promoted']} 个入口，"
                    f"接受 {len(summary.get('semantic_seed_ids', []))} 个 high 语义种子，"
                    f"形成 {len(summary.get('semantic_candidate_seed_ids', []))} 个 medium candidate seed，"
                    "沿已接受调用边扩展到 candidate_reachable，"
                    f"触及 {summary['units_touched']} 个单元；结果写入 {signals_path}。"
                )
                if processing_level != "all" and refilter_supported:
                    print(
                        f"  After reachability filter: {post_filter_count} units",
                        file=sys.stderr,
                    )
                    _print_chinese_log(
                        f"可达性筛选：high 入口/语义种子已重新做 BFS，"
                        f"medium 单元进入独立 candidate BFS，不升级为 strict 入口；"
                        f"下游阶段将处理 {post_filter_count} 个单元，而不是原始 {pre_filter_count} 个单元。"
                    )
                elif processing_level != "all":
                    _print_chinese_log(
                        "可达性筛选：当前解析器没有可用调用图，无法安全重筛；"
                        f"为避免误删，{pre_filter_count} 个单元全部保留到下游，成本可能增加。"
                    )

        collected_step_reports.append(
            _load_step_report(output_dir, "llm-reachability")
        )

        # Evaluation runs sometimes need to measure only reachability recall.
        # Return a normal ScanResult after the artifact and stage report are
        # complete instead of killing the process mid-stage.  The downstream
        # stages are explicitly recorded as skipped so the result remains
        # machine-readable and auditable.
        if stop_after == "llm-reachability":
            downstream_steps = (
                "llm-call-graph-recovery",
                "llm-call-graph-candidate-review",
                "llm-call-graph-projection",
                "openharmony-dispatch-code-evidence",
                "openharmony-gap-tasks",
                "enhance",
                "analyze",
                "verify",
                "build-output",
                "dynamic-test",
                "report",
            )
            for downstream_step in downstream_steps:
                _record_skip(result, downstream_step, "stop_after_llm_reachability")
            result.step_reports = collected_step_reports
            _print_chinese_log(
                "可达性评测阶段已完成：根据 --stop-after llm-reachability "
                "主动结束本次扫描；后续上下文增强、漏洞分析、验证、动态测试和报告阶段均未执行。"
            )
            return result
    else:
        _print_chinese_log(
            "LLM 可达性阶段跳过：未开启 --llm-reachability；"
            "本次只使用解析器的结构化入口和调用图结果。"
        )
        _record_skip(result, "llm-reachability", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 2.75: OpenHarmony LLM call-edge recovery (optional, advisory)
    # ---------------------------------------------------------------
    # This stage consumes parser-produced residual diagnostics and the
    # per-language function index.  It deliberately runs before enhancement
    # and analysis so its artifact is available to the rest of the pipeline,
    # but it never mutates the graph or dataset.  The iterative mode is an
    # explicit opt-in; the legacy one-shot mode remains unchanged.
    if llm_call_graph_recovery or llm_call_graph_iterative_recovery:
        recovery_step = "llm-call-graph-recovery"
        print(_step_label("Running LLM call-graph recovery review..."), file=sys.stderr)
        _print_chinese_log(
            "阶段/OpenHarmony 调用图恢复：正在复核解析器标记的残余间接调用点，"
            f"模式={'迭代多轮' if llm_call_graph_iterative_recovery else '单轮'}；"
            "模型只提交带证据的候选边，不直接改写原生 call_graph.json。"
        )
        if llm_call_graph_iterative_recovery:
            _print_chinese_log(
                "恢复范围决策：迭代模式会同时复核无候选残余和解析器已列出的候选边，"
                "投影后的新目标还能进入下一轮入口驱动 BFS。"
            )
        else:
            _print_chinese_log(
                "恢复范围决策：单轮模式默认处理无候选残余；调用站点台账若明确标记"
                "edge_missing/not_linked，即使已有候选也会排队，避免台账独有缺边被漏掉。"
                "普通候选站点仍需另外开启 --llm-call-graph-candidate-review，或改用迭代恢复；"
                "候选表本身不会被当成已确认调用边。"
            )
        _print_chinese_log(
            "调用图恢复输入：每种语言分别读取 call_graph.json、"
            "call_graph_residuals.json、函数索引和入口提示；缺少残余产物的语言会明确记录为未复核。"
        )

        with step_context(recovery_step, output_dir, inputs={
            "platform": effective_platform,
            "dataset_path": active_dataset_path,
            "source": "call_graph_residuals.json",
            "binding_phase": "llm_reach",
            "mode": (
                "iterative" if llm_call_graph_iterative_recovery else "one_shot"
            ),
        }) as ctx:
            if effective_platform != "openharmony":
                # The protocol is OpenHarmony-specific.  A generic scan that
                # happens to receive the flag must remain a valid scan and,
                # importantly, must not send generic code to an OH prompt.
                ctx.status = "skipped"
                ctx.summary = {
                    "skipped": True,
                    "reason": "unsupported_platform",
                    "platform": effective_platform,
                }
                _record_skip(result, recovery_step, "unsupported_platform")
            else:
                from core.platforms.openharmony.llm_call_graph_recovery import (
                    RECOVERY_SCHEMA_VERSION,
                    RECOVERY_TASK,
                    run_recovery_review,
                )
                from core.platforms.openharmony.llm_call_graph_rounds import (
                    ROUND_SCHEMA_VERSION,
                    ROUND_TASK,
                    run_iterative_recovery_review,
                )

                iterative_mode = llm_call_graph_iterative_recovery
                recovery_path = os.path.join(
                    output_dir,
                    (
                        "llm_call_graph_recovery_rounds.json"
                        if iterative_mode
                        else "llm_call_graph_recovery.json"
                    ),
                )
                reports: list[dict] = []
                missing_artifacts: list[dict] = []

                # Single-language parsers persist a flat call_graph.json;
                # multi-language parses expose one graph per language through
                # call_graphs.json.  resolve_call_graph_dirs() probes the
                # filesystem and handles both layouts without a language list.
                graph_dirs = resolve_call_graph_dirs(output_dir)
                try:
                    recovery_binding = registry.get("llm_reach")
                except Exception as exc:  # defensive: registry is built above
                    recovery_binding = None
                    reports.append({
                        "language": result.language or "unknown",
                        "status": "failed",
                        "error": f"llm_reach binding unavailable: {exc}",
                    })

                dataset_entry_points: set[str] = set()
                dataset_candidate_seed_points: set[str] = set()
                try:
                    dataset_payload = read_json(active_dataset_path)
                    dataset_units = (
                        dataset_payload.get("units", [])
                        if isinstance(dataset_payload, dict)
                        else []
                    )
                    if isinstance(dataset_units, list):
                        dataset_entry_points = {
                            str(unit.get("id"))
                            for unit in dataset_units
                            if isinstance(unit, dict)
                            and (
                                unit.get("is_entry_point") is True
                                or unit.get("semantic_reachability_seed") is True
                            )
                            and unit.get("id")
                        }
                        dataset_candidate_seed_points = {
                            str(unit.get("id"))
                            for unit in dataset_units
                            if isinstance(unit, dict)
                            and unit.get("semantic_reachability_candidate_seed") is True
                            and unit.get("id")
                        }
                except Exception as exc:
                    # Entry-point hints are optional.  The graph's own
                    # ``is_entry_point`` flags remain available, so a malformed
                    # dataset must not discard residual review altogether.
                    print(
                        f"  [Warning] Could not load dataset entry-point hints: {exc}",
                        file=sys.stderr,
                    )
                    _print_chinese_log(
                        f"调用图恢复未读取到 dataset 入口提示（{exc}），"
                        "仍会使用调用图自身的入口标记，不因可选提示缺失而放弃复核。"
                    )

                for language_name, graph_dir in sorted(
                    graph_dirs.items(),
                    key=lambda item: "" if item[0] is None else str(item[0]),
                ):
                    label = language_name or result.language or "unknown"
                    graph_path = os.path.join(graph_dir, "call_graph.json")
                    residual_path = os.path.join(
                        graph_dir, "call_graph_residuals.json"
                    )
                    relative_graph = os.path.relpath(graph_path, output_dir)
                    relative_residual = os.path.relpath(residual_path, output_dir)
                    if not os.path.isfile(residual_path):
                        missing_artifacts.append({
                            "language": label,
                            "call_graph_path": relative_graph,
                            "residuals_path": relative_residual,
                            "reason": "call_graph_residuals_missing",
                        })
                        _print_chinese_log(
                            f"调用图恢复跳过语言={label}：未找到 {relative_residual}，"
                            "因此不向模型发送猜测性输入，缺失情况会写入恢复报告。"
                        )
                        continue

                    try:
                        graph_payload = read_json(graph_path)
                        diagnostics = read_json(residual_path)
                        functions = (
                            graph_payload.get("functions", {})
                            if isinstance(graph_payload, dict)
                            else {}
                        )
                        if not isinstance(functions, dict):
                            raise ValueError("call_graph.functions must be an object")
                        graph_entry_points = {
                            str(function_id)
                            for function_id, function in functions.items()
                            if isinstance(function, dict)
                            and function.get("is_entry_point") is True
                        }
                        if iterative_mode:
                            semantic_payload = None
                            semantic_path = os.path.join(
                                graph_dir, "semantic_graph.json"
                            )
                            if os.path.isfile(semantic_path):
                                semantic_payload = read_json(semantic_path)
                            review = run_iterative_recovery_review(
                                diagnostics,
                                functions,
                                binding=recovery_binding,
                                entry_point_ids=graph_entry_points | dataset_entry_points,
                                candidate_seed_ids=dataset_candidate_seed_points,
                                call_graph=graph_payload.get("call_graph", {}),
                                semantic_graph=semantic_payload,
                                # Iterative mode is the explicit high-recall
                                # path: review both parser-resolved candidate
                                # sites and candidate-less residuals so a
                                # recovered handler can expand the next BFS
                                # frontier.
                                include_candidate_sites=True,
                            )
                        else:
                            review = run_recovery_review(
                                diagnostics,
                                functions,
                                binding=recovery_binding,
                                entry_point_ids=graph_entry_points | dataset_entry_points,
                                call_graph=graph_payload.get("call_graph", {}),
                                reverse_call_graph=graph_payload.get(
                                    "reverse_call_graph", {}
                                ),
                            )
                        reports.append({
                            "language": label,
                            "status": review.get("status", "unknown"),
                            "call_graph_path": relative_graph,
                            "residuals_path": relative_residual,
                            "mode": "iterative" if iterative_mode else "one_shot",
                            "report": review,
                        })
                    except Exception as exc:  # optional stage: keep prior work
                        print(
                            f"  [Warning] Recovery review failed for {label}: {exc}",
                            file=sys.stderr,
                        )
                        _print_chinese_log(
                            f"调用图恢复失败（语言={label}，原因={exc}），"
                            "该语言保留原解析结果，不把无法证明的边写入图。"
                        )
                        reports.append({
                            "language": label,
                            "status": "failed",
                            "call_graph_path": relative_graph,
                            "residuals_path": relative_residual,
                            "mode": "iterative" if iterative_mode else "one_shot",
                            "error": str(exc)[:500],
                        })

                report_statuses = {item.get("status") for item in reports}
                if not reports:
                    overall_status = "no_artifacts"
                elif report_statuses <= {"complete", "no_sites", "no_entry_points"}:
                    overall_status = "complete"
                elif report_statuses & {
                    "complete",
                    "no_sites",
                    "no_entry_points",
                    "partial",
                }:
                    overall_status = "partial"
                else:
                    overall_status = "failed"

                aggregate = {
                    "languages": len(reports),
                    "missing_artifacts": len(missing_artifacts),
                    "worklist_sites": 0,
                    "request_batches": 0,
                    "attempts": 0,
                    "llm_calls": 0,
                    "retry_count": 0,
                    "parsed_decisions": 0,
                    "accepted": 0,
                    "kept_unresolved": 0,
                    "rejected": 0,
                    "unreviewed_sites": 0,
                    "rounds": 0,
                    "sites_scheduled": 0,
                    "sites_reviewed": 0,
                    "accepted_decisions": 0,
                    "projected_edges": 0,
                    "duplicate_edges": 0,
                    "failed_rounds": 0,
                }
                for item in reports:
                    report_payload = item.get("report", {})
                    summary = _normalise_call_graph_review_summary(
                        report_payload,
                        iterative=iterative_mode,
                    )
                    if not isinstance(summary, dict):
                        continue
                    for key in (
                        "worklist_sites",
                        "request_batches",
                        "attempts",
                        "llm_calls",
                        "retry_count",
                        "parsed_decisions",
                        "accepted",
                        "kept_unresolved",
                        "rejected",
                        "unreviewed_sites",
                        "rounds",
                        "sites_scheduled",
                        "sites_reviewed",
                        "accepted_decisions",
                        "projected_edges",
                        "duplicate_edges",
                        "failed_rounds",
                    ):
                        try:
                            aggregate[key] += int(summary.get(key, 0) or 0)
                        except (TypeError, ValueError):
                            continue

                payload = {
                    "schema_version": (
                        ROUND_SCHEMA_VERSION
                        if iterative_mode
                        else RECOVERY_SCHEMA_VERSION
                    ),
                    "task": ROUND_TASK if iterative_mode else RECOVERY_TASK,
                    "platform": "openharmony",
                    "mode": "iterative" if iterative_mode else "one_shot",
                    "status": overall_status,
                    "reports": reports,
                    "missing_artifacts": missing_artifacts,
                    "summary": aggregate,
                }
                write_json(recovery_path, payload, indent=2)
                if iterative_mode:
                    result.llm_call_graph_rounds_path = recovery_path
                else:
                    result.llm_call_graph_recovery_path = recovery_path
                ctx.outputs = {
                    "rounds_path" if iterative_mode else "recovery_path": recovery_path
                }
                ctx.summary = {
                    "status": overall_status,
                    "mode": "iterative" if iterative_mode else "one_shot",
                    **aggregate,
                }
                if overall_status == "no_artifacts":
                    ctx.status = "skipped"
                    _record_skip(result, recovery_step, "no_artifacts")
                elif overall_status == "failed":
                    ctx.status = "skipped"
                    _record_skip(result, recovery_step, "failed")
                elif overall_status == "partial":
                    # The stage ran, but at least one language/report was
                    # incomplete. Preserve that distinction in the step
                    # report instead of presenting a partial review as a
                    # fully covered stage.
                    ctx.status = "partial"
                _print_chinese_log(
                    f"调用图恢复结果：状态={overall_status}，语言数={len(reports)}，"
                    f"待复核站点={aggregate['worklist_sites']}，请求批次={aggregate.get('request_batches', 0)}，"
                    f"模型调用={aggregate['llm_calls']}，"
                    f"接受={aggregate['accepted']}，保留未决={aggregate['kept_unresolved']}，"
                    f"拒绝={aggregate['rejected']}；结果仅写入恢复报告。"
                )

        collected_step_reports.append(_load_step_report(output_dir, recovery_step))
    else:
        _print_chinese_log(
            "OpenHarmony 调用图恢复阶段跳过：未开启恢复相关开关，"
            "本次不会为解析器残余间接调用点额外消耗模型调用。"
        )
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 2.76: OpenHarmony candidate-edge review (optional, advisory)
    # ---------------------------------------------------------------
    # This is intentionally a separate pass from the residual-only recovery
    # above.  Candidate-bearing sites are usually already covered by a
    # deterministic parser heuristic, but a model can audit whether the
    # complete candidate set (for example every Binder transaction handler)
    # should be represented as edges.  The pass writes its own artifact and
    # never changes call_graph.json, dataset.json, or reachability.
    if llm_call_graph_candidate_review:
        _run_openharmony_candidate_review_stage(
            result=result,
            output_dir=output_dir,
            active_dataset_path=active_dataset_path,
            effective_platform=effective_platform,
            registry=registry,
            step_label=_step_label,
            collected_step_reports=collected_step_reports,
        )
    else:
        _print_chinese_log(
            "OpenHarmony 候选边复核阶段跳过：未开启 --llm-call-graph-candidate-review，"
            "不会对已有候选目标再次调用模型。"
        )

    # ---------------------------------------------------------------
    # Step 2.765: OpenHarmony LLM call-edge projection (optional, additive)
    # ---------------------------------------------------------------
    # Projection is deliberately a separate opt-in boundary.  It consumes the
    # persisted recovery/candidate reports and emits a semantic overlay.  For
    # a non-``all`` scan it then re-filters the preserved all-units dataset with
    # that overlay; the parser graph itself is never rewritten.  Keeping both
    # the overlay and the refilter metadata in this stage makes the effect
    # auditable before enhancement/detection consume the resulting dataset.
    if llm_call_graph_projection:
        _run_openharmony_recovery_projection_stage(
            result=result,
            repo_path=repo_path,
            output_dir=output_dir,
            active_dataset_path=active_dataset_path,
            unfiltered_dataset_path=unfiltered_dataset_path,
            processing_level=processing_level,
            library_mode=library_mode,
            effective_platform=effective_platform,
            source_revision=graph_source_revision,
            build_config_id=graph_build_config_id,
            collected_step_reports=collected_step_reports,
            step_label=_step_label,
        )
    else:
        _print_chinese_log(
            "OpenHarmony 调用边投影阶段跳过：未开启 --llm-call-graph-projection，"
            "恢复报告不会影响本次 dataset 的可达性范围。"
        )

    # ---------------------------------------------------------------
    # Step 2.77: OpenHarmony dispatch-code evidence (optional, deterministic)
    # ---------------------------------------------------------------
    # This pass reads source/header constants referenced by parser-produced
    # dispatch registrations.  It is independent of the LLM passes and emits
    # metadata for a future dynamic-test payload builder only.
    if openharmony_dispatch_code_evidence:
        _run_openharmony_dispatch_code_evidence_stage(
            result=result,
            repo_path=repo_path,
            output_dir=output_dir,
            active_dataset_path=active_dataset_path,
            effective_platform=effective_platform,
            collected_step_reports=collected_step_reports,
            step_label=_step_label,
        )
    else:
        _print_chinese_log(
            "OpenHarmony 分派码证据阶段跳过：未开启对应开关，"
            "本次不从源码常量提取动态验证所需的 selector 值。"
        )

    # ---------------------------------------------------------------
    # Step 2.8: OpenHarmony P3 gap-task queue (deterministic)
    # ---------------------------------------------------------------
    # Refresh after recovery/projection so task status and graph versions refer
    # to the effective graph that the following enhancement/Stage 1 consumes.
    if effective_platform == "openharmony":
        p3_step = "openharmony-gap-tasks"
        print(_step_label("Building OpenHarmony gap-task queue..."), file=sys.stderr)
        _print_chinese_log(
            "阶段 P3/缺口任务调度：按调用点聚合未决关系，"
            "为直接绑定、构建上下文、对象/回调分派和候选复核生成有界任务；"
            "任务不会把未经核验的候选边提升到 strict 图。"
        )
        with step_context(p3_step, output_dir, inputs={
            "platform": effective_platform,
            "source": "call_graph_gap_report.json + effective_call_graph.json",
            "revision": graph_source_revision,
            "build_config_id": graph_build_config_id,
        }) as ctx:
            tasks_path, tasks_payload = _write_openharmony_gap_tasks(
                result=result,
                output_dir=output_dir,
                repo_path=repo_path,
                source_revision=graph_source_revision,
                build_config_id=graph_build_config_id,
                effective_platform=effective_platform,
                effective_graphs=(
                    effective_graphs
                    if isinstance(effective_graphs, list)
                    else None
                ),
                gap_report=call_graph_gap_report,
            )
            if tasks_path:
                ctx.outputs = {"gap_tasks_path": tasks_path}
                summary = tasks_payload.get("summary", {}) if isinstance(tasks_payload, Mapping) else {}
                ctx.summary = {
                    "status": "complete",
                    "tasks": summary.get("tasks", 0),
                    "pending": summary.get("pending", 0),
                    "resolved": summary.get("resolved", 0),
                    "by_kind": summary.get("by_kind", {}),
                }
                # Build the deterministic entry-path view on the same graph
                # snapshot. It is written back to the active dataset because
                # both agentic enhancement and Stage 1 consume that file.
                try:
                    from core.reachability_context import build_reachability_context

                    current_dataset = read_json(active_dataset_path)
                    enriched_dataset = build_reachability_context(
                        current_dataset,
                        result.effective_call_graph_paths,
                        platform=effective_platform,
                    )
                    pre_context_path = os.path.join(
                        output_dir, "dataset_pre_reachability_context.json"
                    )
                    if not os.path.exists(pre_context_path):
                        write_json(pre_context_path, current_dataset, indent=2)
                    write_json(active_dataset_path, enriched_dataset, indent=2)
                    context_summary = enriched_dataset.get("metadata", {}).get(
                        "reachability_context", {}
                    )
                    context_path = os.path.join(output_dir, "reachability_context.json")
                    write_json(
                        context_path,
                        {
                            "schema_version": context_summary.get("schema_version", 1),
                            "graph_versions": context_summary.get("graph_versions", []),
                            "summary": context_summary,
                            "units": [
                                {
                                    "id": unit.get("id"),
                                    "reachability_context": unit.get("reachability_context"),
                                }
                                for unit in enriched_dataset.get("units", [])
                                if isinstance(unit, Mapping)
                            ],
                        },
                        indent=2,
                    )
                    ctx.outputs["reachability_context_path"] = context_path
                    ctx.outputs["dataset_pre_reachability_context_path"] = pre_context_path
                    ctx.summary["entry_path_context"] = context_summary
                    _print_chinese_log(
                        "P3 入口血缘上下文：已把有效图重建的顶层入口、路径节点、源码位置和"
                        f"缺失上游信息写入 Stage 1 数据集；有路径单元={context_summary.get('units_with_paths', 0)}，"
                        f"无完整路径={context_summary.get('units_without_paths', 0)}。"
                    )
                except Exception as exc:
                    ctx.status = "partial"
                    ctx.summary["entry_path_context_error"] = str(exc)[:500]
                    _print_chinese_log(
                        f"P3 入口血缘上下文生成失败（{exc}），保留原 dataset；"
                        "Stage 1 会明确看到缺少确定入口路径，而不是伪造路径。"
                    )
            else:
                ctx.status = "partial"
                ctx.summary = tasks_payload if isinstance(tasks_payload, Mapping) else {
                    "status": "partial"
                }
        collected_step_reports.append(_load_step_report(output_dir, p3_step))
        if stop_after == "openharmony-gap-tasks":
            downstream_steps = (
                "enhance",
                "analyze",
                "verify",
                "openharmony-analysis-feedback",
                "build-output",
                "dynamic-test",
                "report",
            )
            for downstream_step in downstream_steps:
                _record_skip(result, downstream_step, "stop_after_openharmony_gap_tasks")
            result.step_reports = collected_step_reports
            _print_chinese_log(
                "OpenHarmony 缺口任务/入口上下文阶段已完成：根据 --stop-after "
                "openharmony-gap-tasks 主动结束本次扫描；未执行上下文增强和 Stage 1。"
            )
            return result
    else:
        _record_skip(result, "openharmony-gap-tasks", "unsupported_platform")

    # ---------------------------------------------------------------
    # Step 3: Enhance (optional)
    # ---------------------------------------------------------------
    if enhance:
        from core.enhancer import enhance_dataset

        print(_step_label("Enhancing dataset..."), file=sys.stderr)
        _print_chinese_log(
            f"阶段 3/上下文增强：对当前数据集 {active_dataset_path} 补充安全语义，"
            f"运行模式={enhance_mode}；该阶段只丰富单元上下文，不改变解析器原始调用图。"
        )

        enhanced_path = os.path.join(output_dir, "dataset_enhanced.json")

        with step_context("enhance", output_dir, inputs={
            "dataset_path": active_dataset_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
            "repo_path": repo_path,
            "mode": enhance_mode,
        }) as ctx:
            # Enhance is OPTIONAL: a failure here must not discard the completed
            # parse work. Catch-and-continue (matching app-context /
            # llm-reachability), since step_context re-raises otherwise.
            try:
                enhance_result = enhance_dataset(
                    dataset_path=active_dataset_path,
                    output_path=enhanced_path,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    repo_path=repo_path,
                    mode=enhance_mode,
                    registry=registry,
                    workers=workers,
                    backoff_seconds=backoff_seconds,
                    # checkpoint_path auto-derived from output_path
                )

                ctx.summary = {
                    "units_enhanced": enhance_result.units_enhanced,
                    "error_count": enhance_result.error_count,
                    "classifications": enhance_result.classifications,
                    "mode": enhance_mode,
                }
                if enhance_result.error_summary:
                    ctx.summary["error_summary"] = enhance_result.error_summary
                ctx.outputs = {
                    "enhanced_dataset_path": enhance_result.enhanced_dataset_path,
                }

                result.enhanced_dataset_path = enhance_result.enhanced_dataset_path
                active_dataset_path = enhance_result.enhanced_dataset_path

                print(f"  Enhanced: {enhance_result.units_enhanced} units", file=sys.stderr)
                print(f"  Classifications: {enhance_result.classifications}", file=sys.stderr)
                _print_chinese_log(
                    f"上下文增强结果：已增强 {enhance_result.units_enhanced} 个单元，"
                    f"分类统计={enhance_result.classifications}；下游将改用 {active_dataset_path}。"
                )
                if enhance_result.error_summary:
                    print(f"  Errors: {enhance_result.error_count} ({enhance_result.error_summary})", file=sys.stderr)
                    _print_chinese_log(
                        f"上下文增强存在 {enhance_result.error_count} 个错误："
                        f"{enhance_result.error_summary}；未失败的单元仍继续进入检测。"
                    )
            except Exception as e:
                print(f"  WARNING: Enhancement failed: {e}", file=sys.stderr)
                print("  Continuing with the un-enhanced dataset.", file=sys.stderr)
                _print_chinese_log(
                    f"上下文增强失败（{e}），已回退到未增强 dataset，"
                    "不会丢弃前面的解析和可达性产物。"
                )
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(e)}
                _record_skip(result, "enhance", "failed")

        collected_step_reports.append(_load_step_report(output_dir, "enhance"))
    else:
        print(_step_label("Skipping enhancement (--no-enhance)."), file=sys.stderr)
        _print_chinese_log(
            "上下文增强阶段跳过：运行参数关闭 --no-enhance；"
            "检测阶段直接使用解析/可达性阶段的 dataset。"
        )
        _record_skip(result, "enhance", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 4: Detect (Stage 1)
    # ---------------------------------------------------------------
    from core.analyzer import run_analysis

    print(_step_label("Running vulnerability detection (Stage 1)..."), file=sys.stderr)
    _print_chinese_log(
        "阶段 4/漏洞检测（第一阶段）：将逐个分析当前数据集中的函数单元，"
        f"输入={active_dataset_path}，模型={registry.get('analyze').provider_name}/"
        f"{registry.get('analyze').model}，并结合应用上下文、调用关系和安全规则给出初步判定。"
    )
    _print_chinese_log(
        "阶段职责：Stage 1 负责初步漏洞检测；参数级 source-to-sink 数据流不作为"
        "Stage 1 准入条件，由 Stage 2 工具复核并记录验证状态。"
    )
    _print_chinese_log(
        f"检测参数：limit={limit or '不限制'}，并行工作线程={workers}；"
        "分析结果先写入 results.json，后续验证阶段才会决定哪些问题可以确认。"
    )

    analyze_binding = registry.get("analyze")
    with step_context("analyze", output_dir, inputs={
        "dataset_path": active_dataset_path,
        "model": analyze_binding.model,
        "provider": analyze_binding.provider_name,
        "limit": limit,
    }) as ctx:
        analyze_result = run_analysis(
            dataset_path=active_dataset_path,
            output_dir=output_dir,
            analyzer_output_path=parse_result.analyzer_output_path,
            app_context_path=app_context_path,
            repo_path=repo_path,
            limit=limit,
            registry=registry,
            workers=workers,
            backoff_seconds=backoff_seconds,
        )

        ctx.summary = {
            "total_units": analyze_result.metrics.total,
            "analyzed": analyze_result.metrics.total - analyze_result.metrics.errors,
            "stage1_role": "vulnerability_detection",
            "parameter_dataflow_owner": "stage2",
            "parameter_dataflow_is_stage1_gate": False,
            "verdicts": {
                "vulnerable": analyze_result.metrics.vulnerable,
                "bypassable": analyze_result.metrics.bypassable,
                "inconclusive": analyze_result.metrics.inconclusive,
                "protected": analyze_result.metrics.protected,
                "safe": analyze_result.metrics.safe,
                "errors": analyze_result.metrics.errors,
            },
        }
        ctx.outputs = {"results_path": analyze_result.results_path}

    result.results_path = analyze_result.results_path
    result.metrics = analyze_result.metrics
    collected_step_reports.append(_load_step_report(output_dir, "analyze"))
    _print_chinese_log(
        f"漏洞检测结果：共分析 {analyze_result.metrics.total} 个单元，"
        f"初步判定为漏洞={analyze_result.metrics.vulnerable}、可绕过={analyze_result.metrics.bypassable}、"
        f"受保护={analyze_result.metrics.protected}、安全={analyze_result.metrics.safe}、"
        f"待定={analyze_result.metrics.inconclusive}、错误={analyze_result.metrics.errors}；"
        f"结果写入 {analyze_result.results_path}。"
    )
    print(file=sys.stderr)

    # Active results path — may be updated by verify step
    active_results_path = analyze_result.results_path

    # ---------------------------------------------------------------
    # Step 5: Verify (Stage 2) — optional
    # ---------------------------------------------------------------
    # Stage 2 can also act as an evidence-recovery pass for Stage-1
    # inconclusive findings.  Keep safe/protected units out of scope, but do
    # not skip verification merely because the first stage found no conclusive
    # vulnerability yet.
    has_findings = (
        analyze_result.metrics.vulnerable > 0
        or analyze_result.metrics.bypassable > 0
        or analyze_result.metrics.inconclusive > 0
    )

    if verify and has_findings:
        from core.verifier import run_verification

        print(_step_label("Running verification (Stage 2)..."), file=sys.stderr)
        _print_chinese_log(
            f"阶段 5/结果验证（第二阶段）：发现 {analyze_result.metrics.vulnerable + analyze_result.metrics.bypassable} 个"
            f"初步高风险条目和 {analyze_result.metrics.inconclusive} 个待定条目，"
            "启动攻击者视角复核及缺失证据补充；模型会尝试寻找可利用路径，"
            "而不是直接接受第一阶段结论。"
        )

        with step_context("verify", output_dir, inputs={
            "results_path": analyze_result.results_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
        }) as ctx:
            # Verify is OPTIONAL: a failure here must not discard completed
            # parse/analyze work (step_context re-raises otherwise).
            try:
                verify_result = run_verification(
                    results_path=analyze_result.results_path,
                    output_dir=output_dir,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    app_context_path=app_context_path,
                    repo_path=repo_path,
                    workers=workers,
                    backoff_seconds=backoff_seconds,
                    registry=registry,
                    include_inconclusive=True,
                )

                ctx.summary = {
                    "findings_input": verify_result.findings_input,
                    "findings_verified": verify_result.findings_verified,
                    "agreed": verify_result.agreed,
                    "disagreed": verify_result.disagreed,
                    "confirmed_vulnerabilities": verify_result.confirmed_vulnerabilities,
                    "needs_review": verify_result.needs_review,
                    "error_count": verify_result.error_count,
                    "inconclusive_input": verify_result.inconclusive_input,
                    "inconclusive_promoted": verify_result.inconclusive_promoted,
                    "inconclusive_resolved": verify_result.inconclusive_resolved,
                    "inconclusive_remaining": verify_result.inconclusive_remaining,
                }
                ctx.outputs = {
                    "verified_results_path": verify_result.verified_results_path,
                }

                result.verified_results_path = verify_result.verified_results_path
                active_results_path = verify_result.verified_results_path

                print(f"  Confirmed: {verify_result.confirmed_vulnerabilities} vulnerabilities",
                      file=sys.stderr)
                if verify_result.needs_review:
                    print(f"  Needs manual review: {verify_result.needs_review} "
                         f"(verification incomplete)", file=sys.stderr)
                    _print_chinese_log(
                        f"验证结果：有 {verify_result.needs_review} 个条目无法完成复核，"
                        "它们保持待人工审阅，不会被错误归类为安全。"
                    )

                # Update metrics from the merged final result buckets.  Using
                # ``disagreed`` as a delta is unsafe now that an inconclusive
                # result can be resolved or promoted; it would leave the old
                # inconclusive count in place and double-count the unit.
                final_counts = verify_result.final_counts or {}
                if all(key in final_counts for key in (
                    "vulnerable", "bypassable", "inconclusive", "protected", "safe", "errors"
                )):
                    result.metrics = AnalysisMetrics(
                        total=analyze_result.metrics.total,
                        vulnerable=final_counts.get("vulnerable", 0),
                        bypassable=final_counts.get("bypassable", 0),
                        inconclusive=final_counts.get("inconclusive", 0),
                        protected=final_counts.get("protected", 0),
                        safe=final_counts.get("safe", 0),
                        errors=final_counts.get("errors", 0),
                        verified=verify_result.findings_verified,
                        stage2_agreed=verify_result.agreed,
                        stage2_disagreed=verify_result.disagreed,
                        needs_review=verify_result.needs_review,
                        stage2_inconclusive_input=verify_result.inconclusive_input,
                        stage2_inconclusive_promoted=verify_result.inconclusive_promoted,
                        stage2_inconclusive_resolved=verify_result.inconclusive_resolved,
                        stage2_inconclusive_remaining=verify_result.inconclusive_remaining,
                    )
                else:
                    # Compatibility fallback for a custom verifier result from
                    # an older extension that does not expose final_counts.
                    result.metrics = AnalysisMetrics(
                        total=analyze_result.metrics.total,
                        vulnerable=verify_result.confirmed_vulnerabilities,
                        bypassable=0,
                        inconclusive=analyze_result.metrics.inconclusive,
                        protected=analyze_result.metrics.protected,
                        safe=analyze_result.metrics.safe + verify_result.disagreed,
                        errors=analyze_result.metrics.errors + verify_result.error_count,
                        verified=verify_result.findings_verified,
                        stage2_agreed=verify_result.agreed,
                        stage2_disagreed=verify_result.disagreed,
                        needs_review=verify_result.needs_review,
                    )
                _print_chinese_log(
                    f"验证结果：输入={verify_result.findings_input}，已完成={verify_result.findings_verified}，"
                    f"确认漏洞={verify_result.confirmed_vulnerabilities}，"
                    f"模型同意={verify_result.agreed}，模型降级为受保护={verify_result.disagreed}，"
                    f"需人工审阅={verify_result.needs_review}；"
                    f"待定补证升级={verify_result.inconclusive_promoted}，"
                    f"待定补证解决={verify_result.inconclusive_resolved}，"
                    f"仍待定={verify_result.inconclusive_remaining}；"
                    f"结果写入 {verify_result.verified_results_path}。"
                )
            except Exception as e:
                print(f"  WARNING: Verification failed: {e}", file=sys.stderr)
                print("  Continuing with unverified Stage 1 results.", file=sys.stderr)
                _print_chinese_log(
                    f"结果验证失败（{e}），回退到第一阶段结果；"
                    "不会把未验证条目静默删除，失败原因会记录到阶段报告。"
                )
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(e)}
                _record_skip(result, "verify", "failed")

        collected_step_reports.append(_load_step_report(output_dir, "verify"))
    elif verify and not has_findings:
        print(_step_label("Skipping verification (no candidates)."),
              file=sys.stderr)
        _print_chinese_log(
            "结果验证阶段跳过：第一阶段没有“漏洞”“可绕过”或“待定”候选，"
            "没有需要进行攻击者模拟或证据补充的条目。"
        )
        _record_skip(result, "verify", "no_candidates")
    else:
        print(_step_label("Skipping verification (--no-verify or not requested)."),
              file=sys.stderr)
        _print_chinese_log(
            "结果验证阶段跳过：运行参数未开启 --verify；"
            "当前输出仍是第一阶段的初步判定。"
        )
        _record_skip(result, "verify", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 5.5: OpenHarmony analysis feedback (P3, deterministic)
    # ---------------------------------------------------------------
    # Enhancement and Stage 1/2 are allowed to discover useful upstream and
    # downstream hints.  Persist them after the final result path is known so
    # the next incremental graph pass can schedule work from one auditable
    # artifact.  The artifact is deliberately advisory and never mutates the
    # effective graph in-place.
    if effective_platform == "openharmony":
        feedback_step = "openharmony-analysis-feedback"
        print(_step_label("Writing OpenHarmony analysis feedback..."), file=sys.stderr)
        _print_chinese_log(
            "阶段 P3/分析反馈：汇总上下文增强、Stage 1/Stage 2 结果和入口路径；"
            "候选事实只进入下一轮调度，不自动改写有效调用图。"
        )
        with step_context(feedback_step, output_dir, inputs={
            "dataset_path": result.enhanced_dataset_path or active_dataset_path,
            "results_path": active_results_path,
            "gap_tasks_path": result.call_graph_gap_tasks_path,
            "revision": graph_source_revision,
            "build_config_id": graph_build_config_id,
        }) as ctx:
            feedback_path, feedback_payload = _write_openharmony_analysis_feedback(
                result=result,
                output_dir=output_dir,
                dataset_path=result.enhanced_dataset_path or active_dataset_path,
                results_path=active_results_path,
                gap_tasks_path=result.call_graph_gap_tasks_path,
                repo_path=repo_path,
                source_revision=graph_source_revision,
                build_config_id=graph_build_config_id,
                effective_platform=effective_platform,
            )
            if feedback_path:
                summary = feedback_payload.get("summary", {}) if isinstance(feedback_payload, Mapping) else {}
                ctx.outputs = {"feedback_path": feedback_path}
                ctx.summary = {
                    "status": "complete",
                    "candidate_facts": summary.get("candidate_facts", 0),
                    "pending_gap_tasks": summary.get("pending_gap_tasks", 0),
                    "units_with_entry_paths": summary.get("units_with_entry_paths", 0),
                    "units_without_entry_paths": summary.get("units_without_entry_paths", 0),
                    "strict_graph_mutated": False,
                }
                _print_chinese_log(
                    "分析反馈完成：候选事实="
                    f"{summary.get('candidate_facts', 0)}，待处理缺口任务="
                    f"{summary.get('pending_gap_tasks', 0)}；产物={feedback_path}。"
                )
            else:
                ctx.status = "partial"
                ctx.summary = feedback_payload if isinstance(feedback_payload, Mapping) else {
                    "status": "partial"
                }
        collected_step_reports.append(_load_step_report(output_dir, feedback_step))
    else:
        _record_skip(result, "openharmony-analysis-feedback", "unsupported_platform")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 6: Build pipeline_output.json
    # ---------------------------------------------------------------
    from core.reporter import build_pipeline_output

    print(_step_label("Building pipeline_output.json..."), file=sys.stderr)
    _print_chinese_log(
        f"阶段 6/汇总输出：把最终结果文件 {active_results_path} 与阶段报告、"
        "平台画像和上下文 provenance 合并成 pipeline_output.json，"
        "供动态测试、Web 详情和报告生成统一消费。"
    )

    pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")

    with step_context("build-output", output_dir, inputs={
        "results_path": active_results_path,
    }) as ctx:
        build_pipeline_output(
            results_path=active_results_path,
            output_path=pipeline_output_path,
            repo_name=repo_name or os.path.basename(repo_path),
            repo_url=repo_url,
            commit_sha=commit_sha,
            language=result.language,
            application_type=(
                app_context_path and _read_app_type(app_context_path)
            ) or (
                "openharmony_component"
                if effective_platform == "openharmony"
                else "web_app"
            ),
            processing_level=processing_level,
            step_reports=collected_step_reports,
            context_source=result.context_source,
            threat_model_sha256=result.threat_model_sha256,
            threat_model_warnings=result.threat_model_warnings,
            application_context_provenance=result.application_context_provenance,
            # Authoritative skip data so pipeline_output.json reflects real
            # pipeline status (esp. a non-aborting verify failure) instead of
            # always reporting "nothing skipped". At this point (Step 6) all
            # pre-build skips incl. verify are already recorded; dynamic-test/
            # report skips are recorded later and remain in scan.report.json.
            skipped_steps=list(result.skipped_steps),
            skipped_step_reasons=dict(result.skipped_step_reasons),
        )

        ctx.outputs = {"pipeline_output_path": pipeline_output_path}

    result.pipeline_output_path = pipeline_output_path
    collected_step_reports.append(_load_step_report(output_dir, "build-output"))
    _print_chinese_log(
        f"汇总输出完成：{pipeline_output_path} 已生成；后续动态测试和报告只读取这份统一入口文件。"
    )
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 7: Dynamic Test (optional, off by default)
    # ---------------------------------------------------------------
    if dynamic_test and has_findings:
        _print_chinese_log(
            f"阶段 7/动态验证：有 {analyze_result.metrics.vulnerable + analyze_result.metrics.bypassable} 个候选条目，"
            f"按模式={dynamic_test_mode} 准备运行时验证；输入是刚生成的 pipeline_output.json，"
            "不会对没有候选的问题制造测试载荷。"
        )
        if dynamic_test_mode == "docker" and not shutil.which("docker"):
            print(_step_label("Skipping dynamic test (Docker not found)."),
                  file=sys.stderr)
            _print_chinese_log(
                "动态验证阶段跳过：选择了 Docker 模式但当前环境没有 docker 命令，"
                "为避免半成品运行，不会伪造动态验证结论。"
            )
            _record_skip(result, "dynamic-test", "docker_unavailable")
        else:
            from core.dynamic_tester import run_tests

            if dynamic_test_mode == "claude-code":
                print(_step_label("Preparing Claude Code dynamic-test task..."), file=sys.stderr)
                _print_chinese_log(
                    "动态验证决策：使用 Claude Code 模式，只准备任务工作目录、工具库、"
                    "候选清单和前置产物，等待用户在 Web 对话窗口中驱动验证。"
                )
            else:
                print(_step_label("Running dynamic tests (Docker)..."), file=sys.stderr)
                _print_chinese_log(
                    "动态验证决策：使用 Docker 隔离执行候选载荷；容器网络和权限边界由动态测试器负责。"
                )

            with step_context("dynamic-test", output_dir, inputs={
                "pipeline_output_path": pipeline_output_path,
                "mode": dynamic_test_mode,
                "repo_path": repo_path,
            }) as ctx:
                # Dynamic test is OPTIONAL: a failure here must not discard
                # completed work (step_context re-raises otherwise).
                try:
                    dt_result = run_tests(
                        pipeline_output_path=pipeline_output_path,
                        output_dir=output_dir,
                        registry=registry,
                        repo_path=repo_path,
                        mode=dynamic_test_mode,
                    )

                    ctx.summary = {
                        "findings_tested": dt_result.findings_tested,
                        "confirmed": dt_result.confirmed,
                        "not_reproduced": dt_result.not_reproduced,
                        "blocked": dt_result.blocked,
                        "inconclusive": dt_result.inconclusive,
                        "errors": dt_result.errors,
                        "mode": dt_result.mode,
                    }
                    ctx.outputs = {
                        "results_json_path": dt_result.results_json_path,
                        "results_md_path": dt_result.results_md_path,
                        "task_workspace": dt_result.task_workspace,
                        "public_tool_library": dt_result.public_tool_library,
                        "task_manifest_path": dt_result.task_manifest_path,
                        "candidate_manifest": dt_result.candidate_manifest,
                        "launch_command": dt_result.launch_command,
                    }

                    result.dynamic_test_path = dt_result.results_json_path

                    if dynamic_test_mode == "claude-code":
                        print(f"  Claude Code task: {dt_result.task_workspace}", file=sys.stderr)
                        _print_chinese_log(
                            f"动态验证任务已准备：工作目录={dt_result.task_workspace}；"
                            "用户可在 Web 对话中查看候选条目、源码上下文和工具执行过程。"
                        )
                    else:
                        print(f"  Dynamic test: {dt_result.confirmed} confirmed, "
                              f"{dt_result.not_reproduced} not reproduced", file=sys.stderr)
                        _print_chinese_log(
                            f"动态验证结果：确认={dt_result.confirmed}，未复现={dt_result.not_reproduced}，"
                            f"阻塞={dt_result.blocked}，待定={dt_result.inconclusive}，错误={dt_result.errors}；"
                            f"结果写入 {dt_result.results_json_path}。"
                        )
                except Exception as e:
                    print(f"  WARNING: Dynamic test failed: {e}", file=sys.stderr)
                    print("  Continuing without dynamic-test results.", file=sys.stderr)
                    _print_chinese_log(
                        f"动态验证失败（{e}），保留静态分析和验证结果，"
                        "不会把动态阶段失败误报为漏洞或安全。"
                    )
                    ctx.status = "skipped"
                    ctx.summary = {"skipped": True, "reason": str(e)}
                    _record_skip(result, "dynamic-test", "failed")

            collected_step_reports.append(
                _load_step_report(output_dir, "dynamic-test"),
            )
    elif dynamic_test and not has_findings:
        print(_step_label("Skipping dynamic test (no findings to test)."),
              file=sys.stderr)
        _print_chinese_log(
            "动态验证阶段跳过：前置阶段没有漏洞/可绕过候选，"
            "因此没有可安全执行的运行时载荷。"
        )
        _record_skip(result, "dynamic-test", "no_candidates")
    else:
        print(_step_label("Skipping dynamic test (not enabled)."), file=sys.stderr)
        _print_chinese_log(
            "动态验证阶段跳过：未开启动态测试；静态扫描流程到此保留候选和验证结论，"
            "不会自动与设备或容器交互。"
        )
        _record_skip(result, "dynamic-test", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 8: Report (optional)
    # ---------------------------------------------------------------
    if generate_report:
        from core.reporter import generate_summary_report, generate_disclosure_docs

        print(_step_label("Generating reports..."), file=sys.stderr)
        _print_chinese_log(
            "阶段 8/报告生成：根据 pipeline_output.json 生成摘要和披露材料；"
            f"当前是否存在初步候选={has_findings}，报告语言由报告生成器分别处理。"
        )

        with step_context("report", output_dir, inputs={
            "pipeline_output_path": pipeline_output_path,
        }) as ctx:
            report_dir = os.path.join(output_dir, "report")
            os.makedirs(report_dir, exist_ok=True)

            summary_path = os.path.join(report_dir, "SUMMARY_REPORT.md")
            disclosures_dir = os.path.join(report_dir, "disclosures")
            disclosures_zh_dir = os.path.join(report_dir, "disclosures.zh-CN")

            outputs = {}

            try:
                # Thread the scan's --llm-config through to the report phase
                # (else it silently falls back to the file's default_llm).
                generate_summary_report(pipeline_output_path, summary_path, llm_config_name)
                result.summary_path = summary_path
                outputs["summary_path"] = summary_path
                print(f"  Summary: {summary_path}", file=sys.stderr)
                _print_chinese_log(f"报告结果：摘要文件已生成到 {summary_path}。")
            except Exception as e:
                print(f"  WARNING: Summary report failed: {e}", file=sys.stderr)
                _print_chinese_log(
                    f"摘要报告生成失败（{e}），不影响前面的扫描产物；失败原因已写入报告阶段记录。"
                )
                ctx.errors.append(f"Summary report: {e}")

            # Only generate disclosures if there are findings
            if has_findings:
                try:
                    generate_disclosure_docs(pipeline_output_path, disclosures_dir, llm_config_name)
                    outputs["disclosures_dir"] = disclosures_dir
                    outputs["disclosures_zh_cn_dir"] = disclosures_zh_dir
                    print(f"  Disclosures: {disclosures_dir}", file=sys.stderr)
                    _print_chinese_log(
                        f"报告结果：已生成英文披露目录 {disclosures_dir}，"
                        f"以及中文披露目录 {disclosures_zh_dir}。"
                    )
                except Exception as e:
                    print(f"  WARNING: Disclosure docs failed: {e}", file=sys.stderr)
                    _print_chinese_log(
                        f"披露文件生成失败（{e}），保留 pipeline_output 和原始结果供人工复核。"
                    )
                    ctx.errors.append(f"Disclosure docs: {e}")

            ctx.summary = {"formats_generated": list(outputs.keys())}
            ctx.outputs = outputs

        collected_step_reports.append(_load_step_report(output_dir, "report"))
    else:
        print(_step_label("Skipping report generation (--no-report)."), file=sys.stderr)
        _print_chinese_log(
            "报告阶段跳过：运行参数关闭 --no-report；"
            "扫描结果仍保存在阶段 JSON 文件中，可稍后单独生成报告。"
        )
        _record_skip(result, "report", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Final: Aggregate scan report
    # ---------------------------------------------------------------
    result.usage = tracking.get_usage()
    result.step_reports = collected_step_reports

    _print_chinese_log(
        "扫描收尾：正在汇总各阶段状态、耗时、模型用量、跳过原因和最终产物路径，"
        "写入 scan.report.json。"
    )
    _write_scan_report(output_dir, result, collected_step_reports)
    _print_summary(result)
    _print_chinese_summary(result)

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _apply_projection_reachability_filter(
    *,
    active_dataset_path: str,
    unfiltered_dataset_path: str | None,
    output_dir: str,
    processing_level: str,
    library_mode: bool,
    effective_platform: str,
    primary_language: str,
    overlay_payload: Mapping | None,
) -> dict:
    """Re-filter the complete dataset with a validated LLM graph overlay.

    The parser's normal ``reachable`` mode may have already removed units
    before the LLM review runs.  When projection is explicitly enabled, the
    scanner preserves the parser's all-units dataset in a sidecar and uses it
    here as the re-filter input.  The deterministic call graph remains
    untouched; ``apply_reachability_filter`` receives the LLM graph only as an
    in-memory additive overlay and guarantees that native reachable units are
    retained.
    """
    if processing_level == "all":
        return {
            "applied": False,
            "reason": "processing_level_all",
            "original_units": 0,
            "reachable_units": 0,
        }

    source_path = (
        unfiltered_dataset_path
        if unfiltered_dataset_path and os.path.isfile(unfiltered_dataset_path)
        else active_dataset_path
    )
    dataset = read_json(source_path)
    if not isinstance(dataset, Mapping):
        raise ValueError("projection reachability dataset must be an object")
    units = dataset.get("units", [])
    if not isinstance(units, list):
        raise ValueError("projection reachability dataset units must be a list")

    # Preserve LLM reachability promotions/signals that may have been written
    # to the active (already filtered) dataset before this stage.
    current_by_id: dict[str, Mapping] = {}
    # Read the active dataset even when it is also the re-filter source.  The
    # fallback path without a dataset_unfiltered sidecar still needs to carry
    # high semantic seeds and medium candidate markers into the final BFS.
    try:
        current_payload = read_json(active_dataset_path)
        current_units = (
            current_payload.get("units", [])
            if isinstance(current_payload, Mapping)
            else []
        )
        if isinstance(current_units, list):
            current_by_id = {
                str(item.get("id")): item
                for item in current_units
                if isinstance(item, Mapping) and item.get("id")
            }
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(
            f"  [Warning] Could not restore LLM reachability signals "
            f"before overlay filtering: {exc}",
            file=sys.stderr,
        )

    extra_entry_points = {
        unit_id
        for unit_id, unit in current_by_id.items()
        if unit.get("is_entry_point") is True
    }
    extra_reachability_seeds = {
        unit_id
        for unit_id, unit in current_by_id.items()
        if unit.get("semantic_reachability_seed") is True
    }
    extra_retain_only_units = {
        unit_id
        for unit_id, unit in current_by_id.items()
        if (
            unit.get("semantic_reachability_retain_only") is True
            or unit.get("reachability_retain_only") is True
        )
    }
    extra_candidate_reachability_seeds = {
        unit_id
        for unit_id, unit in current_by_id.items()
        if unit.get("semantic_reachability_candidate_seed") is True
    }
    graph_dirs = resolve_call_graph_dirs(output_dir)
    if not graph_dirs:
        return {
            "applied": False,
            "reason": "call_graph_missing",
            "original_units": len(units),
            "reachable_units": len(units),
            "unfiltered": True,
        }

    overlay_by_language: dict[str, Mapping] = {}
    if isinstance(overlay_payload, Mapping):
        raw_reports = overlay_payload.get("reports", [])
        if isinstance(raw_reports, list):
            for item in raw_reports:
                if not isinstance(item, Mapping):
                    continue
                overlay = item.get("overlay")
                if not isinstance(overlay, Mapping):
                    continue
                label = str(item.get("language") or "").strip()
                if label:
                    overlay_by_language[label] = overlay

    # A compact hand-written overlay may contain only top-level nodes/edges.
    # Allow it for the single-graph layout, but never apply an ambiguous
    # top-level graph to one partition of a multi-language run.
    top_level_overlay = (
        overlay_payload
        if isinstance(overlay_payload, Mapping)
        and isinstance(overlay_payload.get("edges"), list)
        and len(graph_dirs) == 1
        else None
    )

    from core.parser_adapter import apply_reachability_filter

    partitions = partition_units_by_language(units)
    kept: list[dict] = []
    refilter_by_language: dict[str, dict] = {}
    unfilterable: dict[str, int] = {}
    errors: list[dict] = []

    for language, language_units in partitions.items():
        label = str(language or primary_language or "unknown")
        graph_dir = graph_dirs.get(language)
        if graph_dir is None and None in graph_dirs:
            # Legacy flat layout: the one graph covers units without a
            # language stamp (and is also the safe fallback for old datasets).
            graph_dir = graph_dirs[None]
        language_overlay = overlay_by_language.get(label)
        if language_overlay is None and top_level_overlay is not None:
            language_overlay = top_level_overlay

        if graph_dir is None:
            unfilterable[label] = len(language_units)
            kept.extend(language_units)
            continue

        language_dataset = {
            **dataset,
            "units": language_units,
            "metadata": dict(dataset.get("metadata") or {}),
        }
        try:
            filtered = apply_reachability_filter(
                language_dataset,
                graph_dir,
                processing_level,
                extra_entry_points=scope_entry_points_to_units(
                    extra_entry_points, language_units
                ),
                extra_reachability_seeds=scope_entry_points_to_units(
                    extra_reachability_seeds, language_units
                ),
                extra_retain_only_units=scope_entry_points_to_units(
                    extra_retain_only_units, language_units
                ),
                extra_candidate_reachability_seeds=scope_entry_points_to_units(
                    extra_candidate_reachability_seeds, language_units
                ),
                library_mode=library_mode,
                platform=effective_platform,
                semantic_graph_overlay=language_overlay,
            )
            filtered_units = filtered.get("units", [])
            if not isinstance(filtered_units, list):
                raise ValueError("reachability filter returned a non-list units value")
            # The re-filter starts from the all-units sidecar. Add back the
            # advisory fields from the active dataset for units that survived.
            for unit in filtered_units:
                if not isinstance(unit, dict):
                    continue
                current = current_by_id.get(str(unit.get("id")))
                if current is None:
                    continue
                for key in (
                    "is_entry_point",
                    "entry_point_reason",
                    "llm_reachability_signals",
                    "semantic_reachability_seed",
                    "semantic_reachability_retain_only",
                    "semantic_reachability_candidate_seed",
                    "reachability_retain_only",
                    "reachability_seed_source",
                    "semantic_seed_reasons",
                    "reachability_retain_only_source",
                    "semantic_retain_only_reasons",
                    "reachability_status",
                    "reachability_reason",
                    "analysis_arrangement",
                    "reachability_evidence",
                ):
                    if key in current:
                        unit[key] = current[key]
            kept.extend(filtered_units)
            filter_record = (filtered.get("metadata") or {}).get(
                "reachability_filter"
            )
            if isinstance(filter_record, Mapping):
                refilter_by_language[label] = dict(filter_record)
        except Exception as exc:  # optional projection must not abort scanning
            errors.append({
                "language": label,
                "reason": "reachability_refilter_failed",
                "error": str(exc)[:500],
            })
            kept.extend(language_units)

    dataset = dict(dataset)
    dataset["units"] = kept
    metadata = dict(dataset.get("metadata") or {})
    if refilter_by_language:
        per_language = dict(refilter_by_language)
        unfiltered_count = 0
        for label, count in unfilterable.items():
            unfiltered_count += count
            per_language[label] = {
                "original_units": count,
                "entry_points": 0,
                "semantic_seed_count": 0,
                "semantic_seed_ids": [],
                "semantic_candidate_seed_count": 0,
                "semantic_candidate_seed_ids": [],
                "candidate_reachable_units": count,
                "candidate_reachable_added": count,
                "candidate_reachable_ids": [],
                "strict_path_coverage_count": 0,
                "strict_path_coverage_ids": [],
                "candidate_path_coverage_count": 0,
                "candidate_path_coverage_ids": [],
                "fallback_only_count": count,
                "fallback_only_ids": [],
                "final_analysis_count": count,
                "fallback_triggered": True,
                "fallback_reason": "unfiltered_no_call_graph",
                "reachability_evidence": "unfiltered_no_call_graph",
                "reachable_units": count,
                "filtered_out": 0,
                "reduction_percentage": 0,
                "unfilterable": True,
            }
        original_count = sum(
            int(item.get("original_units", 0) or 0)
            for item in per_language.values()
        )
        reachable_count = sum(
            int(item.get("reachable_units", 0) or 0)
            for item in per_language.values()
        )
        filter_record = {
            "original_units": original_count,
            "entry_points": sum(
                int(item.get("entry_points", 0) or 0)
                for item in per_language.values()
            ),
            "semantic_seed_count": sum(
                int(item.get("semantic_seed_count", 0) or 0)
                for item in per_language.values()
            ),
            "semantic_seed_ids": sorted({
                str(unit_id)
                for item in per_language.values()
                for unit_id in (item.get("semantic_seed_ids", []) or [])
                if unit_id
            }),
            "semantic_candidate_seed_count": sum(
                int(item.get("semantic_candidate_seed_count", 0) or 0)
                for item in per_language.values()
            ),
            "semantic_candidate_seed_ids": sorted({
                str(unit_id)
                for item in per_language.values()
                for unit_id in (
                    item.get("semantic_candidate_seed_ids", []) or []
                )
                if unit_id
            }),
            "candidate_reachable_units": sum(
                int(item.get("candidate_reachable_units", 0) or 0)
                for item in per_language.values()
            ),
            "candidate_reachable_added": sum(
                int(item.get("candidate_reachable_added", 0) or 0)
                for item in per_language.values()
            ),
            "candidate_reachable_ids": sorted({
                str(unit_id)
                for item in per_language.values()
                for unit_id in (item.get("candidate_reachable_ids", []) or [])
                if unit_id
            }),
            "strict_path_coverage_count": sum(
                int(item.get("strict_path_coverage_count", 0) or 0)
                for item in per_language.values()
            ),
            "strict_path_coverage_ids": sorted({
                str(unit_id)
                for item in per_language.values()
                for unit_id in (item.get("strict_path_coverage_ids", []) or [])
                if unit_id
            }),
            "candidate_path_coverage_count": sum(
                int(item.get("candidate_path_coverage_count", 0) or 0)
                for item in per_language.values()
            ),
            "candidate_path_coverage_ids": sorted({
                str(unit_id)
                for item in per_language.values()
                for unit_id in (
                    item.get("candidate_path_coverage_ids", []) or []
                )
                if unit_id
            }),
            "fallback_only_count": sum(
                int(item.get("fallback_only_count", 0) or 0)
                for item in per_language.values()
            ),
            "fallback_only_ids": sorted({
                str(unit_id)
                for item in per_language.values()
                for unit_id in (item.get("fallback_only_ids", []) or [])
                if unit_id
            }),
            "final_analysis_count": sum(
                int(item.get("final_analysis_count", item.get("reachable_units", 0)) or 0)
                for item in per_language.values()
            ),
            "fallback_triggered": any(
                bool(item.get("fallback_triggered"))
                for item in per_language.values()
            ),
            "fallback_reason": "; ".join(
                f"{label}: {reason}"
                for label, item in per_language.items()
                if (reason := item.get("fallback_reason"))
            ),
            "reachability_evidence": (
                "mixed_filtered_and_unfiltered"
                if unfiltered_count
                else "accepted_or_candidate_path"
            ),
            "reachable_units": reachable_count,
            "filtered_out": original_count - reachable_count,
            "unfiltered_units": unfiltered_count,
            "reduction_percentage": (
                round((1 - reachable_count / original_count) * 100, 1)
                if original_count
                else 0
            ),
            "per_language": per_language,
        }
        semantic_records = [
            item.get("semantic_overlay")
            for item in per_language.values()
            if isinstance(item, Mapping)
            and isinstance(item.get("semantic_overlay"), Mapping)
        ]
        if semantic_records:
            edge_kinds = sorted({
                kind
                for item in semantic_records
                for kind in item.get("edge_kinds", []) or []
                if isinstance(kind, str)
            })
            sources = [
                source
                for item in semantic_records
                for source in item.get("sources", []) or []
                if isinstance(source, Mapping)
            ]
            filter_record["native_reachable_units"] = sum(
                int(item.get("native_reachable_units", 0) or 0)
                for item in per_language.values()
                if isinstance(item, Mapping)
            )
            filter_record["semantic_reachable_added"] = sum(
                int(item.get("semantic_reachable_added", 0) or 0)
                for item in per_language.values()
                if isinstance(item, Mapping)
            )
            filter_record["semantic_overlay"] = {
                "enabled": any(
                    item.get("enabled") is True for item in semantic_records
                ),
                "candidate_edges": sum(
                    int(item.get("candidate_edges", 0) or 0)
                    for item in semantic_records
                ),
                "edges_added": sum(
                    int(item.get("edges_added", 0) or 0)
                    for item in semantic_records
                ),
                "edge_kinds": edge_kinds,
                "ignored_edge_count": sum(
                    int(item.get("ignored_edge_count", 0) or 0)
                    for item in semantic_records
                ),
                "invalid_endpoint_count": sum(
                    int(item.get("invalid_endpoint_count", 0) or 0)
                    for item in semantic_records
                ),
                "monotonicity_violation": any(
                    item.get("monotonicity_violation") is True
                    for item in semantic_records
                ),
                "sources": sources,
            }
        warnings = [
            f"{label}: {item['warning']}"
            for label, item in per_language.items()
            if isinstance(item, Mapping) and item.get("warning")
        ]
        if warnings:
            filter_record["warning"] = "; ".join(warnings)
        metadata["reachability_filter"] = filter_record
    elif not unfilterable and not errors:
        # No graph actually ran; avoid leaving a stale claim from a prior
        # dataset copy that says filtering was applied.
        metadata.pop("reachability_filter", None)
    dataset["metadata"] = metadata
    write_json(active_dataset_path, dataset, indent=2)

    aggregate_filter = metadata.get("reachability_filter", {})
    if not isinstance(aggregate_filter, Mapping):
        aggregate_filter = {}
    return {
        "applied": bool(refilter_by_language),
        "source": os.path.relpath(source_path, output_dir),
        "original_units": len(units),
        "reachable_units": len(kept),
        "filtered_out": len(units) - len(kept),
        "semantic_reachable_added": sum(
            int(item.get("semantic_reachable_added", 0) or 0)
            for item in refilter_by_language.values()
            if isinstance(item, Mapping)
        ),
        "unfilterable_units": sum(unfilterable.values()),
        "errors": errors,
        "strict_path_coverage_count": int(
            aggregate_filter.get("strict_path_coverage_count", 0) or 0
        ),
        "candidate_path_coverage_count": int(
            aggregate_filter.get("candidate_path_coverage_count", 0) or 0
        ),
        "fallback_only_count": int(
            aggregate_filter.get("fallback_only_count", 0) or 0
        ),
        "final_analysis_count": int(
            aggregate_filter.get("final_analysis_count", len(kept)) or 0
        ),
        "fallback_triggered": bool(
            aggregate_filter.get("fallback_triggered", False)
        ),
        "fallback_reason": aggregate_filter.get("fallback_reason", ""),
    }


def _run_openharmony_recovery_projection_stage(
    *,
    result: ScanResult,
    repo_path: str,
    output_dir: str,
    active_dataset_path: str,
    unfiltered_dataset_path: str | None,
    processing_level: str,
    library_mode: bool,
    effective_platform: str,
    source_revision: str,
    build_config_id: str,
    collected_step_reports: list[dict],
    step_label,
) -> None:
    """Project validated OH recovery decisions into a separate graph artifact.

    The recovery and candidate-review stages intentionally write advisory
    reports rather than mutating ``call_graph.json``.  This stage is the
    explicit bridge between those reports and a semantic graph payload.  It
    consumes only source reports that are present in the scan directory
    (including the entry-driven rounds artifact) and
    keeps every rejection/provenance detail in the resulting artifact.  For a
    non-``all`` scan, this function is also the explicit bridge that re-runs
    the final reachability filter from the unfiltered dataset; the native graph
    and active dataset are never overwritten in place.
    """
    projection_step = "llm-call-graph-projection"
    print(
        step_label("Projecting validated LLM call edges..."),
        file=sys.stderr,
    )
    _print_chinese_log(
        "阶段/OpenHarmony 调用边投影：读取恢复和候选复核报告，"
        "只接受通过证据门槛的高置信边，写入独立 semantic overlay；"
        f"当前处理范围={processing_level}，原生 call_graph.json 永远不被覆盖。"
    )

    with step_context(projection_step, output_dir, inputs={
        "platform": effective_platform,
        "dataset_path": active_dataset_path,
        "sources": [
            "llm_call_graph_recovery.json",
            "llm_call_graph_recovery_rounds.json",
            "llm_call_graph_candidate_review.json",
        ],
        "binding": "validated_high_confidence_only",
        "reachability_mutation": processing_level != "all",
    }) as ctx:
        if effective_platform != "openharmony":
            _print_chinese_log(
                f"调用边投影阶段跳过：有效平台是 {effective_platform}，"
                "该阶段只允许 OpenHarmony 输入，避免把通用源码送入专用规则。"
            )
            ctx.status = "skipped"
            ctx.summary = {
                "skipped": True,
                "reason": "unsupported_platform",
                "platform": effective_platform,
            }
            _record_skip(result, projection_step, "unsupported_platform")
        else:
            from core.platforms.graph import SemanticGraph, merge_semantic_graphs
            from core.platforms.openharmony.llm_call_graph_projection import (
                PROJECTION_SCHEMA_VERSION,
                PROJECTION_TASK,
                project_recovery_overlay,
            )
            from core.platforms.openharmony.llm_call_graph_rounds import (
                ROUND_TASK,
            )
            source_names = (
                "llm_call_graph_recovery.json",
                "llm_call_graph_recovery_rounds.json",
                "llm_call_graph_candidate_review.json",
            )
            source_payloads: list[tuple[str, Mapping, list[Mapping]]] = []
            source_artifacts: list[dict] = []
            source_errors: list[dict] = []

            for source_name in source_names:
                source_path = os.path.join(output_dir, source_name)
                if not os.path.isfile(source_path):
                    continue
                relative_source = os.path.relpath(source_path, output_dir)
                try:
                    payload = read_json(source_path)
                    if not isinstance(payload, Mapping):
                        raise ValueError("projection source must be an object")
                    raw_reports = payload.get("reports", [])
                    if not isinstance(raw_reports, list):
                        raise ValueError("projection source reports must be a list")
                    reports = [
                        item for item in raw_reports if isinstance(item, Mapping)
                    ]
                    source_payloads.append((source_name, payload, reports))
                    source_artifacts.append({
                        "path": relative_source,
                        "status": str(payload.get("status", "unknown")),
                        "reports": len(reports),
                    })
                except Exception as exc:
                    source_artifacts.append({
                        "path": relative_source,
                        "status": "malformed",
                        "reports": 0,
                    })
                    source_errors.append({
                        "path": relative_source,
                        "reason": "malformed_source_artifact",
                        "error": str(exc)[:500],
                    })

            graph_dirs = resolve_call_graph_dirs(output_dir)
            language_reports: list[dict] = []
            graph_payloads: list[dict] = []
            flattened_rejections: list[dict] = []
            unmatched_reports = 0
            consumed_reports = 0

            def _label(value) -> str:
                text = str(value or "").strip()
                return text or result.language or "unknown"

            def _report_matches(
                item: Mapping,
                *,
                label: str,
                relative_graph: str,
                graph_path: str,
                graph_count: int,
                report_count: int,
            ) -> bool:
                report_graph = str(item.get("call_graph_path") or "").strip()
                if report_graph:
                    normalized = os.path.normpath(report_graph)
                    if normalized in {
                        os.path.normpath(relative_graph),
                        os.path.normpath(graph_path),
                    }:
                        return True
                report_language = str(item.get("language") or "").strip()
                if report_language and report_language == label:
                    return True
                # Older candidate-review artifacts did not persist graph paths.
                # A one-graph/one-report fallback is safe; with multiple graphs
                # an ambiguous language match is recorded as unmatched instead
                # of projecting a report onto the wrong function index.
                return (
                    graph_count == 1
                    and report_count == 1
                    and not report_graph
                    and not report_language
                )

            def _project_nested_report(
                nested: Mapping,
                functions: Mapping,
            ) -> dict:
                """Re-validate one-shot or iterative recovery artifacts.

                Iterative reports already contain per-round overlays, but the
                persisted artifact is user-readable JSON. Replaying each
                round's review through the projection boundary prevents an
                edited rounds file from bypassing endpoint/candidate/evidence
                checks when it is later used for reachability.
                """
                if nested.get("task") != ROUND_TASK:
                    return project_recovery_overlay(nested, functions)
                rounds = nested.get("rounds", [])
                if not isinstance(rounds, list):
                    return SemanticGraph().to_dict()
                round_overlays: list[dict] = []
                for round_item in rounds:
                    if not isinstance(round_item, Mapping):
                        continue
                    round_review = round_item.get("review")
                    if not isinstance(round_review, Mapping):
                        continue
                    round_overlays.append(
                        project_recovery_overlay(round_review, functions)
                    )
                if not round_overlays:
                    return SemanticGraph().to_dict()
                merged_rounds = merge_semantic_graphs(*round_overlays)
                return (
                    merged_rounds.to_dict()
                    if merged_rounds is not None
                    else SemanticGraph().to_dict()
                )

            sorted_graph_dirs = sorted(
                graph_dirs.items(),
                key=lambda item: "" if item[0] is None else str(item[0]),
            )
            graph_count = len(sorted_graph_dirs)
            all_selected_report_ids: set[int] = set()

            for language_name, graph_dir in sorted_graph_dirs:
                label = _label(language_name)
                graph_path = os.path.join(graph_dir, "call_graph.json")
                relative_graph = os.path.relpath(graph_path, output_dir)
                language_errors: list[dict] = []
                try:
                    graph_payload = read_json(graph_path)
                    functions = (
                        graph_payload.get("functions", {})
                        if isinstance(graph_payload, Mapping)
                        else {}
                    )
                    if not isinstance(functions, Mapping):
                        raise ValueError("call_graph.functions must be an object")
                except Exception as exc:
                    language_reports.append({
                        "language": label,
                        "status": "failed",
                        "call_graph_path": relative_graph,
                        "overlay": SemanticGraph().to_dict(),
                        "sources": [],
                        "source_overlays": [],
                        "summary": {},
                        "errors": [{
                            "reason": "call_graph_unreadable",
                            "error": str(exc)[:500],
                        }],
                    })
                    continue

                language_overlays: list[tuple[str, dict]] = []
                language_sources: list[str] = []

                for source_name, _source_payload, reports in source_payloads:
                    for report_index, report_item in enumerate(reports):
                        if not _report_matches(
                            report_item,
                            label=label,
                            relative_graph=relative_graph,
                            graph_path=graph_path,
                            graph_count=graph_count,
                            report_count=len(reports),
                        ):
                            continue
                        nested = report_item.get("report")
                        if not isinstance(nested, Mapping):
                            language_errors.append({
                                "source": source_name,
                                "reason": "nested_report_missing",
                            })
                            continue
                        overlay = _project_nested_report(nested, functions)
                        language_overlays.append((source_name, overlay))
                        language_sources.append(source_name)
                        all_selected_report_ids.add(id(report_item))
                        consumed_reports += 1

                if language_overlays:
                    try:
                        merged_language = merge_semantic_graphs(
                            *(item[1] for item in language_overlays)
                        )
                    except Exception as exc:
                        language_errors.append({
                            "reason": "overlay_merge_failed",
                            "error": str(exc)[:500],
                        })
                        merged_language = None
                else:
                    merged_language = None

                language_graph = (
                    merged_language.to_dict()
                    if merged_language is not None
                    else SemanticGraph().to_dict()
                )
                if merged_language is not None:
                    graph_payloads.append(language_graph)

                source_overlay_summaries: list[dict] = []
                language_summary = {
                    "accepted_input": 0,
                    "projected_edges": len(
                        merged_language.edges
                    ) if merged_language is not None else 0,
                    "rejected": 0,
                    "duplicate_edges": 0,
                }
                for source_name, overlay in language_overlays:
                    overlay_summary = overlay.get("summary", {})
                    if not isinstance(overlay_summary, Mapping):
                        overlay_summary = {}
                    for key in (
                        "accepted_input",
                        "rejected",
                        "duplicate_edges",
                    ):
                        try:
                            language_summary[key] += int(
                                overlay_summary.get(key, 0) or 0
                            )
                        except (TypeError, ValueError):
                            pass
                    rejected = overlay.get("rejected", [])
                    if not isinstance(rejected, list):
                        rejected = []
                    for item in rejected:
                        if isinstance(item, Mapping):
                            flattened_rejections.append({
                                "language": label,
                                "source": source_name,
                                **dict(item),
                            })
                    source_overlay_summaries.append({
                        "source": source_name,
                        "status": overlay.get("status", "unknown"),
                        "summary": dict(overlay_summary),
                        "rejected": rejected,
                    })

                overlay_statuses = {
                    str(item.get("status", "unknown"))
                    for item in source_overlay_summaries
                }
                if language_errors and not source_overlay_summaries:
                    language_status = "failed"
                elif language_errors or "partial" in overlay_statuses:
                    language_status = "partial"
                elif "invalid" in overlay_statuses:
                    language_status = "partial"
                elif source_overlay_summaries:
                    language_status = "complete"
                else:
                    language_status = "no_input_report"

                language_reports.append({
                    "language": label,
                    "status": language_status,
                    "call_graph_path": relative_graph,
                    "sources": sorted(set(language_sources)),
                    "overlay": language_graph,
                    "source_overlays": source_overlay_summaries,
                    "summary": language_summary,
                    "errors": language_errors,
                })

            # Count unmatched reports once, after every graph partition has
            # had a chance to claim it. Counting inside the per-language loop
            # would charge a valid report as "unmatched" for each other
            # language in a multi-language run.
            for _source_name, _source_payload, reports in source_payloads:
                for report_item in reports:
                    if id(report_item) in all_selected_report_ids:
                        continue
                    report_graph = str(
                        report_item.get("call_graph_path") or ""
                    ).strip()
                    report_language = str(
                        report_item.get("language") or ""
                    ).strip()
                    if report_graph or report_language:
                        unmatched_reports += 1

            try:
                merged = merge_semantic_graphs(*graph_payloads)
            except Exception as exc:
                source_errors.append({
                    "reason": "cross_language_overlay_merge_failed",
                    "error": str(exc)[:500],
                })
                merged = None
            final_graph = merged.to_dict() if merged is not None else SemanticGraph().to_dict()

            statuses = {item.get("status") for item in language_reports}
            if not source_payloads:
                overall_status = "failed" if source_errors else "no_artifacts"
            elif not language_reports:
                overall_status = "failed" if source_errors else "no_artifacts"
            elif source_errors or unmatched_reports or "failed" in statuses:
                overall_status = "partial" if merged is not None else "failed"
            elif statuses <= {"complete", "no_input_report"}:
                overall_status = "complete"
            else:
                overall_status = "partial"

            accepted_input = 0
            rejected_count = 0
            duplicate_edges = 0
            strict_edges = 0
            candidate_edges = 0
            evidence_quality_counts: dict[str, int] = {}
            for item in language_reports:
                summary = item.get("summary", {})
                if not isinstance(summary, Mapping):
                    continue
                for key, target in (
                    ("accepted_input", "accepted_input"),
                    ("rejected", "rejected"),
                    ("duplicate_edges", "duplicate_edges"),
                ):
                    try:
                        value = int(summary.get(key, 0) or 0)
                    except (TypeError, ValueError):
                        value = 0
                    if target == "accepted_input":
                        accepted_input += value
                    elif target == "rejected":
                        rejected_count += value
                    else:
                        duplicate_edges += value
                try:
                    strict_edges += int(summary.get("strict_edges", 0) or 0)
                except (TypeError, ValueError):
                    pass
                try:
                    candidate_edges += int(summary.get("candidate_edges", 0) or 0)
                except (TypeError, ValueError):
                    pass
                quality_counts = summary.get("evidence_quality_counts", {})
                if isinstance(quality_counts, Mapping):
                    for quality, count in quality_counts.items():
                        try:
                            evidence_quality_counts[str(quality)] = (
                                evidence_quality_counts.get(str(quality), 0)
                                + int(count or 0)
                            )
                        except (TypeError, ValueError):
                            continue

            projected_from_languages = sum(
                int((item.get("summary") or {}).get("projected_edges", 0) or 0)
                for item in language_reports
                if isinstance(item.get("summary"), Mapping)
            )
            cross_language_duplicates = max(
                0,
                projected_from_languages - len(final_graph.get("edges", [])),
            )
            aggregate = {
                "languages": len(language_reports),
                "source_artifacts": len(source_artifacts),
                "reports_consumed": consumed_reports,
                "accepted_input": accepted_input,
                "projected_edges": len(final_graph.get("edges", [])),
                "rejected": rejected_count,
                "duplicate_edges": duplicate_edges + cross_language_duplicates,
                "strict_edges": strict_edges,
                "candidate_edges": candidate_edges,
                "evidence_quality_counts": evidence_quality_counts,
                "unmatched_reports": unmatched_reports,
                "errors": len(source_errors)
                + sum(len(item.get("errors", [])) for item in language_reports),
            }
            payload = {
                **final_graph,
                "schema_version": PROJECTION_SCHEMA_VERSION,
                "task": PROJECTION_TASK,
                "platform": "openharmony",
                "source_revision": source_revision,
                "build_config_id": build_config_id,
                "status": overall_status,
                "source_artifacts": source_artifacts,
                "reports": language_reports,
                "rejected": flattened_rejections,
                "errors": source_errors,
                "summary": aggregate,
            }
            projection_path = os.path.join(
                output_dir, "llm_call_graph_overlay.json"
            )
            write_json(projection_path, payload, indent=2)
            result.llm_call_graph_overlay_path = projection_path
            effective_graph_refresh = []
            try:
                from core.call_graph_facts import (
                    refresh_effective_call_graphs,
                    synchronize_dataset_dependencies,
                )

                # The projection is the explicit trust boundary: only this
                # validated overlay is allowed to add semantic edges to the
                # effective graph. Recovery/review reports remain advisory.
                effective_graph_refresh = refresh_effective_call_graphs(
                    output_dir,
                    semantic_overlays=[payload],
                    source_revision=source_revision,
                    build_config_id=build_config_id,
                    include_persisted_overlays=False,
                )
                if effective_graph_refresh:
                    dependency_sync = synchronize_dataset_dependencies(
                        active_dataset_path,
                        [
                            item.get("path")
                            for item in effective_graph_refresh
                            if isinstance(item, Mapping) and item.get("path")
                        ],
                    )
                    _print_chinese_log(
                        "调用事实库：已把通过投影校验的边合并到 effective_call_graph.json；"
                        f"更新图目录={len(effective_graph_refresh)}，"
                        f"并同步 {dependency_sync.get('units_updated', 0)} 个单元的依赖版本。"
                    )
                else:
                    dependency_sync = {}
            except Exception as exc:
                dependency_sync = {}
                print(
                    f"  WARNING: effective graph refresh after projection failed: {exc}",
                    file=sys.stderr,
                )
                _print_chinese_log(
                    f"投影后有效调用图刷新失败（{exc}），本次仍保留独立 overlay，"
                    "可达性将使用可用的原生图降级。"
                )
            ablation_path = None
            ablation_summary = {
                "status": "skipped",
                "reason": "requires_single_graph_and_non_all_processing",
            }
            # Produce a fixed-input A/B/C/D diagnostic whenever projection is
            # enabled.  The report is intentionally derived from the same
            # unfiltered dataset and native graph; it is not used to alter
            # the active dataset or to accept any additional edge.
            if processing_level != "all" and graph_count == 1:
                try:
                    from core.reachability_ablation import (
                        run_reachability_ablation,
                    )

                    ablation_dataset_path = (
                        unfiltered_dataset_path
                        if unfiltered_dataset_path
                        and os.path.isfile(unfiltered_dataset_path)
                        else active_dataset_path
                    )
                    ablation_dataset = read_json(ablation_dataset_path)
                    active_payload = read_json(active_dataset_path)
                    if (
                        isinstance(ablation_dataset, Mapping)
                        and isinstance(active_payload, Mapping)
                    ):
                        # The unfiltered sidecar is created before LLM signals
                        # are applied. Copy only semantic annotations from the
                        # active dataset so A/B/C/D share the full unit set
                        # while using the actual medium seeds from this run.
                        active_by_id = {
                            str(item.get("id")): item
                            for item in active_payload.get("units", [])
                            if isinstance(item, Mapping) and item.get("id")
                        }
                        merged_units = []
                        for raw_unit in ablation_dataset.get("units", []):
                            if not isinstance(raw_unit, Mapping):
                                continue
                            unit = dict(raw_unit)
                            current = active_by_id.get(str(unit.get("id")))
                            if isinstance(current, Mapping):
                                for key in (
                                    "is_entry_point",
                                    "semantic_reachability_seed",
                                    "semantic_reachability_candidate_seed",
                                    "semantic_reachability_retain_only",
                                    "reachability_retain_only",
                                ):
                                    if key in current:
                                        unit[key] = current[key]
                            merged_units.append(unit)
                        ablation_dataset = {
                            **dict(ablation_dataset),
                            "units": merged_units,
                        }
                    native_graph_path = os.path.join(
                        sorted_graph_dirs[0][1], "call_graph.json"
                    )
                    native_graph_payload = read_json(native_graph_path)
                    candidate_seed_ids = {
                        str(unit.get("id"))
                        for unit in ablation_dataset.get("units", [])
                        if isinstance(unit, Mapping)
                        and unit.get("id")
                        and unit.get("semantic_reachability_candidate_seed") is True
                    }
                    ablation_report = run_reachability_ablation(
                        ablation_dataset,
                        native_graph_payload,
                        semantic_overlay=payload,
                        candidate_seed_ids=candidate_seed_ids,
                        platform=effective_platform,
                    )
                    ablation_path = os.path.join(
                        output_dir, "llm_call_graph_ablation.json"
                    )
                    write_json(ablation_path, ablation_report, indent=2)
                    result.llm_call_graph_ablation_path = ablation_path
                    ablation_summary = {
                        "status": "complete",
                        "path": os.path.relpath(ablation_path, output_dir),
                        "arms": {
                            name: {
                                "unit_count": value.get("unit_count", 0),
                                "strict_path_coverage_count": value.get(
                                    "strict_path_coverage_count", 0
                                ),
                                "candidate_path_coverage_count": value.get(
                                    "candidate_path_coverage_count", 0
                                ),
                                "fallback_only_count": value.get(
                                    "fallback_only_count", 0
                                ),
                                "final_analysis_count": value.get(
                                    "final_analysis_count", 0
                                ),
                                "fallback_triggered": value.get(
                                    "fallback_triggered", False
                                ),
                                "candidate_reachable_count": value.get(
                                    "candidate_reachable_count", 0
                                ),
                            }
                            for name, value in ablation_report.get("arms", {}).items()
                            if isinstance(value, Mapping)
                        },
                        "target_matrix": ablation_report.get("target_matrix", {}),
                    }
                except Exception as exc:  # diagnostic only; never block projection
                    ablation_summary = {
                        "status": "failed",
                        "reason": str(exc)[:500],
                    }
            refilter_summary = _apply_projection_reachability_filter(
                active_dataset_path=active_dataset_path,
                unfiltered_dataset_path=unfiltered_dataset_path,
                output_dir=output_dir,
                processing_level=processing_level,
                library_mode=library_mode,
                effective_platform=effective_platform,
                primary_language=result.language,
                overlay_payload=payload,
            )
            # Re-filtering may rebuild dataset.json from the preserved
            # all-units sidecar. Re-apply graph provenance afterwards so the
            # active dataset cannot regress to the pre-projection graph
            # version.
            if effective_graph_refresh:
                try:
                    from core.call_graph_facts import synchronize_dataset_dependencies

                    dependency_sync = synchronize_dataset_dependencies(
                        active_dataset_path,
                        [
                            item.get("path")
                            for item in effective_graph_refresh
                            if isinstance(item, Mapping) and item.get("path")
                        ],
                    )
                except Exception as exc:
                    dependency_sync = {
                        "units_seen": 0,
                        "units_updated": 0,
                        "edges_loaded": 0,
                        "error": str(exc)[:500],
                    }
            if refilter_summary.get("applied"):
                result.units_count = int(
                    refilter_summary.get("reachable_units", result.units_count)
                    or 0
                )
            gap_report_path = None
            gap_report = {}
            try:
                gap_report_path, gap_report = _write_call_graph_gap_report(
                    output_dir=output_dir,
                    effective_graphs=effective_graph_refresh,
                    repo_path=repo_path,
                    source_revision=source_revision,
                    build_config_id=build_config_id,
                )
                if gap_report_path:
                    result.call_graph_gap_report_path = gap_report_path
            except Exception as exc:
                _print_chinese_log(f"投影后调用图缺口汇总失败（{exc}），不影响投影结果。")
            ctx.outputs = {
                "overlay_path": projection_path,
                "effective_call_graphs": effective_graph_refresh,
                "dependency_sync": dependency_sync,
                **({"call_graph_gap_report": gap_report_path} if gap_report_path else {}),
                **({"ablation_path": ablation_path} if ablation_path else {}),
                **(
                    {"unfiltered_dataset_path": unfiltered_dataset_path}
                    if unfiltered_dataset_path
                    else {}
                ),
            }
            ctx.summary = {
                "status": overall_status,
                **aggregate,
                "ablation": ablation_summary,
                "reachability_refilter": refilter_summary,
                **(
                    {"call_graph_gap_summary": gap_report.get("summary", {})}
                    if gap_report
                    else {}
                ),
            }
            if overall_status == "no_artifacts":
                ctx.status = "skipped"
                _record_skip(result, projection_step, "no_artifacts")
            elif overall_status == "failed":
                ctx.status = "skipped"
                _record_skip(result, projection_step, "failed")
            elif overall_status == "partial":
                ctx.status = "partial"

            print(
                f"  LLM overlay: {aggregate['projected_edges']} edge(s), "
                f"{aggregate['rejected']} rejected",
                file=sys.stderr,
            )
            _print_chinese_log(
                f"调用边投影结果：状态={overall_status}，投影 {aggregate['projected_edges']} 条边，"
                f"拒绝 {aggregate['rejected']} 条；"
                + (
                    f"已按语义 overlay 重新筛选，保留 {refilter_summary.get('reachable_units', 0)} 个可达单元。"
                    if refilter_summary.get("applied")
                    else "未执行数据集重筛，保留原始 dataset 结构。"
                )
            )

    collected_step_reports.append(_load_step_report(output_dir, projection_step))
    print(file=sys.stderr)


def _run_openharmony_candidate_review_stage(
    *,
    result: ScanResult,
    output_dir: str,
    active_dataset_path: str,
    effective_platform: str,
    registry,
    step_label,
    collected_step_reports: list[dict],
) -> None:
    """Run the opt-in OpenHarmony candidate-edge review pass.

    The implementation intentionally mirrors the advisory recovery stage but
    keeps its artifact and step name separate.  Keeping the two passes
    independent makes API cost explicit and prevents a candidate review from
    silently changing the default residual-only behavior.
    """
    review_step = "llm-call-graph-candidate-review"
    print(
        step_label("Running LLM candidate-edge review..."),
        file=sys.stderr,
    )
    _print_chinese_log(
        "阶段/OpenHarmony 候选边复核：对解析器已经找到候选目标的残余站点做第二次语义核对，"
        "候选注册源码、调用点及有界调用图邻居会一并提供给模型；"
        "只生成独立审计报告，不修改原生调用图、dataset 或可达性结果。"
    )

    with step_context(review_step, output_dir, inputs={
        "platform": effective_platform,
        "dataset_path": active_dataset_path,
        "source": "call_graph_residuals.json",
        "binding_phase": "llm_reach",
        "review_scope": "candidate_edges",
    }) as ctx:
        if effective_platform != "openharmony":
            _print_chinese_log(
                f"候选边复核阶段跳过：有效平台是 {effective_platform}，"
                "不会套用 OpenHarmony Binder/SA 语义。"
            )
            ctx.status = "skipped"
            ctx.summary = {
                "skipped": True,
                "reason": "unsupported_platform",
                "platform": effective_platform,
                "review_scope": "candidate_edges",
            }
            _record_skip(result, review_step, "unsupported_platform")
        else:
            from core.platforms.openharmony.llm_call_graph_recovery import (
                RECOVERY_SCHEMA_VERSION,
                RECOVERY_TASK,
                run_recovery_review,
            )

            review_path = os.path.join(
                output_dir, "llm_call_graph_candidate_review.json"
            )
            reports: list[dict] = []
            missing_artifacts: list[dict] = []
            graph_dirs = resolve_call_graph_dirs(output_dir)

            try:
                review_binding = registry.get("llm_reach")
            except Exception as exc:  # defensive: registry is built above
                review_binding = None
                reports.append({
                    "language": result.language or "unknown",
                    "status": "failed",
                    "error": f"llm_reach binding unavailable: {exc}",
                })

            dataset_entry_points: set[str] = set()
            try:
                dataset_payload = read_json(active_dataset_path)
                dataset_units = (
                    dataset_payload.get("units", [])
                    if isinstance(dataset_payload, dict)
                    else []
                )
                if isinstance(dataset_units, list):
                    dataset_entry_points = {
                        str(unit.get("id"))
                        for unit in dataset_units
                        if isinstance(unit, dict)
                        and (
                            unit.get("is_entry_point") is True
                            or unit.get("semantic_reachability_seed") is True
                        )
                        and unit.get("id")
                    }
            except Exception as exc:
                print(
                    f"  [Warning] Could not load dataset entry-point hints: {exc}",
                    file=sys.stderr,
                )

            for language_name, graph_dir in sorted(
                graph_dirs.items(),
                key=lambda item: "" if item[0] is None else str(item[0]),
            ):
                label = language_name or result.language or "unknown"
                graph_path = os.path.join(graph_dir, "call_graph.json")
                residual_path = os.path.join(
                    graph_dir, "call_graph_residuals.json"
                )
                relative_graph = os.path.relpath(graph_path, output_dir)
                relative_residual = os.path.relpath(residual_path, output_dir)
                if not os.path.isfile(residual_path):
                    missing_artifacts.append({
                        "language": label,
                        "call_graph_path": relative_graph,
                        "residuals_path": relative_residual,
                        "reason": "call_graph_residuals_missing",
                    })
                    _print_chinese_log(
                        f"候选边复核跳过语言={label}：缺少 {relative_residual}，"
                        "不会把未知目标当成候选边。"
                    )
                    continue

                try:
                    graph_payload = read_json(graph_path)
                    diagnostics = read_json(residual_path)
                    functions = (
                        graph_payload.get("functions", {})
                        if isinstance(graph_payload, dict)
                        else {}
                    )
                    if not isinstance(functions, dict):
                        raise ValueError("call_graph.functions must be an object")
                    graph_entry_points = {
                        str(function_id)
                        for function_id, function in functions.items()
                        if isinstance(function, dict)
                        and function.get("is_entry_point") is True
                    }
                    review = run_recovery_review(
                        diagnostics,
                        functions,
                        binding=review_binding,
                        entry_point_ids=graph_entry_points | dataset_entry_points,
                        call_graph=graph_payload.get("call_graph", {}),
                        reverse_call_graph=graph_payload.get(
                            "reverse_call_graph", {}
                        ),
                        include_candidate_sites=True,
                    )
                    reports.append({
                        "language": label,
                        "status": review.get("status", "unknown"),
                        "call_graph_path": relative_graph,
                        "residuals_path": relative_residual,
                        "report": review,
                    })
                except Exception as exc:  # optional stage: keep prior work
                    print(
                        f"  [Warning] Candidate review failed for {label}: {exc}",
                        file=sys.stderr,
                    )
                    _print_chinese_log(
                        f"候选边复核失败（语言={label}，原因={exc}），原生调用图保持不变。"
                    )
                    reports.append({
                        "language": label,
                        "status": "failed",
                        "call_graph_path": relative_graph,
                        "residuals_path": relative_residual,
                        "error": str(exc)[:500],
                    })

            report_statuses = {item.get("status") for item in reports}
            if not reports:
                overall_status = "no_artifacts"
            elif report_statuses <= {"complete", "no_sites"}:
                overall_status = "complete"
            elif report_statuses & {"complete", "no_sites", "partial"}:
                overall_status = "partial"
            else:
                overall_status = "failed"

            aggregate = {
                "languages": len(reports),
                "missing_artifacts": len(missing_artifacts),
                "worklist_sites": 0,
                "request_batches": 0,
                "attempts": 0,
                "llm_calls": 0,
                "retry_count": 0,
                "parsed_decisions": 0,
                "accepted": 0,
                "kept_unresolved": 0,
                "rejected": 0,
                "unreviewed_sites": 0,
            }
            for item in reports:
                summary = item.get("report", {}).get("summary", {})
                if not isinstance(summary, dict):
                    continue
                for key in (
                    "worklist_sites",
                    "request_batches",
                    "attempts",
                    "llm_calls",
                    "retry_count",
                    "parsed_decisions",
                    "accepted",
                    "kept_unresolved",
                    "rejected",
                    "unreviewed_sites",
                ):
                    try:
                        aggregate[key] += int(summary.get(key, 0) or 0)
                    except (TypeError, ValueError):
                        continue

            payload = {
                "schema_version": RECOVERY_SCHEMA_VERSION,
                "task": RECOVERY_TASK,
                "platform": "openharmony",
                "review_scope": "candidate_edges",
                "status": overall_status,
                "reports": reports,
                "missing_artifacts": missing_artifacts,
                "summary": aggregate,
            }
            write_json(review_path, payload, indent=2)
            result.llm_call_graph_candidate_review_path = review_path
            ctx.outputs = {"candidate_review_path": review_path}
            ctx.summary = {
                "status": overall_status,
                "review_scope": "candidate_edges",
                **aggregate,
            }
            if overall_status == "no_artifacts":
                ctx.status = "skipped"
                _record_skip(result, review_step, "no_artifacts")
            elif overall_status == "failed":
                ctx.status = "skipped"
                _record_skip(result, review_step, "failed")
            elif overall_status == "partial":
                ctx.status = "partial"
            _print_chinese_log(
                f"候选边复核结果：状态={overall_status}，待审站点={aggregate['worklist_sites']}，"
                f"请求批次={aggregate.get('request_batches', 0)}，"
                f"模型调用={aggregate['llm_calls']}，接受={aggregate['accepted']}，"
                f"未决={aggregate['kept_unresolved']}，拒绝={aggregate['rejected']}；"
                "结果写入 llm_call_graph_candidate_review.json。"
            )

    collected_step_reports.append(_load_step_report(output_dir, review_step))
    print(file=sys.stderr)


def _run_openharmony_dispatch_code_evidence_stage(
    *,
    result: ScanResult,
    repo_path: str,
    output_dir: str,
    active_dataset_path: str,
    effective_platform: str,
    collected_step_reports: list[dict],
    step_label,
) -> None:
    """Extract source-backed selector values into an independent artifact."""
    evidence_step = "openharmony-dispatch-code-evidence"
    print(
        step_label("Extracting OpenHarmony dispatch-code evidence..."),
        file=sys.stderr,
    )
    _print_chinese_log(
        "阶段/OpenHarmony 分派码证据：从源码和头文件提取 IPC/SA 分派选择值，"
        "为后续动态验证准备可追溯证据；本阶段只新增证据文件，不改变调用图。"
    )

    with step_context(evidence_step, output_dir, inputs={
        "platform": effective_platform,
        "repository": repo_path,
        "dataset_path": active_dataset_path,
        "source": "call_graph_residuals.json",
        "review_scope": "dispatch_code_values",
    }) as ctx:
        if effective_platform != "openharmony":
            _print_chinese_log(
                f"分派码证据阶段跳过：有效平台是 {effective_platform}，"
                "只对 OpenHarmony IPC/SA 分派信息进行源码取证。"
            )
            ctx.status = "skipped"
            ctx.summary = {
                "skipped": True,
                "reason": "unsupported_platform",
                "platform": effective_platform,
                "review_scope": "dispatch_code_values",
            }
            _record_skip(result, evidence_step, "unsupported_platform")
        else:
            from core.platforms.openharmony.dispatch_code_evidence import (
                SCHEMA_VERSION,
                build_dispatch_code_evidence,
            )

            evidence_path = os.path.join(
                output_dir, "openharmony_dispatch_code_evidence.json"
            )
            reports: list[dict] = []
            missing_artifacts: list[dict] = []
            graph_dirs = resolve_call_graph_dirs(output_dir)
            for language_name, graph_dir in sorted(
                graph_dirs.items(),
                key=lambda item: "" if item[0] is None else str(item[0]),
            ):
                label = language_name or result.language or "unknown"
                graph_path = os.path.join(graph_dir, "call_graph.json")
                residual_path = os.path.join(
                    graph_dir, "call_graph_residuals.json"
                )
                relative_graph = os.path.relpath(graph_path, output_dir)
                relative_residual = os.path.relpath(residual_path, output_dir)
                if not os.path.isfile(residual_path):
                    missing_artifacts.append({
                        "language": label,
                        "call_graph_path": relative_graph,
                        "residuals_path": relative_residual,
                        "reason": "call_graph_residuals_missing",
                    })
                    _print_chinese_log(
                        f"分派码证据跳过语言={label}：缺少 {relative_residual}，"
                        "无法从残余站点提取选择值。"
                    )
                    continue
                try:
                    diagnostics = read_json(residual_path)
                    report = build_dispatch_code_evidence(
                        diagnostics,
                        repository=repo_path,
                    )
                    reports.append({
                        "language": label,
                        "status": report.get("status", "unknown"),
                        "call_graph_path": relative_graph,
                        "residuals_path": relative_residual,
                        "report": report,
                    })
                except Exception as exc:  # optional stage: keep prior work
                    print(
                        f"  [Warning] Dispatch-code evidence failed for {label}: {exc}",
                        file=sys.stderr,
                    )
                    _print_chinese_log(
                        f"分派码证据失败（语言={label}，原因={exc}），"
                        "不会生成未经源码证明的选择值。"
                    )
                    reports.append({
                        "language": label,
                        "status": "failed",
                        "call_graph_path": relative_graph,
                        "residuals_path": relative_residual,
                        "error": str(exc)[:500],
                    })

            statuses = {item.get("status") for item in reports}
            if not reports:
                overall_status = "no_artifacts"
            elif statuses <= {"complete"}:
                overall_status = "complete"
            elif statuses & {"complete", "partial"}:
                overall_status = "partial"
            else:
                overall_status = "failed"

            aggregate = {
                "languages": len(reports),
                "missing_artifacts": len(missing_artifacts),
                "sites": 0,
                "candidate_cases": 0,
                "resolved_cases": 0,
                "unresolved_symbols": 0,
                "conflicts": 0,
                "files_scanned": 0,
                "definitions": 0,
            }
            for item in reports:
                summary = item.get("report", {}).get("summary", {})
                if not isinstance(summary, dict):
                    continue
                for key in (
                    "sites",
                    "candidate_cases",
                    "resolved_cases",
                    "unresolved_symbols",
                    "conflicts",
                    "files_scanned",
                    "definitions",
                ):
                    try:
                        aggregate[key] += int(summary.get(key, 0) or 0)
                    except (TypeError, ValueError):
                        continue

            payload = {
                "schema_version": SCHEMA_VERSION,
                "platform": "openharmony",
                "review_scope": "dispatch_code_values",
                "repository": repo_path,
                "status": overall_status,
                "reports": reports,
                "missing_artifacts": missing_artifacts,
                "summary": aggregate,
            }
            write_json(evidence_path, payload, indent=2)
            result.openharmony_dispatch_code_evidence_path = evidence_path
            ctx.outputs = {"evidence_path": evidence_path}
            ctx.summary = {
                "status": overall_status,
                "review_scope": "dispatch_code_values",
                **aggregate,
            }
            if overall_status == "no_artifacts":
                ctx.status = "skipped"
                _record_skip(result, evidence_step, "no_artifacts")
            elif overall_status == "failed":
                ctx.status = "skipped"
                _record_skip(result, evidence_step, "failed")
            elif overall_status == "partial":
                ctx.status = "partial"
            _print_chinese_log(
                f"分派码证据结果：状态={overall_status}，站点={aggregate['sites']}，"
                f"候选分派码={aggregate['candidate_cases']}，已解析={aggregate['resolved_cases']}，"
                f"未解析符号={aggregate['unresolved_symbols']}，冲突={aggregate['conflicts']}；"
                "结果写入 openharmony_dispatch_code_evidence.json。"
            )

    collected_step_reports.append(_load_step_report(output_dir, evidence_step))
    print(file=sys.stderr)


def _count_steps(
    generate_context: bool,
    enhance: bool,
    verify: bool,
    generate_report: bool,
    dynamic_test: bool,
    llm_reachability: bool = False,
    stop_after: str | None = None,
    llm_call_graph_recovery: bool = False,
    llm_call_graph_iterative_recovery: bool = False,
    llm_call_graph_candidate_review: bool = False,
    llm_call_graph_projection: bool = False,
    openharmony_dispatch_code_evidence: bool = False,
    openharmony_gap_tasks: bool = False,
) -> int:
    """Count total steps for progress display (always includes parse, detect, build-output)."""
    if stop_after == "effective-call-graph":
        return 1
    if stop_after == "llm-reachability":
        # The application-context checkpoint is displayed even when the
        # caller explicitly skips it, so it still occupies a progress slot.
        return 3
    if stop_after == "openharmony-gap-tasks":
        # Progress is intentionally conservative: parse plus the selected
        # pre-analysis stages. Optional recovery/projection stages are counted
        # below only for a full run; the stop checkpoint itself remains one
        # auditable terminal stage.
        count = 3  # parse + application-context checkpoint + gap-task checkpoint
        if llm_reachability:
            count += 1
        if llm_call_graph_recovery or llm_call_graph_iterative_recovery:
            count += 1
        if llm_call_graph_candidate_review:
            count += 1
        if llm_call_graph_projection:
            count += 1
        if openharmony_dispatch_code_evidence:
            count += 1
        return count
    # parse + application-context checkpoint + detect + build-output.  The
    # context step remains visible as an explicit skip when disabled, so it is
    # counted in both modes and progress labels do not end in e.g. [5/4].
    count = 4
    if enhance:
        count += 1
    if verify:
        count += 1
    if generate_report:
        count += 1
    if dynamic_test:
        count += 1
    if llm_reachability:
        count += 1
    if llm_call_graph_recovery or llm_call_graph_iterative_recovery:
        count += 1
    if llm_call_graph_candidate_review:
        count += 1
    if llm_call_graph_projection:
        count += 1
    if openharmony_dispatch_code_evidence:
        count += 1
    if openharmony_gap_tasks:
        count += 1
    return count


def _record_skip(result: ScanResult, step: str, reason: str) -> None:
    """Record that ``step`` was skipped.

    Appends the bare step name to ``result.skipped_steps`` (UNCHANGED behaviour
    — telemetry consumers read this flat list) and ADDITIVELY records the
    disambiguated cause in ``result.skipped_step_reasons`` so distinct causes
    (e.g. verify auto-skip 'no_candidates' vs opt-out 'not_requested') are no
    longer conflated to one bare string.
    """
    result.skipped_steps.append(step)
    result.skipped_step_reasons[step] = reason


def _load_step_report(output_dir: str, step: str) -> dict:
    """Load a step report JSON from disk. Returns empty dict on failure."""
    path = os.path.join(output_dir, f"{step}.report.json")
    try:
        return read_json(path)
    except Exception:
        return {"step": step, "status": "unknown"}


def _read_app_type(app_context_path: str) -> str | None:
    """Read application_type from an app context JSON file."""
    try:
        data = read_json(app_context_path)
        return data.get("application_type")
    except Exception:
        return None


# Coverage fields the shared walker (core/repo_walk.py STAT_KEYS) records when it
# refuses a symlink or cannot read a directory. Parsers persist them into their
# per-language scan-result file's ``statistics`` block, NOT into dataset.json —
# so the merge into ``per_language`` never carries them. They are the only signal
# that a scan skipped part of the tree; without them a partially-covered scan of
# a hostile repo looks identical to a clean one. Aggregated here, at report time.
_COVERAGE_COUNT_KEYS = ("symlinks_skipped", "directories_unreadable")
_COVERAGE_EXAMPLE_KEYS = ("symlink_examples", "unreadable_examples")
# Parsers disagree on the filename: the in-process Python parser writes
# scan_result.json (singular); the subprocess parsers write scan_results.json.
_SCAN_RESULT_FILENAMES = ("scan_result.json", "scan_results.json")


def _read_coverage_stats(dir_path: str) -> dict:
    """Return the coverage keys present in a directory's scan-result file, or {}.

    Reads OUR output artifact, not anything from the scanned repo, so a plain
    read is safe. Only keys that are actually present are returned — absence is
    NOT coerced to zero here, because the caller must distinguish "the parser
    instruments coverage and skipped nothing" (a count key present at 0) from
    "the parser does not instrument coverage at all" (the key absent). Coercing
    absence to 0 is exactly the false-``symlinks_skipped: 0`` assurance this
    aggregation exists to avoid.
    """
    for name in _SCAN_RESULT_FILENAMES:
        candidate = os.path.join(dir_path, name)
        if not os.path.isfile(candidate):
            continue
        try:
            stats = read_json(candidate).get("statistics", {}) or {}
        except Exception:
            return {}
        return {
            k: stats[k]
            for k in (*_COVERAGE_COUNT_KEYS, *_COVERAGE_EXAMPLE_KEYS)
            if k in stats
        }
    return {}


def _language_scan_dirs(result: ScanResult) -> list[tuple[str, str]]:
    """``(language, scan-output-dir)`` pairs to probe for coverage.

    Multi-language runs carry a per-language ``output_dir`` in ``per_language``;
    the single-language passthrough writes straight into ``result.output_dir``
    with an empty ``per_language``. Both are normalised to the same pair list so
    coverage is attributable to a named language either way.
    """
    pairs: list[tuple[str, str]] = []
    for lang, spec in (result.per_language or {}).items():
        out = spec.get("output_dir") if isinstance(spec, dict) else None
        pairs.append((lang, out or result.output_dir))
    if not pairs:
        pairs.append((result.language, result.output_dir))
    return pairs


def _collect_coverage(result: ScanResult) -> dict:
    """Aggregate skipped-symlink / unreadable-dir figures across languages.

    A language is "instrumented" iff its scan-result ``statistics`` carries at
    least one coverage COUNT key. This is a presence PROBE, deliberately not a
    hardcoded per-language allowlist: the parser set gains and loses coverage
    instrumentation over time, and a stale allowlist would fail dangerously —
    silently summing a de-instrumented language's absent keys as 0, i.e. a false
    "nothing skipped". The probe fails safe instead: an uninstrumented language
    is disclosed in ``languages_without_coverage_data`` rather than counted as 0,
    so a ``symlinks_skipped: 0`` aggregate is trustworthy ONLY when that list is
    empty. (JavaScript and Go do not yet instrument coverage; they appear in the
    list until their parsers emit the snake_case keys.)
    """
    counts = {k: 0 for k in _COVERAGE_COUNT_KEYS}
    examples: dict[str, list] = {k: [] for k in _COVERAGE_EXAMPLE_KEYS}
    without_data: list[str] = []
    for lang, d in _language_scan_dirs(result):
        stats = _read_coverage_stats(d)
        if not any(k in stats for k in _COVERAGE_COUNT_KEYS):
            without_data.append(lang or "unknown")
            continue
        for k in _COVERAGE_COUNT_KEYS:
            counts[k] += int(stats.get(k, 0) or 0)
        for k in _COVERAGE_EXAMPLE_KEYS:
            for ex in stats.get(k, []) or []:
                if len(examples[k]) < 5 and ex not in examples[k]:
                    examples[k].append(ex)
    return {
        **counts,
        **examples,
        "languages_without_coverage_data": sorted(set(without_data)),
    }


def _write_scan_report(
    output_dir: str,
    result: ScanResult,
    step_reports: list[dict],
) -> str:
    """Write ``scan.report.json`` — the aggregate report for the full pipeline."""
    costs_by_currency: dict[str, float] = {}
    for sr in step_reports:
        recorded = sr.get("costs_by_currency") or {}
        if recorded:
            for currency, amount in recorded.items():
                costs_by_currency[currency] = costs_by_currency.get(currency, 0.0) + float(amount or 0)
        elif sr.get("cost_usd", 0):
            # Historical stage reports predate multi-currency fields.
            costs_by_currency["USD"] = costs_by_currency.get("USD", 0.0) + float(sr.get("cost_usd", 0) or 0)
    total_cost_usd = costs_by_currency.get("USD", 0.0)
    total_cost_cny = costs_by_currency.get("CNY", 0.0)
    total_duration = sum(sr.get("duration_seconds", 0) for sr in step_reports)
    total_input = sum(
        sr.get("token_usage", {}).get("input_tokens", 0) for sr in step_reports
    )
    total_output = sum(
        sr.get("token_usage", {}).get("output_tokens", 0) for sr in step_reports
    )

    scan_report = StepReport(
        step="scan",
        summary={
            "units_count": result.units_count,
            "language": result.language,
            "metrics": result.metrics.to_dict(),
            "steps_completed": [sr.get("step") for sr in step_reports],
            "steps_skipped": result.skipped_steps,
            # ADDITIVE / non-breaking: disambiguated skip cause per step.
            # `steps_skipped` above stays a flat bare list (consumers read it).
            "steps_skipped_reasons": result.skipped_step_reasons,
            # Multi-language coverage + which path supplied the security model.
            # Previously omitted here, so a merged/degraded scan and a
            # single-language clean one produced indistinguishable reports.
            "languages": result.languages,
            "language_stats": result.language_stats,
            "per_language": result.per_language,
            "parse_errors": result.parse_errors,
            "excluded_languages": result.excluded_languages,
            "degraded": result.degraded,
            "context_source": result.context_source,
            # R5: provenance of a repo-supplied threat model. sha is absent (key
            # omitted) when no threat model was loaded — never the empty hash.
            **(
                {"threat_model_sha256": result.threat_model_sha256}
                if result.threat_model_sha256
                else {}
            ),
            "threat_model_warnings": result.threat_model_warnings,
            "application_context_provenance": result.application_context_provenance,
            # Aggregate of what the walker refused (symlinks) or could not read
            # (directories), summed across languages from each scan-result file.
            "coverage": _collect_coverage(result),
            **(
                {"platform_profile": result.platform_profile}
                if result.platform_profile is not None
                else {}
            ),
            **(
                {"platform_selection": result.platform_selection}
                if result.platform_selection is not None
                else {}
            ),
        },
        inputs={"repo_path": result.output_dir.replace(os.path.abspath("."), ".")},
        outputs={
            "dataset_path": result.dataset_path,
            "enhanced_dataset_path": result.enhanced_dataset_path,
            "results_path": result.results_path,
            "verified_results_path": result.verified_results_path,
            "pipeline_output_path": result.pipeline_output_path,
            "summary_path": result.summary_path,
            "dynamic_test_path": result.dynamic_test_path,
            "llm_call_graph_recovery_path": result.llm_call_graph_recovery_path,
            "llm_call_graph_candidate_review_path": (
                result.llm_call_graph_candidate_review_path
            ),
            "llm_call_graph_overlay_path": result.llm_call_graph_overlay_path,
            "llm_call_graph_rounds_path": result.llm_call_graph_rounds_path,
            "llm_call_graph_ablation_path": result.llm_call_graph_ablation_path,
            "call_graph_gap_tasks_path": result.call_graph_gap_tasks_path,
            "analysis_feedback_path": result.analysis_feedback_path,
            "openharmony_dispatch_code_evidence_path": (
                result.openharmony_dispatch_code_evidence_path
            ),
            **(
                {
                    "platform_profile_path": os.path.join(
                        output_dir, "platform_profile.json"
                    )
                }
                if result.platform_profile is not None
                else {}
            ),
        },
        cost_usd=round(total_cost_usd, 6),
        cost_cny=round(total_cost_cny, 6),
        cost_amount=(round(next(iter(costs_by_currency.values())), 6)
                     if len(costs_by_currency) == 1 else 0.0),
        cost_currency=(next(iter(costs_by_currency))
                       if len(costs_by_currency) == 1 else None),
        costs_by_currency={k: round(v, 6) for k, v in costs_by_currency.items()},
        duration_seconds=round(total_duration, 2),
        token_usage={
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_input + total_output,
        },
    )

    path = scan_report.write(output_dir)
    print(f"[Scan] Aggregate report: {path}", file=sys.stderr)
    return path


def _print_banner(
    repo_path: str,
    output_dir: str,
    language: str,
    processing_level: str,
    verify: bool,
    generate_context: bool,
    enhance: bool,
    enhance_mode: str,
    generate_report: bool,
    dynamic_test: bool,
    workers: int = 8,
    backoff_seconds: int = 30,
    stop_after: str | None = None,
    llm_call_graph_recovery: bool = False,
    llm_call_graph_iterative_recovery: bool = False,
    llm_call_graph_candidate_review: bool = False,
    llm_call_graph_projection: bool = False,
    openharmony_dispatch_code_evidence: bool = False,
    clang_semantic: bool = False,
) -> None:
    """Print the scan configuration banner."""
    print("=" * 60, file=sys.stderr)
    print("OPENANT SCAN", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Repository:    {repo_path}", file=sys.stderr)
    print(f"  Output:        {output_dir}", file=sys.stderr)
    print(f"  Language:      {language}", file=sys.stderr)
    print(f"  Level:         {processing_level}", file=sys.stderr)
    print(f"  Enhance:       {enhance} ({enhance_mode})", file=sys.stderr)
    print(f"  Verify (S2):   {verify}", file=sys.stderr)
    print(f"  App context:   {generate_context}", file=sys.stderr)
    print(f"  Report:        {generate_report}", file=sys.stderr)
    print(f"  Dynamic test:  {dynamic_test}", file=sys.stderr)
    print(f"  Stop after:    {stop_after or 'none'}", file=sys.stderr)
    print(f"  OH call-edge recovery: {llm_call_graph_recovery}", file=sys.stderr)
    print(
        f"  OH iterative call-edge recovery: {llm_call_graph_iterative_recovery}",
        file=sys.stderr,
    )
    print(
        f"  OH candidate-edge review: {llm_call_graph_candidate_review}",
        file=sys.stderr,
    )
    print(
        f"  OH LLM call-edge projection: {llm_call_graph_projection}",
        file=sys.stderr,
    )
    print(
        f"  OH dispatch-code evidence: {openharmony_dispatch_code_evidence}",
        file=sys.stderr,
    )
    print(f"  OH Clang semantic batch: {clang_semantic}", file=sys.stderr)
    workers_label = f"{workers} (parallel)" if workers > 1 else "1 (sequential)"
    print(f"  Workers:       {workers_label}", file=sys.stderr)
    print(f"  Rate backoff:  {backoff_seconds}s", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(file=sys.stderr)


def _print_summary(result: ScanResult) -> None:
    """Print the final scan summary."""
    print("=" * 60, file=sys.stderr)
    print("SCAN COMPLETE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Units analyzed: {result.metrics.total}", file=sys.stderr)
    print(f"  Vulnerable:     {result.metrics.vulnerable}", file=sys.stderr)
    print(f"  Bypassable:     {result.metrics.bypassable}", file=sys.stderr)
    print(f"  Protected:      {result.metrics.protected}", file=sys.stderr)
    print(f"  Safe:           {result.metrics.safe}", file=sys.stderr)
    print(f"  Inconclusive:   {result.metrics.inconclusive}", file=sys.stderr)
    # PR #69 F5: surface findings whose Stage-2 verification could not complete
    # so they read distinctly from "safe" in the headline summary.
    if result.metrics.needs_review:
        print(f"  Needs review:   {result.metrics.needs_review} "
              f"(verification incomplete)", file=sys.stderr)
    print(f"  Errors:         {result.metrics.errors}", file=sys.stderr)
    if result.metrics.verified:
        print(f"  Verified:       {result.metrics.verified} "
              f"({result.metrics.stage2_agreed} agreed, "
              f"{result.metrics.stage2_disagreed} disagreed)", file=sys.stderr)
    if result.metrics.stage2_inconclusive_input:
        print(
            "  Inconclusive Stage 2: "
            f"{result.metrics.stage2_inconclusive_input} input, "
            f"{result.metrics.stage2_inconclusive_promoted} promoted, "
            f"{result.metrics.stage2_inconclusive_resolved} resolved, "
            f"{result.metrics.stage2_inconclusive_remaining} remaining",
            file=sys.stderr,
        )
    costs = result.usage.costs_by_currency
    if costs:
        symbols = {"USD": "$", "CNY": "¥"}
        formatted = " / ".join(
            f"{symbols.get(currency, currency + ' ')}{amount:.4f}"
            for currency, amount in sorted(costs.items())
        )
    else:
        formatted = "$0.0000"
    print(f"  Cost:           {formatted}", file=sys.stderr)
    print(f"  Output:         {result.output_dir}", file=sys.stderr)
    if result.skipped_steps:
        print(f"  Skipped:        {', '.join(result.skipped_steps)}", file=sys.stderr)
    if result.usage.total_input_tokens == 0 and result.metrics.errors > 0:
        print("", file=sys.stderr)
        print("  *** No API calls succeeded — repository was NOT analyzed. ***", file=sys.stderr)
        print("  *** Check your API key: openant set-api-key <key>          ***", file=sys.stderr)
    print("=" * 60, file=sys.stderr)


def _print_chinese_summary(result: ScanResult) -> None:
    """Print a concise Chinese explanation of the final pipeline decision."""
    metrics = result.metrics
    _print_chinese_log(
        f"扫描完成：共处理 {metrics.total} 个函数单元，确认漏洞={metrics.vulnerable}，"
        f"可绕过={metrics.bypassable}，受保护={metrics.protected}，安全={metrics.safe}，"
        f"待定={metrics.inconclusive}，错误={metrics.errors}。"
    )
    if metrics.stage2_inconclusive_input:
        _print_chinese_log(
            f"待定补证：输入={metrics.stage2_inconclusive_input}，"
            f"升级为漏洞={metrics.stage2_inconclusive_promoted}，"
            f"已解决={metrics.stage2_inconclusive_resolved}，"
            f"仍待定={metrics.stage2_inconclusive_remaining}。"
        )
    if result.skipped_steps:
        reasons = "、".join(
            f"{step}（{result.skipped_step_reasons.get(step, '未说明')}）"
            for step in result.skipped_steps
        )
        _print_chinese_log(f"跳过阶段：{reasons}。跳过不等于通过，解释以对应阶段报告为准。")
    _print_chinese_log(
        f"最终产物目录：{result.output_dir}；Web 可以从阶段详情查看结构化报告，"
        "运行日志保留了本次所有中文决策说明和原始英文输出。"
    )
