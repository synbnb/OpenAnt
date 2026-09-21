#!/usr/bin/env python3
"""
VulnFounder CLI — unified command-line interface for security analysis.

Commands:
    vulnfounder scan /path/to/repo --output /tmp/results
    vulnfounder parse /path/to/repo --output /tmp/results
    vulnfounder generate-context /path/to/repo -o /tmp/results/application_context.json
    vulnfounder enhance dataset.json --analyzer-output ao.json --repo-path /repo -o enhanced.json
    vulnfounder analyze dataset.json --output /tmp/results
    vulnfounder verify results.json --analyzer-output ao.json --output /tmp/results
    vulnfounder build-output results.json -o pipeline_output.json
    vulnfounder dynamic-test pipeline_output.json -o /tmp/dt/
    vulnfounder report results.json --format html --output report.html

All commands output JSON to stdout and logs to stderr.
Exit codes: 0 = clean, 1 = vulnerabilities found, 2 = error.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from core.language_registry import supported_languages
from core.language_selection import (
    DEFAULT_MIN_FILES,
    DEFAULT_MIN_SHARE,
    report_exclusions,
    select_languages,
)
from core.verdict_taxonomy import FINDING_VERDICT_ORDER
from utilities.branding import first_env, setdefault_env
from utilities.file_io import normalize_results, read_json


def _output_json(data: dict):
    """Write JSON to stdout."""
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _load_step_reports(directory: str) -> list[dict]:
    """Load all {step}.report.json files from a directory.

    Used by standalone commands (build-output, report) to feed
    cost/duration data into pipeline_output.json.
    """
    import glob
    reports = []
    for path in glob.glob(os.path.join(directory, "*.report.json")):
        try:
            reports.append(read_json(path))
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def cmd_scan(args):
    """Scan a repository end-to-end."""
    from core.scanner import scan_repository
    from core.schemas import success, error

    output_dir = args.output or tempfile.mkdtemp(prefix="vulnfounder_")

    try:
        # Resolve multi-language selection BEFORE scanning so an invalid flag
        # combination fails fast rather than after a full parse.
        _selection = _select_languages_for(args)

        result = scan_repository(
            repo_path=args.repo,
            output_dir=output_dir,
            language=args.language or "auto",
            platform=getattr(args, "platform", "auto"),
            languages=_selection.selected if _selection else None,
            excluded_languages=dict(_selection.excluded) if _selection else None,
            strict_languages=getattr(args, "strict_languages", False),
            processing_level=args.level,
            verify=args.verify,
            generate_context=not args.no_context,
            generate_report=not args.no_report,
            skip_tests=not args.no_skip_tests,
            limit=args.limit,
            llm_config_name=args.llm_config,
            enhance=not args.no_enhance,
            enhance_mode=args.enhance_mode,
            dynamic_test=args.dynamic_test,
            dynamic_test_mode=getattr(args, "dynamic_test_mode", "docker"),
            dynamic_device_serial=getattr(args, "dynamic_device", None),
            dynamic_device_hdc_path=getattr(args, "dynamic_hdc", None),
            dynamic_device_max_rounds=getattr(args, "dynamic_device_max_rounds", 16),
            dynamic_device_max_commands=getattr(args, "dynamic_device_max_commands", 512),
            dynamic_device_max_wall_seconds=getattr(args, "dynamic_device_wall_timeout", 1200),
            dynamic_device_command_timeout_seconds=getattr(args, "dynamic_device_timeout", 30),
            dynamic_device_allow_state_change=getattr(args, "dynamic_device_allow_state_change", False),
            dynamic_device_canary_path=getattr(args, "dynamic_device_canary_path", "/data/local/tmp/vulnfounder-canary"),
            dynamic_device_carrier_root=getattr(args, "dynamic_device_carrier_root", None),
            dynamic_device_carrier_id=getattr(args, "dynamic_device_carrier_id", None),
            dynamic_device_carrier_bundle=getattr(args, "dynamic_device_carrier_bundle", "com.security.research.trigger"),
            dynamic_device_carrier_ability=getattr(args, "dynamic_device_carrier_ability", "EntryAbility"),
            dynamic_device_execute_carrier=getattr(args, "dynamic_device_execute_carrier", False),
            dynamic_device_service_observation_delay_seconds=getattr(
                args, "dynamic_device_service_observation_delay", 0.8
            ),
            workers=args.workers,
            backoff_seconds=args.backoff,
            repo_name=getattr(args, "repo_name", None),
            repo_url=getattr(args, "repo_url", None),
            commit_sha=getattr(args, "commit_sha", None),
            diff_manifest=getattr(args, "diff_manifest", None),
            library_mode=getattr(args, "library_mode", False),
            llm_reachability=getattr(args, "llm_reachability", False),
            llm_reachability_max_code_bytes=getattr(
                args, "llm_reachability_max_code_bytes", 1500
            ),
            stop_after=getattr(args, "stop_after", None),
            llm_call_graph_recovery=getattr(
                args, "llm_call_graph_recovery", False
            ),
            llm_call_graph_iterative_recovery=getattr(
                args, "llm_call_graph_iterative_recovery", False
            ),
            llm_call_graph_candidate_review=getattr(
                args, "llm_call_graph_candidate_review", False
            ),
            llm_call_graph_projection=getattr(
                args, "llm_call_graph_projection", False
            ),
            openharmony_dispatch_code_evidence=getattr(
                args, "openharmony_dispatch_code_evidence", False
            ),
            clang_semantic=getattr(args, "clang_semantic", False),
            clang_compile_commands=getattr(args, "clang_compile_commands", None),
            clang_build_status=getattr(args, "clang_build_status", "compile_database"),
            clang_max_files=getattr(args, "clang_max_files", 128),
            clang_timeout_seconds=getattr(args, "clang_timeout_seconds", 30),
            clang_auto_context=getattr(args, "clang_auto_context", True),
            clang_batch_size=getattr(args, "clang_batch_size", 16),
            clang_force_recompute=getattr(args, "clang_force_recompute", False),
            clang_dependency_retry_attempts=getattr(args, "clang_dependency_retry_attempts", 1),
            clang_dependency_retry_low_trust=getattr(args, "clang_dependency_retry_low_trust", False),
            clang_definition_load_max_files=getattr(args, "clang_definition_load_max_files", 16),
            scope_manifest=getattr(args, "scope_manifest", None),
        )

        scan_payload = result.to_dict()
        # Surface the diff block on the envelope so the Go CLI banner can
        # render an "Incremental: base..head" line on success. The block
        # is the same one written into pipeline_output.json by reporter.py.
        if result.pipeline_output_path and os.path.exists(result.pipeline_output_path):
            try:
                po = read_json(result.pipeline_output_path)
                diff_block = po.get("diff")
                if isinstance(diff_block, dict) and diff_block.get("mode") == "incremental":
                    scan_payload["diff"] = diff_block
            except (json.JSONDecodeError, OSError):
                pass
        _output_json(success(scan_payload))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_socket_scope_discover(args):
    """Use the agentic LLM to discover candidate scan roots for a socket target."""
    from core.socket_scope import discover_socket_scope, write_scope_manifest

    try:
        payload = discover_socket_scope(
            args.repo,
            args.target,
            max_candidates=args.max_candidates,
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            # Kept for CLI compatibility; socket-scope discovery is always
            # agentic now and never falls back to deterministic ranking.
            llm_rank=True,
            llm_config=getattr(args, "llm_config", None),
        )
        if args.select:
            from core.socket_scope import select_socket_scope
            payload = select_socket_scope(payload, args.select)
        if args.output:
            write_scope_manifest(payload, args.output)
        _output_json({"status": "success", "scope": payload, "output": args.output})
        return 0
    except Exception as exc:
        _output_json({"status": "error", "errors": [str(exc)]})
        return 2


def cmd_socket_scope_select(args):
    """Select a candidate in an existing socket scope manifest."""
    from core.socket_scope import select_socket_scope, write_scope_manifest

    try:
        payload = read_json(args.manifest)
        selected = select_socket_scope(payload, args.candidate_id)
        output = args.output or args.manifest
        write_scope_manifest(selected, output)
        _output_json({"status": "success", "scope": selected, "output": output})
        return 0
    except Exception as exc:
        _output_json({"status": "error", "errors": [str(exc)]})
        return 2


def cmd_scan_artifact_list(args):
    """List scan-artifact rounds or testable entries (read-only bridge input)."""
    from core.scan_artifact_bridge import (
        ScanBridgeError,
        list_scan_entries,
        list_scan_rounds,
        list_webui_entries,
        list_webui_scans,
    )

    try:
        if getattr(args, "scan_id", None):
            # webui 扫描目录模式
            _output_json({"status": "success", "scan_id": args.scan_id,
                          "entries": [e.to_dict() for e in list_webui_entries(
                              args.webui_dir, args.scan_id, finding=args.finding)]})
            return 0
        if args.result_dir is None:
            # 未给任何输入目录：列出 webui 下全部扫描（供前端选择表单）
            _output_json({"status": "success", "scans": list_webui_scans(args.webui_dir)})
            return 0
        if args.round is None:
            _output_json({"status": "success", "rounds": list_scan_rounds(args.result_dir)})
            return 0
        entries = list_scan_entries(
            args.result_dir,
            round_n=args.round,
            finding=args.finding,
            repository=args.repository,
        )
        _output_json({"status": "success", "round": args.round,
                      "entries": [e.to_dict() for e in entries]})
        return 0
    except ScanBridgeError as exc:
        _output_json({"status": "error", "errors": [str(exc)]})
        return 2
    except Exception as exc:
        _output_json({"status": "error", "errors": [f"{type(exc).__name__}: {exc}"]})
        return 2


def cmd_scan_artifact_run(args):
    """Run the device dynamic test for one scan-artifact entry."""
    from core.scan_artifact_bridge import ScanBridgeError, run_dynamic_from_scan, run_dynamic_from_webui

    try:
        common = dict(
            sample=args.sample,
            serial=args.device,
            hdc_path=args.hdc,
            repo_root=args.repo_root,
            ledger_path=args.ledger,
            progress_path=getattr(args, "progress_file", None),
            clean_room=bool(getattr(args, "clean_room", False)),
        )
        # --scan-id 提供时走 webui 扫描目录输入；否则走聚合产物目录输入。
        if getattr(args, "scan_id", None):
            result = run_dynamic_from_webui(args.scan_id, **common)
        else:
            result = run_dynamic_from_scan(args.result_dir, round_n=args.round, **common)
        payload = result.to_dict()
        _output_json({"status": "success", "result": payload})
        # Exit 1 mirrors dynamic-test: a confirmed device effect is a finding.
        return 1 if result.status == "CONFIRMED" else 0
    except ScanBridgeError as exc:
        _output_json({"status": "error", "errors": [str(exc)]})
        return 2
    except Exception as exc:
        _output_json({"status": "error", "errors": [f"{type(exc).__name__}: {exc}"]})
        return 2


def _select_languages_for(args):
    """LanguageSelection for this invocation, or None only for an explicit ``-l``.

    **`auto` now means every detected language, not the dominant one.** This is a
    deliberate behaviour change and it is the point of the feature: the request was
    "all languages we currently support should be detected in the repo and it
    should scan all of them, not just the main one" — a statement about what the
    tool does by default, which an opt-in flag does not satisfy.

    The machinery this needs already existed and was already reviewed:
    ``select_languages`` applies the file-count and share thresholds, always keeps
    the dominant language so a selection can never be empty, and
    ``report_exclusions`` prints any language it dropped. Only the early return
    here forced the legacy single-language path, so removing it is the whole
    inversion.

    Returns None only when the caller named a single language explicitly with
    ``-l <lang>``, which remains the escape hatch and the way to get the old
    behaviour.

    What changes for existing users: multi-language repositories now cost more to
    scan and produce more findings. That is the intended effect; the loud
    selection/exclusion banner is the mitigation, so the coverage change is never
    silent.
    """
    explicit = getattr(args, "language", "auto") not in (None, "auto")
    multi = (getattr(args, "languages", None)
             or getattr(args, "all_languages", False)
             or getattr(args, "multi_language", False))
    if explicit and not multi:
        return None
    from core.parser_adapter import detect_languages

    return resolve_language_selection(args, detect_languages(args.repo))


def cmd_parse(args):
    """Parse a repository into a dataset."""
    from core.parser_adapter import _maybe_apply_diff_filter, parse_repository
    from core.schemas import ParseResult
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="vulnfounder_parse_")

    try:
        platform = getattr(args, "platform", "auto")
        if platform not in {"auto", "generic", "openharmony"}:
            raise ValueError(f"Unsupported platform: {platform}")
        platform_kwargs = {"platform": platform} if platform != "auto" else {}
        with step_context("parse", output_dir, inputs={
            "repo_path": os.path.abspath(args.repo),
            "language": args.language or "auto",
            "processing_level": args.level,
            "skip_tests": not args.no_skip_tests,
            "platform": platform,
        }) as ctx:
            selection = _select_languages_for(args)

            if selection is not None and selection.is_multi:
                # Multi-language: fan out into <output_dir>/<lang>/, then merge
                # into the single dataset the rest of the pipeline consumes.
                from core.dataset_merge import (
                    merge_analyzer_outputs,
                    merge_datasets,
                    write_call_graph_index,
                )
                from core.parser_adapter import parse_repository_multi

                outcomes = parse_repository_multi(
                    repo_path=args.repo,
                    run_dir=output_dir,
                    languages=selection.selected,
                    processing_level=args.level,
                    skip_tests=not args.no_skip_tests,
                    name=getattr(args, "name", None),
                    fresh=getattr(args, "fresh", False),
                    library_mode=getattr(args, "library_mode", False),
                    strict=getattr(args, "strict_languages", False),
                    **platform_kwargs,
                )
                dataset_path = os.path.join(output_dir, "dataset.json")
                analyzer_path = os.path.join(output_dir, "analyzer_output.json")
                merge_stats = merge_datasets(outcomes, dataset_path)
                merge_analyzer_outputs(outcomes, analyzer_path)
                write_call_graph_index(
                    outcomes, os.path.join(output_dir, "call_graphs.json")
                )

                failed = [o for o in outcomes if not o.ok]
                result = ParseResult(
                    dataset_path=dataset_path,
                    analyzer_output_path=analyzer_path if os.path.exists(analyzer_path) else None,
                    units_count=merge_stats.total_units,
                    # Scalar stays the PRIMARY language for back-compat.
                    language=selection.primary,
                    processing_level=args.level,
                    languages=merge_stats.languages,
                    language_stats=merge_stats.units_per_language,
                    per_language={o.language: o.to_dict() for o in outcomes},
                    parse_errors=[o.to_dict() for o in failed],
                    excluded_languages=dict(selection.excluded),
                )
                _maybe_apply_diff_filter(
                    result, output_dir, getattr(args, "diff_manifest", None)
                )
            else:
                # NOTE: exclusions are attached AFTER this call — see below.
                # The one-language case is exactly when a coverage gap exists,
                # so the legacy branch must report it too.
                result = parse_repository(
                    repo_path=args.repo,
                    output_dir=output_dir,
                    # Honour an explicit single-language selection. `-l` is
                    # mutually exclusive with --languages, so args.language is
                    # ALWAYS "auto" here — using it silently re-detected the
                    # dominant language and parsed something the user did not
                    # ask for, while reporting success.
                    language=(
                        selection.selected[0] if selection and selection.selected
                        else (args.language or "auto")
                    ),
                    processing_level=args.level,
                    skip_tests=not args.no_skip_tests,
                    name=getattr(args, "name", None),
                    diff_manifest=getattr(args, "diff_manifest", None),
                    fresh=getattr(args, "fresh", False),
                    library_mode=getattr(args, "library_mode", False),
                    **platform_kwargs,
                )

            # Attach exclusions on BOTH branches. The multi-language branch
            # sets them when constructing its ParseResult; the single-language
            # branch gets them here, because parse_repository knows nothing
            # about selection policy.
            if selection is not None and not result.excluded_languages:
                result.excluded_languages = dict(selection.excluded)

            if platform != "auto":
                result.platform_selection = platform

            ctx.summary = {
                "total_units": result.units_count,
                "language": result.language,
                "processing_level": result.processing_level,
                "excluded_languages": result.excluded_languages,
            }
            # Surface diff stats in the parse step report if present.
            diff_report = os.path.join(output_dir, "diff_filter.report.json")
            if os.path.exists(diff_report):
                try:
                    ctx.summary["diff_stats"] = read_json(diff_report)
                except (json.JSONDecodeError, OSError):
                    pass
            ctx.outputs = {
                "dataset_path": result.dataset_path,
                "analyzer_output_path": result.analyzer_output_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_generate_context(args):
    """Generate application security context for a repository."""
    from pathlib import Path
    from context.application_context import (
        generate_application_context,
        save_context,
        format_context_for_prompt,
    )
    from core.schemas import success, error
    from core.step_report import step_context
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )

    # Default output to the CWD, NOT the scanned repo root: writing the context
    # into the checkout would let a later scan silently auto-load it as
    # finding-suppression config. Suppression must be an explicit operator act.
    output_path = args.output or os.path.join(os.getcwd(), "application_context.json")
    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("generate-context", output_dir, inputs={
            "repo_path": os.path.abspath(args.repo),
            "force": args.force,
        }) as ctx:
            # generate_application_context requires a PhaseBinding for the
            # app_context phase (model + adapter live in the binding, not
            # caller-side). Same registry idiom as the threat-model command.
            cf = load_config_file()
            registry = build_phase_registry(
                cf, resolve_llm_config(cf, getattr(args, "llm_config", None))
            )
            probe_registry_or_raise(registry)
            app_context = generate_application_context(
                Path(args.repo),
                registry.get("app_context"),
                force_regenerate=args.force,
            )
            # generate_application_context returns None when the LLM yields an
            # incomplete context; surface a clear message instead of letting
            # save_context(None) raise an opaque asdict() error.
            if app_context is None:
                _output_json(error("Could not generate application context (LLM returned an incomplete result)."))
                return 2
            save_context(app_context, Path(output_path))

            ctx.summary = {
                "application_type": app_context.application_type,
                "confidence": app_context.confidence,
                "source": app_context.source,
            }
            ctx.outputs = {"app_context_path": os.path.abspath(output_path)}

        result = {
            "app_context_path": os.path.abspath(output_path),
            "application_type": app_context.application_type,
            "purpose": app_context.purpose,
            "confidence": app_context.confidence,
            "source": app_context.source,
        }

        if args.show_prompt:
            result["prompt_format"] = format_context_for_prompt(app_context)

        _output_json(success(result))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_enhance(args):
    """Enhance a dataset with security context."""
    from core.enhancer import enhance_dataset
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    # Default output path: same dir as input, with _enhanced suffix
    if args.output:
        output_path = args.output
    else:
        base, ext = os.path.splitext(args.dataset)
        output_path = f"{base}_enhanced{ext}"

    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("enhance", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "analyzer_output_path": os.path.abspath(args.analyzer_output) if args.analyzer_output else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
            "mode": args.mode,
        }) as ctx:
            result = enhance_dataset(
                dataset_path=args.dataset,
                output_path=output_path,
                analyzer_output_path=args.analyzer_output,
                repo_path=args.repo_path,
                mode=args.mode,
                checkpoint_path=args.checkpoint,
                llm_config_name=args.llm_config,
                workers=args.workers,
                backoff_seconds=args.backoff,
                limit=args.limit,
            )

            ctx.summary = {
                "units_enhanced": result.units_enhanced,
                "error_count": result.error_count,
                "classifications": result.classifications,
                "mode": args.mode,
            }
            if result.error_summary:
                ctx.summary["error_summary"] = result.error_summary
            ctx.outputs = {
                "enhanced_dataset_path": result.enhanced_dataset_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_analyze(args):
    """Run vulnerability analysis on a dataset.

    With --verify, chains Stage 1 detection into Stage 2 verification
    automatically (convenience shortcut for ``analyze`` + ``verify``).
    """
    from core.analyzer import run_analysis
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="vulnfounder_analyze_")

    exploitable_filter = "all" if args.exploitable_all else ("strict" if args.exploitable_only else None)

    # Application context is used ONLY when the operator passes it explicitly.
    # Auto-discovering it from the scanned repo (or stale output dirs) would let
    # repo-supplied config silently suppress findings — an explicit act only.
    app_context_path = args.app_context

    try:
        with step_context("analyze", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "llm_config": args.llm_config,
            "exploitable_filter": exploitable_filter,
            "limit": args.limit,
        }) as ctx:
            result = run_analysis(
                dataset_path=args.dataset,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=app_context_path,
                repo_path=args.repo_path,
                limit=args.limit,
                llm_config_name=args.llm_config,
                exploitable_filter=exploitable_filter,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "total_units": result.metrics.total,
                "analyzed": result.metrics.total - result.metrics.errors,
                "verdicts": {
                    "vulnerable": result.metrics.vulnerable,
                    "bypassable": result.metrics.bypassable,
                    "inconclusive": result.metrics.inconclusive,
                    "protected": result.metrics.protected,
                    "safe": result.metrics.safe,
                    "errors": result.metrics.errors,
                },
            }
            ctx.outputs = {
                "results_path": result.results_path,
            }

        # If --verify, chain into Stage 2
        if args.verify:
            if not args.analyzer_output:
                print("[Analyze] WARNING: --verify requires --analyzer-output. "
                      "Skipping verification.", file=sys.stderr)
            else:
                from core.verifier import run_verification
                with step_context("verify", output_dir, inputs={
                    "results_path": result.results_path,
                    "analyzer_output_path": os.path.abspath(args.analyzer_output),
                }) as vctx:
                    vresult = run_verification(
                        results_path=result.results_path,
                        output_dir=output_dir,
                        analyzer_output_path=args.analyzer_output,
                        app_context_path=app_context_path,
                        repo_path=args.repo_path,
                        workers=args.workers,
                        backoff_seconds=args.backoff,
                        # Propagate --llm-config so the chained verify stage
                        # uses the same configured model as analyze, not the default.
                        llm_config_name=args.llm_config,
                    )

                    vctx.summary = {
                        "findings_input": vresult.findings_input,
                        "findings_verified": vresult.findings_verified,
                        "agreed": vresult.agreed,
                        "disagreed": vresult.disagreed,
                        "confirmed_vulnerabilities": vresult.confirmed_vulnerabilities,
                        "inconclusive_input": vresult.inconclusive_input,
                        "inconclusive_promoted": vresult.inconclusive_promoted,
                        "inconclusive_resolved": vresult.inconclusive_resolved,
                        "inconclusive_remaining": vresult.inconclusive_remaining,
                        "needs_review": vresult.needs_review,
                    }
                    vctx.outputs = {
                        "verified_results_path": vresult.verified_results_path,
                    }

                _output_json(success(vresult.to_dict()))
                if vresult.confirmed_vulnerabilities > 0:
                    return 1
                return 0

        _output_json(success(result.to_dict()))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_verify(args):
    """Run Stage 2 attacker-simulation verification on Stage 1 results."""
    from core.verifier import run_verification
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="vulnfounder_verify_")

    # Application context is used ONLY when the operator passes it explicitly
    # (see the analyze command for the rationale — no silent auto-discovery).
    app_context_path = args.app_context

    try:
        with step_context("verify", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "analyzer_output_path": os.path.abspath(args.analyzer_output),
            "app_context_path": os.path.abspath(app_context_path) if app_context_path else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
        }) as ctx:
            result = run_verification(
                results_path=args.results,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=app_context_path,
                repo_path=args.repo_path,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
                llm_config_name=args.llm_config,
            )

            ctx.summary = {
                "findings_input": result.findings_input,
                "findings_verified": result.findings_verified,
                "agreed": result.agreed,
                "disagreed": result.disagreed,
                "confirmed_vulnerabilities": result.confirmed_vulnerabilities,
                "inconclusive_input": result.inconclusive_input,
                "inconclusive_promoted": result.inconclusive_promoted,
                "inconclusive_resolved": result.inconclusive_resolved,
                "inconclusive_remaining": result.inconclusive_remaining,
                "needs_review": result.needs_review,
            }
            ctx.outputs = {
                "verified_results_path": result.verified_results_path,
            }

        _output_json(success(result.to_dict()))

        # Exit 1 if confirmed vulnerabilities
        if result.confirmed_vulnerabilities > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_build_output(args):
    """Build pipeline_output.json from analysis results."""
    from core.reporter import build_pipeline_output
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = os.path.dirname(os.path.abspath(args.output))

    # Load existing step reports for cost/duration data
    results_dir = os.path.dirname(os.path.abspath(args.results))
    step_reports = _load_step_reports(results_dir)

    try:
        with step_context("build-output", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
        }) as ctx:
            path, findings_count = build_pipeline_output(
                results_path=args.results,
                output_path=args.output,
                repo_name=args.repo_name,
                repo_url=args.repo_url,
                language=args.language,
                commit_sha=args.commit_sha,
                application_type=args.app_type or "web_app",
                processing_level=args.processing_level,
                step_reports=step_reports,
            )

            ctx.outputs = {"pipeline_output_path": path}

        _output_json(success({"pipeline_output_path": path, "findings_count": findings_count}))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_dynamic_test(args):
    """Run Docker testing or prepare a Claude Code task workspace."""
    from core.dynamic_tester import run_tests
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="vulnfounder_dyntest_")

    try:
        with step_context("dynamic-test", output_dir, inputs={
            "pipeline_output_path": os.path.abspath(args.pipeline_output),
            "max_retries": args.max_retries,
            "mode": args.mode,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
        }) as ctx:
            result = run_tests(
                pipeline_output_path=args.pipeline_output,
                output_dir=output_dir,
                max_retries=args.max_retries,
                repo_path=args.repo_path,
                llm_config_name=args.llm_config,
                mode=args.mode,
                device_serial=getattr(args, "device", None),
                device_hdc_path=getattr(args, "hdc", None),
                dynamic_device_max_rounds=getattr(args, "max_rounds", 16),
                dynamic_device_max_commands=getattr(args, "max_commands", 512),
                dynamic_device_max_wall_seconds=getattr(args, "device_wall_timeout", 1200),
                dynamic_device_command_timeout_seconds=getattr(args, "device_timeout", 30),
                dynamic_device_allow_state_change=getattr(args, "allow_state_change", False),
                dynamic_device_canary_path=getattr(args, "canary_path", "/data/local/tmp/vulnfounder-canary"),
                dynamic_device_carrier_root=getattr(args, "carrier_root", None),
                dynamic_device_carrier_id=getattr(args, "carrier_id", None),
                dynamic_device_carrier_bundle=getattr(args, "carrier_bundle", "com.security.research.trigger"),
                dynamic_device_carrier_ability=getattr(args, "carrier_ability", "EntryAbility"),
                dynamic_device_execute_carrier=getattr(args, "execute_carrier", False),
                dynamic_device_service_observation_delay_seconds=getattr(
                    args, "service_observation_delay", 0.8
                ),
            )

            ctx.summary = {
                "findings_tested": result.findings_tested,
                "confirmed": result.confirmed,
                "not_reproduced": result.not_reproduced,
                "blocked": result.blocked,
                "inconclusive": result.inconclusive,
                "errors": result.errors,
                "mode": result.mode,
            }
            ctx.outputs = {
                "results_json_path": result.results_json_path,
                "results_md_path": result.results_md_path,
                "task_workspace": result.task_workspace,
                "public_tool_library": result.public_tool_library,
                "task_manifest_path": result.task_manifest_path,
                "candidate_manifest": result.candidate_manifest,
                "launch_command": result.launch_command,
            }

        _output_json(success(result.to_dict()))

        if result.confirmed > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def _default_report_output(results_path: str, fmt: str, language: str = "en") -> str:
    """Derive a sensible default output path based on format."""
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(results_path)), "final-reports")
    defaults = {
        "html": os.path.join(reports_dir, "report.html"),
        "csv": os.path.join(reports_dir, "report.csv"),
        "summary": os.path.join(reports_dir, "report.md"),
        "disclosure": os.path.join(reports_dir, "disclosures"),
    }
    output = defaults.get(fmt, os.path.join(reports_dir, "report"))
    if language == "zh-CN" and fmt == "summary":
        root, ext = os.path.splitext(output)
        output = f"{root}.zh-CN{ext}"
    return output


def cmd_report(args):
    """Generate reports from analysis results.

    Accepts either a ``pipeline_output.json`` (via ``--pipeline-output``) or
    a raw ``results.json`` as positional argument.  For summary/disclosure
    formats, ``pipeline_output.json`` is required; if only results are given,
    it is built automatically.
    """
    from core.reporter import (
        build_pipeline_output,
        generate_csv_report,
        generate_summary_report,
        generate_disclosure_docs,
    )
    from core.schemas import success, error
    from core.step_report import step_context

    fmt = args.format
    language = getattr(args, "language", "en") or "en"
    output_path = args.output or _default_report_output(args.results, fmt, language)
    output_dir = os.path.dirname(os.path.abspath(output_path))

    # Check if dynamic tests have been run (for summary/disclosure formats)
    if fmt in ("summary", "disclosure") and not getattr(args, "skip_dt_check", False):
        results_dir = os.path.dirname(os.path.abspath(args.results))
        dt_results_path = os.path.join(results_dir, "dynamic_test_results.json")
        if not os.path.exists(dt_results_path):
            print(
                "\nDynamic tests haven't been run yet.\n"
                "If this is intentional, press Y to generate reports without dynamic test data.\n"
                "Otherwise, run 'vulnfounder dynamic-test' first.\n",
                file=sys.stderr,
            )
            if not sys.stdin.isatty():
                # Non-interactive (Go CLI pipes stdin) — continue silently.
                answer = "y"
            else:
                sys.stderr.write("[Y/n] ")
                sys.stderr.flush()
                try:
                    answer = sys.stdin.readline().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"
            if answer not in ("y", "yes", ""):
                print("Aborted. Run 'vulnfounder dynamic-test' first.", file=sys.stderr)
                return 0

    try:
        with step_context("report", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "format": fmt,
        }) as ctx:
            # For summary/disclosure, we need pipeline_output.json
            pipeline_output_path = args.pipeline_output
            if fmt in ("summary", "disclosure") and not pipeline_output_path:
                # Auto-build pipeline_output from results, with step report data
                results_dir = os.path.dirname(os.path.abspath(args.results))
                step_reports = _load_step_reports(results_dir)
                pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")
                build_pipeline_output(
                    results_path=args.results,
                    output_path=pipeline_output_path,
                    repo_name=args.repo_name,
                    step_reports=step_reports,
                )

            if fmt == "html":
                # HTML reports are now rendered by the Go CLI via report-data.
                # This code path should not be reached — Go handles html directly.
                _output_json(error("HTML reports are generated by the Go CLI. Use 'vulnfounder report -f html' instead."))
                return 2
            elif fmt == "csv":
                if not args.dataset:
                    _output_json(error("--dataset is required for CSV reports"))
                    return 2
                result = generate_csv_report(args.results, args.dataset, output_path)
            elif fmt == "summary":
                result = generate_summary_report(
                    pipeline_output_path, output_path,
                    llm_config_name=args.llm_config,
                    language=language,
                )
            elif fmt == "disclosure":
                result = generate_disclosure_docs(
                    pipeline_output_path, output_path,
                    llm_config_name=args.llm_config,
                )
            else:
                _output_json(error(f"Unknown format: {fmt}"))
                return 2

            ctx.summary = {"format": fmt}
            ctx.outputs = {"output_path": output_path}

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_checkpoint_status(args):
    """Report checkpoint status for a checkpoint directory.

    Internal subcommand — not user-facing. Called by the Go CLI to get
    accurate completed/errored counts by reading actual checkpoint files.
    """
    from core.checkpoint import StepCheckpoint
    from core.schemas import success, error

    checkpoint_dir = args.checkpoint_dir
    if not os.path.isdir(checkpoint_dir):
        _output_json(error(f"Checkpoint directory not found: {checkpoint_dir}"))
        return 2

    try:
        status = StepCheckpoint.status(checkpoint_dir)
        _output_json(success(status))
        return 0
    except Exception as e:
        _output_json(error(str(e)))
        return 2


def _source_locator_store(root: str):
    from core.source_locator import LocatorSessionStore

    return LocatorSessionStore(root)


def _source_locator_payload(machine):
    events = machine.store.events(machine.session.session_id).load()
    return {
        "session": machine.session.to_dict(),
        "event_count": len(events),
        "last_event": events[-1].to_dict() if events else None,
    }


def _load_source_locator_machine(args):
    return _source_locator_store(args.root).load(args.session_id)


def _source_locator_project_root(args) -> str:
    """Resolve the trusted VulnFounder root used by locator-side file operations."""

    explicit = getattr(args, "project_root", None)
    if explicit:
        return os.path.abspath(os.path.expanduser(str(explicit)))
    # The CLI module is installed below ``<root>/libs/vulnfounder-core/vulnfounder``.
    # Do not use the scanned repository's cwd as an implicit trusted root.
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _source_locator_config_path(args) -> str:
    explicit = getattr(args, "config_path", None)
    if explicit:
        return os.path.abspath(os.path.expanduser(str(explicit)))
    environment = first_env("VULNFOUNDER_CONFIG_FILE", "OPENANT_CONFIG_FILE")
    if environment:
        return os.path.abspath(os.path.expanduser(environment))
    return os.path.join(_source_locator_project_root(args), "config", "vulnfounder", "config.json")


def _source_locator_runtime(args):
    """Build a configured runtime when source_locator is present.

    An absent optional section is deliberately represented by an empty runtime;
    the worker then records ``OPENGROK_UNAVAILABLE`` instead of guessing a
    public endpoint or silently reading a user credential file.
    """

    from core.source_locator import SourceLocatorRuntime, runtime_from_config
    from core.source_locator.config import load_source_locator_config

    config_path = _source_locator_config_path(args)
    config = load_source_locator_config(config_path, required=False)
    if config is None:
        return SourceLocatorRuntime(project_root=_source_locator_project_root(args))
    llm_planner = _source_locator_llm_planner(args)
    llm_role_attributor = _source_locator_llm_role_attributor(args)
    llm_entrypoint_attributor = _source_locator_llm_entrypoint_attributor(args)
    llm_candidate_reviewer = _source_locator_llm_candidate_reviewer(args)
    return runtime_from_config(
        config_path,
        project_root=_source_locator_project_root(args),
        max_paths=getattr(args, "max_paths", 32),
        max_source_bytes=getattr(args, "max_source_bytes", None),
        llm_planner=llm_planner,
        llm_role_attributor=llm_role_attributor,
        llm_entrypoint_attributor=llm_entrypoint_attributor,
        llm_candidate_reviewer=llm_candidate_reviewer,
    )


def _source_locator_llm_planner(args):
    """Build the optional semantic search planner from the normal LLM registry.

    The planner is opt-in (``--llm-search``) so a normal locator run remains
    deterministic and does not unexpectedly spend tokens.  When enabled the
    worker may perform a small, bounded sequence of semantic rounds. Any adapter/config
    failure is downgraded to deterministic search; the worker records no
    credential and never exposes a provider exception to the model context.
    """

    if not bool(getattr(args, "llm_search", False)):
        return None
    # Source-locator planning only needs a short structured action JSON.  The
    # normal analysis phases intentionally allow larger reasoning budgets, but
    # carrying those defaults into this bounded search loop can make one
    # Responses request occupy the whole Web request window.  These defaults
    # are process-local (the source-locator command runs in its own Python
    # worker) and remain overridable through the environment for diagnostics.
    setdefault_env("VULNFOUNDER_OPENAI_REASONING_EFFORT", "OPENANT_OPENAI_REASONING_EFFORT", "low")
    setdefault_env("VULNFOUNDER_OPENAI_MIN_OUTPUT_TOKENS", "OPENANT_OPENAI_MIN_OUTPUT_TOKENS", "4096")
    setdefault_env("VULNFOUNDER_OPENAI_REQUEST_TIMEOUT_SECONDS", "OPENANT_OPENAI_REQUEST_TIMEOUT_SECONDS", "120")
    setdefault_env("VULNFOUNDER_OPENAI_MAX_RETRIES", "OPENANT_OPENAI_MAX_RETRIES", "0")
    try:
        from core.source_locator import LLM_SEARCH_MAX_ACTIONS
    except Exception as exc:  # optional locator module must not block fallback
        print(f"source-locator 语义规划器不可用，继续确定性检索：{_compact_cli_error(exc)}", file=sys.stderr)
        return None
    configured_rounds = getattr(args, "llm_search_rounds", None)
    # Validate the user-selected budget before entering the optional-provider
    # fallback block.  A malformed explicit value is an API/CLI input error;
    # it must not be mistaken for a temporarily unavailable model and silently
    # downgrade the run to deterministic search.
    if (
        configured_rounds is not None
        and (
            isinstance(configured_rounds, bool)
            or not isinstance(configured_rounds, int)
            or not 1 <= configured_rounds <= LLM_SEARCH_MAX_ACTIONS
        )
    ):
        raise ValueError(f"llm_search_rounds 必须是 1 到 {LLM_SEARCH_MAX_ACTIONS} 的整数")
    try:
        from core.source_locator import (
            LLM_SEARCH_DEFAULT_MAX_ACTIONS,
            LLM_SEARCH_DEFAULT_MAX_MODEL_CALLS,
            LLM_SEARCH_MAX_ACTIONS,
            LLMSearchPlanner,
            PlannerBudget,
        )
        from core.source_locator.prompts import SEARCH_PLANNER_SYSTEM
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
            simple_text,
        )

        config_path = _source_locator_config_path(args)
        config_file = load_config_file(Path(config_path))
        llm_config = resolve_llm_config(config_file, getattr(args, "llm_config", None))
        registry = build_phase_registry(config_file, llm_config)
        # app_context is a simple-completion phase and works with providers
        # that do not implement tools; use llm_reach only as a compatibility
        # fallback for older configurations.
        try:
            binding = registry.get("app_context")
        except KeyError:
            binding = registry.get("llm_reach")

        def call(prompt: str):
            # Keep this narrow adapter local to the CLI.  The planner itself
            # remains provider-agnostic and is fully testable with a callable.
            return simple_text(
                binding,
                prompt,
                system=SEARCH_PLANNER_SYSTEM,
                max_tokens=2048,
            )

        if configured_rounds is None:
            max_actions = LLM_SEARCH_DEFAULT_MAX_ACTIONS
        else:
            max_actions = configured_rounds

        # The worker applies the per-session ``max_llm_actions`` cap.  The
        # planner receives the selected round budget and a separate 48-call budget
        # so duplicate proposals, transient failures and the one schema-repair
        # request do not silently truncate the effective action loop.
        return LLMSearchPlanner(
            model_call=call,
            budget=PlannerBudget(
                max_actions=max_actions,
                max_model_calls=LLM_SEARCH_DEFAULT_MAX_MODEL_CALLS,
            ),
        )
    except Exception as exc:  # optional enhancement must never block locator
        print(f"source-locator 语义规划器不可用，继续确定性检索：{_compact_cli_error(exc)}", file=sys.stderr)
        return None


def _source_locator_llm_role_attributor(args):
    """Build the optional evidence-constrained server/client adjudicator.

    It shares the selected provider/configuration with the search planner but
    uses a dedicated system instruction.  The worker calls it at most once per
    locator session and stores only the validated JSON decision.
    """

    if not bool(getattr(args, "llm_search", False)):
        return None
    setdefault_env("VULNFOUNDER_OPENAI_REASONING_EFFORT", "OPENANT_OPENAI_REASONING_EFFORT", "low")
    setdefault_env("VULNFOUNDER_OPENAI_MIN_OUTPUT_TOKENS", "OPENANT_OPENAI_MIN_OUTPUT_TOKENS", "4096")
    setdefault_env("VULNFOUNDER_OPENAI_REQUEST_TIMEOUT_SECONDS", "OPENANT_OPENAI_REQUEST_TIMEOUT_SECONDS", "120")
    setdefault_env("VULNFOUNDER_OPENAI_MAX_RETRIES", "OPENANT_OPENAI_MAX_RETRIES", "0")
    try:
        from core.source_locator import LLMRoleAttributor
        from core.source_locator.llm_role_attributor import ROLE_ATTRIBUTION_SYSTEM
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
            simple_text,
        )

        config_path = _source_locator_config_path(args)
        config_file = load_config_file(Path(config_path))
        llm_config = resolve_llm_config(config_file, getattr(args, "llm_config", None))
        registry = build_phase_registry(config_file, llm_config)
        try:
            binding = registry.get("app_context")
        except KeyError:
            binding = registry.get("llm_reach")

        def call(prompt: str):
            return simple_text(
                binding,
                prompt,
                system=ROLE_ATTRIBUTION_SYSTEM,
                max_tokens=2048,
            )

        return LLMRoleAttributor(model_call=call)
    except Exception as exc:  # optional enhancement must never block locator
        print(f"source-locator LLM 角色复核不可用，继续确定性归因：{_compact_cli_error(exc)}", file=sys.stderr)
        return None


def _source_locator_llm_entrypoint_attributor(args):
    """Build the optional semantic reviewer for concrete socket entrypoints.

    This shares the configured provider with the other source-locator LLM
    steps, while using a dedicated prompt/schema.  It is enabled by the
    existing ``--llm-search`` switch so the Web and CLI paths keep one
    explicit opt-in and deterministic runs make no extra model request.
    """

    if not bool(getattr(args, "llm_search", False)):
        return None
    setdefault_env("VULNFOUNDER_OPENAI_REASONING_EFFORT", "OPENANT_OPENAI_REASONING_EFFORT", "low")
    setdefault_env("VULNFOUNDER_OPENAI_MIN_OUTPUT_TOKENS", "OPENANT_OPENAI_MIN_OUTPUT_TOKENS", "4096")
    setdefault_env("VULNFOUNDER_OPENAI_REQUEST_TIMEOUT_SECONDS", "OPENANT_OPENAI_REQUEST_TIMEOUT_SECONDS", "120")
    setdefault_env("VULNFOUNDER_OPENAI_MAX_RETRIES", "OPENANT_OPENAI_MAX_RETRIES", "0")
    try:
        from core.source_locator import LLMEntrypointAttributor
        from core.source_locator.llm_entrypoint_attributor import ENTRYPOINT_ATTRIBUTION_SYSTEM
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
            simple_text,
        )

        config_path = _source_locator_config_path(args)
        config_file = load_config_file(Path(config_path))
        llm_config = resolve_llm_config(config_file, getattr(args, "llm_config", None))
        registry = build_phase_registry(config_file, llm_config)
        try:
            binding = registry.get("app_context")
        except KeyError:
            binding = registry.get("llm_reach")

        def call(prompt: str):
            return simple_text(
                binding,
                prompt,
                system=ENTRYPOINT_ATTRIBUTION_SYSTEM,
                max_tokens=4096,
            )

        return LLMEntrypointAttributor(model_call=call)
    except Exception as exc:  # optional enhancement must never block locator
        print(f"source-locator LLM 入口函数复核不可用，继续确定性筛选：{_compact_cli_error(exc)}", file=sys.stderr)
        return None


def _source_locator_llm_candidate_reviewer(args):
    """Build the optional final repository-candidate PK model."""

    if not bool(getattr(args, "llm_search", False)):
        return None
    setdefault_env("VULNFOUNDER_OPENAI_REASONING_EFFORT", "OPENANT_OPENAI_REASONING_EFFORT", "low")
    setdefault_env("VULNFOUNDER_OPENAI_MIN_OUTPUT_TOKENS", "OPENANT_OPENAI_MIN_OUTPUT_TOKENS", "4096")
    setdefault_env("VULNFOUNDER_OPENAI_REQUEST_TIMEOUT_SECONDS", "OPENANT_OPENAI_REQUEST_TIMEOUT_SECONDS", "120")
    setdefault_env("VULNFOUNDER_OPENAI_MAX_RETRIES", "OPENANT_OPENAI_MAX_RETRIES", "0")
    try:
        from core.source_locator import LLMCandidateReviewer
        from core.source_locator.candidate_reviewer import CANDIDATE_REVIEW_SYSTEM
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
            simple_text,
        )

        config_path = _source_locator_config_path(args)
        config_file = load_config_file(Path(config_path))
        llm_config = resolve_llm_config(config_file, getattr(args, "llm_config", None))
        registry = build_phase_registry(config_file, llm_config)
        try:
            binding = registry.get("app_context")
        except KeyError:
            binding = registry.get("llm_reach")

        def call(prompt: str):
            return simple_text(
                binding,
                prompt,
                system=CANDIDATE_REVIEW_SYSTEM,
                max_tokens=2048,
            )

        return LLMCandidateReviewer(model_call=call)
    except Exception as exc:  # optional enhancement must never block locator
        print(f"source-locator LLM 候选 PK 不可用，继续确定性归因：{_compact_cli_error(exc)}", file=sys.stderr)
        return None


def _compact_cli_error(value, limit: int = 256) -> str:
    return " ".join(str(value).split())[:limit]


def _parse_locator_updates(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("--updates-json 必须是合法 JSON 对象") from exc
    if not isinstance(payload, dict):
        raise ValueError("--updates-json 必须是 JSON 对象")
    return payload


def cmd_source_locator_create(args):
    from core.schemas import error, success

    try:
        machine = _source_locator_store(args.root).create(
            args.target,
            target_revision=args.target_revision,
            budget=_parse_locator_updates(args.budget_json),
            session_id=args.session_id,
        )
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_status(args):
    from core.schemas import error, success

    try:
        machine = _load_source_locator_machine(args)
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_handoff(args):
    """Return the verified scanner handoff for a completed locator session.

    The command is intentionally read-only and does not accept an arbitrary
    path.  It only returns ``source_handoff.json`` after the persisted session
    is DONE and the artifact is explicitly registered by the state machine.
    """

    from core.schemas import error, success
    from core.source_locator import SourceHandoff

    try:
        machine = _load_source_locator_machine(args)
        session = machine.session
        if session.state != "DONE" or not session.handoff:
            raise ValueError("源码定位 session 尚未完成，不能交接给静态扫描")
        if "source_handoff.json" not in session.artifacts:
            raise ValueError("已完成 session 缺少 source_handoff.json 交接产物")
        handoff_path = machine.store.session_dir(session.session_id) / "source_handoff.json"
        if handoff_path.is_symlink() or not handoff_path.is_file():
            raise ValueError("source_handoff.json 不是安全的普通文件")
        if handoff_path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("source_handoff.json 超过大小上限")
        payload = json.loads(handoff_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("status") != "ready_for_analysis":
            raise ValueError("交接产物不是 ready_for_analysis")
        # Re-validate the persisted object at the process boundary.  The
        # state machine normally writes this file, but a user may inspect or
        # restore a session from disk; returning a merely status-labelled JSON
        # object would bypass SourceHandoff's absolute-path, commit, source
        # path and evidence-ID invariants.
        handoff = SourceHandoff(
            project_name=payload.get("project_name"),
            repository_path=payload.get("repository_path"),
            repo_url=payload.get("repo_url"),
            revision=payload.get("revision"),
            resolved_commit=payload.get("resolved_commit"),
            source_paths=tuple(payload.get("source_paths", ())),
            evidence_ids=tuple(payload.get("evidence_ids", ())),
            status=payload.get("status", ""),
            schema_version=payload.get("schema_version", ""),
        )
        output = {
            "session_id": session.session_id,
            "primary_analysis_repo": handoff.repository_path,
            "handoff": handoff.to_dict(),
            "artifact": "source_handoff.json",
        }
        _output_json(success(output))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_list(args):
    from core.schemas import error, success

    try:
        store = _source_locator_store(args.root)
        sessions = store.list_sessions()
        _output_json(
            success(
                {
                    "root": str(store.root),
                    "sessions": [session.to_dict() for session in sessions],
                }
            )
        )
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_delete(args):
    from core.schemas import error, success

    try:
        store = _source_locator_store(args.root)
        store.delete(args.session_id)
        _output_json(
            success(
                {
                    "session_id": args.session_id,
                    "deleted": True,
                    "note": "仅删除 source-locator session 目录及其产物，不删除 source_code_base 中的源码仓库",
                }
            )
        )
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_events(args):
    from core.schemas import error, success

    try:
        log = _source_locator_store(args.root).events(args.session_id)
        events = log.after(args.after)
        _output_json(success({"session_id": args.session_id, "events": [event.to_dict() for event in events]}))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_message(args):
    from core.schemas import error, success

    try:
        message = str(args.message).strip()
        if not message:
            raise ValueError("--message 不能为空")
        if len(message) > 4096:
            raise ValueError("--message 超过长度上限 4096")
        if any(ord(char) < 0x20 and char not in "\n\t" or ord(char) == 0x7F for char in message):
            raise ValueError("--message 包含控制字符")
        machine = _load_source_locator_machine(args)
        machine.record_event(
            event_type="user.message",
            summary_zh="已收到用户补充说明",
            details={"message": message},
        )
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_transition(args):
    from core.schemas import error, success

    try:
        machine = _load_source_locator_machine(args)
        machine.transition(
            args.next_state,
            summary_zh=args.summary_zh,
            event_type=args.event_type,
            updates=_parse_locator_updates(args.updates_json),
            evidence_ids=args.evidence_id,
        )
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_confirm(args):
    from core.schemas import error, success

    try:
        machine = _load_source_locator_machine(args)
        machine.confirm(confirmation_id=args.confirmation_id)
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_select_version(args):
    """Select one worker-discovered revision and resume the clone stage.

    The candidate artifact is re-read and validated here instead of trusting
    the browser's copy of ``session.version_selection``.  A revision becomes
    a Git argument only after it is present in both the signed-by-checkpoint
    summary and the bounded, allowlisted artifact generated by the worker.
    """

    from core.schemas import error, success
    from core.source_locator import RepositoryVersionCandidate

    try:
        machine = _load_source_locator_machine(args)
        session = machine.session
        if session.state != "VERSION_SELECTION_REQUIRED":
            raise ValueError("当前 session 不在等待版本选择状态")
        if "repository_version_candidates.json" not in session.artifacts:
            raise ValueError("session 缺少 repository_version_candidates.json 候选产物")
        artifact_path = machine.store.session_dir(session.session_id) / "repository_version_candidates.json"
        if artifact_path.is_symlink() or not artifact_path.is_file():
            raise ValueError("版本候选产物不是安全的普通文件")
        if artifact_path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("版本候选产物超过大小上限")
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            raise ValueError("版本候选产物不可用于选择")
        summary = session.version_selection
        if not isinstance(summary, dict):
            raise ValueError("session 缺少版本候选摘要")
        if payload.get("project_name") != summary.get("project_name"):
            raise ValueError("版本候选项目与 session 摘要不一致")
        raw_candidates = payload.get("candidates")
        if not isinstance(raw_candidates, list) or not raw_candidates:
            raise ValueError("版本候选产物没有可选择的候选")
        candidates = []
        for item in raw_candidates[:64]:
            if not isinstance(item, dict):
                raise ValueError("版本候选产物包含无效条目")
            candidates.append(RepositoryVersionCandidate(**item))
        candidate_revisions = tuple(item.revision for item in candidates)
        machine.select_version(
            args.revision,
            candidate_revisions=candidate_revisions,
            confirmation_id=args.confirmation_id,
        )
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_reject(args):
    from core.schemas import error, success

    try:
        machine = _load_source_locator_machine(args)
        machine.reject(
            args.reason,
            excluded_paths=args.exclude_path,
            excluded_repos=args.exclude_repo,
            required_role=args.required_role,
        )
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_apply_feedback(args):
    from core.schemas import error, success

    try:
        machine = _load_source_locator_machine(args)
        machine.resume_after_feedback()
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_cancel(args):
    from core.schemas import error, success

    try:
        machine = _load_source_locator_machine(args)
        machine.cancel(reason=args.reason)
        _output_json(success(_source_locator_payload(machine)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_source_locator_advance(args):
    """Execute at most N deterministic source-locator stages and checkpoint."""

    from core.schemas import error, success
    from core.source_locator import SourceLocatorWorker

    try:
        machine = _load_source_locator_machine(args)
        runtime = _source_locator_runtime(args)
        worker = SourceLocatorWorker(machine, runtime=runtime)
        session = worker.run_until_pause(max_steps=args.max_steps)
        _output_json(success(_source_locator_payload(machine)))
        return 0 if session.state not in {"FAILED", "CLONE_FAILED", "POST_CLONE_VERIFY_FAILED"} else 2
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


# ---------------------------------------------------------------------------
# exposure-surface — standalone OpenHarmony device inspection
# ---------------------------------------------------------------------------

def _exposure_surface_store(args):
    from core.exposure_surface import ExposureSessionStore

    return ExposureSessionStore(args.root)


def _exposure_surface_payload(session: dict) -> dict:
    """Return a stable, display-friendly payload without exposing raw files."""

    session_view = dict(session)
    artifacts = session.get("artifacts", {})
    # The session file internally stores absolute paths for the collector, but
    # they are implementation details and may disclose the host layout. The
    # Web/CLI contract exposes only registered artifact names; the Go endpoint
    # serves the files through its own root/allowlist check.
    session_view["artifacts"] = {
        str(name): str(name)
        for name in artifacts
    } if isinstance(artifacts, dict) else {}
    return {
        "session": session_view,
        "session_id": session_view.get("session_id"),
        "state": session_view.get("state"),
        "summary": session_view.get("summary"),
        "artifacts": session_view.get("artifacts", {}),
    }


def cmd_exposure_surface_create(args):
    from core.schemas import error, success

    try:
        session = _exposure_surface_store(args).create(
            args.target,
            device_serial=args.device_serial,
            llm_assist=args.llm_assist,
            session_id=args.session_id,
            mode=args.mode,
            allow_model_commands=args.allow_model_commands,
            rag_mode=args.rag_mode,
            max_rounds=args.max_rounds,
            max_commands=args.max_commands,
            batch_id=getattr(args, "batch_id", None),
            batch_index=getattr(args, "batch_index", None),
            batch_total=getattr(args, "batch_total", None),
        )
        _output_json(success(_exposure_surface_payload(session)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_status(args):
    from core.schemas import error, success

    try:
        session = _exposure_surface_store(args).load(args.session_id)
        _output_json(success(_exposure_surface_payload(session)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_list(args):
    from core.schemas import error, success

    try:
        store = _exposure_surface_store(args)
        _output_json(success({"root": str(store.root), "sessions": [_exposure_surface_payload(session)["session"] for session in store.list_sessions()]}))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_events(args):
    from core.schemas import error, success

    try:
        events = _exposure_surface_store(args).events(args.session_id, after=args.after)
        _output_json(success({"session_id": args.session_id, "events": events}))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_start(args):
    from core.schemas import error, success
    from core.exposure_surface import run_exposure_session

    try:
        session = run_exposure_session(args.root, args.session_id, hdc_path=args.hdc_path)
        _output_json(success(_exposure_surface_payload(session)))
        return 0 if session.get("state") not in {"FAILED", "OFFLINE", "PERMISSION_DENIED"} else 2
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_start_service(args):
    """在用户明确确认后启动服务，并重新执行暴露面探测。"""

    from core.schemas import error, success
    from core.exposure_surface import start_exposure_service

    try:
        session = start_exposure_service(
            args.root,
            args.session_id,
            option_id=args.option_id,
            hdc_path=args.hdc_path,
        )
        _output_json(success(_exposure_surface_payload(session)))
        return 0 if session.get("state") not in {"FAILED", "OFFLINE", "PERMISSION_DENIED"} else 2
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_skip_start(args):
    """记录用户拒绝启动服务的决定，不向开发板写入参数。"""

    from core.schemas import error, success
    from core.exposure_surface import decline_exposure_service

    try:
        session = decline_exposure_service(args.root, args.session_id, args.reason)
        _output_json(success(_exposure_surface_payload(session)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_cancel(args):
    from core.schemas import error, success

    try:
        store = _exposure_surface_store(args)
        session = store.load(args.session_id)
        if session.get("state") not in {"DONE", "PARTIAL", "OFFLINE", "NOT_FOUND", "PERMISSION_DENIED", "CANCELLED", "FAILED"}:
            session = store.update(
                args.session_id,
                state="CANCELLED",
                summary_zh=args.reason or "已取消暴露面识别",
                cancel_reason=(args.reason or "用户取消"),
            )
        _output_json(success(_exposure_surface_payload(session)))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_exposure_surface_delete(args):
    from core.schemas import error, success

    try:
        _exposure_surface_store(args).delete(args.session_id)
        _output_json(success({"session_id": args.session_id, "deleted": True}))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


# ---------------------------------------------------------------------------
# device-socket-inventory — device-scoped Agentic Socket asset discovery
# ---------------------------------------------------------------------------

def _device_socket_inventory_store(args):
    from core.device_socket_inventory import DeviceSocketAssetStore

    return DeviceSocketAssetStore(args.root)


def cmd_device_socket_inventory_scan(args):
    """让 Agent 动态选择只读 HDC 命令，生成当前设备的 Socket 资产快照。"""

    from core.schemas import error, success
    from core.device_socket_inventory import SocketInventoryConfig, run_socket_asset_discovery
    from core.observability import print_chinese_log

    try:
        from core.exposure_surface import _resolve_exposure_llm_binding

        print_chinese_log("设备 Socket 资产 Agent 开始准备设备身份和模型绑定")
        binding = _resolve_exposure_llm_binding(getattr(args, "llm_config", None))
        config = SocketInventoryConfig(
            max_rounds=args.max_rounds,
            max_commands=args.max_commands,
            max_wall_seconds=args.max_wall_seconds,
            command_timeout_seconds=args.command_timeout_seconds,
            max_output_bytes=args.max_output_bytes,
            rag_mode=args.rag_mode,
        )
        result = run_socket_asset_discovery(
            args.root,
            device_serial=args.device_serial,
            hdc_path=args.hdc_path,
            binding=binding,
            llm_config_name=getattr(args, "llm_config", None),
            config=config,
            guide_path=args.guide_path,
            resume_run_id=getattr(args, "resume_run", None),
            run_id=getattr(args, "run_id", None),
            task_goal=getattr(args, "task_goal", None),
            event_callback=lambda stage, summary, details: print_chinese_log(summary, category=f"设备资产/{stage}"),
        )
        payload = dict(result)
        payload.pop("trace", None)
        payload.pop("commands", None)
        payload["artifacts"] = {str(name): str(name) for name in result.get("artifacts", {})}
        _output_json(success(payload))
        return 0 if result.get("status") in {"complete", "partial"} else 2
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_device_socket_inventory_status(args):
    from core.schemas import error, success

    try:
        payload = _device_socket_inventory_store(args).load(args.device_serial)
        payload = dict(payload)
        payload["artifacts"] = {str(name): str(name) for name in (payload.get("artifacts") or {})}
        _output_json(success(payload))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_device_socket_inventory_list(args):
    from core.schemas import error, success

    try:
        store = _device_socket_inventory_store(args)
        _output_json(success({"root": str(store.root), "devices": store.list_devices()}))
        return 0
    except Exception as exc:
        _output_json(error(str(exc)))
        return 2


def cmd_report_data(args):
    """Prepare pre-computed report data as JSON for the Go HTML renderer.

    Internal subcommand — not user-facing. Called by the Go CLI to get
    all data needed to render the HTML overview report.

    Outputs a JSON blob with stats, chart data, findings, remediation HTML,
    and step reports — everything display-ready.
    """
    import html as html_mod
    from core.schemas import success, error
    from core.observability import print_chinese_log
    from core.step_report import step_context
    from utilities.llm_client import get_global_tracker
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        resolve_llm_config,
        simple_text,
    )

    results_path = args.results
    dataset_path = args.dataset
    language = getattr(args, "language", "en") or "en"
    is_zh_report = language == "zh-CN"

    if not dataset_path:
        _output_json(error("--dataset is required for report-data"))
        return 2

    results_dir = os.path.dirname(os.path.abspath(results_path))

    try:
        with step_context("report-data", results_dir, inputs={
            "results_path": os.path.abspath(results_path),
            "dataset_path": os.path.abspath(dataset_path),
            "language": language,
        }) as ctx:
            # Load data
            experiment = read_json(results_path)
            # fa17 TRUST BOUNDARY: normalize model-supplied `results` to dicts-only
            # once at load. This also fixes the total_units stat below —
            # `len(experiment.get("results", []))` now counts the filtered list
            # (matching len(findings)) instead of the raw, poisoned array.
            normalize_results(experiment)
            dataset = read_json(dataset_path)
            print_chinese_log(
                f"HTML 报告数据准备：读取结果 {results_path} 和数据集 {dataset_path}，"
                f"报告语言={language}；先规范化外部结果，再进行统计和渲染。",
                category="报告决策",
            )

            # --- Load dynamic test results if available ---
            # Dynamic tests use VULN-XXX IDs from pipeline_output.json,
            # but report-data works with route_keys from results_verified.json.
            # Bridge by reconstructing route_key = location.file + ":" + location.function
            # (location.function is the bare name; file+":"+function == route_key, D3b).
            dt_by_route_key = {}
            dt_path = os.path.join(results_dir, "dynamic_test_results.json")
            po_path = os.path.join(results_dir, "pipeline_output.json")
            if os.path.exists(dt_path) and os.path.exists(po_path):
                dt_data = read_json(dt_path)
                # fa17 TRUST BOUNDARY: dynamic_test_results.json is a separate
                # model-supplied schema; normalize its `results` to dicts-only so
                # the `for dr in dt_data.get("results", [])` loop below is safe.
                normalize_results(dt_data)
                po_data = read_json(po_path)
                # fa18 TRUST BOUNDARY: normalize model `findings` from
                # pipeline_output.json to dicts-only at load (presence-guarded)
                # so the `finding.get("id")` mapping loop below is safe.
                if "findings" in po_data:
                    normalize_results(po_data, "findings")

                # Map VULN-ID → route_key from pipeline_output
                vuln_id_to_route = {}
                for finding in po_data.get("findings", []):
                    fid = finding.get("id")
                    loc = finding.get("location", {})
                    route = (
                        f"{loc.get('file', '')}:{loc.get('function', '')}"
                        if loc.get("file") else loc.get("function", "")
                    )
                    if fid and route:
                        vuln_id_to_route[fid] = route

                # Map route_key → dynamic test result
                for dr in dt_data.get("results", []):
                    fid = dr.get("finding_id")
                    route = vuln_id_to_route.get(fid)
                    if route:
                        dt_by_route_key[route] = dr

                print(f"[Report] Loaded {len(dt_by_route_key)} dynamic test results", file=sys.stderr)
                print_chinese_log(
                    f"报告数据准备：已将 {len(dt_by_route_key)} 条动态验证结果按文件和函数关联到静态问题。",
                    category="报告决策",
                )

            # --- Prepare findings ---
            units_by_id = {u["id"]: u for u in dataset.get("units", [])}

            verdict_order = list(FINDING_VERDICT_ORDER)
            verdict_colors = {
                "vulnerable": "#dc3545",
                "bypassable": "#fd7e14",
                "inconclusive": "#6c757d",
                "protected": "#28a745",
                "safe": "#20c997",
            }
            verdict_priority = {v: i for i, v in enumerate(verdict_order)}
            dt_status_order = ["CONFIRMED", "INCONCLUSIVE", "ERROR", "", "BLOCKED", "NOT_REPRODUCED"]
            dt_status_priority = {s: i for i, s in enumerate(dt_status_order)}

            verdict_counts = {}
            file_verdicts = {}
            findings = []

            # FAM-ROBUST (fa16): `results` is model-supplied; a non-Anthropic
            # model can emit a bare string/number where a result dict is
            # expected. Drop non-dict elements at loop entry so every `.get()`
            # below is safe (mirrors the fa15 guard in core/reporter.py).
            for result in [r for r in experiment.get("results", []) if isinstance(r, dict)]:
                route_key = result.get("route_key", "")
                # Fall back to the raw ``verdict`` field when ``finding`` is
                # absent, else finding-less vulnerable results are dropped from
                # the count. Mirrors the canonical read in reporter.py.
                verdict = str(result.get("finding") or result.get("verdict", "")).lower()
                file_path = route_key.rsplit(":", 1)[0] if ":" in route_key else route_key
                unit = units_by_id.get(route_key, {})
                llm_context = unit.get("llm_context") or {}
                verification = result.get("verification") or {}

                # Justification: prefer stage2, fallback to stage1
                justification = verification.get("explanation", "")
                if not justification:
                    justification = result.get("reasoning", "")
                justification = justification[:300]

                # Downgrade unverified findings to inconclusive
                if justification.strip() == "Max iterations reached":
                    verdict = "inconclusive"

                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

                # Track worst verdict per file
                if file_path not in file_verdicts:
                    file_verdicts[file_path] = verdict
                elif verdict_priority.get(verdict, 3) < verdict_priority.get(file_verdicts[file_path], 3):
                    file_verdicts[file_path] = verdict

                func_name = route_key.split(":")[-1] if ":" in route_key else route_key

                # Dynamic test result for this finding
                dt_result = dt_by_route_key.get(route_key)
                dt_status = ""
                dt_details = ""
                if dt_result:
                    dt_status = dt_result.get("status", "")
                    dt_details = dt_result.get("details", "")

                findings.append({
                    "verdict": verdict,
                    "verdict_color": verdict_colors.get(verdict, "#6c757d"),
                    "file": file_path,
                    "function": func_name,
                    "attack_vector": result.get("attack_vector", "") or "",
                    "analysis": justification,
                    "dynamic_test_status": dt_status,
                    "dynamic_test_details": dt_details,
                    "number": 0,  # assigned after sort
                })

            # Sort by verdict priority, then by dynamic test status within each group
            findings.sort(key=lambda f: (
                verdict_priority.get(f["verdict"], 3),
                dt_status_priority.get(f["dynamic_test_status"], 3),
            ))
            for i, f in enumerate(findings, 1):
                f["number"] = i

            print_chinese_log(
                f"报告统计：按 verdict 整理 {len(findings)} 个结果，覆盖 {len(file_verdicts)} 个文件；"
                "同一文件取最严重 verdict 展示，问题详情仍保留完整分析文本。",
                category="报告决策",
            )

            # --- Group findings by verdict, sub-grouped by dynamic test outcome ---
            dt_subgroup_defs = [
                ("Confirmed", lambda s: s == "CONFIRMED"),
                ("Not reproduced", lambda s: s in ("NOT_REPRODUCED", "BLOCKED")),
                ("Test error", lambda s: s == "ERROR"),
                ("Not tested", lambda s: s in ("", "INCONCLUSIVE")),
            ]

            findings_by_verdict = []
            for v in verdict_order:
                group = [f for f in findings if f["verdict"] == v]
                if not group:
                    continue

                subgroups = []
                for label, predicate in dt_subgroup_defs:
                    sg_findings = [f for f in group if predicate(f.get("dynamic_test_status", ""))]
                    if sg_findings:
                        subgroups.append({"label": label, "findings": sg_findings})

                findings_by_verdict.append({
                    "verdict": v,
                    "verdict_color": verdict_colors[v],
                    "count": len(group),
                    "open_by_default": v in ("vulnerable", "bypassable"),
                    "findings": group,
                    "subgroups": subgroups,
                    "has_subgroups": len(subgroups) > 1,
                })

            # --- Chart data ---
            unit_chart = {
                "labels": [v for v in verdict_order if v in verdict_counts],
                "data": [verdict_counts.get(v, 0) for v in verdict_order if v in verdict_counts],
                "colors": [verdict_colors[v] for v in verdict_order if v in verdict_counts],
            }

            file_verdict_counts = {}
            for v in file_verdicts.values():
                file_verdict_counts[v] = file_verdict_counts.get(v, 0) + 1

            file_chart = {
                "labels": [v for v in verdict_order if v in file_verdict_counts],
                "data": [file_verdict_counts.get(v, 0) for v in verdict_order if v in file_verdict_counts],
                "colors": [verdict_colors[v] for v in verdict_order if v in file_verdict_counts],
            }

            # --- Stats ---
            total_units = len(experiment.get("results", []))
            total_files = len(file_verdicts)

            stats = {
                "total_units": total_units,
                "total_files": total_files,
                "vulnerable": verdict_counts.get("vulnerable", 0),
                "bypassable": verdict_counts.get("bypassable", 0),
                "secure": verdict_counts.get("protected", 0) + verdict_counts.get("safe", 0),
            }

            # --- Remediation guidance (LLM call) ---
            actionable = [f for f in findings if f["verdict"] in ("vulnerable", "bypassable", "inconclusive")]

            if not actionable:
                remediation_html = (
                    "<p>未发现漏洞或安全隐患。所有代码单元均为安全状态或已受到有效保护。</p>"
                    if is_zh_report else
                    "<p>No vulnerabilities or security concerns found. All code units are either safe or properly protected.</p>"
                )
            else:
                print_chinese_log(
                    f"报告决策：发现 {len(actionable)} 个漏洞/可绕过/待定条目，"
                    "调用报告模型生成修复建议；安全条目不会进入修复提示。",
                    category="报告决策",
                )
                # attack_vector and analysis are untrusted Stage-1/2 LLM output.
                # Interpolated raw they could inject prompt instructions (or a
                # fake `### Finding` header) into the remediation prompt. Fence
                # each with a length-adaptive run so it stays inert data. (The
                # remediation_html sink is also an XSS vector — HTML-escaping at
                # the sink is a separate, deferred hardening; this closes the
                # prompt-injection half.)
                from prompts._fence import safe_code_fence, collapse_inline
                findings_text = ""
                for f in actionable:
                    _av = f['attack_vector'] or 'Not specified'
                    _an = f['analysis'][:500]
                    _avf = safe_code_fence(_av)
                    _anf = safe_code_fence(_an)
                    # file/function derive from the (poisonable) route_key; collapse
                    # newlines so they can't forge a `### Finding` header line.
                    _file = collapse_inline(f['file'])
                    _func = collapse_inline(f['function'])
                    findings_text += f"""
### Finding #{f['number']}: {_file}:{_func}
- **Verdict**: {f['verdict']}
- **Attack Vector**:
{_avf}
{_av}
{_avf}
- **Analysis**:
{_anf}
{_an}
{_anf}
"""
                prompt = (f"""请分析下面的安全问题，并使用简体中文输出：

1. **安全状况概览**：用 2 到 3 句话概括整体安全状况。

2. **按优先级排列的修复事项**：按高优先级、中优先级、低优先级分组。
   每项说明：
   - 要修复的内容
   - 修复原因
   - 具体修复方法
   引用问题时必须使用原始编号和 # 前缀（例如 #4、#12、#13、#14）。
   不要编造“72 小时内修复”等具体期限，只使用上述优先级。

3. **快速改进项**：列出可以立即提升安全性的简单修复。

请将结果格式化为 HTML（使用 <h3>、<p>、<ul>、<li>、<strong> 标签），不要包含 ```html 标记。

## 待分析的问题：
{findings_text}
""" if is_zh_report else f"""Analyze these security findings and provide:

1. **Executive Summary**: A brief overview of the security posture (2-3 sentences)

2. **Prioritized Action Items**: Group remediation steps by priority: Critical Priority, High Priority, Medium Priority.
   For each item:
   - What to fix
   - Why it's important
   - How to fix it (concrete steps)
   When referencing findings, use their exact numbers with # prefix (e.g. #4, #12, #13, #14).
   Do NOT invent specific timeframes like "fix within 72 hours" — use only the priority labels above.

3. **Quick Wins**: Any simple fixes that would immediately improve security

Format your response as HTML (use <h3>, <p>, <ul>, <li>, <strong> tags). Do not include ```html markers.

## Findings to Analyze:
{findings_text}
""")
                print("[Report] Generating remediation guidance (LLM)...", file=sys.stderr)
                # The remediation-guidance call rides the report phase
                # so a single ``--llm-config`` flips it together with
                # the summary/disclosure generation in report/generator.py.
                cf = load_config_file()
                registry = build_phase_registry(
                    cf, resolve_llm_config(cf, getattr(args, "llm_config", None))
                )
                tracker = get_global_tracker()
                remediation_html = simple_text(
                    registry.get("report"),
                    prompt,
                    max_tokens=4096,
                    tracker=tracker,
                )

                # Post-process: linkify finding references like #4, #12-#14
                import re
                def _linkify_finding(m):
                    num = m.group(1)
                    return f'<a href="#finding-{num}" class="finding-ref">#{num}</a>'
                remediation_html = re.sub(r'#(\d+)', _linkify_finding, remediation_html)

            # --- Step reports ---
            step_reports_data = []
            for sr in _load_step_reports(results_dir):
                duration = sr.get("duration_seconds", 0)
                stage_costs = sr.get("costs_by_currency") or {}
                if not stage_costs and sr.get("cost_usd", 0):
                    stage_costs = {"USD": sr.get("cost_usd", 0)}
                if duration >= 60:
                    dur_str = f"{duration / 60:.1f}m"
                else:
                    dur_str = f"{duration:.1f}s"
                symbols = {"USD": "$", "CNY": "¥"}
                cost_str = " / ".join(
                    f"{symbols.get(currency, currency + ' ')}{float(amount):.2f}"
                    for currency, amount in sorted(stage_costs.items())
                    if float(amount or 0) > 0
                ) or "-"

                step_reports_data.append({
                    "step": sr.get("step", "unknown"),
                    "duration": dur_str,
                    "cost": cost_str,
                    "status": sr.get("status", "unknown"),
                    "timestamp": sr.get("timestamp", ""),
                })

            # Sort by timestamp
            step_reports_data.sort(key=lambda s: s.get("timestamp", ""))

            # --- Category descriptions (static) ---
            categories = (
                [
                    {"verdict": "vulnerable", "color": "#dc3545", "description": "代码包含可被利用且没有有效防护的安全漏洞，需要立即修复。"},
                    {"verdict": "bypassable", "color": "#fd7e14", "description": "代码存在安全控制，但在特定条件下可以被绕过，需要复核并加强防护。"},
                    {"verdict": "inconclusive", "color": "#6c757d", "description": "无法确定代码的安全状态，建议人工复核风险。"},
                    {"verdict": "protected", "color": "#28a745", "description": "代码处理潜在危险操作，但已有有效的安全控制。"},
                    {"verdict": "safe", "color": "#20c997", "description": "代码不涉及安全敏感操作，或不存在已识别的安全风险。"},
                ] if is_zh_report else [
                    {"verdict": "vulnerable", "color": "#dc3545", "description": "Code contains an exploitable security vulnerability with no effective protection. Immediate remediation required."},
                    {"verdict": "bypassable", "color": "#fd7e14", "description": "Security controls exist but can be circumvented under certain conditions. Review and strengthen protections."},
                    {"verdict": "inconclusive", "color": "#6c757d", "description": "Security posture could not be determined. Manual review recommended to assess risk."},
                    {"verdict": "protected", "color": "#28a745", "description": "Code handles potentially dangerous operations but has effective security controls in place."},
                    {"verdict": "safe", "color": "#20c997", "description": "Code does not involve security-sensitive operations or poses no security risk."},
                ]
            )

            from datetime import datetime

            # --- Repo info from pipeline_output.json ---
            repo_name = ""
            commit_sha = ""
            language = ""
            repo_url = ""
            diff_block = None
            if os.path.exists(po_path):
                try:
                    po = read_json(po_path)
                    repo_info = po.get("repository", {})
                    repo_name = repo_info.get("name", "")
                    commit_sha = repo_info.get("commit_sha", "")
                    language = repo_info.get("language", "")
                    repo_url = repo_info.get("url", "")
                    # Pass through the diff block when this scan ran in
                    # incremental mode; the Go renderer surfaces base..head
                    # in the report header.
                    raw_diff = po.get("diff")
                    if isinstance(raw_diff, dict) and raw_diff.get("mode") == "incremental":
                        diff_block = {
                            "mode": raw_diff.get("mode"),
                            "base_sha": raw_diff.get("base_sha", ""),
                            "head_sha": raw_diff.get("head_sha", ""),
                            "scope": raw_diff.get("scope", ""),
                            "units_in_diff": raw_diff.get("units_in_diff", 0) or 0,
                            "units_total_parsed": raw_diff.get("units_total_parsed", 0) or 0,
                            "changed_files": raw_diff.get("changed_files", 0) or 0,
                            "pr_number": raw_diff.get("pr_number") or 0,
                        }
                except (json.JSONDecodeError, OSError):
                    pass

            # --- Totals from step reports ---
            total_duration_seconds = 0.0
            total_costs: dict[str, float] = {}
            for sr in _load_step_reports(results_dir):
                total_duration_seconds += sr.get("duration_seconds", 0)
                stage_costs = sr.get("costs_by_currency") or {}
                if not stage_costs and sr.get("cost_usd", 0):
                    stage_costs = {"USD": sr.get("cost_usd", 0)}
                for currency, amount in stage_costs.items():
                    total_costs[currency] = total_costs.get(currency, 0.0) + float(amount or 0)

            report_data = {
                "title": "安全分析报告" if is_zh_report else "Security Analysis Report",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "repo_name": repo_name,
                "commit_sha": commit_sha,
                "language": language,
                "repo_url": repo_url,
                "total_duration_seconds": total_duration_seconds,
                # Legacy consumers keep total_cost_usd; the additive map is
                # authoritative when a scan uses CNY or multiple currencies.
                "total_cost_usd": total_costs.get("USD", 0.0),
                "total_cost_cny": total_costs.get("CNY", 0.0),
                "costs_by_currency": total_costs,
                "stats": stats,
                "unit_chart": unit_chart,
                "file_chart": file_chart,
                "remediation_html": remediation_html,
                "findings": findings,
                "findings_by_verdict": findings_by_verdict,
                "step_reports": step_reports_data,
                "categories": categories,
                "diff": diff_block,
            }

            ctx.summary = {"findings": len(findings), "actionable": len(actionable)}
            print_chinese_log(
                f"HTML 报告数据准备完成：可渲染问题={len(findings)}，可行动问题={len(actionable)}，"
                "报告数据将通过标准 JSON envelope 返回给 Web 渲染器。",
                category="报告结果",
            )

        _output_json(success(report_data))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2



def resolve_language_selection(args, counts: dict[str, int]):
    """Turn parsed CLI flags into a :class:`LanguageSelection`.

    Kept as a standalone function so the flag semantics are testable without
    running a scan, and so `scan` and `parse` cannot drift apart.

    `-l auto` (the default) means every detected language above the size
    threshold — not the dominant one (see ``_select_languages_for``). ``-l <lang>``
    narrows to a single language, ``--languages`` to a named subset, and
    ``--all-languages`` scans everything detected regardless of the threshold.

    Raises:
        ValueError: If an explicit `-l <lang>` is combined with a multi-language
            flag — one names a single language, the other names a set, and
            silently preferring either would surprise someone.
    """
    explicit = getattr(args, "language", "auto") not in (None, "auto")
    # `multi_language` was missing here while `_select_languages_for` did treat it
    # as a trigger, so `-l go --multi-language` silently dropped the multi flag and
    # then blamed the exclusion on `--languages`, which the user never passed.
    multi = (getattr(args, "languages", None)
             or getattr(args, "all_languages", False)
             or getattr(args, "multi_language", False))

    if explicit and multi:
        raise ValueError(
            "-l/--language is mutually exclusive with --languages/--all-languages/"
            f"--multi-language: got -l {args.language} alongside a multi-language "
            "flag. Use one or the other."
        )

    if explicit:
        include = [args.language]
    elif getattr(args, "languages", None):
        include = [p.strip() for p in args.languages.split(",") if p.strip()]
    else:
        include = None

    selection = select_languages(
        counts,
        include=include,
        all_languages=getattr(args, "all_languages", False),
        min_files=getattr(args, "min_language_files", DEFAULT_MIN_FILES),
        min_share=getattr(args, "min_language_share", DEFAULT_MIN_SHARE),
    )
    # Report here rather than at each call site: this is the single point every
    # command funnels through, so a coverage gap cannot escape by way of a
    # caller that forgot to print it.
    report_exclusions(selection.excluded)
    return selection



def cmd_threat_model(args):
    """Generate or validate a repository's VULNFOUNDER.THREATMODEL.md."""
    from pathlib import Path

    from context.threat_model import (
        THREAT_MODEL_FILENAME,
        ThreatModelValidationError,
        existing_threat_model_path,
        load_threat_model,
    )
    from core.schemas import error, success

    repo = Path(args.repo)

    if args.validate_only:
        # CI-friendly: parse and validate a committed model, spend nothing.
        target = existing_threat_model_path(repo)
        if target is None:
            _output_json(error(f"{THREAT_MODEL_FILENAME} not found in {repo}"))
            return 2
        try:
            context = load_threat_model(repo)
        except ThreatModelValidationError as exc:
            _output_json(error(str(exc)))
            return 2
        _output_json(success({
            "path": str(target),
            "application_type": context.application_type,
            "attacker_profiles": len(context.attacker_profiles or []),
            "valid": True,
        }))
        return 0

    from context.threat_model_agent import (
        ThreatModelGenerationError,
        generate_threat_model,
    )
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )

    try:
        config = load_config_file()
        registry = build_phase_registry(
            config, resolve_llm_config(config, args.llm_config))
        probe_registry_or_raise(registry)
        # Reuses the app_context phase — adding a phase would break every
        # existing user config (see context/threat_model_agent.py).
        path = generate_threat_model(
            repo,
            registry.get("app_context"),
            force=args.force,
            output_path=Path(args.output_md) if args.output_md else None,
        )
    except ThreatModelGenerationError as exc:
        _output_json(error(str(exc)))
        return 2
    except Exception as exc:  # noqa: BLE001 - surface any provider error cleanly
        _output_json(error(str(exc)))
        return 2

    _output_json(success({"path": str(path)}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI parser.

    Split out of ``main()`` so tests can introspect the parser — in
    particular to assert that ``--language`` choices stay in lock-step with
    ``config/languages.json`` rather than drifting as hardcoded literals.
    """
    parser = argparse.ArgumentParser(
        prog="vulnfounder",
        description="Two-stage SAST tool using Claude for vulnerability analysis",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------------------------------------------------------------
    # scan — all-in-one
    # ---------------------------------------------------------------
    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a repository (full pipeline: parse + enhance + detect + verify + report)",
    )
    scan_p.add_argument("repo", help="Path to repository")
    scan_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    scan_p.add_argument(
        "--language", "-l",
        choices=["auto", *supported_languages()],
        default="auto",
        help="Language (default: auto-detect)",
    )
    scan_p.add_argument(
        "--platform",
        choices=["auto", "generic", "openharmony"],
        default="auto",
        help="Platform mode (default: auto; openharmony enables supported parser scope metadata)",
    )
    scan_p.add_argument(
        "--languages",
        default=None,
        help=(
            "Comma-separated languages to parse, e.g. 'python,go'. Bypasses the "
            "detection thresholds. Mutually exclusive with an explicit -l <lang>."
        ),
    )
    scan_p.add_argument(
        "--all-languages",
        action="store_true",
        help="Parse every detected language, ignoring the size thresholds.",
    )
    scan_p.add_argument(
        "--multi-language",
        action="store_true",
        help=(
            "Scan every detected language that clears the size thresholds. "
            "Excluded languages are reported as an explicit coverage gap."
        ),
    )
    scan_p.add_argument(
        "--min-language-files",
        type=int,
        default=DEFAULT_MIN_FILES,
        help=f"Minimum source files for a language to be scanned (default: {DEFAULT_MIN_FILES}).",
    )
    scan_p.add_argument(
        "--min-language-share",
        type=float,
        default=DEFAULT_MIN_SHARE,
        help=f"Minimum share of source files for a language (default: {DEFAULT_MIN_SHARE}).",
    )
    scan_p.add_argument(
        "--strict-languages",
        action="store_true",
        help="Abort the run if any selected language fails to parse (default: continue degraded).",
    )
    scan_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    scan_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    scan_p.add_argument("--no-context", action="store_true", help="Skip application context generation")
    scan_p.add_argument("--no-enhance", action="store_true", help="Skip context enhancement step")
    scan_p.add_argument(
        "--enhance-mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    scan_p.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_p.add_argument("--dynamic-test", action="store_true",
                        help="Enable the selected dynamic testing mode (off by default)")
    scan_p.add_argument(
        "--dynamic-test-mode",
        choices=["docker", "claude-code", "openharmony-device"],
        default="docker",
        help="Dynamic-test mode when --dynamic-test is enabled: docker, claude-code, or openharmony-device",
    )
    scan_p.add_argument("--dynamic-device", default=None, help="Explicit HDC serial for openharmony-device")
    scan_p.add_argument("--dynamic-hdc", default=None, help="HDC executable path for openharmony-device")
    scan_p.add_argument("--dynamic-device-max-rounds", type=int, default=16, help="OpenHarmony Agentic Loop maximum rounds")
    scan_p.add_argument("--dynamic-device-max-commands", type=int, default=512, help="OpenHarmony maximum device commands")
    scan_p.add_argument("--dynamic-device-timeout", type=int, default=30, help="OpenHarmony per-command timeout")
    scan_p.add_argument("--dynamic-device-wall-timeout", type=int, default=1200, help="OpenHarmony total device timeout")
    scan_p.add_argument("--dynamic-device-allow-state-change", action="store_true", help="Allow state-changing OpenHarmony device commands")
    scan_p.add_argument("--dynamic-device-canary-path", default="/data/local/tmp/vulnfounder-canary", help="Safe OpenHarmony canary root")
    scan_p.add_argument("--dynamic-device-carrier-root", default=None, help="Reviewed HAP carrier root")
    scan_p.add_argument("--dynamic-device-carrier-id", default=None, help="Only execute reviewed carrier for this finding ID")
    scan_p.add_argument("--dynamic-device-carrier-bundle", default="com.security.research.trigger", help="Reviewed HAP carrier bundle")
    scan_p.add_argument("--dynamic-device-carrier-ability", default="EntryAbility", help="Reviewed HAP carrier Ability")
    scan_p.add_argument("--dynamic-device-execute-carrier", action="store_true", help="Explicitly execute reviewed HAP carriers")
    scan_p.add_argument(
        "--dynamic-device-service-observation-delay",
        type=float,
        default=0.8,
        help="载体发送后延迟日志采样的等待秒数（0-5，默认 0.8）",
    )
    scan_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    scan_p.add_argument("--library-mode", action="store_true",
                        help="Seed the exported public API as entry points (for libraries with no main/route/CLI entry point)")
    scan_p.add_argument("--limit", type=int, help="Max units to analyze")
    scan_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists). See "
            "docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md."
        ),
    )
    scan_p.add_argument("--workers", type=int, default=8,
                        help="Number of parallel workers for LLM steps (default: 8)")
    scan_p.add_argument("--repo-name", help="Repository name (org/repo)")
    scan_p.add_argument("--repo-url", help="Repository URL")
    scan_p.add_argument("--commit-sha", help="Commit SHA")
    scan_p.add_argument("--backoff", type=int, default=30,
                        help="Seconds to wait when rate-limited (default: 30)")
    scan_p.add_argument("--diff-manifest", help="Path to diff_manifest.json for incremental scanning")
    scan_p.add_argument(
        "--llm-reachability",
        action="store_true",
        dest="llm_reachability",
        help="Enable the LLM reachability review stage (Opus). "
             "Surfaces entry points and external-input sites the structural "
             "pass would miss by reviewing the full codebase before the "
             "reachability filter is applied. Off by default — enabling "
             "this incurs cost proportional to total repo size, not the "
             "filtered unit count (~one Opus call per 25 units across the "
             "whole codebase).",
    )
    scan_p.add_argument(
        "--llm-reachability-max-code-bytes",
        type=int,
        default=1500,
        dest="llm_reachability_max_code_bytes",
        help="Max code bytes per unit sent to the LLM reachability stage "
             "(default: 1500). Higher values (e.g. 4096, 8192) catch "
             "entry-point indicators past byte 1500 in long handlers / "
             "generated code, at proportional Opus cost increase. Only "
             "meaningful with --llm-reachability.",
    )
    scan_p.add_argument(
        "--stop-after",
        choices=["effective-call-graph", "llm-reachability", "openharmony-gap-tasks"],
        default=None,
        help=(
            "Stop cleanly after the selected stage. Currently only "
            "'effective-call-graph', 'llm-reachability' and "
            "'openharmony-gap-tasks' are supported. The latter two stop before "
            "the downstream enhancement/Stage 1 analysis unless the selected "
            "stage has already completed."
        ),
    )
    scan_p.add_argument(
        "--llm-call-graph-recovery",
        action="store_true",
        dest="llm_call_graph_recovery",
        help=(
            "Enable the advisory OpenHarmony indirect-call review stage. "
            "It consumes call_graph_residuals.json and writes "
            "llm_call_graph_recovery.json without modifying the call graph. "
            "Only active for OpenHarmony scans; off by default."
        ),
    )
    scan_p.add_argument(
        "--llm-call-graph-iterative-recovery",
        action="store_true",
        dest="llm_call_graph_iterative_recovery",
        help=(
            "Enable the entry-driven, bounded multi-round OpenHarmony "
            "indirect-call recovery. It writes "
            "llm_call_graph_recovery_rounds.json and keeps the native call "
            "graph unchanged. This option is explicit and does not replace "
            "the legacy one-shot recovery path."
        ),
    )
    scan_p.add_argument(
        "--llm-call-graph-candidate-review",
        action="store_true",
        dest="llm_call_graph_candidate_review",
        help=(
            "Enable a separate advisory OpenHarmony review for residual "
            "sites that already have deterministic candidate handlers. "
            "It writes llm_call_graph_candidate_review.json without "
            "modifying the call graph. Off by default."
        ),
    )
    scan_p.add_argument(
        "--llm-call-graph-projection",
        action="store_true",
        dest="llm_call_graph_projection",
        help=(
            "Project validated high-confidence OpenHarmony recovery decisions "
            "into llm_call_graph_overlay.json. The overlay is independent and "
            "does not modify call_graph.json, dataset.json, or reachability. "
            "It consumes existing recovery/candidate-review artifacts and is "
            "off by default."
        ),
    )
    scan_p.add_argument(
        "--openharmony-dispatch-code-evidence",
        action="store_true",
        dest="openharmony_dispatch_code_evidence",
        help=(
            "Extract integer values for OpenHarmony dispatch selectors from "
            "enum/macro/constexpr source definitions. Writes an independent "
            "openharmony_dispatch_code_evidence.json artifact without "
            "modifying the call graph. Off by default."
        ),
    )
    scan_p.add_argument(
        "--clang-semantic",
        action="store_true",
        dest="clang_semantic",
        help=(
            "Run the bounded Clang AST fact extractor. The scanner first "
            "reuses compile_commands.json or ninja -t compdb, then may "
            "reconstruct candidate commands from BUILD.gn; validated facts "
            "refresh the effective call graph and provenance is recorded."
        ),
    )
    scan_p.add_argument(
        "--clang-compile-commands",
        default=None,
        dest="clang_compile_commands",
        help="Optional path to compile_commands.json for --clang-semantic.",
    )
    scan_p.add_argument(
        "--clang-build-status",
        choices=[
            "compile_database",
            "complete",
            "manual_rebuild",
            "reconstructed_candidate",
            "unknown",
        ],
        default="compile_database",
        dest="clang_build_status",
        help=(
            "Build-context provenance for Clang facts. compile_database/complete "
            "can enter the concrete analysis graph; manual_rebuild, "
            "reconstructed_candidate, and unknown stay candidate facts."
        ),
    )
    scan_p.add_argument(
        "--clang-max-files",
        type=int,
        default=128,
        dest="clang_max_files",
        help="Maximum translation units processed by --clang-semantic (default: 128).",
    )
    scan_p.add_argument(
        "--clang-timeout-seconds",
        type=int,
        default=30,
        dest="clang_timeout_seconds",
        help="Per-translation-unit Clang timeout (default: 30).",
    )
    scan_p.add_argument(
        "--clang-batch-size",
        type=int,
        default=16,
        dest="clang_batch_size",
        help=(
            "Number of translation units per resumable Clang batch; progress "
            "is checkpointed after each unit (default: 16)."
        ),
    )
    scan_p.add_argument(
        "--clang-force-recompute",
        action="store_true",
        dest="clang_force_recompute",
        help="Ignore an existing clang_batch_checkpoint.json and rerun selected units.",
    )
    scan_p.add_argument(
        "--clang-dependency-retries",
        type=int,
        default=1,
        dest="clang_dependency_retry_attempts",
        help=(
            "Bounded retries for missing-header failures using locally found "
            "candidate dependency include roots (default: 1)."
        ),
    )
    scan_p.add_argument(
        "--clang-dependency-retry-low-trust",
        action="store_true",
        dest="clang_dependency_retry_low_trust",
        help=(
            "Allow candidate include roots under test/mock directories; "
            "facts remain candidate-only."
        ),
    )
    scan_p.add_argument(
        "--clang-definition-load-max-files",
        type=int,
        default=16,
        dest="clang_definition_load_max_files",
        help=(
            "Maximum extra translation units loaded for unique declaration-to-"
            "definition candidates (default: 16; 0 disables)."
        ),
    )
    scan_p.add_argument(
        "--clang-no-auto-context",
        action="store_false",
        dest="clang_auto_context",
        help=(
            "Disable automatic context discovery and BUILD.gn candidate "
            "reconstruction; use only --clang-compile-commands."
        ),
    )
    scan_p.add_argument(
        "--scope-manifest",
        default=None,
        help=(
            "Use a user-confirmed socket scan_scope.json. The selected scan_root "
            "must be inside the repository; without this option the full repository "
            "is preserved as the baseline."
        ),
    )
    scan_p.set_defaults(func=cmd_scan)

    # ---------------------------------------------------------------
    # parse — repository parsing only
    # ---------------------------------------------------------------
    parse_p = subparsers.add_parser("parse", help="Parse a repository into a dataset")
    parse_p.add_argument("repo", help="Path to repository")
    parse_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    parse_p.add_argument(
        "--language", "-l",
        choices=["auto", *supported_languages()],
        default="auto",
        help="Language (default: auto-detect)",
    )
    parse_p.add_argument(
        "--platform",
        choices=["auto", "generic", "openharmony"],
        default="auto",
        help="Platform mode (default: auto; openharmony enables supported parser scope metadata)",
    )
    parse_p.add_argument(
        "--languages",
        default=None,
        help=(
            "Comma-separated languages to parse, e.g. 'python,go'. Bypasses the "
            "detection thresholds. Mutually exclusive with an explicit -l <lang>."
        ),
    )
    parse_p.add_argument(
        "--all-languages",
        action="store_true",
        help="Parse every detected language, ignoring the size thresholds.",
    )
    parse_p.add_argument(
        "--multi-language",
        action="store_true",
        help=(
            "Scan every detected language that clears the size thresholds. "
            "Excluded languages are reported as an explicit coverage gap."
        ),
    )
    parse_p.add_argument(
        "--min-language-files",
        type=int,
        default=DEFAULT_MIN_FILES,
        help=f"Minimum source files for a language to be scanned (default: {DEFAULT_MIN_FILES}).",
    )
    parse_p.add_argument(
        "--min-language-share",
        type=float,
        default=DEFAULT_MIN_SHARE,
        help=f"Minimum share of source files for a language (default: {DEFAULT_MIN_SHARE}).",
    )
    parse_p.add_argument(
        "--strict-languages",
        action="store_true",
        help="Abort the run if any selected language fails to parse (default: continue degraded).",
    )
    parse_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    parse_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    parse_p.add_argument("--library-mode", action="store_true",
                         help="Seed the exported public API as entry points (for libraries with no main/route/CLI entry point)")
    parse_p.add_argument("--name", help="Dataset name (default: derived from repo path)")
    parse_p.add_argument("--diff-manifest", help="Path to diff_manifest.json; tags units with diff_selected")
    parse_p.add_argument("--fresh", action="store_true",
                         help="Delete existing dataset.json and reparse from scratch (default: reuse existing units; other artifacts preserved)")
    parse_p.set_defaults(func=cmd_parse)

    # ---------------------------------------------------------------
    # generate-context — generate application security context
    # ---------------------------------------------------------------
    gc_p = subparsers.add_parser(
        "generate-context",
        help="Generate application security context for a repository",
    )
    gc_p.add_argument("repo", help="Path to repository")
    gc_p.add_argument("--output", "-o",
                       help="Output path (default: ./application_context.json in the "
                            "current directory — never written into the scanned repo)")
    gc_p.add_argument("--force", action="store_true",
                       help="Force regeneration, ignoring VULNFOUNDER.md override files")
    gc_p.add_argument("--show-prompt", action="store_true",
                       help="Include formatted prompt text in output")
    gc_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm."
        ),
    )
    gc_p.set_defaults(func=cmd_generate_context)

    # ---------------------------------------------------------------
    # enhance — add security context to a dataset
    # ---------------------------------------------------------------
    enhance_p = subparsers.add_parser("enhance", help="Enhance a dataset with security context")
    enhance_p.add_argument("dataset", help="Path to dataset JSON from parse step")
    enhance_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (required for agentic mode)")
    enhance_p.add_argument("--repo-path", help="Path to the repository (required for agentic mode)")
    enhance_p.add_argument("--output", "-o", help="Output path for enhanced dataset (default: {input}_enhanced.json)")
    enhance_p.add_argument("--checkpoint", help="Path to save/resume checkpoint (agentic mode)")
    enhance_p.add_argument("--limit", type=int, help="Max units to enhance")
    enhance_p.add_argument(
        "--mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    enhance_p.add_argument("--workers", type=int, default=8,
                           help="Number of parallel workers for LLM calls (default: 8)")
    enhance_p.add_argument("--backoff", type=int, default=30,
                           help="Seconds to wait when rate-limited (default: 30)")
    enhance_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists)."
        ),
    )
    enhance_p.set_defaults(func=cmd_enhance)

    # ---------------------------------------------------------------
    # analyze — run analysis on existing dataset
    # ---------------------------------------------------------------
    analyze_p = subparsers.add_parser("analyze", help="Run vulnerability analysis on a dataset")
    analyze_p.add_argument("dataset", help="Path to dataset JSON")
    analyze_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    analyze_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    analyze_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (for Stage 2)")
    analyze_p.add_argument("--app-context", help="Path to application_context.json")
    analyze_p.add_argument("--limit", type=int, help="Max units to analyze")
    analyze_p.add_argument("--repo-path", help="Path to the repository (for context correction)")
    exploit_group = analyze_p.add_mutually_exclusive_group()
    exploit_group.add_argument("--exploitable-all", action="store_true",
                               help="Analyze units classified as exploitable or vulnerable_internal (safer, compensates for parser gaps)")
    exploit_group.add_argument("--exploitable-only", action="store_true",
                               help="Analyze only units classified as exploitable (strict, use after parser entry point fixes)")
    analyze_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists)."
        ),
    )
    analyze_p.add_argument("--workers", type=int, default=8,
                           help="Number of parallel workers for LLM calls (default: 8)")
    analyze_p.add_argument("--checkpoint", help="Path to checkpoint directory for save/resume")
    analyze_p.add_argument("--backoff", type=int, default=30,
                           help="Seconds to wait when rate-limited (default: 30)")
    analyze_p.set_defaults(func=cmd_analyze)

    # ---------------------------------------------------------------
    # verify — Stage 2 attacker simulation (standalone)
    # ---------------------------------------------------------------
    verify_p = subparsers.add_parser("verify", help="Run Stage 2 verification on analysis results")
    verify_p.add_argument("results", help="Path to results.json from analyze step")
    verify_p.add_argument("--analyzer-output", required=True, help="Path to analyzer_output.json")
    verify_p.add_argument("--app-context", help="Path to application_context.json")
    verify_p.add_argument("--repo-path", help="Path to the repository")
    verify_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    verify_p.add_argument("--workers", type=int, default=8,
                          help="Number of parallel workers for LLM calls (default: 8)")
    verify_p.add_argument("--checkpoint", help="Path to checkpoint directory for save/resume")
    verify_p.add_argument("--backoff", type=int, default=30,
                          help="Seconds to wait when rate-limited (default: 30)")
    verify_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists)."
        ),
    )
    verify_p.set_defaults(func=cmd_verify)

    # ---------------------------------------------------------------
    # build-output — assemble pipeline_output.json
    # ---------------------------------------------------------------
    bo_p = subparsers.add_parser("build-output", help="Build pipeline_output.json from results")
    bo_p.add_argument("results", help="Path to results.json or results_verified.json")
    bo_p.add_argument("--output", "-o", required=True, help="Output path for pipeline_output.json")
    bo_p.add_argument("--repo-name", help="Repository name (e.g. owner/repo)")
    bo_p.add_argument("--repo-url", help="Repository URL")
    bo_p.add_argument("--language", help="Primary language")
    bo_p.add_argument("--commit-sha", help="Commit SHA")
    bo_p.add_argument("--app-type", help="Application type (default: web_app)")
    bo_p.add_argument("--processing-level", help="Processing level used")
    bo_p.set_defaults(func=cmd_build_output)

    # ---------------------------------------------------------------
    # dynamic-test — Docker, Claude Code or OpenHarmony device dynamic testing
    # ---------------------------------------------------------------
    dt_p = subparsers.add_parser(
        "dynamic-test",
        help="Run Docker/Claude Code dynamic testing or the OpenHarmony device Agentic Loop",
    )
    dt_p.add_argument("pipeline_output", help="Path to pipeline_output.json")
    dt_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    dt_p.add_argument("--repo-path", help="Path to the repository root (required by claude-code mode)")
    dt_p.add_argument(
        "--mode",
        choices=["docker", "claude-code", "openharmony-device"],
        default="docker",
        help="Execution mode: docker, claude-code task workspace, or openharmony-device",
    )
    dt_p.add_argument("--device", help="Explicit HDC serial (required by openharmony-device)")
    dt_p.add_argument("--hdc", help="HDC executable path (optional)")
    dt_p.add_argument("--max-rounds", type=int, default=16, help="OpenHarmony Agentic Loop maximum rounds")
    dt_p.add_argument("--max-commands", type=int, default=64, help="Maximum OpenHarmony device commands")
    dt_p.add_argument("--device-timeout", type=int, default=30, help="OpenHarmony per-command timeout")
    dt_p.add_argument("--device-wall-timeout", type=int, default=1200, help="OpenHarmony total device timeout")
    dt_p.add_argument("--allow-state-change", action="store_true", help="Allow state-changing OpenHarmony device commands")
    dt_p.add_argument("--canary-path", default="/data/local/tmp/vulnfounder-canary", help="Safe OpenHarmony device canary root")
    dt_p.add_argument("--carrier-root", default=None, help="Reviewed HAP carrier root")
    dt_p.add_argument("--carrier-id", default=None, help="Only execute reviewed carrier for this finding ID")
    dt_p.add_argument("--carrier-bundle", default="com.security.research.trigger", help="Reviewed HAP carrier bundle")
    dt_p.add_argument("--carrier-ability", default="EntryAbility", help="Reviewed HAP carrier Ability")
    dt_p.add_argument("--execute-carrier", action="store_true", help="Explicitly execute reviewed HAP carriers")
    dt_p.add_argument(
        "--service-observation-delay",
        type=float,
        default=0.8,
        help="载体发送后延迟日志采样的等待秒数（0-5，默认 0.8）",
    )
    dt_p.add_argument("--max-retries", type=int, default=3,
                      help="Max retries per finding on error (default: 3)")
    dt_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists)."
        ),
    )
    dt_p.set_defaults(func=cmd_dynamic_test)

    # ---------------------------------------------------------------
    # report — generate reports from results
    # ---------------------------------------------------------------
    report_p = subparsers.add_parser("report", help="Generate reports from analysis results")
    report_p.add_argument("results", help="Path to results JSON or pipeline_output.json")
    report_p.add_argument(
        "--format", "-f",
        choices=["html", "csv", "summary", "disclosure"],
        default="disclosure",
        help="Report format (default: disclosure)",
    )
    report_p.add_argument("--dataset", help="Path to dataset JSON (required for html/csv)")
    report_p.add_argument("--pipeline-output", help="Path to pipeline_output.json (for summary/disclosure; auto-built if absent)")
    report_p.add_argument("--repo-name", help="Repository name (used when auto-building pipeline_output)")
    report_p.add_argument("--output", "-o", help="Output path (default: derived from results path and format)")
    report_p.add_argument(
        "--language",
        choices=["en", "zh-CN"],
        default="en",
        help="Report language (default: en; summary supports en and zh-CN).",
    )
    report_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists). Used by "
            "the summary and disclosure formats; ignored for csv/html."
        ),
    )
    report_p.set_defaults(func=cmd_report)

    # ---------------------------------------------------------------
    # report-data — internal: prepare pre-computed report data as JSON
    # ---------------------------------------------------------------
    rd_p = subparsers.add_parser("report-data", help="(internal) Prepare report data for Go renderer")
    rd_p.add_argument("results", help="Path to results/experiment JSON")
    rd_p.add_argument("--dataset", required=True, help="Path to dataset JSON")
    rd_p.add_argument(
        "--language",
        choices=["en", "zh-CN"],
        default="en",
        help="Language for display labels and remediation guidance (default: en).",
    )
    rd_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory. "
            "Defaults to the file's default_llm (or the built-in "
            "`vulnfounder-default` when no config file exists). Used by the "
            "HTML-report remediation guidance, which rides the report phase."
        ),
    )
    rd_p.set_defaults(func=cmd_report_data)

    # ---------------------------------------------------------------
    # checkpoint-status — internal: report checkpoint status for Go CLI
    # ---------------------------------------------------------------
    cs_p = subparsers.add_parser("checkpoint-status",
        help="(internal) Report checkpoint status for a directory")
    cs_p.add_argument("checkpoint_dir", help="Path to checkpoint directory")
    # ---------------------------------------------------------------
    # threat-model — generate or validate VULNFOUNDER.THREATMODEL.md
    # ---------------------------------------------------------------
    tm_p = subparsers.add_parser(
        "threat-model",
        help="Generate or validate a repository's VULNFOUNDER.THREATMODEL.md",
    )
    tm_p.add_argument("repo", help="Path to repository")
    tm_p.add_argument(
        "--force", action="store_true",
        help="Regenerate even if a threat model exists (backs it up first)",
    )
    tm_p.add_argument(
        "--validate-only", action="store_true",
        help="Validate an existing threat model and exit. Makes no LLM call.",
    )
    tm_p.add_argument("--output-md", help="Write here instead of the repo root")
    tm_p.add_argument(
        "--llm-config", default=None,
        help=(
            "Name of the llm-config. Configuration is resolved from "
            "VULNFOUNDER_CONFIG_FILE, project-local config/vulnfounder/config.json (legacy aliases accepted), "
            "or the legacy user config directory."
        ),
    )
    tm_p.set_defaults(func=cmd_threat_model)

    cs_p.set_defaults(func=cmd_checkpoint_status)

    # ---------------------------------------------------------------
    # source-locator — persistent, one-step JSON bridge for Web/worker
    # ---------------------------------------------------------------
    sl_p = subparsers.add_parser(
        "source-locator",
        help="管理 OpenHarmony 源码定位 session（每次调用只执行一个状态操作）",
    )

    # ---------------------------------------------------------------
    # socket-scope — agentic socket-guided scan scope discovery
    # ---------------------------------------------------------------
    ss_p = subparsers.add_parser(
        "socket-scope",
        help="根据 Unix/TCP/UDP socket 源码证据发现并确认普通扫描范围",
    )
    ss_sub = ss_p.add_subparsers(dest="socket_scope_command", required=True)
    ss_discover = ss_sub.add_parser("discover", help="发现候选服务目录和入口证据")
    ss_discover.add_argument("--repo", required=True, help="本地源码仓库")
    ss_discover.add_argument("--target", required=True, help="Unix socket 或 TCP/UDP endpoint")
    ss_discover.add_argument("--output", "-o", required=True, help="写入 scan_scope.json")
    ss_discover.add_argument("--select", default=None, help="可选：发现后直接确认 candidate_id")
    # This flag was part of the previous deterministic-plus-ranking design.
    # Accept it silently for old scripts, but it no longer toggles behaviour.
    ss_discover.add_argument("--llm-rank", action="store_true", help=argparse.SUPPRESS)
    ss_discover.add_argument("--llm-config", default=None, help="Socket 范围 agent 使用的 llm-config 名称")
    ss_discover.add_argument("--max-candidates", type=int, default=8)
    ss_discover.add_argument("--max-files", type=int, default=100000)
    ss_discover.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    ss_discover.set_defaults(func=cmd_socket_scope_discover)

    ss_select = ss_sub.add_parser("select", help="确认已有 manifest 中的候选范围")
    ss_select.add_argument("manifest", help="scan_scope.json")
    ss_select.add_argument("--candidate-id", required=True)
    ss_select.add_argument("--output", default=None, help="输出新 manifest；默认原地更新")
    ss_select.set_defaults(func=cmd_socket_scope_select)

    # ---------------------------------------------------------------
    # scan-artifact — bridge scan intermediates to device dynamic testing
    # ---------------------------------------------------------------
    sa_p = subparsers.add_parser(
        "scan-artifact",
        help="以扫描中间产物（result/N.json + stage1_runs_N）为输入的真机动态测试",
    )
    sa_sub = sa_p.add_subparsers(dest="scan_artifact_command", required=True)

    sa_list = sa_sub.add_parser("list", help="列出历史扫描及可动态测试条目（只读）")
    sa_list.add_argument("--result-dir", default=None,
                         help="聚合产物目录（evaluation_dataset/vulnerability/result）；"
                              "--scan-id 模式下不需要")
    sa_list.add_argument("--scan-id", default=None,
                         help="webui 扫描 ID（~/.openant/webui/<id>）；--webui-dir 配合使用")
    sa_list.add_argument("--webui-dir", default=None,
                         help="webui 根目录（缺省 ~/.vulnfounder/webui 或 ~/.openant/webui）")
    sa_list.add_argument("--round", type=int, default=None,
                         help="聚合产物模式：指定轮次列出该轮条目；缺省列出全部轮次摘要")
    sa_list.add_argument("--finding", choices=["vulnerable", "inconclusive"], default=None,
                         help="按 finding 过滤（两者都是可动态测试集合）")
    sa_list.add_argument("--repository", default=None,
                         help="聚合产物模式：按仓库过滤")
    sa_list.set_defaults(func=cmd_scan_artifact_list)

    sa_run = sa_sub.add_parser("run", help="对一条扫描产物条目执行真机动态测试")
    sa_run.add_argument("--result-dir", default=None,
                        help="聚合产物目录；--scan-id 模式下不需要")
    sa_run.add_argument("--scan-id", default=None,
                        help="webui 扫描 ID（提供后 --round 不需要）")
    sa_run.add_argument("--webui-dir", default=None, help="webui 根目录（缺省自动发现）")
    sa_run.add_argument("--round", type=int, default=None, help="聚合产物轮次 N")
    sa_run.add_argument("--sample", required=True,
                        help="条目标识：聚合产物为 sample（如 DP-02），webui 为 primary_finding_id 或 unit_id")
    sa_run.add_argument("--device", required=True,
                        help="显式 HDC 设备 serial（绝不隐式选择板卡）")
    sa_run.add_argument("--hdc", default=None, help="HDC 可执行路径（缺省 hdc）")
    sa_run.add_argument("--repo-root", default=None,
                        help="仓库根目录（缺省项目内 service_scopes/<repo>_socket_scope）")
    sa_run.add_argument("--ledger", default=None, help="命令账本 JSONL 落点")
    sa_run.add_argument("--progress-file", default=None,
                        help="进度事件 JSONL 落点（每事件一行；Web 桥接实时展示用）")
    sa_run.add_argument(
        "--clean-room", action="store_true",
        help="隔离历史 exemplar 与设备事实库；仅使用当前 finding、源码证据和本轮临时探测结果",
    )
    sa_run.set_defaults(func=cmd_scan_artifact_run)

    sl_sub = sl_p.add_subparsers(dest="source_locator_command", required=True)

    sl_create = sl_sub.add_parser("create", help="创建源码定位 session")
    sl_create.add_argument("target", help="用户描述的服务名、socket 路径或源码目标")
    sl_create.add_argument("--root", required=True, help="session 持久化根目录")
    sl_create.add_argument("--target-revision", default=None)
    sl_create.add_argument("--budget-json", default=None, help="预算 JSON 对象，例如 '{\"max_queries\":20}'")
    sl_create.add_argument("--session-id", default=None)
    sl_create.set_defaults(func=cmd_source_locator_create)

    sl_status = sl_sub.add_parser("status", help="读取 session 当前状态")
    sl_status.add_argument("session_id")
    sl_status.add_argument("--root", required=True)
    sl_status.set_defaults(func=cmd_source_locator_status)

    sl_handoff = sl_sub.add_parser("handoff", help="读取已验证的静态扫描交接对象（只读）")
    sl_handoff.add_argument("session_id")
    sl_handoff.add_argument("--root", required=True)
    sl_handoff.set_defaults(func=cmd_source_locator_handoff)

    sl_list = sl_sub.add_parser("list", help="列出历史源码定位 session")
    sl_list.add_argument("--root", required=True)
    sl_list.set_defaults(func=cmd_source_locator_list)

    sl_delete = sl_sub.add_parser("delete", help="删除一个源码定位 session 及其产物")
    sl_delete.add_argument("session_id")
    sl_delete.add_argument("--root", required=True)
    sl_delete.set_defaults(func=cmd_source_locator_delete)

    sl_events = sl_sub.add_parser("events", help="读取 session 事件（可用于 SSE 恢复）")
    sl_events.add_argument("session_id")
    sl_events.add_argument("--root", required=True)
    sl_events.add_argument("--after", type=int, default=0, help="只返回 seq 大于该值的事件")
    sl_events.set_defaults(func=cmd_source_locator_events)

    sl_message = sl_sub.add_parser("message", help="记录用户补充说明，不改变状态")
    sl_message.add_argument("session_id")
    sl_message.add_argument("--root", required=True)
    sl_message.add_argument("--message", required=True)
    sl_message.set_defaults(func=cmd_source_locator_message)

    sl_transition = sl_sub.add_parser("transition", help="执行一个受约束的状态转换")
    sl_transition.add_argument("session_id")
    sl_transition.add_argument("next_state")
    sl_transition.add_argument("--root", required=True)
    sl_transition.add_argument("--summary-zh", required=True)
    sl_transition.add_argument("--event-type", default="state.changed")
    sl_transition.add_argument("--updates-json", default=None)
    sl_transition.add_argument("--evidence-id", action="append", default=[])
    sl_transition.set_defaults(func=cmd_source_locator_transition)

    sl_confirm = sl_sub.add_parser("confirm", help="确认候选仓库并进入拉取阶段")
    sl_confirm.add_argument("session_id")
    sl_confirm.add_argument("--root", required=True)
    sl_confirm.add_argument("--confirmation-id", default=None)
    sl_confirm.set_defaults(func=cmd_source_locator_confirm)

    sl_select_version = sl_sub.add_parser(
        "select-version",
        help="从失败阶段生成的候选列表中选择 revision 并重新拉取",
    )
    sl_select_version.add_argument("session_id")
    sl_select_version.add_argument("--root", required=True)
    sl_select_version.add_argument("--revision", required=True, help="候选列表中的 branch/tag revision")
    sl_select_version.add_argument("--confirmation-id", default=None)
    sl_select_version.set_defaults(func=cmd_source_locator_select_version)

    sl_reject = sl_sub.add_parser("reject", help="拒绝候选并登记重新检索约束")
    sl_reject.add_argument("session_id")
    sl_reject.add_argument("--root", required=True)
    sl_reject.add_argument("--reason", required=True)
    sl_reject.add_argument("--exclude-path", action="append", default=[])
    sl_reject.add_argument("--exclude-repo", action="append", default=[])
    sl_reject.add_argument("--required-role", default=None)
    sl_reject.set_defaults(func=cmd_source_locator_reject)

    sl_feedback = sl_sub.add_parser("apply-feedback", help="应用拒绝反馈并重新开始检索")
    sl_feedback.add_argument("session_id")
    sl_feedback.add_argument("--root", required=True)
    sl_feedback.set_defaults(func=cmd_source_locator_apply_feedback)

    sl_cancel = sl_sub.add_parser("cancel", help="取消源码定位 session")
    sl_cancel.add_argument("session_id")
    sl_cancel.add_argument("--root", required=True)
    sl_cancel.add_argument("--reason", default="用户取消定位")
    sl_cancel.set_defaults(func=cmd_source_locator_cancel)

    sl_advance = sl_sub.add_parser(
        "advance",
        help="执行最多 N 个源码定位阶段；遇到确认、终态或错误自动暂停",
    )
    sl_advance.add_argument("session_id")
    sl_advance.add_argument("--root", required=True, help="session 持久化根目录")
    sl_advance.add_argument(
        "--config-path",
        default=None,
        help="包含 source_locator 配置的显式 config.json（默认使用项目内配置）",
    )
    sl_advance.add_argument(
        "--project-root",
        default=None,
        help="VulnFounder 项目根目录；用于 Manifest 和 source_code_base 写入",
    )
    sl_advance.add_argument("--max-steps", type=int, default=1, help="本次最多推进阶段数（1-32）")
    sl_advance.add_argument("--max-paths", type=int, default=32, help="源码读取最多候选路径数（1-32）")
    sl_advance.add_argument("--max-source-bytes", type=int, default=None, help="单个源码读取上限")
    sl_advance.add_argument(
        "--llm-search",
        action="store_true",
        help="启用有界多轮 LLM 语义检索循环（默认关闭，避免意外产生模型费用）",
    )
    sl_advance.add_argument(
        "--llm-search-rounds",
        type=int,
        default=None,
        help="本次 LLM 语义检索最多接受的有效动作数（1-40；默认 40）",
    )
    sl_advance.add_argument(
        "--llm-config",
        default=None,
        help="语义检索使用的模型配置名；未指定时沿用配置文件默认模型",
    )
    sl_advance.set_defaults(func=cmd_source_locator_advance)

    sl_run = sl_sub.add_parser(
        "run",
        help="连续执行源码定位，直到用户确认、终态或达到步数上限",
    )
    sl_run.add_argument("session_id")
    sl_run.add_argument("--root", required=True, help="session 持久化根目录")
    sl_run.add_argument("--config-path", default=None)
    sl_run.add_argument("--project-root", default=None)
    sl_run.add_argument("--max-steps", type=int, default=16, help="本次最多推进阶段数（1-32）")
    sl_run.add_argument("--max-paths", type=int, default=32)
    sl_run.add_argument("--max-source-bytes", type=int, default=None)
    sl_run.add_argument(
        "--llm-search",
        action="store_true",
        help="启用有界多轮 LLM 语义检索循环（默认关闭，避免意外产生模型费用）",
    )
    sl_run.add_argument(
        "--llm-search-rounds",
        type=int,
        default=None,
        help="本次 LLM 语义检索最多接受的有效动作数（1-40；默认 40）",
    )
    sl_run.add_argument(
        "--llm-config",
        default=None,
        help="语义检索使用的模型配置名；未指定时沿用配置文件默认模型",
    )
    sl_run.set_defaults(func=cmd_source_locator_advance)

    # ---------------------------------------------------------------
    # exposure-surface — standalone OpenHarmony device exposure inspection
    # ---------------------------------------------------------------
    es_p = subparsers.add_parser(
        "exposure-surface",
        help="创建并执行 OpenHarmony 设备暴露面识别 session（启动需用户确认）",
    )
    es_sub = es_p.add_subparsers(dest="exposure_surface_command", required=True)

    es_create = es_sub.add_parser("create", help="创建暴露面识别 session")
    es_create.add_argument(
        "target",
        help="Unix socket 路径/名称，或网络端点描述（例如：SP_daemon UDP 127.0.0.1:8283）",
    )
    es_create.add_argument("--root", required=True, help="session 持久化根目录")
    es_create.add_argument("--device-serial", default=None, help="可选的 HDC 设备 serial")
    es_create.add_argument(
        "--llm-assist",
        action="store_true",
        help="使用 app_context 模型从已采集设备证据提取字段（失败时回退确定性结果）",
    )
    es_create.add_argument(
        "--mode",
        choices=("fixed", "agentic"),
        default="fixed",
        help="执行模式：fixed 固定探测；agentic 由模型循环选择设备命令",
    )
    es_create.add_argument(
        "--allow-model-commands",
        action="store_true",
        help="明确授权 Agentic Loop 执行模型提出的设备命令",
    )
    es_create.add_argument(
        "--rag-mode",
        choices=("off", "local"),
        default="local",
        help="Agent 本地命令指南检索模式",
    )
    es_create.add_argument(
        "--max-rounds",
        type=int,
        default=20,
        help="Agent 最大模型轮数（最多 20）",
    )
    es_create.add_argument(
        "--max-commands",
        type=int,
        default=100,
        help="Agent 最大设备命令数（最多 100）",
    )
    es_create.add_argument(
        "--batch-id",
        default=None,
        help=argparse.SUPPRESS,
    )
    es_create.add_argument(
        "--batch-index",
        type=int,
        default=None,
        help=argparse.SUPPRESS,
    )
    es_create.add_argument(
        "--batch-total",
        type=int,
        default=None,
        help=argparse.SUPPRESS,
    )
    es_create.add_argument("--session-id", default=None)
    es_create.set_defaults(func=cmd_exposure_surface_create)

    es_status = es_sub.add_parser("status", help="读取暴露面 session")
    es_status.add_argument("session_id")
    es_status.add_argument("--root", required=True)
    es_status.set_defaults(func=cmd_exposure_surface_status)

    es_list = es_sub.add_parser("list", help="列出历史暴露面 session")
    es_list.add_argument("--root", required=True)
    es_list.set_defaults(func=cmd_exposure_surface_list)

    es_events = es_sub.add_parser("events", help="读取暴露面 session 事件")
    es_events.add_argument("session_id")
    es_events.add_argument("--root", required=True)
    es_events.add_argument("--after", type=int, default=0)
    es_events.set_defaults(func=cmd_exposure_surface_events)

    es_start = es_sub.add_parser("start", help="执行一次只读设备探测；发现停止服务时等待确认")
    es_start.add_argument("session_id")
    es_start.add_argument("--root", required=True)
    es_start.add_argument("--hdc-path", default=None, help=argparse.SUPPRESS)
    es_start.set_defaults(func=cmd_exposure_surface_start)

    es_start_service = es_sub.add_parser(
        "start-service",
        help="在用户确认后启动已配置但停止的服务并重新侦查",
    )
    es_start_service.add_argument("session_id")
    es_start_service.add_argument("--root", required=True)
    es_start_service.add_argument("--option-id", default=None, help="待启动服务选项 ID")
    es_start_service.add_argument("--hdc-path", default=None, help=argparse.SUPPRESS)
    es_start_service.set_defaults(func=cmd_exposure_surface_start_service)

    es_skip_start = es_sub.add_parser(
        "skip-start",
        help="拒绝启动已停止服务并保留设备当前状态",
    )
    es_skip_start.add_argument("session_id")
    es_skip_start.add_argument("--root", required=True)
    es_skip_start.add_argument("--reason", default="用户选择保持停止")
    es_skip_start.set_defaults(func=cmd_exposure_surface_skip_start)

    es_cancel = es_sub.add_parser("cancel", help="取消暴露面识别 session")
    es_cancel.add_argument("session_id")
    es_cancel.add_argument("--root", required=True)
    es_cancel.add_argument("--reason", default="用户取消暴露面识别")
    es_cancel.set_defaults(func=cmd_exposure_surface_cancel)

    es_delete = es_sub.add_parser("delete", help="删除暴露面 session 及其产物")
    es_delete.add_argument("session_id")
    es_delete.add_argument("--root", required=True)
    es_delete.set_defaults(func=cmd_exposure_surface_delete)

    # ---------------------------------------------------------------
    # device-socket-inventory — device-scoped Agentic asset database
    # ---------------------------------------------------------------
    dsi_p = subparsers.add_parser(
        "device-socket-inventory",
        help="由 Agent 动态侦查并维护每块开发板的 Socket 暴露面资产快照",
    )
    dsi_sub = dsi_p.add_subparsers(dest="device_socket_inventory_command", required=True)

    dsi_scan = dsi_sub.add_parser("scan", help="运行一轮设备级 Agentic Socket 资产发现")
    dsi_scan.add_argument("--root", required=True, help="设备资产数据库根目录")
    dsi_scan.add_argument("--device-serial", default=None, help="可选 HDC serial；未提供时要求唯一在线设备")
    dsi_scan.add_argument("--hdc-path", default=None, help=argparse.SUPPRESS)
    dsi_scan.add_argument("--llm-config", default=None, help="设备资产 Agent 使用的模型配置名")
    dsi_scan.add_argument("--guide-path", default=None, help="可选的单文件 OpenHarmony 命令指南")
    dsi_scan.add_argument("--task-goal", default=None, help="用户自定义开发板只读侦查任务；留空为扫描所有 Socket 暴露面")
    dsi_scan.add_argument("--resume-run", default=None, help="从同一设备的未完成 run 恢复任务树和证据")
    dsi_scan.add_argument("--run-id", default=None, help="由调用方预先分配的安全 run ID，便于订阅实时进度")
    dsi_scan.add_argument("--rag-mode", choices=("off", "local"), default="local")
    dsi_scan.add_argument("--max-rounds", type=int, default=24)
    dsi_scan.add_argument("--max-commands", type=int, default=96)
    dsi_scan.add_argument("--max-wall-seconds", type=int, default=20 * 60)
    dsi_scan.add_argument("--command-timeout-seconds", type=int, default=30)
    dsi_scan.add_argument("--max-output-bytes", type=int, default=1 << 20)
    dsi_scan.set_defaults(func=cmd_device_socket_inventory_scan)

    dsi_status = dsi_sub.add_parser("status", help="读取一块设备的最新 Socket 资产快照")
    dsi_status.add_argument("--root", required=True)
    dsi_status.add_argument("--device-serial", required=True)
    dsi_status.set_defaults(func=cmd_device_socket_inventory_status)

    dsi_list = dsi_sub.add_parser("list", help="列出资产数据库中的设备快照")
    dsi_list.add_argument("--root", required=True)
    dsi_list.set_defaults(func=cmd_device_socket_inventory_list)

    return parser


def main():
    args = build_parser().parse_args()
    return args.func(args)


def _get_version() -> str:
    """Get version from package."""
    try:
        from vulnfounder import __version__
        return __version__
    except ImportError:
        return "0.1.0"


if __name__ == "__main__":
    sys.exit(main())
