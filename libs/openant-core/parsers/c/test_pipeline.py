#!/usr/bin/env python3
"""
C/C++ Parser Pipeline

Tests the C/C++ parser pipeline components:
1. RepositoryScanner - Enumerates .c/.h/.cpp/.hpp files
2. FunctionExtractor - Extracts functions via tree-sitter
3. CallGraphBuilder  - Builds bidirectional call graphs
4. UnitGenerator     - Creates OpenAnt dataset format
5. CodeQL (optional) - Static analysis pre-filter
6. ContextEnhancer (optional) - LLM enhancement using Claude Sonnet

Usage:
    python test_pipeline.py <repo_path> [--output <dir>] [--llm] [--agentic] [--processing-level LEVEL]

Processing Levels (cumulative filtering):
    Level 1: all         - Process all units (no filtering)
    Level 2: reachable   - Process only units reachable from entry points
    Level 3: codeql      - Process only reachable + CodeQL-flagged units
    Level 4: exploitable - Process only reachable + CodeQL-flagged + exploitable units

Example:
    # Static analysis only
    python test_pipeline.py /path/to/repo --output /tmp/output

    # With agentic LLM enhancement
    python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic

    # CodeQL pre-filter + agentic classification
    python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic --processing-level codeql

    # Maximum cost savings: only exploitable units
    python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic --processing-level exploitable
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Set

# Add parent directory to path so utilities/ imports resolve when this script
# is invoked as a subprocess by core/parser_adapter.py (cwd may not include it).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utilities.file_io import open_utf8, read_json, run_utf8, write_json
from utilities.context_enhancer import ContextEnhancer
from utilities.agentic_enhancer import (
    EntryPointDetector,
    ReachabilityAnalyzer,
    blackout_warning,
    library_seed_ids,
)
from utilities.agentic_enhancer.entry_point_detector import real_entry_point_ids
from core.platforms.openharmony.reachability import (
    build_semantic_reachability_overlay,
    merge_reachability_graph,
)
from core.platforms.openharmony.dispatch_recovery_diff import (
    build_dispatch_recovery_diff,
)

# Local imports
from repository_scanner import RepositoryScanner
from function_extractor import FunctionExtractor
from call_graph_builder import CallGraphBuilder
from unit_generator import UnitGenerator


def _build_openharmony_unit_context(repo_path: str, scan_result: Dict[str, Any]) -> Dict[str, Any] | None:
    """Adapt scanner scope/build inventory to the unit-context contract."""
    scope = scan_result.get('scope')
    if not isinstance(scope, dict) or scope.get('platform') != 'openharmony':
        return None

    file_roles = {
        item.get('path'): item.get('role')
        for item in scan_result.get('files', [])
        if isinstance(item, dict) and item.get('path') and item.get('role')
    }
    build_metadata = scope.get('build_metadata')
    if not isinstance(build_metadata, dict):
        build_metadata = {}

    components = []
    for item in build_metadata.get('bundle_manifests', []):
        if not isinstance(item, dict):
            continue
        name = item.get('component') or item.get('name')
        if name:
            components.append({'name': name, 'manifest_path': item.get('path', '')})

    # Prefer the detailed, read-only GN parser so a group target without
    # sources is not incorrectly attached to every source in the BUILD.gn.
    targets = []
    try:
        from core.platforms.openharmony.gn import OpenHarmonyGNParser

        targets = OpenHarmonyGNParser().collect(repo_path).to_dict().get('targets', [])
    except (OSError, UnicodeError, ValueError):
        targets = []
    if not targets:
        for item in build_metadata.get('build_files', []):
            if not isinstance(item, dict):
                continue
            names = [name for name in item.get('targets', []) if isinstance(name, str) and name]
            sources = item.get('sources', [])
            target_sources = sources if len(names) == 1 and isinstance(sources, list) else []
            for name in names:
                if isinstance(name, str) and name:
                    targets.append(
                        {
                            'name': name,
                            'path': item.get('path', ''),
                            'sources': target_sources,
                        }
                    )

    return {
        'platform': 'openharmony',
        'source_scope': scope.get('source_scope'),
        'file_roles': file_roles,
        'components': components,
        'targets': targets,
        'boundaries': [],
    }


def _build_openharmony_semantic_graph(
    repo_path: str,
    extract_result: Dict[str, Any],
    call_graph_result: Dict[str, Any] | None = None,
    call_graph_diagnostics: Dict[str, Any] | None = None,
) -> Dict[str, Any] | None:
    """Resolve bounded IDL/native IPC evidence for Unit context assembly.

    IDL edges and native member-function-table edges are independent evidence
    sources.  When both are present they are merged into one semantic graph;
    either source may be absent without disabling the other.
    """
    idl_graph = None
    try:
        from core.platforms.openharmony.idl import OpenHarmonyIDLParser
        from core.platforms.openharmony.ipc_graph import OpenHarmonyIPCResolver

        idl_result = OpenHarmonyIDLParser().collect(repo_path).to_dict()
        if idl_result.get('files') and idl_result.get('interfaces'):
            idl_graph = OpenHarmonyIPCResolver().resolve(
                idl_result,
                extract_result,
                call_graph=call_graph_result,
            )
    except (OSError, UnicodeError, TypeError, ValueError):
        # Semantic enrichment is optional.  A malformed IDL must not prevent
        # the ordinary C/C++ parser pipeline from producing a dataset.
        idl_graph = None

    native_graph = None
    try:
        from core.platforms.openharmony.native_dispatch import (
            build_native_dispatch_graph,
            merge_semantic_graphs,
        )

        native_graph = build_native_dispatch_graph(
            extract_result,
            call_graph_result,
            diagnostics=call_graph_diagnostics,
        )
        merged = merge_semantic_graphs(idl_graph, native_graph)
        if merged is None:
            return None
        return merged.to_dict()
    except (OSError, UnicodeError, TypeError, ValueError):
        # Native dispatch enrichment is optional for the same reason as IDL
        # enrichment.  Keep a successfully resolved IDL graph if its optional
        # companion resolver cannot consume this repository.
        return idl_graph.to_dict() if idl_graph is not None else None


def _build_openharmony_call_graph_diagnostics(
    extract_result: Dict[str, Any],
    call_graph_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Build optional indirect-call diagnostics without affecting parsing."""
    try:
        from core.platforms.openharmony.call_graph_diagnostics import (
            build_call_graph_diagnostics,
        )

        return build_call_graph_diagnostics(extract_result, call_graph_result)
    except Exception as exc:  # noqa: BLE001 - diagnostics must degrade safely
        return {
            'schema_version': 1,
            'platform': 'openharmony',
            'status': 'failed',
            'repository': extract_result.get('repository', ''),
            'summary': {
                'unresolved_call_sites': 0,
                'dispatch_assignments': 0,
                'candidate_edges': 0,
                'unresolved_without_candidates': 0,
                'orphan_assignments': 0,
            },
            'unresolved_call_sites': [],
            'dispatch_assignments': [],
            'orphans': [],
            'error': {
                'type': type(exc).__name__,
                'message': str(exc),
            },
        }


class ProcessingLevel(Enum):
    """
    Processing level determines which units are processed.
    Levels are cumulative - each level includes filters from previous levels.
    """
    ALL = "all"
    REACHABLE = "reachable"
    CODEQL = "codeql"
    EXPLOITABLE = "exploitable"


# Pipeline stages that are OPTIONAL: they may fail or be skipped (e.g. CodeQL not installed, no entry
# points) without the run being a failure. They record success=False on failure, so they must be
# excluded from the overall-success conjunction -- otherwise an optional-stage failure forces exit 1.
OPTIONAL_STAGES = frozenset({
    'reachability_filter', 'codeql_analysis', 'codeql_filter',
    'context_enhancer', 'exploitable_filter',
})


class CPipelineTest:
    def __init__(
        self,
        repo_path: str,
        output_dir: str = None,
        enable_llm: bool = False,
        agentic: bool = False,
        processing_level: ProcessingLevel = ProcessingLevel.ALL,
        skip_tests: bool = False,
        depth: int = 3,
        name: str = None,
        library_mode: bool = False,
        platform: str = 'auto',
    ):
        if platform not in {'auto', 'generic', 'openharmony'}:
            raise ValueError('platform must be one of: auto, generic, openharmony')
        self.repo_path = os.path.abspath(repo_path)
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), 'test_output')
        self.parser_dir = os.path.dirname(os.path.abspath(__file__))
        self.enable_llm = enable_llm
        self.agentic = agentic
        self.processing_level = processing_level
        self.skip_tests = skip_tests
        self.depth = depth
        self.dataset_name = name
        self.library_mode = library_mode
        self.platform = platform

        # Pipeline artifacts
        self.scan_results_file = None
        self.analyzer_output_file = None
        self.dataset_file = None
        self.semantic_graph_file = None
        self.call_graph_residuals_file = None
        self.dispatch_recovery_diff_file = None

        # Reachability data
        self.entry_points: Set[str] = set()
        self.reachable_units: Set[str] = set()

        # CodeQL data
        self.codeql_flagged_units: Set[str] = set()
        self.codeql_findings: list = []

        # Results
        self.results = {
            'repository': self.repo_path,
            'test_time': datetime.now().isoformat(),
            'processing_level': processing_level.value,
            'stages': {}
        }

    def setup(self):
        """Create output directory."""
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"Output directory: {self.output_dir}")
        print()
        return True

    def _write_openharmony_dispatch_recovery_diff(
        self,
        call_graph_result: dict,
        diagnostics: dict | None,
        semantic_graph: dict | None,
        *,
        baseline_reachable: Set[str] | None = None,
        recovered_reachable: Set[str] | None = None,
    ) -> dict | None:
        """Persist the additive OpenHarmony dispatch-recovery audit report."""
        if self.platform != 'openharmony':
            return None
        self.dispatch_recovery_diff_file = os.path.join(
            self.output_dir, 'dispatch_recovery_diff.json'
        )
        try:
            report = build_dispatch_recovery_diff(
                call_graph_result,
                diagnostics,
                semantic_graph,
                baseline_reachable=baseline_reachable,
                recovered_reachable=recovered_reachable,
            )
            write_json(self.dispatch_recovery_diff_file, report)
            return report
        except Exception as exc:  # noqa: BLE001 - audit output is optional
            print(
                f"  [Warning] Dispatch-recovery diff unavailable: {exc}",
                file=sys.stderr,
            )
            return None

    def run_parser_pipeline(self) -> bool:
        """Run the full C/C++ parser pipeline (scan, extract, call graph, generate)."""
        self.dataset_file = os.path.join(self.output_dir, 'dataset.json')
        self.analyzer_output_file = os.path.join(self.output_dir, 'analyzer_output.json')
        self.semantic_graph_file = None
        self.call_graph_residuals_file = None
        self.dispatch_recovery_diff_file = None

        print("=" * 60)
        print("STAGE: c_parser_pipeline")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            # Stage 1: Scan
            print("  [1/4] Scanning repository for C/C++ files...")
            scanner_options = {
                'skip_tests': self.skip_tests,
                'platform': self.platform,
            }
            scanner = RepositoryScanner(self.repo_path, scanner_options)
            scan_result = scanner.scan()
            file_count = scan_result['statistics']['total_files']
            print(f"         Found {file_count} files ({scan_result['statistics']['total_size_bytes']:,} bytes)")

            # Save scan results
            self.scan_results_file = os.path.join(self.output_dir, 'scan_results.json')
            write_json(self.scan_results_file, scan_result)

            # Stage 2: Extract functions
            print("  [2/4] Extracting functions via tree-sitter...")
            extractor = FunctionExtractor(self.repo_path)
            extract_result = extractor.extract_from_scan(scan_result)
            func_count = extract_result['statistics']['total_functions']
            print(f"         Extracted {func_count} functions from {extract_result['statistics']['files_processed']} files")
            if extract_result['statistics']['files_with_errors'] > 0:
                print(f"         ({extract_result['statistics']['files_with_errors']} files with errors)")

            # Print type breakdown
            by_type = extract_result['statistics'].get('by_type', {})
            if by_type:
                print(f"         Types: {', '.join(f'{t}={c}' for t, c in sorted(by_type.items()))}")

            # Stage 3: Build call graph
            print("  [3/4] Building call graph...")
            builder = CallGraphBuilder(
                extract_result,
                {'max_depth': self.depth, 'platform': self.platform},
            )
            builder.build_call_graph()
            graph_result = builder.export()
            graph_stats = graph_result['statistics']
            print(f"         {graph_stats['total_edges']} edges, avg out-degree: {graph_stats['avg_out_degree']}")
            print(f"         {graph_stats['isolated_functions']} isolated functions")

            call_graph_diagnostics = None
            if self.platform == 'openharmony':
                call_graph_diagnostics = _build_openharmony_call_graph_diagnostics(
                    extract_result,
                    graph_result,
                )
                self.call_graph_residuals_file = os.path.join(
                    self.output_dir, 'call_graph_residuals.json'
                )
                write_json(
                    self.call_graph_residuals_file,
                    call_graph_diagnostics,
                )
                diagnostic_summary = call_graph_diagnostics.get('summary', {})
                print(
                    "         Indirect-call diagnostics: "
                    f"{diagnostic_summary.get('unresolved_call_sites', 0)} residuals, "
                    f"{diagnostic_summary.get('candidate_edges', 0)} candidates"
                )

            # Stage 4: Generate units
            print("  [4/4] Generating dataset units...")
            opts = {'max_depth': self.depth}
            if self.dataset_name:
                opts['dataset_name'] = self.dataset_name
            semantic_graph = None
            if self.platform == 'openharmony':
                platform_context = _build_openharmony_unit_context(
                    self.repo_path, scan_result
                )
                if platform_context is not None:
                    opts['platform_context'] = platform_context
                semantic_graph = _build_openharmony_semantic_graph(
                    self.repo_path,
                    extract_result,
                    graph_result,
                    call_graph_diagnostics,
                )
                if semantic_graph is not None:
                    opts['semantic_graph'] = semantic_graph
                    self.semantic_graph_file = os.path.join(
                        self.output_dir, 'semantic_graph.json'
                    )
                    write_json(self.semantic_graph_file, semantic_graph)
            generator = UnitGenerator(graph_result, opts)
            dataset = generator.generate_units()
            if self.platform == 'openharmony' and scan_result.get('scope'):
                dataset.setdefault('metadata', {})['openharmony_scope'] = scan_result['scope']
                dataset.setdefault('metadata', {})['openharmony_unit_context'] = {
                    'platform': 'openharmony',
                    'source_scope': scan_result['scope'].get('source_scope'),
                }
                if self.semantic_graph_file:
                    dataset.setdefault('metadata', {})['openharmony_semantic_graph'] = {
                        'path': 'semantic_graph.json',
                        'edge_count': len(semantic_graph.get('edges', [])),
                        'orphan_count': len(semantic_graph.get('orphans', [])),
                    }
                if self.call_graph_residuals_file and call_graph_diagnostics:
                    dataset.setdefault('metadata', {})[
                        'openharmony_call_graph_diagnostics'
                    ] = {
                        'path': 'call_graph_residuals.json',
                        'status': call_graph_diagnostics.get('status', 'unknown'),
                        **call_graph_diagnostics.get('summary', {}),
                    }
            dispatch_recovery_diff = None
            if self.platform == 'openharmony':
                dispatch_recovery_diff = (
                    self._write_openharmony_dispatch_recovery_diff(
                        graph_result,
                        call_graph_diagnostics,
                        semantic_graph,
                    )
                )
                if dispatch_recovery_diff is not None:
                    dataset.setdefault('metadata', {})[
                        'openharmony_dispatch_recovery_diff'
                    ] = {
                        'path': 'dispatch_recovery_diff.json',
                        'status': dispatch_recovery_diff.get('status', 'unknown'),
                        **dispatch_recovery_diff.get('summary', {}),
                    }
            unit_count = dataset['statistics']['total_units']
            print(f"         Generated {unit_count} units")
            print(f"         Enhanced: {dataset['statistics']['units_enhanced']}")
            print(f"         Avg upstream deps: {dataset['statistics']['avg_upstream']}")

            # Write dataset
            write_json(self.dataset_file, dataset)

            # Write analyzer output
            analyzer_output = generator.generate_analyzer_output()
            write_json(self.analyzer_output_file, analyzer_output)

            # Write call graph for post-LLM reachability re-filtering
            self.call_graph_file = os.path.join(self.output_dir, 'call_graph.json')
            write_json(self.call_graph_file, graph_result)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'total_files': file_count,
                'total_functions': func_count,
                'total_units': unit_count,
                'by_type': by_type,
                'call_graph_edges': graph_stats['total_edges'],
                'avg_out_degree': graph_stats['avg_out_degree'],
            }
            if call_graph_diagnostics:
                summary['call_graph_diagnostics'] = {
                    'path': 'call_graph_residuals.json',
                    'status': call_graph_diagnostics.get('status', 'unknown'),
                    **call_graph_diagnostics.get('summary', {}),
                }
            if dispatch_recovery_diff is not None:
                summary['dispatch_recovery_diff'] = {
                    'path': 'dispatch_recovery_diff.json',
                    'status': dispatch_recovery_diff.get('status', 'unknown'),
                    **dispatch_recovery_diff.get('summary', {}),
                }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print()
            print(f"  Success ({elapsed:.2f}s)")
            print()

            self.results['stages']['c_parser'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['c_parser'] = result
            return False

    def apply_reachability_filter(self) -> bool:
        """Filter dataset to only include units reachable from entry points."""
        if not self.analyzer_output_file or not os.path.exists(self.analyzer_output_file):
            print("No analyzer output for reachability filtering")
            return False

        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to filter")
            return False

        print("=" * 60)
        print("STAGE: reachability_filter (static analysis)")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            analyzer = read_json(self.analyzer_output_file)

            functions = analyzer.get("functions", {})

            # Normalize for EntryPointDetector (expects camelCase)
            normalized_functions = {}
            for func_id, func_data in functions.items():
                normalized_functions[func_id] = {
                    'name': func_data.get('name', ''),
                    'unitType': func_data.get('unitType', func_data.get('unit_type', 'function')),
                    'code': func_data.get('code', ''),
                    'filePath': func_data.get('filePath', func_data.get('file_path', '')),
                    'startLine': func_data.get('startLine', func_data.get('start_line', 0)),
                    'endLine': func_data.get('endLine', func_data.get('end_line', 0)),
                    'isExported': func_data.get('isExported', func_data.get('is_exported', False)),
                    'isStatic': func_data.get('isStatic', func_data.get('is_static', False)),
                }

            # Build call graph from dataset unit metadata
            dataset = read_json(self.dataset_file)

            call_graph = {}
            reverse_call_graph = {}
            for unit in dataset.get('units', []):
                unit_id = unit.get('id')
                metadata = unit.get('metadata', {})
                direct_calls = metadata.get('direct_calls', metadata.get('directCalls', []))
                direct_callers = metadata.get('direct_callers', metadata.get('directCallers', []))

                if direct_calls:
                    call_graph[unit_id] = direct_calls
                if direct_callers:
                    reverse_call_graph[unit_id] = direct_callers

            # Detect entry points
            detector = EntryPointDetector(
                normalized_functions,
                call_graph,
                platform=self.platform,
                file_evidence=read_json(self.call_graph_file).get(
                    'openharmony_file_evidence', {}
                ) if self.platform == 'openharmony' else None,
            )
            self.entry_points = detector.detect_entry_points()

            # Library-mode: a library's entry surface is its exported public API,
            # which carries no main/route/CLI marker. Seed it so the BFS reaches
            # the core instead of blacking out. Union-only — never drops a
            # structurally-detected entry point.
            if self.library_mode:
                self.entry_points = self.entry_points | library_seed_ids(normalized_functions)

            # Build the native result first.  OpenHarmony semantic IPC edges
            # are an additive overlay used only for this reachability pass; the
            # detector and the persisted native call graph remain unchanged.
            native_reachability = ReachabilityAnalyzer(
                functions=normalized_functions,
                reverse_call_graph=reverse_call_graph,
                entry_points=self.entry_points
            )
            native_reachable_units = native_reachability.get_all_reachable()
            reachability_reverse_call_graph = reverse_call_graph
            semantic_overlay_metadata = None
            semantic_graph_payload = None
            if self.platform == 'openharmony':
                semantic_overlay = {
                    'enabled': False,
                    'candidate_edges': 0,
                    'edges_added': 0,
                    'entry_points_added': 0,
                    'entry_points': [],
                    'edge_kinds': [],
                    'monotonicity_violation': False,
                }
                existing_entry_points = set(self.entry_points)
                semantic_path = self.semantic_graph_file or os.path.join(
                    self.output_dir, 'semantic_graph.json'
                )
                if semantic_path and os.path.exists(semantic_path):
                    try:
                        semantic_graph = read_json(semantic_path)
                        semantic_graph_payload = semantic_graph
                        overlay = build_semantic_reachability_overlay(
                            semantic_graph,
                            normalized_functions.keys(),
                        )
                        semantic_entry_points = {
                            item for item in overlay.get('entry_points', []) or []
                            if isinstance(item, str) and item in normalized_functions
                        }
                        self.entry_points |= semantic_entry_points
                        semantic_entry_points_added = (
                            semantic_entry_points - existing_entry_points
                        )
                        _, reachability_reverse_call_graph = merge_reachability_graph(
                            call_graph,
                            reverse_call_graph,
                            overlay,
                        )
                        native_pairs = {
                            (caller, callee)
                            for callee, callers in reverse_call_graph.items()
                            for caller in callers
                        }
                        edges_added = sum(
                            1
                            for edge in overlay.get('edges', [])
                            if (
                                edge.get('source_id'), edge.get('target_id')
                            ) not in native_pairs
                        )
                        semantic_overlay = {
                            'enabled': bool(
                                overlay.get('edges') or semantic_entry_points_added
                            ),
                            'candidate_edges': overlay.get('candidate_edges', 0),
                            'edges_added': edges_added,
                            'entry_points_added': len(semantic_entry_points_added),
                            'entry_points': sorted(semantic_entry_points),
                            'edge_kinds': overlay.get('edge_kinds', []),
                            'ignored_edge_count': overlay.get('ignored_edge_count', 0),
                            'invalid_endpoint_count': overlay.get(
                                'invalid_endpoint_count', 0
                            ),
                            'monotonicity_violation': False,
                        }
                    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        print(
                            f"  [Warning] Ignoring malformed semantic graph: {exc}",
                            file=sys.stderr,
                        )
                        reachability_reverse_call_graph = reverse_call_graph
                semantic_overlay_metadata = semantic_overlay

            # Build the combined reachability result.  Since the merged graph
            # contains every native reverse edge, this set must be a superset
            # of the native result; keep the native set defensively if an
            # unexpected resolver/graph shape ever violates that invariant.
            reachability = ReachabilityAnalyzer(
                functions=normalized_functions,
                reverse_call_graph=reachability_reverse_call_graph,
                entry_points=self.entry_points
            )
            self.reachable_units = reachability.get_all_reachable()
            monotonicity_violation = not native_reachable_units.issubset(
                self.reachable_units
            )
            if monotonicity_violation:
                self.reachable_units |= native_reachable_units
            if semantic_overlay_metadata is not None:
                semantic_overlay_metadata['monotonicity_violation'] = monotonicity_violation

            units = dataset.get("units", [])
            original_count = len(units)

            # N4 fix: empty-seed safety-net (mirrors core/parser_adapter.py). No
            # entry points => the reachable set is empty => every unit is pruned,
            # silently blacking out the dataset (dominant failure for library /
            # no-entry-point targets). Degrade to keep-all + warn instead.
            if not real_entry_point_ids(self.entry_points, normalized_functions) and units:
                print("  [Warning] No real entry points detected — keeping all units "
                      "unfiltered to avoid a silent blackout.", file=sys.stderr)
                self.reachable_units = {u.get("id", "") for u in units}

            # Write the audit after the empty-seed safety-net has established
            # the actual recovered set, so the report matches the dataset.
            dispatch_recovery_diff = None
            if self.platform == 'openharmony':
                call_graph_result = {
                    'functions': functions,
                    'call_graph': call_graph,
                    'reverse_call_graph': reverse_call_graph,
                }
                if getattr(self, 'call_graph_file', None) and os.path.exists(
                    self.call_graph_file
                ):
                    try:
                        call_graph_result = read_json(self.call_graph_file)
                    except (OSError, TypeError, ValueError, json.JSONDecodeError):
                        pass
                diagnostics = {}
                if (
                    self.call_graph_residuals_file
                    and os.path.exists(self.call_graph_residuals_file)
                ):
                    try:
                        diagnostics = read_json(self.call_graph_residuals_file)
                    except (OSError, TypeError, ValueError, json.JSONDecodeError):
                        diagnostics = {}
                if semantic_graph_payload is None:
                    semantic_path = self.semantic_graph_file or os.path.join(
                        self.output_dir, 'semantic_graph.json'
                    )
                    if semantic_path and os.path.exists(semantic_path):
                        try:
                            semantic_graph_payload = read_json(semantic_path)
                        except (OSError, TypeError, ValueError, json.JSONDecodeError):
                            semantic_graph_payload = None
                dispatch_recovery_diff = (
                    self._write_openharmony_dispatch_recovery_diff(
                        call_graph_result,
                        diagnostics,
                        semantic_graph_payload,
                        baseline_reachable=native_reachable_units,
                        recovered_reachable=self.reachable_units,
                    )
                )

            filtered_units = []
            for u in units:
                unit_id = u.get("id", "")
                if unit_id in self.reachable_units:
                    u["reachable"] = True
                    u["is_entry_point"] = unit_id in self.entry_points
                    if unit_id in self.entry_points:
                        u["entry_point_reason"] = detector.get_entry_point_reason(unit_id)
                    filtered_units.append(u)

            dataset["units"] = filtered_units
            dataset["metadata"] = dataset.get("metadata", {})
            filter_metadata = {
                "original_units": original_count,
                "entry_points": len(self.entry_points),
                "reachable_units": len(filtered_units),
                "filtered_out": original_count - len(filtered_units),
                "reduction_percentage": round((1 - len(filtered_units) / original_count) * 100, 1) if original_count > 0 else 0
            }
            if semantic_overlay_metadata is not None:
                unit_ids = {u.get('id', '') for u in units}
                native_unit_ids = native_reachable_units & unit_ids
                combined_unit_ids = self.reachable_units & unit_ids
                filter_metadata['native_reachable_units'] = len(native_unit_ids)
                filter_metadata['semantic_reachable_added'] = len(
                    combined_unit_ids - native_unit_ids
                )
                filter_metadata['semantic_overlay'] = semantic_overlay_metadata
            if dispatch_recovery_diff is not None:
                filter_metadata['dispatch_recovery_diff'] = {
                    'path': 'dispatch_recovery_diff.json',
                    'status': dispatch_recovery_diff.get('status', 'unknown'),
                    **dispatch_recovery_diff.get('summary', {}),
                }
            dataset["metadata"]["reachability_filter"] = filter_metadata

            _blackout = blackout_warning(detector.entry_point_details, original_count,
                                         len(filtered_units),
                                         library_mode=getattr(self, "library_mode", False))
            if _blackout:
                dataset["metadata"]["reachability_filter"]["warning"] = _blackout
                print(f"  [Warning] {_blackout}", file=sys.stderr)

            write_json(self.dataset_file, dataset)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'original_units': original_count,
                'entry_points': len(self.entry_points),
                'reachable_units': len(filtered_units),
                'reduction_percentage': dataset["metadata"]["reachability_filter"]["reduction_percentage"]
            }
            if dispatch_recovery_diff is not None:
                summary['dispatch_recovery_diff'] = {
                    'path': 'dispatch_recovery_diff.json',
                    'status': dispatch_recovery_diff.get('status', 'unknown'),
                    **dispatch_recovery_diff.get('summary', {}),
                }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print(f"  Success ({elapsed:.2f}s)")
            print(f"  Entry points detected: {len(self.entry_points)}")
            print(f"  Units: {original_count} -> {len(filtered_units)} ({summary['reduction_percentage']}% reduction)")
            print()

            self.results['stages']['reachability_filter'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['reachability_filter'] = result
            return False

    def run_codeql_analysis(self) -> bool:
        """Run CodeQL analysis on the repository."""
        print("=" * 60)
        print("STAGE: codeql_analysis")
        print("=" * 60)
        print()

        start_time = datetime.now()

        language = "cpp"
        print(f"Language: {language}")

        codeql_db_path = os.path.join(self.output_dir, 'codeql-db')
        sarif_output = os.path.join(self.output_dir, 'codeql-results.sarif')

        try:
            # Step 1: Create CodeQL database
            print("Creating CodeQL database...")
            create_db_cmd = [
                'codeql', 'database', 'create',
                codeql_db_path,
                f'--language={language}',
                f'--source-root={self.repo_path}',
                # These repos carry extracted source with no build system to run, so use the
                # build-mode-none extractor: a compiled language (cpp) is indexed without autobuild,
                # which would otherwise fail/degrade on no-build/autotools repos and silently drop
                # CodeQL findings.
                '--build-mode=none',
                '--overwrite'
            ]

            result = run_utf8(
                create_db_cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode != 0:
                print(f"  CodeQL database creation failed")
                print(f"  stderr: {result.stderr[:500] if result.stderr else 'none'}")
                elapsed = (datetime.now() - start_time).total_seconds()
                self.results['stages']['codeql_analysis'] = {
                    'success': False,
                    'elapsed_seconds': elapsed,
                    'error': 'Database creation failed',
                    'stderr': result.stderr
                }
                return False

            print("  Database created successfully")

            # Step 2: Run security queries
            print("Running security queries...")
            analyze_cmd = [
                'codeql', 'database', 'analyze',
                codeql_db_path,
                '--format=sarif-latest',
                f'--output={sarif_output}',
                f'codeql/{language}-queries:codeql-suites/{language}-security-extended.qls'
            ]

            result = run_utf8(
                analyze_cmd,
                capture_output=True,
                text=True,
                timeout=1800
            )

            if result.returncode != 0:
                print(f"  CodeQL analysis failed")
                print(f"  stderr: {result.stderr[:500] if result.stderr else 'none'}")
                elapsed = (datetime.now() - start_time).total_seconds()
                self.results['stages']['codeql_analysis'] = {
                    'success': False,
                    'elapsed_seconds': elapsed,
                    'error': 'Analysis failed',
                    'stderr': result.stderr
                }
                return False

            print("  Analysis completed")

            # Step 3: Parse SARIF output
            print("Parsing results...")
            if not os.path.exists(sarif_output):
                print("  SARIF output not found")
                elapsed = (datetime.now() - start_time).total_seconds()
                self.results['stages']['codeql_analysis'] = {
                    'success': False,
                    'elapsed_seconds': elapsed,
                    'error': 'SARIF output not found'
                }
                return False

            sarif_data = read_json(sarif_output)

            self.codeql_findings = []

            for run in sarif_data.get('runs', []):
                for result_item in run.get('results', []):
                    rule_id = result_item.get('ruleId', 'unknown')
                    message = result_item.get('message', {}).get('text', '')
                    level = result_item.get('level', 'warning')

                    for location in result_item.get('locations', []):
                        physical = location.get('physicalLocation', {})
                        artifact = physical.get('artifactLocation', {})
                        uri = artifact.get('uri', '')
                        region = physical.get('region', {})
                        finding_start = region.get('startLine', 0)
                        finding_end = region.get('endLine', finding_start)

                        finding = {
                            'rule_id': rule_id,
                            'message': message,
                            'level': level,
                            'file': uri,
                            'start_line': finding_start,
                            'end_line': finding_end
                        }
                        self.codeql_findings.append(finding)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'total_findings': len(self.codeql_findings),
                'unique_files': len(set(f['file'] for f in self.codeql_findings)),
                'by_level': {},
                'by_rule': {}
            }

            for finding in self.codeql_findings:
                level = finding['level']
                rule = finding['rule_id']
                summary['by_level'][level] = summary['by_level'].get(level, 0) + 1
                summary['by_rule'][rule] = summary['by_rule'].get(rule, 0) + 1

            result_data = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': sarif_output,
                'summary': summary
            }

            print(f"  Success ({elapsed:.2f}s)")
            print(f"  Total findings: {len(self.codeql_findings)}")
            print(f"  Unique files: {summary['unique_files']}")
            if summary['by_level']:
                print(f"  By level: {summary['by_level']}")
            print()

            self.results['stages']['codeql_analysis'] = result_data
            return True

        except FileNotFoundError:
            elapsed = (datetime.now() - start_time).total_seconds()
            print("  CodeQL not found. Please install CodeQL CLI.")
            print("  See: https://docs.github.com/en/code-security/codeql-cli")
            self.results['stages']['codeql_analysis'] = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': 'CodeQL CLI not installed'
            }
            return False

        except subprocess.TimeoutExpired:
            elapsed = (datetime.now() - start_time).total_seconds()
            print("  CodeQL analysis timed out")
            self.results['stages']['codeql_analysis'] = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': 'Timeout'
            }
            return False

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            self.results['stages']['codeql_analysis'] = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            return False

    def apply_codeql_filter(self) -> bool:
        """Filter dataset to only include units flagged by CodeQL."""
        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to filter")
            return False

        if not self.codeql_findings:
            print("No CodeQL findings to filter by")
            return False

        print("=" * 60)
        print("STAGE: codeql_filter")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            dataset = read_json(self.dataset_file)

            # Build mapping of file -> [(start_line, end_line, func_id)]
            file_functions = {}
            for unit in dataset.get('units', []):
                unit_id = unit.get('id', '')
                origin = unit.get('code', {}).get('primary_origin', {})
                file_path = origin.get('file_path', '')
                unit_start = origin.get('start_line', 0)
                unit_end = origin.get('end_line', unit_start)

                if file_path:
                    if file_path not in file_functions:
                        file_functions[file_path] = []
                    file_functions[file_path].append((unit_start, unit_end, unit_id))

            # Map CodeQL findings to function units
            for finding in self.codeql_findings:
                file_uri = finding['file']
                finding_start = finding['start_line']
                finding_end = finding['end_line']

                matched_file = None
                for file_path in file_functions.keys():
                    if file_path.endswith(file_uri) or file_uri.endswith(file_path) or file_path == file_uri:
                        matched_file = file_path
                        break

                if matched_file:
                    for start, end, func_id in file_functions[matched_file]:
                        if start <= finding_start <= end or start <= finding_end <= end:
                            self.codeql_flagged_units.add(func_id)

            units = dataset.get("units", [])
            original_count = len(units)

            filtered_units = [u for u in units if u.get("id") in self.codeql_flagged_units]

            dataset["units"] = filtered_units
            dataset["metadata"] = dataset.get("metadata", {})
            dataset["metadata"]["codeql_filter"] = {
                "original_units": original_count,
                "codeql_findings": len(self.codeql_findings),
                "flagged_units": len(self.codeql_flagged_units),
                "filtered_units": len(filtered_units),
                "filtered_out": original_count - len(filtered_units),
                "reduction_percentage": round((1 - len(filtered_units) / original_count) * 100, 1) if original_count > 0 else 0
            }

            write_json(self.dataset_file, dataset)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'original_units': original_count,
                'codeql_findings': len(self.codeql_findings),
                'flagged_units': len(self.codeql_flagged_units),
                'filtered_units': len(filtered_units),
                'reduction_percentage': dataset["metadata"]["codeql_filter"]["reduction_percentage"]
            }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print(f"  Success ({elapsed:.2f}s)")
            print(f"  CodeQL findings: {len(self.codeql_findings)}")
            print(f"  Flagged function units: {len(self.codeql_flagged_units)}")
            print(f"  Units: {original_count} -> {len(filtered_units)} ({summary['reduction_percentage']}% reduction)")
            print()

            self.results['stages']['codeql_filter'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['codeql_filter'] = result
            return False

    def run_context_enhancer(self) -> bool:
        """Stage 4 (optional): Enhance dataset with LLM context."""
        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to enhance")
            return False

        mode = "agentic" if self.agentic else "single-shot"
        print("=" * 60)
        print(f"STAGE: context_enhancer (Python, {mode} mode)")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            dataset = read_json(self.dataset_file)

            # Build a phase registry from the default llm-config (name=None)
            # and hand the enhancer the enhance-phase binding — mirrors
            # core/enhancer.py. The bare ContextEnhancer() form no longer
            # works (binding required).
            from utilities.llm import (
                build_phase_registry,
                load_config_file,
                probe_registry_or_raise,
                resolve_llm_config,
            )

            cf = load_config_file()
            registry = build_phase_registry(cf, resolve_llm_config(cf, None))
            probe_registry_or_raise(registry)
            enhancer = ContextEnhancer(binding=registry.get("enhance"))

            if self.agentic:
                enhanced = enhancer.enhance_dataset_agentic(
                    dataset,
                    analyzer_output_path=self.analyzer_output_file,
                    repo_path=self.repo_path,
                    batch_size=5,
                    verbose=False
                )
                agentic_stats = enhanced.get('metadata', {}).get('agentic_stats', {})
                summary = {
                    'mode': 'agentic',
                    'units_processed': agentic_stats.get('units_processed', 0),
                    'units_with_context': agentic_stats.get('units_with_context', 0),
                    'functions_added': agentic_stats.get('functions_added', 0),
                    'security_controls_found': agentic_stats.get('security_controls_found', 0),
                    'vulnerable_found': agentic_stats.get('vulnerable_found', 0),
                    'neutral_found': agentic_stats.get('neutral_found', 0)
                }
            else:
                enhanced = enhancer.enhance_dataset(dataset)
                summary = {
                    'mode': 'single-shot',
                    'units_enhanced': enhancer.stats['units_enhanced'],
                    'dependencies_added': enhancer.stats['dependencies_added'],
                    'callers_added': enhancer.stats['callers_added'],
                    'data_flows_extracted': enhancer.stats['data_flows_extracted']
                }

            write_json(self.dataset_file, enhanced)

            elapsed = (datetime.now() - start_time).total_seconds()

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print()
            print(f"  Success ({elapsed:.2f}s)")

            self.results['stages']['context_enhancer'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['context_enhancer'] = result
            return False

    def apply_exploitable_filter(self) -> bool:
        """Filter dataset to only include units classified as 'exploitable'."""
        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to filter")
            return False

        print("=" * 60)
        print("STAGE: exploitable_filter")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            dataset = read_json(self.dataset_file)

            units = dataset.get("units", [])
            original_count = len(units)

            filtered_units = []
            classification_counts = {}

            for unit in units:
                agent_context = unit.get("agent_context", {})
                classification = agent_context.get("security_classification", "unknown")
                classification_counts[classification] = classification_counts.get(classification, 0) + 1

                if classification == "exploitable":
                    filtered_units.append(unit)

            dataset["units"] = filtered_units
            dataset["metadata"] = dataset.get("metadata", {})
            dataset["metadata"]["exploitable_filter"] = {
                "original_units": original_count,
                "exploitable_units": len(filtered_units),
                "filtered_out": original_count - len(filtered_units),
                "classification_counts": classification_counts,
                "reduction_percentage": round((1 - len(filtered_units) / original_count) * 100, 1) if original_count > 0 else 0
            }

            write_json(self.dataset_file, dataset)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'original_units': original_count,
                'exploitable_units': len(filtered_units),
                'classification_counts': classification_counts,
                'reduction_percentage': dataset["metadata"]["exploitable_filter"]["reduction_percentage"]
            }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print(f"  Success ({elapsed:.2f}s)")
            print(f"  Classification breakdown:")
            for cls, count in sorted(classification_counts.items()):
                marker = "->" if cls == "exploitable" else "  "
                print(f"    {marker} {cls}: {count}")
            print(f"  Units: {original_count} -> {len(filtered_units)} ({summary['reduction_percentage']}% reduction)")
            print()

            self.results['stages']['exploitable_filter'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['exploitable_filter'] = result
            return False

    def _compute_success(self) -> bool:
        """Overall success = all REQUIRED stages succeeded.

        Optional stages (CodeQL, reachability filter, context enhancer, exploitable filter) write
        success=False on failure/skip; ANDing them into overall success made an optional-stage
        failure a spurious pipeline failure (exit 1). Exclude them from the conjunction.
        """
        return all(
            stage.get('success', False)
            for name, stage in self.results['stages'].items()
            if name not in OPTIONAL_STAGES
        )

    def run_full_pipeline(self):
        """Run the complete pipeline."""
        print("=" * 60)
        print("C/C++ PARSER PIPELINE")
        print("=" * 60)
        print(f"Repository: {self.repo_path}")
        print(f"Processing Level: {self.processing_level.value}")
        print(f"Started: {self.results['test_time']}")
        print()

        if not self.setup():
            print("Pipeline stopped: Setup failed")
            return self.results

        # Stage 1-4: Run parser pipeline
        if not self.run_parser_pipeline():
            print("Pipeline stopped: Parser pipeline failed")
            return self.results

        # Stage 3.5 (optional): Reachability Filter
        if self.processing_level in (ProcessingLevel.REACHABLE, ProcessingLevel.CODEQL, ProcessingLevel.EXPLOITABLE):
            if not self.apply_reachability_filter():
                print("Warning: Reachability filter failed, continuing with all units")

        # Stage 3.6-3.7 (optional): CodeQL Analysis and Filter
        if self.processing_level in (ProcessingLevel.CODEQL, ProcessingLevel.EXPLOITABLE):
            codeql_success = self.run_codeql_analysis()
            if codeql_success:
                if not self.apply_codeql_filter():
                    print("Warning: CodeQL filter failed, continuing with reachable units")
            else:
                print("Warning: CodeQL analysis failed, continuing with reachable units only")

        # Stage 4 (optional): Context Enhancer
        if self.enable_llm:
            if not self.run_context_enhancer():
                print("Warning: Context enhancer failed, continuing with static analysis only")

            # Stage 4.5 (optional): Exploitable Filter
            if self.processing_level == ProcessingLevel.EXPLOITABLE:
                if self.agentic:
                    if not self.apply_exploitable_filter():
                        print("Warning: Exploitable filter failed")
                else:
                    print()
                    print("Warning: Exploitable filter requires --agentic mode for classification")
                    print("Skipping exploitable filter")
        else:
            print()
            print("Skipping LLM enhancement (use --llm to enable)")
            if self.processing_level == ProcessingLevel.EXPLOITABLE:
                print("Warning: Exploitable level requires --llm --agentic for classification")

        # Summary
        print("=" * 60)
        print("PIPELINE SUMMARY")
        print("=" * 60)

        all_success = self._compute_success()

        self.results['success'] = all_success

        if all_success:
            print("  All stages completed successfully")
        else:
            print("  Some stages failed")

        print()
        for stage_name, stage_result in self.results['stages'].items():
            status = "OK" if stage_result.get('success') else "FAIL"
            elapsed = stage_result.get('elapsed_seconds', 0)
            print(f"  [{status}] {stage_name}: {elapsed:.2f}s")

            if 'summary' in stage_result:
                summary = stage_result['summary']
                if 'total_files' in summary:
                    print(f"      Files: {summary['total_files']}")
                if 'total_functions' in summary:
                    print(f"      Functions: {summary['total_functions']}")
                if 'total_units' in summary:
                    print(f"      Units: {summary['total_units']}")
                    edges = summary.get('call_graph_edges', 0)
                    avg_deg = summary.get('avg_out_degree', 0)
                    if edges:
                        print(f"      Call graph: {edges} edges, avg degree: {avg_deg:.2f}")
                if 'entry_points' in summary:
                    print(f"      Entry points: {summary['entry_points']}")
                    print(f"      Reachable: {summary.get('reachable_units', 0)}")
                    print(f"      Reduction: {summary.get('reduction_percentage', 0)}%")

        print()
        print(f"Output files in: {self.output_dir}")

        # Save results summary
        results_file = os.path.join(self.output_dir, 'pipeline_results.json')
        with open_utf8(results_file, 'w') as f:
            clean_results = {
                'repository': self.results['repository'],
                'test_time': self.results['test_time'],
                'processing_level': self.results.get('processing_level', 'all'),
                'success': self.results.get('success', False),
                'stages': {}
            }
            for stage_name, stage_result in self.results['stages'].items():
                clean_results['stages'][stage_name] = {
                    'success': stage_result.get('success', False),
                    'elapsed_seconds': stage_result.get('elapsed_seconds', 0),
                    'output_file': stage_result.get('output_file'),
                    'summary': stage_result.get('summary', {})
                }
            json.dump(clean_results, f, indent=2)

        print(f"Results summary: {results_file}")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Run the C/C++ parser pipeline on a repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Processing Levels (cumulative filtering):
  all         Level 1: Process all units (no filtering, highest cost)
  reachable   Level 2: Filter to units reachable from entry points
  codeql      Level 3: Filter to reachable + CodeQL-flagged units (requires CodeQL CLI)
  exploitable Level 4: Filter to reachable + CodeQL-flagged + exploitable (requires --llm --agentic)

Examples:
  # Static analysis only (all units)
  python test_pipeline.py /path/to/repo

  # With reachability filtering only
  python test_pipeline.py /path/to/repo --processing-level reachable

  # With CodeQL pre-filter + agentic classification
  python test_pipeline.py /path/to/repo --llm --agentic --processing-level codeql

  # Maximum cost savings: only exploitable units
  python test_pipeline.py /path/to/repo --llm --agentic --processing-level exploitable
"""
    )
    parser.add_argument(
        'repo_path',
        help='Path to the C/C++ repository to analyze'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output directory for pipeline artifacts',
        default=None
    )
    parser.add_argument(
        '--llm',
        action='store_true',
        help='Enable LLM context enhancement (uses Claude Sonnet)'
    )
    parser.add_argument(
        '--agentic',
        action='store_true',
        help='Use agentic mode with iterative tool use (more accurate, more expensive)'
    )
    parser.add_argument(
        '--processing-level',
        choices=['all', 'reachable', 'codeql', 'exploitable'],
        default='all',
        help='Processing level: all (L1), reachable (L2), codeql (L3), exploitable (L4)'
    )
    parser.add_argument(
        '--skip-tests',
        action='store_true',
        help='Skip test files'
    )
    parser.add_argument(
        '--platform',
        choices=['auto', 'generic', 'openharmony'],
        default='auto',
        help='Platform mode: auto, generic, openharmony',
    )
    parser.add_argument(
        '--depth', '-d',
        type=int,
        default=3,
        help='Max dependency resolution depth (default: 3)'
    )
    parser.add_argument(
        '--name', '-n',
        default=None,
        help='Dataset name (default: derived from repo path)'
    )
    parser.add_argument(
        '--library-mode',
        action='store_true',
        help='Seed the exported public API as entry points (for libraries with no main/route/CLI)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.repo_path):
        print(f"Error: Repository not found: {args.repo_path}")
        sys.exit(1)

    processing_level = ProcessingLevel(args.processing_level)

    if processing_level == ProcessingLevel.EXPLOITABLE and not (args.llm and args.agentic):
        print("Warning: --processing-level exploitable requires --llm --agentic for classification")
        print("Units will be filtered by reachability only, not by exploitability")

    pipeline = CPipelineTest(
        args.repo_path,
        args.output,
        enable_llm=args.llm,
        agentic=args.agentic,
        processing_level=processing_level,
        skip_tests=args.skip_tests,
        depth=args.depth,
        name=args.name,
        library_mode=args.library_mode,
        platform=args.platform,
    )
    results = pipeline.run_full_pipeline()

    sys.exit(0 if results.get('success', False) else 1)


if __name__ == '__main__':
    main()
