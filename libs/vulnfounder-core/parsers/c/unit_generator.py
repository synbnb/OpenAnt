#!/usr/bin/env python3
"""
Unit Generator for C/C++ Codebases

Creates self-contained analysis units for ALL functions extracted from a repository.
Each unit includes:
- Primary code (the function itself)
- Upstream dependencies (functions this calls)
- Downstream callers (functions that call this)
- Assembled enhanced code with file boundaries

This is Phase 4 of the C/C++ parser - dataset generation.

Usage:
    python unit_generator.py <call_graph.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "name": "dataset_name",
        "repository": "/path/to/repo",
        "units": [ ... ],
        "statistics": { ... }
    }
"""

import json
import posixpath
import re
import sys
from datetime import datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Set
from utilities.file_io import read_json, write_json, open_utf8
from core.file_boundary import neutralize_boundaries


# File boundary marker for enhanced code (C-style comment, matching Go parser)
FILE_BOUNDARY = '\n\n// ========== File Boundary ==========\n\n'

_C_LANGUAGE_EXTENSIONS = frozenset({'.c', '.h'})
_CPP_LANGUAGE_EXTENSIONS = frozenset({'.cc', '.cpp', '.cxx', '.hh', '.hpp', '.hxx'})
_LANGUAGE_ALIASES = {
    'c++': 'cpp',
    'cc': 'cpp',
    'cpp': 'cpp',
    'cxx': 'cpp',
}

_BOUNDARY_SIGNAL_PATTERNS = (
    ("binder_ipc", re.compile(r"\b(?:MessageParcel|IRemoteStub|IRemoteProxy|OnRemoteRequest|SendRequest)\b")),
    ("system_ability", re.compile(r"\b(?:SystemAbility|DECLARE_SYSTEM_ABILITY|REGISTER_SYSTEM_ABILITY)\b")),
    ("hdf", re.compile(r"\b(?:HDF_INIT|HdfSbuf|HdfDriverEntry)\b")),
)
_GUARD_SIGNAL_PATTERNS = (
    ("interface_token", re.compile(r"\b(?:ReadInterfaceToken|WriteInterfaceToken|EnforceInterface)\b")),
    ("caller_identity", re.compile(r"\b(?:GetCallingUid|GetCallingPid|GetCallingTokenID|GetCallingFullTokenID)\b")),
    ("permission_check", re.compile(r"\b(?:CheckPermission|HasPermission|VerifyPermission|VerifyAccessToken)\b")),
    ("system_app_check", re.compile(r"\b(?:IsSystemApp|IsSAsCalling)\b")),
)
_SEMANTIC_CONTEXT_EDGE_KINDS = frozenset(
    {
        "proxy_to_transaction",
        "stub_to_transaction",
        "transaction_to_handler",
        "native_dispatch_to_handler",
        "native_dispatch_to_service",
    }
)


def _normalise_context_path(value: object) -> str:
    """Normalize a repository-relative path used by platform metadata."""
    if not isinstance(value, str):
        return ""
    raw = value.replace("\\", "/").strip()
    if raw.startswith("/") and not raw.startswith("//"):
        return ""
    if raw.startswith("//"):
        raw = raw[2:]
    raw = posixpath.normpath(raw)
    if raw in {"", "."}:
        return ""
    if ".." in PurePosixPath(raw).parts:
        return ""
    return raw[2:] if raw.startswith("./") else raw


def _context_values(value: object) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _unique_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _record_name(record: object) -> str:
    if isinstance(record, str):
        return record
    if not isinstance(record, dict):
        return ""
    for key in ("name", "component", "component_name", "target"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _record_path(record: object, *keys: str) -> str:
    if not isinstance(record, dict):
        return ""
    for key in keys:
        value = record.get(key)
        path = _normalise_context_path(value)
        if path:
            return path
    return ""


def _resolve_target_source(target_path: str, source: str) -> str:
    """Resolve a GN source against its BUILD.gn path for exact matching."""
    source_path = _normalise_context_path(source)
    if not source_path:
        return ""
    if str(source).replace("\\", "/").startswith("//"):
        return source_path
    target_parent = posixpath.dirname(target_path)
    return _normalise_context_path(posixpath.join(target_parent, source_path))


def _normalise_guard(value: object) -> list[dict[str, str]]:
    """Normalize explicitly supplied guard evidence without inventing claims."""
    result: list[dict[str, str]] = []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return result
    for item in value:
        if isinstance(item, str) and item:
            result.append({"kind": item, "matched": item})
        elif isinstance(item, dict):
            kind = item.get("kind") or item.get("name")
            matched = item.get("matched") or item.get("signal") or kind
            if isinstance(kind, str) and kind and isinstance(matched, str) and matched:
                result.append({"kind": kind, "matched": matched})
    return result


def _mask_native_comments_and_strings(text: str) -> str:
    """Mask C/C++ comments and literals while preserving line structure."""
    output: list[str] = []
    index = 0
    state = 'code'
    escaped = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ''
        if state == 'line_comment':
            if char in '\r\n':
                output.append(char)
                state = 'code'
            else:
                output.append(' ')
            index += 1
            continue
        if state == 'block_comment':
            if char == '*' and next_char == '/':
                output.extend((' ', ' '))
                index += 2
                state = 'code'
            else:
                output.append(char if char in '\r\n' else ' ')
                index += 1
            continue
        if state in {'string', 'char'}:
            if char in '\r\n':
                output.append(char)
            else:
                output.append(' ')
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif (state == 'string' and char == '"') or (state == 'char' and char == "'"):
                state = 'code'
            index += 1
            continue
        if char == '/' and next_char == '/':
            output.extend((' ', ' '))
            index += 2
            state = 'line_comment'
            continue
        if char == '/' and next_char == '*':
            output.extend((' ', ' '))
            index += 2
            state = 'block_comment'
            continue
        if char == '"':
            output.append(' ')
            index += 1
            state = 'string'
            escaped = False
            continue
        if char == "'":
            output.append(' ')
            index += 1
            state = 'char'
            escaped = False
            continue
        output.append(char)
        index += 1
    return ''.join(output)


def _normalize_language(value: object) -> str:
    if not isinstance(value, str):
        return ''
    language = value.strip().lower()
    return _LANGUAGE_ALIASES.get(language, language)


def _language_for_function(func_data: Dict) -> str:
    explicit = _normalize_language(func_data.get('language'))
    if explicit:
        return explicit

    file_path = str(func_data.get('file_path', ''))
    extension = Path(file_path).suffix.lower()
    if extension in _CPP_LANGUAGE_EXTENSIONS:
        return 'cpp'
    if extension in _C_LANGUAGE_EXTENSIONS:
        return 'c'
    return 'code'


class UnitGenerator:
    """
    Generate self-contained analysis units from call graph data.

    This is Stage 4 (final stage) of the C/C++ parser pipeline.
    """

    def __init__(self, call_graph_data: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = call_graph_data.get('functions', {})
        self.call_graph = call_graph_data.get('call_graph', {})
        self.reverse_call_graph = call_graph_data.get('reverse_call_graph', {})
        self.repo_path = call_graph_data.get('repository', '')

        self.max_depth = options.get('max_depth', 3)
        self.dataset_name = options.get('dataset_name', Path(self.repo_path).name if self.repo_path else 'dataset')
        self.platform_context = self._prepare_platform_context(
            options.get('platform_context')
        )
        self.semantic_graph = self._prepare_semantic_graph(
            options.get('semantic_graph')
        )

        self.units: List[Dict] = []
        self.statistics = {
            'total_units': 0,
            'by_type': {},
            'units_with_upstream': 0,
            'units_with_downstream': 0,
            'units_with_semantic_context': 0,
            'semantic_context_functions': 0,
            'units_enhanced': 0,
            'avg_upstream': 0,
            'avg_downstream': 0,
        }

    @staticmethod
    def _prepare_platform_context(value: object) -> Optional[Dict[str, Any]]:
        """Normalize the bounded context produced by the repository scanner.

        The scanner's scope format intentionally stays independent from the
        unit schema.  This adapter accepts both the small scope shape used by
        ``RepositoryScanner`` and the richer profile-shaped context used by
        callers/tests, while retaining only data needed for per-file evidence.
        """
        if not isinstance(value, dict) or value.get('platform') != 'openharmony':
            return None

        build_metadata = value.get('build_metadata')
        if not isinstance(build_metadata, dict):
            build_metadata = {}

        file_roles: Dict[str, str] = {}
        raw_file_roles = value.get('file_roles')
        if isinstance(raw_file_roles, dict):
            for path, role in raw_file_roles.items():
                normalized = _normalise_context_path(path)
                if normalized and isinstance(role, str) and role:
                    file_roles[normalized] = role
        raw_files = value.get('files')
        if isinstance(raw_files, list):
            for item in raw_files:
                if not isinstance(item, dict):
                    continue
                path = _normalise_context_path(item.get('path'))
                role = item.get('role')
                if path and isinstance(role, str) and role:
                    file_roles[path] = role

        components: list[dict[str, Any]] = []
        raw_components = value.get('components')
        if isinstance(raw_components, list):
            components.extend(item for item in raw_components if isinstance(item, dict))
        raw_manifests = build_metadata.get('bundle_manifests')
        if isinstance(raw_manifests, list):
            for item in raw_manifests:
                if not isinstance(item, dict):
                    continue
                components.append(
                    {
                        'name': item.get('component') or item.get('name'),
                        'manifest_path': item.get('path'),
                    }
                )

        targets: list[dict[str, Any]] = []
        raw_targets = value.get('targets')
        if isinstance(raw_targets, list):
            targets.extend(item if isinstance(item, dict) else {'name': item} for item in raw_targets)
        gn_metadata = build_metadata.get('gn')
        if isinstance(gn_metadata, dict) and isinstance(gn_metadata.get('targets'), list):
            targets.extend(
                item for item in gn_metadata['targets'] if isinstance(item, dict)
            )
        raw_build_files = build_metadata.get('build_files')
        if isinstance(raw_build_files, list):
            for item in raw_build_files:
                if not isinstance(item, dict):
                    continue
                path = item.get('path')
                names = _context_values(item.get('targets'))
                sources = item.get('sources')
                # The legacy scope parser does not retain source ownership
                # when one BUILD.gn declares multiple targets.  Keep the
                # target names, but do not attach the shared source list to
                # every target and create false memberships.
                target_sources = sources if len(names) == 1 and isinstance(sources, list) else []
                for name in names:
                    targets.append(
                        {
                            'name': name,
                            'path': path,
                            'sources': target_sources,
                        }
                    )

        return {
            'platform': 'openharmony',
            'file_roles': file_roles,
            'components': components,
            'targets': targets,
            'boundaries': _context_values(
                value.get('boundary', value.get('boundaries', []))
            ),
            'guards': _normalise_guard(value.get('guard', value.get('guards', []))),
        }

    @staticmethod
    def _prepare_semantic_graph(value: object) -> Dict[str, Any]:
        """Keep only validated, evidence-backed IPC overlay edges.

        The native call graph remains untouched.  A semantic graph is an
        optional overlay and malformed/unsupported entries are ignored so an
        incomplete resolver result cannot abort legacy unit generation.
        """
        if value is None:
            return {'nodes': set(), 'edges': [], 'adjacency': {}, 'reverse': {}}
        if hasattr(value, 'to_dict'):
            try:
                value = value.to_dict()
            except (AttributeError, TypeError, ValueError):
                return {'nodes': set(), 'edges': [], 'adjacency': {}, 'reverse': {}}
        if not isinstance(value, dict):
            return {'nodes': set(), 'edges': [], 'adjacency': {}, 'reverse': {}}

        raw_nodes = value.get('nodes', [])
        node_ids = {
            item.get('id')
            for item in raw_nodes
            if isinstance(item, dict) and isinstance(item.get('id'), str)
        }
        edges: list[dict[str, Any]] = []
        for item in value.get('edges', []):
            if not isinstance(item, dict):
                continue
            source_id = item.get('source_id')
            target_id = item.get('target_id')
            kind = item.get('kind')
            if (
                not isinstance(source_id, str)
                or not isinstance(target_id, str)
                or not isinstance(kind, str)
                or kind not in _SEMANTIC_CONTEXT_EDGE_KINDS
            ):
                continue
            if not node_ids or source_id not in node_ids or target_id not in node_ids:
                continue
            confidence = item.get('confidence', 0.0)
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                continue
            evidence = item.get('evidence', [])
            if not isinstance(evidence, list):
                evidence = []
            edges.append(
                {
                    'source_id': source_id,
                    'target_id': target_id,
                    'kind': kind,
                    'confidence': max(0.0, min(1.0, float(confidence))),
                    'evidence': [
                        dict(entry)
                        for entry in evidence
                        if isinstance(entry, dict)
                    ],
                }
            )

        edges.sort(key=lambda item: (
            item['source_id'], item['target_id'], item['kind']
        ))
        adjacency: dict[str, list[dict[str, Any]]] = {}
        reverse: dict[str, list[dict[str, Any]]] = {}
        for edge in edges:
            adjacency.setdefault(edge['source_id'], []).append(edge)
            reverse.setdefault(edge['target_id'], []).append(edge)
        return {
            'nodes': node_ids,
            'edges': edges,
            'adjacency': adjacency,
            'reverse': reverse,
        }

    @staticmethod
    def _semantic_function_id(node_id: object) -> str:
        if isinstance(node_id, str) and node_id.startswith('function:'):
            return node_id[len('function:'):]
        return ''

    @staticmethod
    def _semantic_path_key(path: list[dict[str, Any]]) -> tuple:
        return tuple(
            (
                item.get('source_id', ''),
                item.get('target_id', ''),
                item.get('kind', ''),
            )
            for item in path
        )

    def get_semantic_context(self, func_id: str) -> List[Dict[str, Any]]:
        """Return native functions connected by explicit IPC overlay edges.

        A stub/proxy reaches a handler through a transaction in the forward
        direction.  A handler can likewise expose its stub/proxy context via
        reverse traversal.  Transaction nodes themselves are not inlined as
        source functions.
        """
        graph = self.semantic_graph
        root = f'function:{func_id}'
        if not graph['edges']:
            return []

        candidates: dict[str, list[dict[str, Any]]] = {}
        for adjacency_key, reverse in (
            ('adjacency', False),
            ('reverse', True),
        ):
            queue: list[tuple[str, list[dict[str, Any]], int]] = [(root, [], 0)]
            visited: set[tuple[str, bool]] = {(root, reverse)}
            while queue:
                current, path, depth = queue.pop(0)
                if depth >= self.max_depth:
                    continue
                for edge in graph[adjacency_key].get(current, []):
                    next_id = edge['source_id'] if reverse else edge['target_id']
                    next_path = [*path, edge]
                    function_id = self._semantic_function_id(next_id)
                    if function_id and function_id != func_id and function_id in self.functions:
                        candidates.setdefault(function_id, []).append(
                            {
                                'path': next_path,
                                'confidence': min(
                                    item['confidence'] for item in next_path
                                ),
                            }
                        )
                        continue
                    visit_key = (next_id, reverse)
                    if visit_key not in visited:
                        visited.add(visit_key)
                        queue.append((next_id, next_path, depth + 1))

        result: list[Dict[str, Any]] = []
        for function_id, paths in candidates.items():
            selected = sorted(
                paths,
                key=lambda item: (
                    -item['confidence'],
                    len(item['path']),
                    self._semantic_path_key(item['path']),
                ),
            )[0]
            function = self.functions[function_id]
            result.append(
                {
                    'id': function_id,
                    'name': function.get('name', ''),
                    'code': function.get('code', ''),
                    'file_path': function.get('file_path', ''),
                    'unit_type': function.get('unit_type', 'function'),
                    'class_name': function.get('class_name'),
                    'semantic_path': selected['path'],
                    'edge_kinds': [
                        edge['kind'] for edge in selected['path']
                    ],
                    'confidence': selected['confidence'],
                }
            )
        return sorted(result, key=lambda item: item['id'])

    @staticmethod
    def _semantic_context_metadata(context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': context['id'],
            'name': context.get('name'),
            'file_path': context.get('file_path', ''),
            'unit_type': context.get('unit_type', 'function'),
            'edge_kinds': list(context.get('edge_kinds', [])),
            'confidence': context.get('confidence', 0.0),
            'semantic_path': [
                {
                    'source_id': edge.get('source_id', ''),
                    'target_id': edge.get('target_id', ''),
                    'kind': edge.get('kind', ''),
                    'confidence': edge.get('confidence', 0.0),
                    'evidence': list(edge.get('evidence', [])),
                }
                for edge in context.get('semantic_path', [])
            ],
        }

    def _platform_context_for_function(
        self, func_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Build auditable, conservative OpenHarmony context for one function.

        Component/target membership is emitted only for explicit file/source
        matches.  Boundary and guard values are signals, not proof that a
        security check dominates every path through the function.
        """
        context = self.platform_context
        if context is None:
            return None

        file_path = _normalise_context_path(func_data.get('file_path'))
        code = str(func_data.get('code', ''))
        signal_code = _mask_native_comments_and_strings(code)
        component_names: list[str] = []
        target_names: list[str] = []
        evidence: list[dict[str, str]] = []

        role = context['file_roles'].get(file_path, '')
        if role:
            evidence.append(
                {'source': 'scope_file_role', 'path': file_path, 'value': role}
            )

        for component in context['components']:
            name = _record_name(component)
            manifest_path = _record_path(component, 'manifest_path', 'path')
            explicit_files = {
                _normalise_context_path(item)
                for item in _context_values(
                    component.get('files') if isinstance(component, dict) else []
                )
            }
            manifest_parent = posixpath.dirname(manifest_path)
            matches = bool(file_path and file_path in explicit_files)
            if not matches and file_path and manifest_path:
                matches = manifest_parent in {'', '.'} or file_path.startswith(
                    manifest_parent.rstrip('/') + '/'
                )
            if matches and name:
                component_names.append(name)
                evidence.append(
                    {
                        'source': 'bundle_manifest',
                        'path': manifest_path,
                        'value': name,
                    }
                )

        for target in context['targets']:
            name = _record_name(target)
            target_path = _record_path(target, 'path', 'build_file')
            explicit_files = {
                _normalise_context_path(item)
                for item in _context_values(
                    target.get('files') if isinstance(target, dict) else []
                )
            }
            matches = bool(file_path and file_path in explicit_files)
            sources = target.get('sources', []) if isinstance(target, dict) else []
            if not isinstance(sources, (list, tuple)):
                sources = []
            if not matches and file_path and target_path:
                matches = any(
                    _resolve_target_source(target_path, source) == file_path
                    for source in sources
                    if isinstance(source, str)
                )
            if matches and name:
                target_names.append(name)
                evidence.append(
                    {
                        'source': 'gn_target',
                        'path': target_path,
                        'value': name,
                    }
                )

        boundaries = _unique_strings(context['boundaries'])
        for boundary, pattern in _BOUNDARY_SIGNAL_PATTERNS:
            if pattern.search(signal_code) or boundary == 'hdf' and 'hdf' in file_path.lower():
                if boundary not in boundaries:
                    boundaries.append(boundary)
                if pattern.search(signal_code):
                    evidence.append(
                        {
                            'source': 'native_boundary_signal',
                            'value': boundary,
                        }
                    )

        guards = list(context['guards'])
        guard_keys = {(item['kind'], item['matched']) for item in guards}
        for guard in guards:
            evidence.append(
                {
                    'source': 'profile_guard_signal',
                    'kind': guard['kind'],
                    'value': guard['matched'],
                }
            )
        for kind, pattern in _GUARD_SIGNAL_PATTERNS:
            for match in pattern.finditer(signal_code):
                matched = match.group(0)
                key = (kind, matched)
                if key in guard_keys:
                    continue
                guard_keys.add(key)
                guard = {'kind': kind, 'matched': matched}
                guards.append(guard)
                evidence.append(
                    {
                        'source': 'native_guard_signal',
                        'kind': kind,
                        'value': matched,
                    }
                )

        platform_context: Dict[str, Any] = {
            'platform': 'openharmony',
            'source_role': role,
            'component': _unique_strings(component_names),
            'target': _unique_strings(target_names),
            'boundary': boundaries,
            'guard': guards,
            'evidence': evidence,
        }
        return platform_context

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all dependencies (callees) for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        dependencies = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            calls = self.call_graph.get(current_id, [])
            for called_id in calls:
                if called_id not in visited:
                    visited.add(called_id)
                    dependencies.append(called_id)
                    queue.append((called_id, current_depth + 1))

        return dependencies

    def get_callers(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all callers for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        callers = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            caller_ids = self.reverse_call_graph.get(current_id, [])
            for caller_id in caller_ids:
                if caller_id not in visited:
                    visited.add(caller_id)
                    callers.append(caller_id)
                    queue.append((caller_id, current_depth + 1))

        return callers

    def assemble_enhanced_code(self, func_data: Dict,
                                upstream_deps: List[Dict],
                                downstream_callers: List[Dict],
                                semantic_context: Optional[List[Dict]] = None) -> str:
        """Assemble enhanced code with all dependencies using file boundary markers."""
        parts = []
        included_code: Set[str] = set()

        # Add primary code first
        primary_code = func_data.get('code', '')
        parts.append(primary_code)
        included_code.add(primary_code)

        # Add upstream dependencies (functions this calls)
        for dep in upstream_deps:
            dep_code = dep.get('code', '')
            if dep_code and dep_code not in included_code:
                parts.append(dep_code)
                included_code.add(dep_code)

        # Add downstream callers (functions that call this)
        for caller in downstream_callers:
            caller_code = caller.get('code', '')
            if caller_code and caller_code not in included_code:
                parts.append(caller_code)
                included_code.add(caller_code)

        # Semantic IPC functions are context evidence, not ordinary language
        # calls.  Append them after native callers so the Prompt renderer can
        # keep the primary function distinct from all supporting code.
        for context in semantic_context or []:
            context_code = context.get('code', '')
            if context_code and context_code not in included_code:
                parts.append(context_code)
                included_code.add(context_code)

        # See parsers/python/unit_generator.py: each part is scanned-repository
        # source and may forge the separator. Neutralize before joining.
        return FILE_BOUNDARY.join(neutralize_boundaries(p) for p in parts)

    def collect_files_included(self, primary_file: str,
                                upstream_deps: List[Dict],
                                downstream_callers: List[Dict],
                                semantic_context: Optional[List[Dict]] = None) -> List[str]:
        """Collect unique file paths from primary and all dependencies."""
        files: Set[str] = {primary_file}

        for dep in upstream_deps:
            file_path = dep.get('file_path', '')
            if file_path:
                files.add(file_path)

        for caller in downstream_callers:
            file_path = caller.get('file_path', '')
            if file_path:
                files.add(file_path)

        for context in semantic_context or []:
            file_path = context.get('file_path', '')
            if file_path:
                files.add(file_path)

        return sorted(list(files))

    def create_unit(self, func_id: str, func_data: Dict) -> Dict:
        """Create a single analysis unit with full context."""
        file_path = func_data.get('file_path', '')
        func_name = func_data.get('name', '')
        class_name = func_data.get('class_name')
        unit_type = func_data.get('unit_type', 'function')
        language = _language_for_function(func_data)

        # Get upstream dependencies (functions this calls)
        upstream_ids = self.get_dependencies(func_id)
        upstream_deps = []
        for dep_id in upstream_ids:
            dep_func = self.functions.get(dep_id, {})
            if dep_func:
                upstream_deps.append({
                    'id': dep_id,
                    'name': dep_func.get('name'),
                    'code': dep_func.get('code', ''),
                    'file_path': dep_func.get('file_path', ''),
                    'unit_type': dep_func.get('unit_type', 'function'),
                    'class_name': dep_func.get('class_name'),
                })

        # Get downstream callers (functions that call this)
        caller_ids = self.get_callers(func_id)
        downstream_callers = []
        for caller_id in caller_ids:
            caller_func = self.functions.get(caller_id, {})
            if caller_func:
                downstream_callers.append({
                    'id': caller_id,
                    'name': caller_func.get('name'),
                    'code': caller_func.get('code', ''),
                    'file_path': caller_func.get('file_path', ''),
                    'unit_type': caller_func.get('unit_type', 'function'),
                    'class_name': caller_func.get('class_name'),
                })

        semantic_context_functions = self.get_semantic_context(func_id)

        enhanced_code = self.assemble_enhanced_code(
            func_data,
            upstream_deps,
            downstream_callers,
            semantic_context_functions,
        )
        files_included = self.collect_files_included(
            file_path,
            upstream_deps,
            downstream_callers,
            semantic_context_functions,
        )
        has_deps_inlined = len(upstream_deps) > 0 or len(downstream_callers) > 0
        has_semantic_context = len(semantic_context_functions) > 0

        # Get direct calls/callers (depth 1 only)
        direct_calls = self.call_graph.get(func_id, [])
        direct_callers = self.reverse_call_graph.get(func_id, [])

        unit = {
            'id': func_id,
            'language': language,
            'unit_type': unit_type,
            'code': {
                'primary_code': enhanced_code,
                'primary_origin': {
                    'file_path': file_path,
                    'start_line': func_data.get('start_line'),
                    'end_line': func_data.get('end_line'),
                    'function_name': func_name,
                    'class_name': class_name,
                    'deps_inlined': has_deps_inlined,
                    'semantic_context_inlined': has_semantic_context,
                    'semantic_context_ids': [
                        item['id'] for item in semantic_context_functions
                    ],
                    'files_included': files_included,
                    'original_length': len(func_data.get('code', '')),
                    'enhanced_length': len(enhanced_code),
                },
                'dependencies': [],
                'dependency_metadata': {
                    'depth': self.max_depth,
                    'total_upstream': len(upstream_deps),
                    'total_downstream': len(downstream_callers),
                    'total_semantic_context': len(semantic_context_functions),
                    'semantic_context_ids': [
                        item['id'] for item in semantic_context_functions
                    ],
                    'direct_calls': len(direct_calls),
                    'direct_callers': len(direct_callers),
                }
            },
            'ground_truth': {
                'status': 'UNKNOWN',
                'vulnerability_types': [],
                'issues': [],
                'annotation_source': None,
                'annotation_key': None,
                'notes': None,
            },
            'metadata': {
                'language': language,
                'is_static': func_data.get('is_static', False),
                'is_exported': func_data.get('is_exported', True),
                'is_inline': func_data.get('is_inline', False),
                'return_type': func_data.get('return_type', ''),
                'parameters': func_data.get('parameters', []),
                'generator': 'c_unit_generator.py',
                'direct_calls': direct_calls,
                'direct_callers': direct_callers,
                'context_functions': [
                    self._semantic_context_metadata(item)
                    for item in semantic_context_functions
                ],
            }
        }

        platform_context = self._platform_context_for_function(func_data)
        if platform_context is not None:
            unit['platform_context'] = platform_context

        return unit

    def update_statistics(self, unit: Dict) -> None:
        """Update statistics for a unit."""
        self.statistics['total_units'] += 1

        unit_type = unit.get('unit_type', 'function')
        self.statistics['by_type'][unit_type] = self.statistics['by_type'].get(unit_type, 0) + 1

        dep_meta = unit.get('code', {}).get('dependency_metadata', {})
        if dep_meta.get('total_upstream', 0) > 0:
            self.statistics['units_with_upstream'] += 1
        if dep_meta.get('total_downstream', 0) > 0:
            self.statistics['units_with_downstream'] += 1
        semantic_count = dep_meta.get('total_semantic_context', 0)
        if semantic_count > 0:
            self.statistics['units_with_semantic_context'] += 1
            self.statistics['semantic_context_functions'] += semantic_count
        origin = unit.get('code', {}).get('primary_origin', {})
        if origin.get('deps_inlined', False) or origin.get('semantic_context_inlined', False):
            self.statistics['units_enhanced'] += 1

    def generate_units(self) -> Dict:
        """Generate analysis units for all functions."""
        total_upstream = 0
        total_downstream = 0

        for func_id, func_data in self.functions.items():
            unit = self.create_unit(func_id, func_data)
            self.units.append(unit)
            self.update_statistics(unit)

            dep_meta = unit.get('code', {}).get('dependency_metadata', {})
            total_upstream += dep_meta.get('total_upstream', 0)
            total_downstream += dep_meta.get('total_downstream', 0)

        if self.statistics['total_units'] > 0:
            self.statistics['avg_upstream'] = round(total_upstream / self.statistics['total_units'], 2)
            self.statistics['avg_downstream'] = round(total_downstream / self.statistics['total_units'], 2)

        return {
            'name': self.dataset_name,
            'repository': self.repo_path,
            'units': self.units,
            'statistics': self.statistics,
            'metadata': {
                'generator': 'c_unit_generator.py',
                'generated_at': datetime.now().isoformat(),
                'dependency_depth': self.max_depth,
            }
        }

    def generate_analyzer_output(self) -> Dict:
        """Generate analyzer_output.json with camelCase fields for compatibility."""
        functions = {}
        for func_id, func_data in self.functions.items():
            language = _language_for_function(func_data)
            function_output = {
                'name': func_data.get('name', ''),
                'language': language,
                'unitType': func_data.get('unit_type', 'function'),
                'code': func_data.get('code', ''),
                'filePath': func_data.get('file_path', ''),
                'startLine': func_data.get('start_line', 0),
                'endLine': func_data.get('end_line', 0),
                'isStatic': func_data.get('is_static', False),
                'isExported': func_data.get('is_exported', True),
                'isInline': func_data.get('is_inline', False),
                'returnType': func_data.get('return_type', ''),
                'parameters': func_data.get('parameters', []),
                'className': func_data.get('class_name'),
            }
            platform_context = self._platform_context_for_function(func_data)
            if platform_context is not None:
                function_output['platformContext'] = platform_context
            functions[func_id] = function_output

        return {
            'repository': self.repo_path,
            'functions': functions,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate analysis units from C/C++ call graph data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python unit_generator.py call_graph.json
  python unit_generator.py call_graph.json --output dataset.json
  python unit_generator.py call_graph.json --depth 2 --name my_dataset
        '''
    )

    parser.add_argument('input_file', help='Call graph JSON file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--analyzer-output', help='Path for analyzer_output.json')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')
    parser.add_argument('--name', '-n', help='Dataset name (default: derived from repo path)')

    args = parser.parse_args()

    try:
        call_graph_data = read_json(args.input_file)
        options = {
            'max_depth': args.depth,
        }
        if args.name:
            options['dataset_name'] = args.name

        print(f"Processing {len(call_graph_data.get('functions', {}))} functions...", file=sys.stderr)
        print(f"Dependency resolution depth: {args.depth}", file=sys.stderr)

        generator = UnitGenerator(call_graph_data, options)
        result = generator.generate_units()

        stats = result['statistics']
        print(f"\nDataset generated:", file=sys.stderr)
        print(f"  Total units: {stats['total_units']}", file=sys.stderr)
        print(f"  Units with upstream deps: {stats['units_with_upstream']}", file=sys.stderr)
        print(f"  Units with downstream callers: {stats['units_with_downstream']}", file=sys.stderr)
        print(f"  Enhanced units: {stats['units_enhanced']}", file=sys.stderr)
        print(f"  Avg upstream deps: {stats['avg_upstream']}", file=sys.stderr)
        print(f"  Avg downstream callers: {stats['avg_downstream']}", file=sys.stderr)
        print(f"\nBy type:", file=sys.stderr)
        for unit_type, count in sorted(stats['by_type'].items()):
            print(f"  {unit_type}: {count}", file=sys.stderr)

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"\nOutput written to: {args.output}", file=sys.stderr)
        else:
            print(output)

        # Write analyzer output if requested
        if args.analyzer_output:
            analyzer = generator.generate_analyzer_output()
            write_json(args.analyzer_output, analyzer)
            print(f"Analyzer output written to: {args.analyzer_output}", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
