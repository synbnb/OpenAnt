"""按 ``compile_commands.json`` 批量提取 C/C++ 的 Clang 直接调用事实。

这是 P1 的保守语义前端，而不是完整的指针分析器：它只把 Clang AST
中能够绑定到直接函数声明或成员声明的调用提交给
``clang_semantic_overlay`` 做统一校验。解析失败、动态目标不明确和缺少
构建上下文的翻译单元都会保留在 ``diagnostics``，不会被伪装成“没有调用”。
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shlex
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .clang_context import _repository_roots, prepare_clang_context
from .clang_semantic_overlay import load_clang_semantic_overlay


SCHEMA_VERSION = 1
TASK = "openharmony_clang_batch_extraction"
CHECKPOINT_SCHEMA_VERSION = 1
DEPENDENCY_GAP_SCHEMA_VERSION = 1
_HEADER_CANDIDATE_CACHE: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
_FUNCTION_KINDS = {"FunctionDecl", "CXXMethodDecl", "ObjCMethodDecl"}
# Operator overloads are represented by a separate AST kind and require
# overload/type-argument handling beyond this conservative direct-call sidecar.
# Leaving them out avoids manufacturing edges from dependent libc++ templates.
_CALL_KINDS = {"CallExpr", "CXXMemberCallExpr"}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _path(value: Any, *, base: Path | None = None) -> Path:
    candidate = Path(_text(value))
    if not candidate.is_absolute() and base is not None:
        candidate = base / candidate
    try:
        return candidate.resolve()
    except OSError:
        return candidate.absolute()


def _path_key(value: Any) -> str:
    return _text(value).replace("\\", "/").rstrip("/")


def _is_source(path: Path) -> bool:
    return path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def _priority_source_keys(
    values: Iterable[str | os.PathLike[str]] | None,
    *,
    repository: Path,
) -> tuple[list[str], set[str]]:
    """Normalise gap-report paths for deterministic compile-entry ordering.

    Call-site ledgers generally store repository-relative paths while
    compilation databases usually contain absolute paths.  Keep both the
    resolved path and the normalised user spelling so a priority hint remains
    useful across those representations.  The hint changes scheduling only;
    it never changes which fact is accepted as a semantic edge.
    """
    display: list[str] = []
    keys: set[str] = set()
    for raw in values or []:
        text = _text(raw).replace("\\", "/")
        if not text:
            continue
        candidate = _path(text, base=repository)
        keys.add(_path_key(candidate))
        # A repository-relative spelling is also useful when a compile entry
        # was generated with a relative ``file`` field.
        if not Path(text).is_absolute():
            keys.add(text.lstrip("./"))
        if text not in display:
            display.append(text)
    return display, keys


def _entry_source_matches_priority(
    source_path: Path,
    entry: Mapping[str, Any],
    *,
    repository: Path,
    priority_keys: set[str],
) -> bool:
    if not priority_keys:
        return False
    candidates = {_path_key(source_path)}
    raw_file = _text(entry.get("file"))
    if raw_file and not Path(raw_file).is_absolute():
        candidates.add(raw_file.replace("\\", "/").lstrip("./"))
        candidates.add(_path_key(_path(raw_file, base=_path(entry.get("directory") or repository))))
    return bool(candidates & priority_keys)


def load_compile_commands(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Load and minimally validate a compilation database."""
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError("compile_commands.json must contain an array")
    entries: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, Mapping) or not _text(item.get("file")):
            continue
        entries.append(dict(item))
    return entries


def find_compile_commands(
    repository: str | os.PathLike[str],
    explicit: str | os.PathLike[str] | None = None,
) -> Path | None:
    """Find a bounded compilation database without scanning unrelated trees."""
    root = Path(repository).resolve()
    if explicit:
        candidate = _path(explicit, base=root)
        return candidate if candidate.is_file() else None
    candidates = [
        root / "compile_commands.json",
        root / "out" / "compile_commands.json",
        root / "out" / "default" / "compile_commands.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    # Build systems often put it one level below a product directory.  Keep
    # discovery bounded to avoid traversing caches and external dependencies.
    try:
        for candidate in sorted(root.glob("out/*/compile_commands.json")):
            if candidate.is_file():
                return candidate
    except OSError:
        pass
    return None


def _command_argv(entry: Mapping[str, Any], source: Path) -> list[str]:
    raw = entry.get("arguments")
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        argv = list(raw)
    else:
        command = _text(entry.get("command"))
        if not command:
            raise ValueError("compile entry has neither arguments nor command")
        argv = shlex.split(command)
    if not argv:
        raise ValueError("empty compile command")
    cleaned: list[str] = []
    skip_next = False
    for index, value in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if value == "-c":
            continue
        if value in {"-o", "--output", "-MF", "-MT", "-MQ", "-MJ"}:
            skip_next = True
            continue
        cleaned.append(value)
    # The compile database normally includes the source path.  If a generator
    # omitted it, append the resolved path so Clang parses the intended unit.
    source_resolved = _path(source)
    has_source = False
    for value in cleaned:
        if value.startswith("-"):
            continue
        try:
            if _path(value, base=source.parent) == source_resolved:
                has_source = True
                break
        except OSError:
            continue
    if not has_source:
        cleaned.append(str(source))
    cleaned.extend(["-fsyntax-only", "-Xclang", "-ast-dump=json"])
    return cleaned


def _line_from_offset(source: str, offset: Any) -> int:
    try:
        value = int(offset)
    except (TypeError, ValueError):
        return 1
    value = max(0, min(value, len(source)))
    return source.count("\n", 0, value) + 1


def _range_start(node: Mapping[str, Any]) -> int:
    raw_range = node.get("range")
    if not isinstance(raw_range, Mapping):
        return -1
    begin = raw_range.get("begin")
    return int(begin.get("offset", -1)) if isinstance(begin, Mapping) and str(begin.get("offset", "")).lstrip("-").isdigit() else -1


def _range_end(node: Mapping[str, Any]) -> int:
    raw_range = node.get("range")
    if not isinstance(raw_range, Mapping):
        return -1
    end = raw_range.get("end")
    if not isinstance(end, Mapping):
        return -1
    try:
        offset = int(end.get("offset", -1))
        token_length = int(end.get("tokLen", 0) or 0)
    except (TypeError, ValueError):
        return -1
    return offset + max(0, token_length)


def _node_line(node: Mapping[str, Any], source: str) -> int:
    loc = node.get("loc")
    if isinstance(loc, Mapping) and loc.get("line") is not None:
        try:
            return max(1, int(loc["line"]))
        except (TypeError, ValueError):
            pass
    return _line_from_offset(source, _range_start(node))


def _children(node: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    raw = node.get("inner")
    if not isinstance(raw, list):
        return []
    return (item for item in raw if isinstance(item, Mapping))


def _qualified_name(node: Mapping[str, Any], contexts: tuple[str, ...]) -> str:
    name = _text(node.get("name"))
    if not name:
        return ""
    # RecordDecl/NamespaceDecl names are carried in the traversal context.
    # Avoid the synthetic translation-unit context.
    context = [item for item in contexts if item and item not in {"<anonymous>", "::"}]
    return "::".join([*context, name]) if context else name


def _walk_ast(
    node: Mapping[str, Any],
    *,
    source: str,
    contexts: tuple[str, ...] = (),
    parent_function: Mapping[str, Any] | None = None,
) -> Iterable[tuple[str, Mapping[str, Any], tuple[str, ...], Mapping[str, Any] | None]]:
    kind = _text(node.get("kind"))
    next_contexts = contexts
    if kind in {"NamespaceDecl", "CXXRecordDecl", "RecordDecl", "ClassTemplateDecl"}:
        name = _text(node.get("name"))
        if name:
            next_contexts = (*contexts, name)
    current_function = parent_function
    if kind in _FUNCTION_KINDS and _range_start(node) >= 0:
        current_function = node
    yield kind, node, next_contexts, current_function
    for child in _children(node):
        yield from _walk_ast(
            child,
            source=source,
            contexts=next_contexts,
            parent_function=current_function,
        )


def _index_functions(
    ast: Mapping[str, Any], source: str
) -> tuple[dict[str, Mapping[str, Any]], dict[str, str], dict[str, Mapping[str, Any]]]:
    declarations: dict[str, Mapping[str, Any]] = {}
    all_nodes: dict[str, Mapping[str, Any]] = {}
    canonical: dict[str, str] = {}
    for kind, node, contexts, _parent in _walk_ast(ast, source=source):
        node_id = _text(node.get("id"))
        if node_id:
            all_nodes[node_id] = node
        if kind not in _FUNCTION_KINDS:
            continue
        ast_id = node_id
        if not ast_id:
            continue
        declarations[ast_id] = node
        previous = _text(node.get("previousDecl"))
        canonical[ast_id] = previous if previous and previous in declarations else ast_id
    # Resolve chains such as definition -> declaration -> prior declaration.
    for ast_id in list(canonical):
        seen: set[str] = set()
        current = canonical[ast_id]
        while current in canonical and current not in seen and canonical[current] != current:
            seen.add(current)
            current = canonical[current]
        canonical[ast_id] = current
    return declarations, canonical, all_nodes


def _known_match(
    functions: Mapping[str, Mapping[str, Any]],
    source_path: Path,
    qualified_name: str,
    line: int,
) -> str | None:
    path_text = _path_key(source_path)
    exact: list[str] = []
    suffix: list[str] = []
    for function_id, function in functions.items():
        file_path = _path_key(function.get("file_path") or function.get("filePath"))
        if not file_path:
            continue
        if not (path_text == file_path or path_text.endswith("/" + file_path) or file_path.endswith("/" + path_text)):
            continue
        try:
            start = int(function.get("start_line", 1) or 1)
            end = int(function.get("end_line", start) or start)
        except (TypeError, ValueError):
            start, end = 1, 10**9
        if not (start <= line <= end):
            continue
        name = _text(function.get("name"))
        suffix.append(function_id)
        if qualified_name and name == qualified_name:
            exact.append(function_id)
    if len(exact) == 1:
        return exact[0]
    if len(suffix) == 1:
        return suffix[0]
    return exact[0] if exact else (suffix[0] if suffix else None)


def _ast_decl_name(decl: Mapping[str, Any], declarations: Mapping[str, Mapping[str, Any]]) -> str:
    name = _text(decl.get("name"))
    parent_id = _text(decl.get("parentDeclContextId"))
    parent = declarations.get(parent_id)
    if parent is not None:
        parent_name = _text(parent.get("name"))
        if parent_name and name:
            return f"{parent_name}::{name}"
    return name


def _decl_source_file(decl: Mapping[str, Any], fallback: Path) -> str:
    """Best-effort source file for an AST declaration.

    ``loc.file`` is not emitted for every declaration.  Clang does however
    preserve the originating header in ``includedFrom`` for declarations
    imported into a translation unit, which is enough to avoid interpreting a
    header line number as a line in the main source file.
    """
    loc = decl.get("loc")
    if isinstance(loc, Mapping) and loc.get("file"):
        return _path_key(loc.get("file"))
    markers = _include_marker_paths(decl)
    if markers:
        return markers[0]
    raw_range = decl.get("range")
    if isinstance(raw_range, Mapping):
        begin = raw_range.get("begin")
        if isinstance(begin, Mapping):
            marker = begin.get("includedFrom")
            if isinstance(marker, Mapping) and marker.get("file"):
                return _path_key(marker.get("file"))
    return _path_key(fallback)


def _receiver_type(member: Mapping[str, Any]) -> str:
    """Extract the static receiver type from a MemberExpr base."""
    for child in _children(member):
        type_info = child.get("type")
        if isinstance(type_info, Mapping):
            value = _text(type_info.get("desugaredQualType") or type_info.get("qualType"))
            if value:
                return value
    return ""


def _short_type(type_name: str) -> str:
    value = _text(type_name)
    value = value.replace("const ", "").replace("volatile ", "")
    value = value.rstrip("&* ")
    if "<" in value:
        value = value.split("<", 1)[0]
    return value.split("::")[-1].strip()


def _target_evidence_text(function: Mapping[str, Any] | None, fallback: str) -> str:
    """Return a bounded target-source quote instead of only a method name."""
    if isinstance(function, Mapping):
        code = _text(function.get("code"))
        if code:
            # Keep report evidence useful without copying a large function
            # into every edge record.
            quote = "\n".join(code.splitlines()[:12]).strip()
            if len(quote) > 2400:
                quote = quote[:2400] + "…"
            if quote:
                return quote
    return fallback


def _attach_definition_candidates(
    symbols: dict[str, dict[str, Any]],
    functions: Mapping[str, Mapping[str, Any]],
) -> dict[str, int]:
    """Attach conservative cross-translation-unit body candidates to symbols.

    A matching function name is only a definition *candidate*.  It does not
    prove that a declaration and body are the same overload, nor does it add
    an edge.  The metadata lets a later type-aware resolver load the relevant
    translation unit instead of losing the symbol at the dataset boundary.
    """
    counts = {"unique": 0, "ambiguous": 0, "none": 0}
    for symbol in symbols.values():
        if not isinstance(symbol, dict):
            continue
        name = _text(symbol.get("name"))
        if not name:
            counts["none"] += 1
            symbol["definition_resolution"] = "none"
            symbol["definition_candidates"] = []
            continue
        exact = [
            str(function_id)
            for function_id, function in functions.items()
            if isinstance(function, Mapping)
            and _text(function.get("name")) == name
        ]
        exact = sorted(set(exact))
        symbol["definition_candidates"] = exact[:32]
        if len(exact) == 1:
            counts["unique"] += 1
            symbol["definition_resolution"] = "unique_candidate"
        elif len(exact) > 1:
            counts["ambiguous"] += 1
            symbol["definition_resolution"] = "ambiguous_candidates"
        else:
            counts["none"] += 1
            symbol["definition_resolution"] = "none"
    return counts


def _build_definition_loading_plan(
    symbols: Mapping[str, Mapping[str, Any]],
    functions: Mapping[str, Mapping[str, Any]],
    compile_entries: Iterable[Mapping[str, Any]],
    *,
    repository: Path,
    selected_sources: Iterable[Path],
    max_files: int,
) -> list[dict[str, Any]]:
    """Plan bounded loading of translation units containing symbol bodies.

    The plan is conservative: only a symbol with exactly one current
    definition candidate is scheduled. Ambiguous and missing definitions stay
    explicit tasks. The plan itself is not a binding decision and never adds
    a call edge.
    """
    entry_by_source: dict[str, tuple[dict[str, Any], Path, Path]] = {}
    for raw_entry in compile_entries:
        if not isinstance(raw_entry, Mapping) or not _text(raw_entry.get("file")):
            continue
        entry = dict(raw_entry)
        cwd = _path(entry.get("directory") or repository)
        source_path = _path(entry.get("file"), base=cwd)
        if _is_source(source_path):
            entry_by_source[_path_key(source_path)] = (entry, cwd, source_path)
    selected_keys = {_path_key(path) for path in selected_sources}
    scheduled_sources: set[str] = set()
    plan: list[dict[str, Any]] = []
    budget = max(0, int(max_files or 0))
    for symbol_id, symbol in sorted(symbols.items(), key=lambda item: str(item[0])):
        if not isinstance(symbol, Mapping):
            continue
        candidates = [
            _text(value) for value in symbol.get("definition_candidates", [])
            if _text(value)
        ]
        resolution = _text(symbol.get("definition_resolution")) or "none"
        item: dict[str, Any] = {
            "symbol_id": str(symbol_id),
            "symbol_name": _text(symbol.get("name")),
            "definition_resolution": resolution,
            "definition_candidates": sorted(set(candidates)),
            "status": "unresolved",
        }
        if resolution != "unique_candidate" or len(candidates) != 1:
            item["status"] = (
                "ambiguous_definition" if resolution == "ambiguous_candidates"
                else "definition_not_found"
            )
            plan.append(item)
            continue
        definition_id = candidates[0]
        definition = functions.get(definition_id)
        if not isinstance(definition, Mapping):
            item["status"] = "definition_function_missing"
            plan.append(item)
            continue
        definition_path = _path(
            definition.get("file_path") or definition.get("filePath"),
            base=repository,
        )
        item["definition_id"] = definition_id
        item["definition_file"] = str(definition_path)
        source_key = _path_key(definition_path)
        if source_key in selected_keys:
            item["status"] = "already_in_initial_batch"
            plan.append(item)
            continue
        command_entry = entry_by_source.get(source_key)
        if command_entry is None:
            item["status"] = "definition_compile_entry_missing"
            plan.append(item)
            continue
        if source_key in scheduled_sources:
            item["status"] = "deduplicated_definition_file"
            plan.append(item)
            continue
        if len(scheduled_sources) >= budget:
            item["status"] = "definition_load_budget_exceeded"
            plan.append(item)
            continue
        entry, cwd, source_path = command_entry
        scheduled_sources.add(source_key)
        item.update({
            "status": "scheduled",
            "compile_entry": entry,
            "working_directory": str(cwd),
            "source_path": str(source_path),
        })
        plan.append(item)
    return plan


def _run_definition_loading(
    *,
    plan: list[dict[str, Any]],
    functions: Mapping[str, Mapping[str, Any]],
    source_revision: str | None,
    effective_build_status: str,
    timeout_seconds: int,
    base: dict[str, Any],
    raw_edges: list[dict[str, Any]],
    raw_symbols: dict[str, dict[str, Any]],
    raw_unindexed_calls: list[dict[str, Any]],
    file_results: list[dict[str, Any]],
    checkpoint: dict[str, Any],
    resolved_checkpoint: Path | None,
) -> None:
    """Execute scheduled definition loads and retain all outcomes."""
    for item in plan:
        if item.get("status") != "scheduled":
            continue
        entry = item.get("compile_entry")
        if not isinstance(entry, Mapping):
            item["status"] = "definition_compile_entry_missing"
            continue
        source_path = _path(item.get("source_path"))
        cwd = _path(item.get("working_directory") or source_path.parent)
        fingerprint = _checkpoint_entry_fingerprint(
            entry,
            source_path=source_path,
            source_revision=source_revision,
            build_status=effective_build_status,
        )
        unit_key = f"{source_path}::{fingerprint[:16]}"
        item["unit_key"] = unit_key
        item["fingerprint"] = fingerprint
        checkpoint_record = checkpoint.get("files", {}).get(unit_key)
        if (
            isinstance(checkpoint_record, Mapping)
            and checkpoint_record.get("fingerprint") == fingerprint
            and checkpoint_record.get("status") == "succeeded"
            and checkpoint_record.get("definition_load") is True
        ):
            cached_edges = checkpoint_record.get("edges", [])
            cached_symbols = checkpoint_record.get("symbols", {})
            cached_unindexed = checkpoint_record.get("unindexed_calls", [])
            cached_counters = checkpoint_record.get("counters", {})
            if isinstance(cached_edges, list) and isinstance(cached_symbols, Mapping):
                raw_edges.extend(item for item in cached_edges if isinstance(item, Mapping))
                raw_symbols.update({
                    str(key): dict(value)
                    for key, value in cached_symbols.items()
                    if isinstance(value, Mapping)
                })
                raw_unindexed_calls.extend(
                    item for item in cached_unindexed if isinstance(item, Mapping)
                )
                base["summary"]["files_succeeded"] += 1
                base["summary"]["files_reused"] += 1
                base["summary"]["definition_files_reused"] += 1
                item["status"] = "reused"
                item["counters"] = dict(cached_counters)
                file_results.append({
                    "file": str(source_path),
                    "status": "definition_reused",
                    "source_kind": "definition_load",
                    "build_status": effective_build_status,
                    "unit_key": unit_key,
                    "fingerprint": fingerprint,
                    "call_sites": cached_counters.get("call_sites", 0),
                    "bound_calls": cached_counters.get("bound_calls", 0),
                    "ambiguous_calls": cached_counters.get("ambiguous_calls", 0),
                    "caller_not_in_index": cached_counters.get("caller_not_in_index", 0),
                    "caller_symbols_added": cached_counters.get("caller_symbols_added", 0),
                    "edge_count": len(cached_edges),
                })
                continue
        base["summary"]["definition_files_executed"] += 1
        base["summary"]["files_executed"] += 1
        try:
            edges, symbols, counters, unindexed_calls = _execute_translation_unit(
                entry,
                cwd=cwd,
                source_path=source_path,
                functions=functions,
                source_revision=source_revision,
                timeout_seconds=timeout_seconds,
            )
            raw_edges.extend(edges)
            raw_symbols.update(symbols)
            raw_unindexed_calls.extend(unindexed_calls)
            for key, value in counters.items():
                if key in base["summary"]:
                    base["summary"][key] += int(value or 0)
            base["summary"]["definition_files_succeeded"] += 1
            base["summary"]["files_succeeded"] += 1
            item.update({
                "status": "loaded",
                "counters": counters,
                "edge_count": len(edges),
            })
            file_results.append({
                "file": str(source_path),
                "status": "definition_loaded",
                "source_kind": "definition_load",
                "build_status": effective_build_status,
                "unit_key": unit_key,
                "fingerprint": fingerprint,
                "call_sites": counters.get("call_sites", 0),
                "bound_calls": counters.get("bound_calls", 0),
                "ambiguous_calls": counters.get("ambiguous_calls", 0),
                "caller_not_in_index": counters.get("caller_not_in_index", 0),
                "caller_symbols_added": counters.get("caller_symbols_added", 0),
                "edge_count": len(edges),
            })
            checkpoint["files"][unit_key] = {
                "file": str(source_path),
                "fingerprint": fingerprint,
                "status": "succeeded",
                "definition_load": True,
                "counters": counters,
                "edges": edges,
                "symbols": symbols,
                "unindexed_calls": unindexed_calls,
            }
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            base["summary"]["definition_files_failed"] += 1
            item.update({"status": "failed", "error": str(exc)[:4000]})
            file_results.append({
                "file": str(source_path),
                "status": "failed",
                "source_kind": "definition_load",
                "build_status": effective_build_status,
                "unit_key": unit_key,
                "fingerprint": fingerprint,
                "error": str(exc)[:4000],
            })
            base["diagnostics"].append({
                "file": str(source_path),
                "reason": "clang_definition_load_failed",
                "error": str(exc)[:4000],
            })
        _write_checkpoint(resolved_checkpoint, checkpoint)


def _persist_definition_loading_report(
    *,
    plan: list[dict[str, Any]],
    base: Mapping[str, Any],
    repository: Path,
    source_revision: str | None,
    build_status: str,
    context_output_dir: str | os.PathLike[str] | None,
) -> str | None:
    """Persist the final definition-load plan after dependency retries."""
    if not context_output_dir:
        return None
    path = Path(context_output_dir).resolve() / "clang_definition_loading_report.json"
    summary = base.get("summary") if isinstance(base.get("summary"), Mapping) else {}
    payload = {
        "schema_version": 1,
        "task": "openharmony_clang_definition_loading",
        "repository": str(repository),
        "source_revision": source_revision,
        "build_status": build_status,
        "summary": {
            key: summary.get(key, 0)
            for key in (
                "definition_files_scheduled",
                "definition_files_executed",
                "definition_files_reused",
                "definition_files_succeeded",
                "definition_files_failed",
                "symbols_with_unique_definition_candidate",
                "symbols_with_ambiguous_definition_candidates",
                "symbols_without_definition_candidate",
            )
        },
        "plan": plan,
        "interpretation": (
            "定义加载结果是增量语义事实；唯一候选也不自动证明重载/动态分派等价，"
            "必须继续经过统一 overlay 校验后才能形成有效边。"
        ),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)
    except OSError:
        return None


def _match_member_function(
    functions: Mapping[str, Mapping[str, Any]],
    receiver_type: str,
    method_name: str,
) -> str | None:
    receiver = _short_type(receiver_type)
    method = _text(method_name)
    if not receiver or not method:
        return None
    candidates: list[str] = []
    suffix = f"::{method}"
    for function_id, function in functions.items():
        name = _text(function.get("name"))
        if name.endswith(suffix) and receiver in name.split("::"):
            candidates.append(function_id)
    return candidates[0] if len(candidates) == 1 else None


def _match_function_name(
    functions: Mapping[str, Mapping[str, Any]],
    qualified_name: str,
    method_name: str,
) -> str | None:
    qualified = _text(qualified_name)
    if qualified:
        exact = [
            function_id for function_id, function in functions.items()
            if _text(function.get("name")) == qualified
        ]
        if len(exact) == 1:
            return exact[0]
    short = _text(method_name).split("::")[-1]
    candidates = [
        function_id for function_id, function in functions.items()
        if _text(function.get("name")).endswith(f"::{short}")
    ]
    return candidates[0] if len(candidates) == 1 else None


def _source_snippet(source: str, start: int, end: int) -> str:
    if start < 0 or end < start:
        return ""
    return source[start:min(len(source), end + 1)].strip()


def _source_line(source: str, line: int) -> str:
    lines = source.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def _find_call_line(
    source: str,
    function: Mapping[str, Any],
    call_name: str,
    fallback: int,
) -> int:
    """Use the source spelling to repair Clang offsets from macro/header ASTs."""
    method = _text(call_name)
    if not method or method.startswith("operator"):
        return fallback
    try:
        start = max(1, int(function.get("start_line", 1) or 1))
        end = min(len(source.splitlines()), int(function.get("end_line", start) or start))
    except (TypeError, ValueError):
        return fallback
    pattern = re.compile(r"\b" + re.escape(method) + r"\s*\(")
    matches = [line_no for line_no, line in enumerate(source.splitlines(), 1)
               if start <= line_no <= end and pattern.search(line)]
    if len(matches) == 1:
        return matches[0]
    if fallback in matches:
        return fallback
    return matches[0] if matches else fallback


def _include_marker_paths(node: Mapping[str, Any]) -> list[str]:
    """Return source paths recorded by Clang's ``includedFrom`` markers."""
    paths: list[str] = []
    raw_range = node.get("range")
    if isinstance(raw_range, Mapping):
        for key in ("begin", "end"):
            location = raw_range.get(key)
            if isinstance(location, Mapping):
                marker = location.get("includedFrom")
                if isinstance(marker, Mapping) and marker.get("file"):
                    paths.append(_path_key(marker.get("file")))
    location = node.get("loc")
    if isinstance(location, Mapping):
        marker = location.get("includedFrom")
        if isinstance(marker, Mapping) and marker.get("file"):
            paths.append(_path_key(marker.get("file")))
    return paths


def _has_include_marker(node: Mapping[str, Any]) -> bool:
    """Return whether an AST range belongs to an included header.

    Clang's JSON AST omits ``loc`` for many nodes and instead records an
    ``includedFrom`` marker on the range.  The batch extractor must not turn
    every libc/libc++ call into a ``caller_not_in_function_index`` diagnostic
    for the translation unit being analysed.
    """
    return bool(_include_marker_paths(node))


def _is_source_range(node: Mapping[str, Any], source_path: Path, source: str) -> bool:
    """Keep diagnostics limited to nodes physically in the main source file."""
    source_key = _path_key(source_path)
    for marker in _include_marker_paths(node):
        # Clang records the main translation unit as includedFrom for some
        # instantiated nodes.  Only markers that point elsewhere are foreign
        # header nodes.
        if not (marker == source_key or marker.endswith("/" + source_key)):
            return False
    start = _range_start(node)
    return start >= 0 and start <= len(source)


def _raw_edges_for_translation_unit(
    ast: Mapping[str, Any],
    *,
    source_path: Path,
    source: str,
    functions: Mapping[str, Mapping[str, Any]],
    source_revision: str | None,
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, int],
    list[dict[str, Any]],
]:
    declarations, canonical, all_nodes = _index_functions(ast, source)
    symbols: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    counters = {
        "call_sites": 0,
        "bound_calls": 0,
        "ambiguous_calls": 0,
        "caller_not_in_index": 0,
        "caller_symbols_added": 0,
    }
    unindexed_calls: list[dict[str, Any]] = []
    for kind, node, contexts, parent in _walk_ast(ast, source=source):
        if kind not in _CALL_KINDS or parent is None:
            continue
        if not _is_source_range(node, source_path, source) or not _is_source_range(parent, source_path, source):
            continue
        counters["call_sites"] += 1
        caller_line = _node_line(parent, source)
        caller_name = _qualified_name(parent, contexts)
        caller_id = _known_match(functions, source_path, caller_name, caller_line)
        if caller_id is None:
            call_start = _range_start(node)
            call_end = _range_end(node)
            expression = _source_snippet(source, call_start, call_end)
            counters["caller_not_in_index"] += 1
            call_record = {
                "file": _path_key(source_path),
                "line": _line_from_offset(source, call_start),
                "expression": expression,
                "caller_name": caller_name,
                "call_kind": kind,
                "reason": "caller_not_in_function_index",
            }
            # Preserve a source-backed symbol for a real user-defined caller
            # even when the parser's function index omitted its body. This is
            # deliberately a symbol node, not an analyzable function unit and
            # not an entry-point promotion. Standard-library/template
            # implementation callers remain diagnostics only.
            if caller_name and not caller_name.startswith(("std::", "__")):
                symbol_start = max(1, caller_line)
                symbol_end = _line_from_offset(
                    source, max(_range_start(parent), _range_end(parent))
                )
                if symbol_end < symbol_start:
                    symbol_end = symbol_start
                symbol_id = f"{_path_key(source_path)}:{caller_name}"
                symbol_code = "\n".join(
                    source.splitlines()[symbol_start - 1:min(symbol_end, symbol_start + 11)]
                ).strip()
                symbol_candidate = {
                    "name": caller_name,
                    "file_path": _path_key(source_path),
                    "start_line": symbol_start,
                    "end_line": symbol_end,
                    "unit_type": "symbol",
                    "declaration_only": True,
                    "body_available": False,
                    "index_status": "caller_not_in_function_index",
                    "source_kind": "clang_ast_caller",
                    "code": symbol_code,
                }
                existing = symbols.get(symbol_id)
                if existing is None:
                    symbols[symbol_id] = symbol_candidate
                    counters["caller_symbols_added"] += 1
                elif existing != symbol_candidate:
                    # The same qualified name can occur in generated or
                    # macro-expanded source. Keep each distinct declaration
                    # visible without manufacturing a collision.
                    suffix = symbol_start
                    qualified_id = f"{symbol_id}@{suffix}"
                    while qualified_id in symbols and symbols[qualified_id] != symbol_candidate:
                        suffix += 1
                        qualified_id = f"{symbol_id}@{suffix}"
                    if qualified_id not in symbols:
                        symbols[qualified_id] = symbol_candidate
                        counters["caller_symbols_added"] += 1
                    symbol_id = qualified_id
                call_record["caller_symbol_id"] = symbol_id
                call_record["caller_symbol_status"] = "declaration_only"
            unindexed_calls.append(call_record)
            continue
        inner = list(_children(node))
        referenced_id = ""
        call_name = ""
        receiver_type = ""
        if inner:
            callee_node = inner[0]
            if kind == "CXXMemberCallExpr" and _text(callee_node.get("kind")) == "MemberExpr":
                referenced_id = _text(callee_node.get("referencedMemberDecl"))
                call_name = _text(callee_node.get("name"))
                receiver_type = _receiver_type(callee_node)
            else:
                for candidate in [callee_node, *list(_children(callee_node))]:
                    if _text(candidate.get("referencedDecl")):
                        referenced = candidate.get("referencedDecl")
                        referenced_id = _text(referenced.get("id") if isinstance(referenced, Mapping) else referenced)
                        call_name = _text(candidate.get("name"))
                        break
        if not referenced_id:
            counters["ambiguous_calls"] += 1
            continue
        canonical_id = canonical.get(referenced_id, referenced_id)
        declaration = declarations.get(canonical_id) or declarations.get(referenced_id)
        if declaration is None:
            counters["ambiguous_calls"] += 1
            continue
        is_virtual_dispatch = bool(
            declaration.get("virtual")
            or declaration.get("pure")
        )
        target_line = _node_line(declaration, source)
        target_name = _ast_decl_name(declaration, all_nodes) or call_name
        declaration_file = _decl_source_file(declaration, source_path)
        declaration_is_main_file = (
            declaration_file == _path_key(source_path)
            or declaration_file.endswith("/" + _path_key(source_path))
        )
        # Header declarations carry header-local line numbers.  Never use
        # those line numbers to match a function in the main translation unit;
        # prefer the receiver's static type and method spelling instead.
        callee_id = None
        if kind == "CXXMemberCallExpr":
            callee_id = _match_member_function(functions, receiver_type, call_name)
        if callee_id is None and declaration_is_main_file:
            callee_id = _known_match(functions, source_path, target_name, target_line)
        if callee_id is None:
            callee_id = _match_function_name(functions, target_name, call_name)
        target_file = source_path
        target_start = _range_start(declaration)
        target_end = _range_end(declaration)
        if callee_id is not None:
            callee_function = functions[callee_id]
            target_file = Path(_text(callee_function.get("file_path")))
            target_start = int(callee_function.get("start_line", target_line) or target_line)
            target_end = int(callee_function.get("end_line", target_line) or target_line)
        else:
            # Keep a declaration-only symbol. It may be defined in another
            # translation unit and can still participate in the effective graph.
            declaration_loc = declaration.get("loc")
            relative_file = declaration_file or _path_key(source_path)
            target_id = f"{relative_file}:{target_name or call_name or 'anonymous'}"
            # A declaration-only name is not necessarily unique: overloaded
            # methods and repeated declarations can share the same spelling.
            # Reuse an identical declaration, but make a stable line-qualified
            # identity for conflicting declarations so the semantic graph does
            # not fail later with a node-definition collision.
            symbol_name = target_name or call_name or "anonymous"
            target_start = target_line
            target_end = target_line
            symbol_candidate = {
                "name": symbol_name,
                "file_path": relative_file,
                "start_line": target_line,
                "end_line": target_end,
                "unit_type": "declaration",
                "declaration_only": True,
            }
            existing = symbols.get(target_id)
            if existing is not None and any(
                existing.get(key) != value
                for key, value in symbol_candidate.items()
            ):
                suffix = target_line
                qualified_id = f"{target_id}@{suffix}"
                while qualified_id in symbols and any(
                    symbols[qualified_id].get(key) != value
                    for key, value in symbol_candidate.items()
                ):
                    suffix += 1
                    qualified_id = f"{target_id}@{suffix}"
                target_id = qualified_id
            callee_id = target_id
            target_file = Path(relative_file)
            symbols[callee_id] = symbol_candidate
        call_start = _range_start(node)
        call_end = _range_end(node)
        caller_function = functions[caller_id]
        call_line = _line_from_offset(source, call_start)
        call_line = _find_call_line(source, caller_function, call_name, call_line)
        expression = _source_line(source, call_line)
        if not expression:
            expression = _source_snippet(source, call_start, call_end)
        if not expression:
            counters["ambiguous_calls"] += 1
            continue
        counters["bound_calls"] += 1
        caller_file = _text(caller_function.get("file_path")) or _path_key(source_path)
        target_file_text = _text(target_file) or _path_key(source_path)
        edges.append({
            "caller_id": caller_id,
            "callee_id": callee_id,
            "edge_kind": "direct_member_call" if kind == "CXXMemberCallExpr" else "direct_call",
            "resolver": "clang",
            "binding_status": "resolved",
            "dispatch_kind": "virtual" if is_virtual_dispatch else "direct",
            # A virtual declaration identifies the static slot, not the full
            # dynamic target set. Keep that uncertainty explicit so the
            # overlay can retain the fact as candidate-only evidence.
            "candidate_completeness": (
                "unknown" if is_virtual_dispatch else "complete"
            ),
            "binding_evidence": {
                "binding_rule": "clang_ast_declaration",
                "declaration_verified": True,
                "type_verified": bool(receiver_type) or kind != "CXXMemberCallExpr",
                "dynamic_dispatch": is_virtual_dispatch,
            },
            "source_revision": source_revision,
            "callsite": {
                "file": caller_file,
                "line": call_line,
                "expression": expression,
            },
            "evidence": [
                {
                    "kind": "call_site",
                    "file": caller_file,
                    "start_line": call_line,
                    "end_line": call_line,
                    "text": expression,
                },
                {
                    "kind": "target",
                    "file": target_file_text,
                    "start_line": target_start,
                    "end_line": target_end,
                    "text": _target_evidence_text(
                        functions.get(callee_id), target_name or call_name
                    ),
                    "function_id": callee_id,
                },
            ],
        })
    return edges, symbols, counters, unindexed_calls


def _execute_translation_unit(
    entry: Mapping[str, Any],
    *,
    cwd: Path,
    source_path: Path,
    functions: Mapping[str, Mapping[str, Any]],
    source_revision: str | None,
    timeout_seconds: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    """Run Clang and extract one unit; errors are raised to the caller."""
    argv = _command_argv(entry, source_path)
    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=max(1, int(timeout_seconds)),
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or "clang failed")[-4000:])
    ast = json.loads(completed.stdout)
    # Clang offsets are byte offsets and the source snapshot uses CRLF in
    # several OpenHarmony files. Preserve newlines for line mapping.
    with source_path.open("r", encoding="utf-8", errors="replace", newline="") as source_handle:
        source = source_handle.read()
    return _raw_edges_for_translation_unit(
        ast,
        source_path=source_path,
        source=source,
        functions=functions,
        source_revision=source_revision,
    )


def _stable_json_hash(value: Any) -> str:
    """Return a deterministic fingerprint for checkpoint identity."""
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _checkpoint_path(
    checkpoint_path: str | os.PathLike[str] | None,
    context_output_dir: str | os.PathLike[str] | None,
) -> Path | None:
    if checkpoint_path:
        return Path(checkpoint_path).expanduser().resolve()
    if context_output_dir:
        return Path(context_output_dir).expanduser().resolve() / "clang_batch_checkpoint.json"
    return None


def _load_checkpoint(
    path: Path | None,
    *,
    repository: Path,
    database: Path,
    database_hash: str,
) -> tuple[dict[str, Any], str | None]:
    """Load a checkpoint only when it belongs to the same source/database."""
    empty = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "repository": str(repository),
        "compile_commands": str(database),
        "compile_commands_sha256": database_hash,
        "files": {},
        "completed_units": [],
    }
    if path is None or not path.is_file():
        return empty, None
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError) as exc:
        return empty, f"checkpoint_unreadable:{exc}"
    if not isinstance(payload, Mapping):
        return empty, "checkpoint_not_object"
    if payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        return empty, "checkpoint_schema_version_mismatch"
    if _text(payload.get("repository")) != str(repository):
        return empty, "checkpoint_repository_mismatch"
    if _text(payload.get("compile_commands")) != str(database):
        return empty, "checkpoint_compile_commands_mismatch"
    if _text(payload.get("compile_commands_sha256")) != database_hash:
        return empty, "checkpoint_compile_commands_changed"
    files = payload.get("files")
    if not isinstance(files, Mapping):
        return empty, "checkpoint_files_invalid"
    normalised = dict(empty)
    normalised.update(dict(payload))
    normalised["files"] = dict(files)
    return normalised, None


def _write_checkpoint(path: Path | None, payload: Mapping[str, Any]) -> str | None:
    """Atomically persist progress so an interrupted batch can be resumed."""
    if path is None:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(path)
        return str(path)
    except OSError:
        return None


def _checkpoint_entry_fingerprint(
    entry: Mapping[str, Any],
    *,
    source_path: Path,
    source_revision: str | None,
    build_status: str,
) -> str:
    return _stable_json_hash({
        "entry": dict(entry),
        "source": str(source_path),
        "source_sha256": _file_hash(source_path),
        "source_revision": source_revision,
        "build_status": build_status,
    })


def _flatten_named_values(value: Any, name: str) -> list[Any]:
    """Collect values for a key from nested context diagnostics."""
    found: list[Any] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == name:
                found.append(child)
            found.extend(_flatten_named_values(child, name))
    elif isinstance(value, list):
        for child in value:
            found.extend(_flatten_named_values(child, name))
    return found


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Mapping):
        result: list[str] = []
        for child in value.values():
            result.extend(_flatten_strings(child))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for child in value:
            result.extend(_flatten_strings(child))
        return result
    return []


_MISSING_HEADER_PATTERNS = (
    re.compile(r"fatal error:\s*['\"]([^'\"]+)['\"]\s+file not found", re.I),
    re.compile(r"fatal error:\s*([^\s:'\"]+)\s+file not found", re.I),
    re.compile(r"fatal error:\s*['\"]([^'\"]+)['\"]\s*:\s*No such file", re.I),
)


def _missing_headers(text: str) -> list[str]:
    result: list[str] = []
    for pattern in _MISSING_HEADER_PATTERNS:
        for match in pattern.finditer(text or ""):
            header = match.group(1).strip()
            if header and header not in result:
                result.append(header)
    return result


def _is_low_trust_dependency_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return bool(parts & {
        "test", "tests", "mock", "mocks", "unittest", "unittests",
        "example", "examples", "sample", "samples", "previewer", "demo",
    })


def _dependency_roots_from_context(
    repository: Path,
    context: Mapping[str, Any] | None,
) -> list[Path]:
    roots: list[Path] = list(_repository_roots(repository))
    if isinstance(context, Mapping):
        for value in _flatten_named_values(context, "dependency_search_roots"):
            roots.extend(Path(text).expanduser() for text in _flatten_strings(value))
        for value in _flatten_named_values(context, "resolved_external_deps"):
            roots.extend(Path(text).expanduser() for text in _flatten_strings(value))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in roots:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        key = str(resolved)
        if resolved.is_dir() and key not in seen:
            seen.add(key)
            unique.append(resolved)
    return unique


def _find_header_candidates(
    header: str,
    roots: Iterable[Path],
    *,
    max_candidates: int = 16,
    max_directories_per_root: int = 20000,
) -> list[dict[str, Any]]:
    """Find bounded local candidates for a missing header.

    This is deliberately an evidence collector, not an automatic repository
    downloader. Test/mock paths are reported but marked low trust. They are
    excluded from automatic retry by default; the explicit low-trust option
    may include them, but the resulting facts remain candidate-only.
    """
    header_text = header.strip().strip("'\"")
    root_list = list(roots)
    root_keys = tuple(str(path) for path in root_list)
    cache_key = (header_text, root_keys)
    cached = _HEADER_CANDIDATE_CACHE.get(cache_key)
    if cached is not None:
        return [dict(item) for item in cached]
    header_parts = tuple(part for part in Path(header_text).parts if part not in {".", ""})
    basename = Path(header_text).name
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in root_list:
        direct = root.joinpath(*header_parts)
        candidates: list[Path] = []
        if direct.is_file():
            candidates.append(direct)
        try:
            visited = 0
            for current, directories, files in os.walk(root, followlinks=False):
                visited += 1
                if visited > max_directories_per_root:
                    break
                current_path = Path(current)
                directories[:] = sorted(
                    directory for directory in directories
                    if directory not in {".git", "out", "build", "node_modules", ".ccache"}
                    and not (current_path / directory).is_symlink()
                )
                if basename not in files:
                    continue
                candidate = current_path / basename
                if header_parts and tuple(candidate.parts[-len(header_parts):]) == header_parts:
                    candidates.append(candidate)
                elif len(candidates) < max_candidates * 2:
                    candidates.append(candidate)
        except OSError:
            continue
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                resolved = candidate
            key = str(resolved)
            if key in seen or not resolved.is_file():
                continue
            seen.add(key)
            include_dir = resolved.parent
            if len(header_parts) > 1 and tuple(resolved.parts[-len(header_parts):]) == header_parts:
                include_dir = resolved.parent
                # For ``transaction/x.h`` the include root is the directory
                # containing ``transaction`` rather than ``transaction``.
                if len(header_parts) >= 2:
                    include_dir = resolved.parents[len(header_parts) - 2]
            low_trust = _is_low_trust_dependency_path(resolved)
            score = 100 if low_trust else 0
            if "interfaces" in {part.lower() for part in resolved.parts}:
                score -= 10
            if "include" in {part.lower() for part in resolved.parts}:
                score -= 5
            found.append({
                "path": str(resolved),
                "include_dir": str(include_dir),
                "source_root": str(root),
                "low_trust": low_trust,
                "score": score,
            })
    found.sort(key=lambda item: (int(item.get("score", 0)), item.get("path", "")))
    result = found[:max_candidates]
    _HEADER_CANDIDATE_CACHE[cache_key] = [dict(item) for item in result]
    return result


def _failure_missing_headers(file_result: Mapping[str, Any]) -> list[str]:
    return _missing_headers(
        _text(file_result.get("dependency_retry_error"))
        or _text(file_result.get("error"))
    )


def _augment_compile_entry(
    entry: Mapping[str, Any],
    include_dirs: Iterable[str],
) -> dict[str, Any]:
    """Add candidate include roots without mutating the original database."""
    augmented = dict(entry)
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and all(isinstance(item, str) for item in arguments):
        argv = list(arguments)
    else:
        argv = shlex.split(_text(entry.get("command")))
    existing = {item[2:] for item in argv if isinstance(item, str) and item.startswith("-I")}
    for include_dir in include_dirs:
        if include_dir and include_dir not in existing:
            argv.insert(1, f"-I{include_dir}")
            existing.add(include_dir)
    augmented["arguments"] = argv
    augmented.pop("command", None)
    return augmented


def _run_dependency_retry_round(
    *,
    retry_round: int,
    file_results: list[dict[str, Any]],
    selected_by_key: Mapping[str, tuple[Mapping[str, Any], Path, Path, str]],
    dependency_roots: list[Path],
    functions: Mapping[str, Mapping[str, Any]],
    source_revision: str | None,
    effective_build_status: str,
    timeout_seconds: int,
    dependency_retry_low_trust: bool,
    base: dict[str, Any],
    raw_edges: list[dict[str, Any]],
    raw_symbols: dict[str, dict[str, Any]],
    raw_unindexed_calls: list[dict[str, Any]],
    checkpoint: dict[str, Any],
    resolved_checkpoint: Path | None,
) -> list[dict[str, Any]]:
    """Retry failed units once using newly discovered local include roots."""
    retry_entries: list[dict[str, Any]] = []
    for file_result in list(file_results):
        if file_result.get("status") != "failed":
            continue
        missing_headers = _failure_missing_headers(file_result)
        if not missing_headers:
            continue
        candidates_by_header: dict[str, list[dict[str, Any]]] = {
            header: _find_header_candidates(header, dependency_roots)
            for header in missing_headers
        }
        include_dirs: list[str] = [
            _text(value) for value in file_result.get("include_dirs", [])
            if _text(value)
        ]
        candidate_records: list[dict[str, Any]] = []
        for header in missing_headers:
            candidates = candidates_by_header.get(header, [])
            usable = [
                item for item in candidates
                if dependency_retry_low_trust or not item.get("low_trust")
            ]
            if not usable:
                continue
            selected_candidate = usable[0]
            include_dir = _text(selected_candidate.get("include_dir"))
            if include_dir and include_dir not in include_dirs:
                include_dirs.append(include_dir)
            candidate_records.append({
                "header": header,
                "selected": selected_candidate,
                "candidates": candidates,
            })
        previous_dirs = {
            _text(value) for value in file_result.get("include_dirs", []) if _text(value)
        }
        new_dirs = [value for value in include_dirs if value not in previous_dirs]
        if not new_dirs:
            # Repeating the same candidate cannot add evidence. Leave the
            # failure visible and let the next outer stage report it.
            file_result["dependency_candidates"] = candidate_records
            continue
        original_key = _text(file_result.get("unit_key"))
        selected = selected_by_key.get(original_key)
        if selected is None:
            continue
        original_entry, cwd, source_path, original_fingerprint = selected
        augmented_entry = _augment_compile_entry(original_entry, include_dirs)
        retry_entries.append(augmented_entry)
        retry_fingerprint = _checkpoint_entry_fingerprint(
            augmented_entry,
            source_path=source_path,
            source_revision=source_revision,
            build_status=effective_build_status,
        )
        retry_key = f"{source_path}::{retry_fingerprint[:16]}"
        retry_record: dict[str, Any] = {
            "file": str(source_path),
            "missing_headers": missing_headers,
            "include_dirs": include_dirs,
            "new_include_dirs": new_dirs,
            "candidates": candidate_records,
            "original_unit_key": original_key,
            "retry_unit_key": retry_key,
            "attempt": retry_round,
            "error": _text(file_result.get("error")),
        }
        base["summary"]["dependency_retry_attempts"] += 1
        try:
            edges, symbols, counters, unindexed_calls = _execute_translation_unit(
                augmented_entry,
                cwd=cwd,
                source_path=source_path,
                functions=functions,
                source_revision=source_revision,
                timeout_seconds=timeout_seconds,
            )
            raw_edges.extend(edges)
            raw_symbols.update(symbols)
            raw_unindexed_calls.extend(unindexed_calls)
            for key in counters:
                base["summary"][key] += counters[key]
            base["summary"]["files_failed"] = max(0, base["summary"]["files_failed"] - 1)
            base["summary"]["files_succeeded"] += 1
            base["summary"]["files_executed"] += 1
            base["summary"]["files_recovered_by_dependency_retry"] += 1
            file_result.update({
                "status": "succeeded_after_dependency_retry",
                "retry_unit_key": retry_key,
                "retry_fingerprint": retry_fingerprint,
                "dependency_candidates": candidate_records,
                "include_dirs": include_dirs,
                "call_sites": counters["call_sites"],
                "bound_calls": counters["bound_calls"],
                "ambiguous_calls": counters["ambiguous_calls"],
                "caller_not_in_index": counters["caller_not_in_index"],
                "caller_symbols_added": counters.get("caller_symbols_added", 0),
                "edge_count": len(edges),
                "error": None,
            })
            if file_result.get("source_kind") == "definition_load":
                base["summary"]["definition_files_executed"] += 1
                base["summary"]["definition_files_failed"] = max(
                    0, base["summary"]["definition_files_failed"] - 1
                )
                base["summary"]["definition_files_succeeded"] += 1
            retry_record.update({"status": "recovered", "retry_error": None})
            checkpoint["files"][original_key] = {
                "file": str(source_path),
                "fingerprint": original_fingerprint,
                "status": "succeeded",
                "counters": counters,
                "edges": edges,
                "symbols": symbols,
                "unindexed_calls": unindexed_calls,
                "dependency_retry": True,
                "definition_load": file_result.get("source_kind") == "definition_load",
                "dependency_retry_include_dirs": include_dirs,
                "dependency_retry_candidates": candidate_records,
                "file_result": file_result,
            }
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            base["summary"]["files_executed"] += 1
            if file_result.get("source_kind") == "definition_load":
                base["summary"]["definition_files_executed"] += 1
            retry_record.update({"status": "failed", "retry_error": str(exc)[:4000]})
            file_result["dependency_retry_error"] = str(exc)[:4000]
            file_result["include_dirs"] = include_dirs
            base["diagnostics"].append({
                "file": str(source_path),
                "reason": "clang_dependency_retry_failed",
                "error": str(exc)[:4000],
            })
        base["dependency_retry_history"].append(retry_record)
        _write_checkpoint(resolved_checkpoint, checkpoint)
    return retry_entries


def _as_unique_strings(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        for text in _flatten_strings(value):
            if text not in result:
                result.append(text)
    return result


def _build_dependency_gap_report(batch: Mapping[str, Any]) -> dict[str, Any]:
    """Summarise missing dependencies and headers without hiding parse failures."""
    context = batch.get("clang_context") if isinstance(batch, Mapping) else None
    context = context if isinstance(context, Mapping) else {}
    unresolved = _as_unique_strings(_flatten_named_values(context, "unresolved_external_deps"))
    resolved = _as_unique_strings(_flatten_named_values(context, "resolved_external_deps"))
    failed_units: list[dict[str, Any]] = []
    missing_by_header: dict[str, dict[str, Any]] = {}
    file_results = batch.get("file_results")
    if isinstance(file_results, list):
        for item in file_results:
            if not isinstance(item, Mapping) or item.get("status") not in {"failed", "pending"}:
                continue
            error = _text(item.get("error"))
            headers = _missing_headers(error)
            record = {
                "file": _text(item.get("file")),
                "status": _text(item.get("status")),
                "error": error,
                "missing_headers": headers,
            }
            failed_units.append(record)
            for header in headers:
                header_record = missing_by_header.setdefault(
                    header, {"header": header, "files": [], "errors": []}
                )
                if record["file"] and record["file"] not in header_record["files"]:
                    header_record["files"].append(record["file"])
                if error and error not in header_record["errors"]:
                    header_record["errors"].append(error)
    # Context-level diagnostics can also contain compiler errors when no file
    # was attempted.  Include their missing headers in the same report.
    context_text = "\n".join(_flatten_strings(context.get("diagnostics", [])))
    for header in _missing_headers(context_text):
        missing_by_header.setdefault(header, {"header": header, "files": [], "errors": []})
    diagnostics = batch.get("diagnostics")
    diagnostic_text = "\n".join(_flatten_strings(diagnostics))
    for header in _missing_headers(diagnostic_text):
        missing_by_header.setdefault(header, {"header": header, "files": [], "errors": []})
    retry_history = batch.get("dependency_retry_history")
    if not isinstance(retry_history, list):
        retry_history = []
    for retry in retry_history:
        if not isinstance(retry, Mapping):
            continue
        for header in retry.get("missing_headers", []):
            header_text = _text(header)
            if not header_text:
                continue
            record = missing_by_header.setdefault(
                header_text, {"header": header_text, "files": [], "errors": []}
            )
            if retry.get("file") and retry["file"] not in record["files"]:
                record["files"].append(retry["file"])
            if retry.get("error") and retry["error"] not in record["errors"]:
                record["errors"].append(retry["error"])
    repository = Path(_text(batch.get("repository"))) if _text(batch.get("repository")) else Path(".")
    dependency_roots = _dependency_roots_from_context(repository, context)
    header_candidates: list[dict[str, Any]] = []
    for header_record in sorted(missing_by_header.values(), key=lambda item: item["header"]):
        header_record["candidates"] = _find_header_candidates(
            header_record["header"], dependency_roots,
        )
        header_candidates.append(header_record)
    summary = batch.get("summary") if isinstance(batch.get("summary"), Mapping) else {}
    missing_headers = sorted(missing_by_header.values(), key=lambda item: item["header"])
    recommendations: list[str] = []
    if unresolved:
        recommendations.append("补齐与源码版本匹配的 OpenHarmony 外部依赖，并将其 include 根加入真实构建上下文。")
    if missing_headers:
        recommendations.append("定位缺失头文件所属仓库或生成任务；不要用空头文件替代真实依赖。")
    if failed_units and not unresolved and not missing_headers:
        recommendations.append("检查失败翻译单元的完整编译参数、宏、sysroot 与生成头文件。")
    if context.get("status") == "reconstructed_candidate":
        recommendations.append("当前命令来自 BUILD.gn 有界重建，仅可作为 candidate 事实；取得匹配产品构建命令后再准入 strict。")
    status = "gaps_present" if (unresolved or missing_headers or failed_units or context.get("status") in {"context_unavailable", "no_compile_commands"}) else "no_gaps"
    return {
        "schema_version": DEPENDENCY_GAP_SCHEMA_VERSION,
        "task": "openharmony_clang_dependency_gap_report",
        "repository": _text(batch.get("repository")),
        "source_revision": batch.get("source_revision"),
        "build_status": _text(batch.get("build_status")),
        "context_status": _text(context.get("status")),
        "context_source": _text(context.get("source")),
        "compile_commands": _text(batch.get("batch_summary", {}).get("compile_commands") if isinstance(batch.get("batch_summary"), Mapping) else summary.get("compile_commands")),
        "status": status,
        "summary": {
            "unresolved_external_deps": len(unresolved),
            "resolved_external_deps": len(resolved),
            "missing_headers": len(missing_headers),
        "failed_translation_units": len(failed_units),
            "files_seen": summary.get("files_seen", 0),
            "files_attempted": summary.get("files_attempted", 0),
            "files_succeeded": summary.get("files_succeeded", 0),
            "dependency_retry_attempts": summary.get("dependency_retry_attempts", 0),
            "files_recovered_by_dependency_retry": summary.get("files_recovered_by_dependency_retry", 0),
            "files_still_failed_after_dependency_retry": summary.get("files_still_failed_after_dependency_retry", 0),
            "definition_files_scheduled": summary.get("definition_files_scheduled", 0),
            "definition_files_executed": summary.get("definition_files_executed", 0),
            "definition_files_reused": summary.get("definition_files_reused", 0),
            "definition_files_succeeded": summary.get("definition_files_succeeded", 0),
            "definition_files_failed": summary.get("definition_files_failed", 0),
            "symbols_with_unique_definition_candidate": summary.get(
                "symbols_with_unique_definition_candidate", 0
            ),
            "symbols_with_ambiguous_definition_candidates": summary.get(
                "symbols_with_ambiguous_definition_candidates", 0
            ),
            "symbols_without_definition_candidate": summary.get(
                "symbols_without_definition_candidate", 0
            ),
        },
        "unresolved_external_deps": unresolved,
        "resolved_external_deps": resolved,
        "missing_headers": missing_headers,
        "failed_translation_units": failed_units,
        "dependency_retry_history": retry_history,
        "recommendations": recommendations,
        "dependency_search_roots": [str(path) for path in dependency_roots],
        "header_candidates": header_candidates,
    }


def _persist_dependency_gap_report(
    batch: dict[str, Any],
    context_output_dir: str | os.PathLike[str] | None,
) -> None:
    if not context_output_dir:
        return
    path = Path(context_output_dir).expanduser().resolve() / "clang_dependency_gap_report.json"
    report = _build_dependency_gap_report(batch)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        batch["dependency_gap_report"] = str(path)
        batch["dependency_gap_summary"] = report["summary"]
    except OSError as exc:
        batch.setdefault("diagnostics", []).append({
            "reason": "clang_dependency_gap_report_write_failed",
            "error": str(exc),
        })


def extract_clang_semantic_overlay(
    repository: str | os.PathLike[str],
    functions: Mapping[str, Mapping[str, Any]],
    *,
    compile_commands: str | os.PathLike[str] | None = None,
    source_revision: str | None = None,
    build_status: str = "compile_database",
    max_files: int = 128,
    timeout_seconds: int = 30,
    auto_context: bool = True,
    context_output_dir: str | os.PathLike[str] | None = None,
    batch_size: int = 16,
    checkpoint_path: str | os.PathLike[str] | None = None,
    resume: bool = True,
    force_recompute: bool = False,
    dependency_retry_attempts: int = 1,
    dependency_retry_low_trust: bool = False,
    definition_load_max_files: int = 16,
    priority_sources: Iterable[str | os.PathLike[str]] | None = None,
) -> dict[str, Any]:
    """Run bounded Clang AST extraction and return a validated overlay.

    When ``compile_commands`` is not supplied, the extractor performs a
    bounded context-discovery pass. It never runs GN/Ninja build targets:
    existing compile databases are reused, existing Ninja metadata may be
    queried with ``ninja -t compdb``, and otherwise a BUILD.gn-derived
    candidate database is attempted before reporting ``context_unavailable``.

    When an output directory (or explicit ``checkpoint_path``) is supplied,
    progress is persisted after each translation unit. A later invocation
    reuses only successful units whose source, command, revision, and build
    status fingerprint is unchanged.

    ``priority_sources`` is an optional list of repository-relative or
    absolute source files obtained from a pre-Clang call-site gap report.
    Matching translation units are scheduled before the remaining compilation
    database entries, subject to ``max_files``. This is a cost-allocation hint
    only; it never promotes a fact or changes strict/candidate admission.
    """
    root = Path(repository).resolve()
    priority_display, priority_keys = _priority_source_keys(
        priority_sources, repository=root
    )
    database: Path | None = None
    context_report: dict[str, Any] | None = None
    if auto_context:
        requested_files = sorted({
            _text(function.get("file_path") or function.get("filePath"))
            for function in functions.values()
            if isinstance(function, Mapping)
            and _text(function.get("file_path") or function.get("filePath"))
        })
        # GN reconstruction is bounded and otherwise sorts sources
        # lexicographically. Prefer affected files in that first context pass
        # so the budget is spent on actual call-graph gaps.
        priority_requested = [
            value for value in priority_display
            if _is_source(_path(value, base=root))
        ]
        if priority_requested:
            requested_files = priority_requested
        context_max_files = max(
            int(max_files or 0), len(priority_requested)
        ) if priority_requested else max_files
        context_report = prepare_clang_context(
            root,
            explicit_compile_commands=compile_commands,
            output_dir=context_output_dir,
            timeout_seconds=timeout_seconds,
            requested_files=requested_files,
            priority_files=priority_requested,
            # Keep all affected files in a reconstructed candidate database;
            # the extractor still enforces the actual Clang execution budget
            # below. Otherwise lexical GN ordering could hide later gap files
            # before priority scheduling ever sees them.
            max_files=context_max_files,
        )
        discovered = context_report.get("compile_commands")
        if discovered:
            database = Path(str(discovered)).resolve()
    else:
        database = find_compile_commands(root, compile_commands)
    effective_build_status = _text(build_status) or "unknown"
    if context_report and context_report.get("status") == "reconstructed_candidate":
        # Reconstructed commands are useful for semantic diagnostics but can
        # never be promoted to strict product evidence by a caller's default
        # ``compile_database`` label.
        effective_build_status = "reconstructed_candidate"
    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "repository": str(root),
        "source_revision": source_revision,
        "build_status": effective_build_status,
        "priority_sources": priority_display,
        "status": "no_compile_commands",
        "summary": {
            "compile_commands": None,
            "files_seen": 0,
            "files_attempted": 0,
            "files_succeeded": 0,
            "files_failed": 0,
            "call_sites": 0,
            "bound_calls": 0,
            "ambiguous_calls": 0,
            "caller_not_in_index": 0,
            "caller_symbols_added": 0,
            "files_executed": 0,
            "files_reused": 0,
            "batches_total": 0,
            "batches_completed": 0,
            "dependency_retry_attempts": 0,
            "files_recovered_by_dependency_retry": 0,
            "files_still_failed_after_dependency_retry": 0,
            "symbols_with_unique_definition_candidate": 0,
            "symbols_with_ambiguous_definition_candidates": 0,
            "symbols_without_definition_candidate": 0,
            "definition_files_scheduled": 0,
            "definition_files_executed": 0,
            "definition_files_reused": 0,
            "definition_files_succeeded": 0,
            "definition_files_failed": 0,
            "priority_sources_requested": len(priority_display),
            "priority_sources_matched": 0,
            "priority_files_selected": 0,
            "non_priority_files_selected": 0,
            "priority_sources_unmatched": [],
        },
        "edges": [],
        "symbols": {},
        "unindexed_calls": [],
        "diagnostics": [],
        "dependency_retry_history": [],
        "definition_loading": [],
    }
    if context_report is not None:
        base["clang_context"] = context_report
        if context_output_dir:
            context_path = Path(context_output_dir).resolve() / "clang_context.json"
            try:
                context_path.parent.mkdir(parents=True, exist_ok=True)
                context_path.write_text(
                    json.dumps(context_report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                base["clang_context_report"] = str(context_path)
            except OSError as exc:
                base["diagnostics"].append({
                    "reason": "clang_context_report_write_failed",
                    "error": str(exc),
                })
    if database is None:
        _persist_dependency_gap_report(base, context_output_dir)
        return base
    base["summary"]["compile_commands"] = str(database)
    try:
        entries = load_compile_commands(database)
    except (OSError, ValueError, TypeError) as exc:
        base["status"] = "compile_commands_invalid"
        base["diagnostics"].append({"reason": "compile_commands_invalid", "error": str(exc)})
        _persist_dependency_gap_report(base, context_output_dir)
        return base
    base["summary"]["files_seen"] = len(entries)
    # Resolve all source entries before applying the file budget. The previous
    # ``entries[:max_files]`` truncation could permanently hide a gap file
    # appearing later in a large compilation database.
    prepared_entries: list[tuple[int, dict[str, Any], Path, Path, bool]] = []
    for entry_index, entry in enumerate(entries):
        cwd = _path(entry.get("directory") or root)
        source_path = _path(entry.get("file"), base=cwd)
        if not _is_source(source_path):
            continue
        is_priority = _entry_source_matches_priority(
            source_path,
            entry,
            repository=root,
            priority_keys=priority_keys,
        )
        prepared_entries.append(
            (entry_index, dict(entry), cwd, source_path, is_priority)
        )
    prepared_entries.sort(key=lambda item: (0 if item[4] else 1, item[0]))
    selected_entries: list[tuple[dict[str, Any], Path, Path, str, str]] = []
    selected_priority_paths: set[str] = set()
    for _entry_index, entry, cwd, source_path, is_priority in prepared_entries[
        : max(0, int(max_files))
    ]:
        fingerprint = _checkpoint_entry_fingerprint(
            entry,
            source_path=source_path,
            source_revision=source_revision,
            build_status=effective_build_status,
        )
        unit_key = f"{source_path}::{fingerprint[:16]}"
        selected_entries.append((dict(entry), cwd, source_path, fingerprint, unit_key))
        if is_priority:
            selected_priority_paths.add(_path_key(source_path))
    base["summary"]["files_attempted"] = len(selected_entries)
    base["summary"]["priority_files_selected"] = len(selected_priority_paths)
    base["summary"]["non_priority_files_selected"] = max(
        0, len(selected_entries) - len(selected_priority_paths)
    )
    matched_priority_paths = {
        _path_key(source_path)
        for _entry_index, _entry, _cwd, source_path, is_priority in prepared_entries
        if is_priority
    }
    base["summary"]["priority_sources_matched"] = len(matched_priority_paths)
    base["summary"]["priority_sources_unmatched"] = [
        value for value in priority_display
        if _path_key(_path(value, base=root)) not in matched_priority_paths
    ]
    effective_batch_size = max(1, int(batch_size or 1))
    base["summary"]["batches_total"] = (
        (len(selected_entries) + effective_batch_size - 1) // effective_batch_size
        if selected_entries else 0
    )
    resolved_checkpoint = _checkpoint_path(checkpoint_path, context_output_dir)
    database_hash = _file_hash(database)
    if resume and not force_recompute:
        checkpoint, checkpoint_warning = _load_checkpoint(
            resolved_checkpoint,
            repository=root,
            database=database,
            database_hash=database_hash,
        )
    else:
        checkpoint, checkpoint_warning = _load_checkpoint(
            None,
            repository=root,
            database=database,
            database_hash=database_hash,
        )
    checkpoint.update({
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "repository": str(root),
        "compile_commands": str(database),
        "compile_commands_sha256": database_hash,
        "batch_size": effective_batch_size,
        "max_files": int(max_files),
        "source_revision": source_revision,
        "build_status": effective_build_status,
        "files": checkpoint.get("files", {}) if isinstance(checkpoint.get("files"), Mapping) else {},
    })
    base["checkpoint_path"] = str(resolved_checkpoint) if resolved_checkpoint else None
    base["resume_enabled"] = bool(resume and not force_recompute and resolved_checkpoint)
    if checkpoint_warning:
        base["diagnostics"].append({
            "reason": "clang_checkpoint_ignored",
            "detail": checkpoint_warning,
        })
    _write_checkpoint(resolved_checkpoint, checkpoint)
    raw_edges: list[dict[str, Any]] = []
    raw_symbols: dict[str, dict[str, Any]] = {}
    raw_unindexed_calls: list[dict[str, Any]] = []
    file_results: list[dict[str, Any]] = []
    for index, (entry, cwd, source_path, fingerprint, unit_key) in enumerate(selected_entries):
        file_result: dict[str, Any] = {
            "file": str(source_path),
            "status": "pending",
            "build_status": effective_build_status,
            "unit_key": unit_key,
            "fingerprint": fingerprint,
        }
        checkpoint_record = checkpoint.get("files", {}).get(unit_key)
        if (
            resume
            and not force_recompute
            and isinstance(checkpoint_record, Mapping)
            and checkpoint_record.get("fingerprint") == fingerprint
            and checkpoint_record.get("status") == "succeeded"
        ):
            cached_edges = checkpoint_record.get("edges", [])
            cached_symbols = checkpoint_record.get("symbols", {})
            cached_unindexed = checkpoint_record.get("unindexed_calls", [])
            cached_counters = checkpoint_record.get("counters", {})
            if isinstance(cached_edges, list) and isinstance(cached_symbols, Mapping):
                raw_edges.extend(item for item in cached_edges if isinstance(item, Mapping))
                raw_symbols.update({
                    str(key): dict(value)
                    for key, value in cached_symbols.items()
                    if isinstance(value, Mapping)
                })
                raw_unindexed_calls.extend(
                    item for item in cached_unindexed if isinstance(item, Mapping)
                )
                for key in (
                    "call_sites", "bound_calls", "ambiguous_calls",
                    "caller_not_in_index", "caller_symbols_added",
                ):
                    base["summary"][key] += int(cached_counters.get(key, 0) or 0)
                base["summary"]["files_succeeded"] += 1
                base["summary"]["files_reused"] += 1
                cached_file = checkpoint_record.get("file_result")
                if isinstance(cached_file, Mapping):
                    file_result.update(dict(cached_file))
                file_result["status"] = "reused"
                file_results.append(file_result)
                continue
        try:
            edges, symbols, counters, unindexed_calls = _execute_translation_unit(
                entry,
                cwd=cwd,
                source_path=source_path,
                functions=functions,
                source_revision=source_revision,
                timeout_seconds=timeout_seconds,
            )
            raw_edges.extend(edges)
            raw_symbols.update(symbols)
            raw_unindexed_calls.extend(unindexed_calls)
            for key in counters:
                base["summary"][key] += counters[key]
            base["summary"]["files_succeeded"] += 1
            base["summary"]["files_executed"] += 1
            file_result.update({
                "status": "succeeded",
                "call_sites": counters["call_sites"],
                "bound_calls": counters["bound_calls"],
                "ambiguous_calls": counters["ambiguous_calls"],
                "caller_not_in_index": counters["caller_not_in_index"],
                "caller_symbols_added": counters.get("caller_symbols_added", 0),
                "edge_count": len(edges),
            })
            checkpoint["files"][unit_key] = {
                "file": str(source_path),
                "fingerprint": fingerprint,
                "status": "succeeded",
                "counters": counters,
                "edges": edges,
                "symbols": symbols,
                "unindexed_calls": unindexed_calls,
                "file_result": file_result,
            }
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            base["summary"]["files_failed"] += 1
            base["summary"]["files_executed"] += 1
            file_result.update({"status": "failed", "error": str(exc)[:4000]})
            base["diagnostics"].append({
                "file": str(source_path),
                "reason": "clang_translation_unit_failed",
                "error": str(exc)[:4000],
            })
        file_results.append(file_result)
        checkpoint["completed_units"] = [
            item.get("unit_key") for item in file_results
            if isinstance(item, Mapping)
            and item.get("status") in {
                "succeeded", "succeeded_after_dependency_retry", "reused",
                "definition_loaded", "definition_reused", "failed"
            }
        ]
        checkpoint["last_unit_key"] = unit_key
        checkpoint["last_batch"] = index // effective_batch_size
        _write_checkpoint(resolved_checkpoint, checkpoint)
        if (index + 1) % effective_batch_size == 0 or index + 1 == len(selected_entries):
            base["summary"]["batches_completed"] = (index // effective_batch_size) + 1
            checkpoint["batches_completed"] = base["summary"]["batches_completed"]
            _write_checkpoint(resolved_checkpoint, checkpoint)

    # Before retrying missing headers, use the symbols already observed in the
    # batch to schedule a bounded second pass for unique definitions outside
    # the initial file budget. Ambiguous or missing definitions are retained as
    # explicit facts/tasks and are never guessed into edges.
    definition_counts = _attach_definition_candidates(raw_symbols, functions)
    base["summary"]["symbols_with_unique_definition_candidate"] = definition_counts["unique"]
    base["summary"]["symbols_with_ambiguous_definition_candidates"] = definition_counts["ambiguous"]
    base["summary"]["symbols_without_definition_candidate"] = definition_counts["none"]
    definition_plan = _build_definition_loading_plan(
        raw_symbols,
        functions,
        entries,
        repository=root,
        selected_sources=[item[2] for item in selected_entries],
        max_files=definition_load_max_files,
    )
    scheduled_definition_files = sum(
        1 for item in definition_plan if item.get("status") == "scheduled"
    )
    base["summary"]["definition_files_scheduled"] = scheduled_definition_files
    if scheduled_definition_files:
        _run_definition_loading(
            plan=definition_plan,
            functions=functions,
            source_revision=source_revision,
            effective_build_status=effective_build_status,
            timeout_seconds=timeout_seconds,
            base=base,
            raw_edges=raw_edges,
            raw_symbols=raw_symbols,
            raw_unindexed_calls=raw_unindexed_calls,
            file_results=file_results,
            checkpoint=checkpoint,
            resolved_checkpoint=resolved_checkpoint,
        )
    # Definition-load failures are ordinary translation-unit failures and can
    # participate in the same bounded local-header retry as the initial batch.
    # Keep the original command/fingerprint so the retry remains auditable.
    definition_retry_entries = {
        _text(item.get("unit_key")): item
        for item in definition_plan
        if item.get("status") == "failed" and _text(item.get("unit_key"))
    }
    definition_counts = _attach_definition_candidates(raw_symbols, functions)
    base["summary"]["symbols_with_unique_definition_candidate"] = definition_counts["unique"]
    base["summary"]["symbols_with_ambiguous_definition_candidates"] = definition_counts["ambiguous"]
    base["summary"]["symbols_without_definition_candidate"] = definition_counts["none"]
    base["definition_loading"] = definition_plan

    # A missing header can belong to a sibling OpenHarmony component. Use the
    # bounded local candidate index to retry only affected translation units;
    # never download code or promote augmented commands to strict facts.
    retry_entries: list[dict[str, Any]] = []
    if max(0, int(dependency_retry_attempts or 0)) > 0:
        context_for_roots = context_report if isinstance(context_report, Mapping) else {}
        dependency_roots = _dependency_roots_from_context(root, context_for_roots)
        selected_by_key = {
            unit_key: (entry, cwd, source_path, fingerprint)
            for entry, cwd, source_path, fingerprint, unit_key in selected_entries
        }
        for unit_key, item in definition_retry_entries.items():
            entry = item.get("compile_entry")
            if not isinstance(entry, Mapping):
                continue
            selected_by_key[unit_key] = (
                dict(entry),
                _path(item.get("working_directory") or root),
                _path(item.get("source_path"), base=root),
                _text(item.get("fingerprint")),
            )
        retry_rounds = max(1, int(dependency_retry_attempts))
        for retry_round in range(1, retry_rounds + 1):
            round_entries = _run_dependency_retry_round(
                retry_round=retry_round,
                file_results=file_results,
                selected_by_key=selected_by_key,
                dependency_roots=dependency_roots,
                functions=functions,
                source_revision=source_revision,
                effective_build_status=effective_build_status,
                timeout_seconds=timeout_seconds,
                dependency_retry_low_trust=dependency_retry_low_trust,
                base=base,
                raw_edges=raw_edges,
                raw_symbols=raw_symbols,
                raw_unindexed_calls=raw_unindexed_calls,
                checkpoint=checkpoint,
                resolved_checkpoint=resolved_checkpoint,
            )
            retry_entries.extend(round_entries)
            if not round_entries or not any(
                item.get("status") == "failed" for item in file_results
            ):
                break
        # Keep an auditable retry-only compilation database. It is explicitly
        # candidate context and never replaces the original product command DB.
        if retry_entries and context_output_dir:
            retry_db = Path(context_output_dir).resolve() / "compile_commands.dependency_retry.json"
            try:
                retry_db.parent.mkdir(parents=True, exist_ok=True)
                retry_db.write_text(json.dumps(retry_entries, ensure_ascii=False, indent=2), encoding="utf-8")
                base["dependency_retry_compile_commands"] = str(retry_db)
            except OSError as exc:
                base["diagnostics"].append({
                    "reason": "clang_dependency_retry_database_write_failed",
                    "error": str(exc),
                })
        for item in definition_plan:
            unit_key = _text(item.get("unit_key"))
            if not unit_key:
                continue
            result = next(
                (
                    file_result for file_result in file_results
                    if _text(file_result.get("unit_key")) == unit_key
                ),
                None,
            )
            if isinstance(result, Mapping) and result.get("status") == "succeeded_after_dependency_retry":
                item["status"] = "recovered_after_dependency_retry"
                item["retry_unit_key"] = result.get("retry_unit_key")
    definition_report_path = _persist_definition_loading_report(
        plan=definition_plan,
        base=base,
        repository=root,
        source_revision=source_revision,
        build_status=effective_build_status,
        context_output_dir=context_output_dir,
    )
    if definition_report_path:
        base["definition_loading_report"] = definition_report_path
    elif context_output_dir and definition_plan:
        base["diagnostics"].append({
            "reason": "clang_definition_loading_report_write_failed",
        })
    base["summary"]["files_still_failed_after_dependency_retry"] = base["summary"]["files_failed"]
    definition_counts = _attach_definition_candidates(raw_symbols, functions)
    base["summary"]["symbols_with_unique_definition_candidate"] = definition_counts["unique"]
    base["summary"]["symbols_with_ambiguous_definition_candidates"] = definition_counts["ambiguous"]
    base["summary"]["symbols_without_definition_candidate"] = definition_counts["none"]
    base["edges"] = raw_edges
    base["symbols"] = raw_symbols
    base["unindexed_calls"] = raw_unindexed_calls
    base["file_results"] = file_results
    base["summary"]["batches_completed"] = base["summary"]["batches_total"]
    checkpoint["batches_completed"] = base["summary"]["batches_completed"]
    checkpoint["completed_units"] = [
        item.get("unit_key") for item in file_results
        if isinstance(item, Mapping)
        and item.get("status") in {
            "succeeded", "succeeded_after_dependency_retry", "reused",
            "definition_loaded", "definition_reused", "failed"
        }
    ]
    _write_checkpoint(resolved_checkpoint, checkpoint)
    _persist_dependency_gap_report(base, context_output_dir)
    if raw_edges or raw_symbols:
        try:
            validated = load_clang_semantic_overlay(
                base,
                functions,
                expected_source_revision=source_revision,
            )
        except (TypeError, ValueError) as exc:
            # A malformed/conflicting fact must remain observable as a batch
            # validation failure, not abort the whole scan.  Preserve raw
            # edges and diagnostics so the caller can repair the identity
            # collision without losing the successful Clang parse.
            base["status"] = "validation_failed"
            base["diagnostics"].append({
                "reason": "overlay_validation_failed",
                "error": str(exc)[:4000],
            })
            _persist_dependency_gap_report(base, context_output_dir)
            return base
        validated["task"] = TASK
        validated["repository"] = str(root)
        validated["build_status"] = effective_build_status
        validated["batch_summary"] = base["summary"]
        validated["diagnostics"] = base["diagnostics"]
        validated["unindexed_calls"] = raw_unindexed_calls
        validated["file_results"] = file_results
        validated["dependency_retry_history"] = base.get("dependency_retry_history", [])
        validated["definition_loading"] = base.get("definition_loading", [])
        if context_report is not None:
            validated["clang_context"] = context_report
        if base.get("clang_context_report"):
            validated["clang_context_report"] = base["clang_context_report"]
        for key in (
            "checkpoint_path",
            "resume_enabled",
            "dependency_gap_report",
            "dependency_gap_summary",
            "dependency_retry_compile_commands",
            "definition_loading_report",
        ):
            if key in base:
                validated[key] = base[key]
        validated["status"] = "complete" if validated.get("summary", {}).get("projected_edges", 0) else "partial"
        return validated
    base["status"] = "failed" if base["summary"]["files_failed"] else "complete"
    _persist_dependency_gap_report(base, context_output_dir)
    return base


__all__ = [
    "SCHEMA_VERSION",
    "TASK",
    "CHECKPOINT_SCHEMA_VERSION",
    "DEPENDENCY_GAP_SCHEMA_VERSION",
    "extract_clang_semantic_overlay",
    "find_compile_commands",
    "load_compile_commands",
]
