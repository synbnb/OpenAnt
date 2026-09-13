"""构建并注入 Stage 1 可审计的入口血缘上下文。

可达性过滤只回答“单元是否被保留”，而漏洞分析还需要知道输入从哪个
最上层入口进入、经过哪些调用点到达目标。这个模块从有效调用图重新计算一条
有界的入口路径，把路径节点的源码位置和短代码片段写入 dataset 单元。

它不把路径当作漏洞结论：图边、入口分类和运行时数据流仍需 Stage 1 独立
核验；找不到入口时保留 ``unknown``，不会伪造一个根节点。
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Mapping

from utilities.file_io import read_json
from core.attack_chain_context import context_from_unit, normalize_attack_chain_context


SCHEMA_VERSION = 2
MAX_PATHS_PER_UNIT = 3
MAX_PATH_DEPTH = 64
MAX_PATH_NODES = 24
MAX_NODE_CODE_CHARS = 600
MAX_SUPPORTING_CONTEXT_NODES = 8
MAX_CANDIDATE_PATH_EXPANSIONS = 4096

_NORMAL_LOG_MACRO = re.compile(r"\bLOG(?:D|I|W|E)\s*\(")
_WRITE_LOG_MACRO = re.compile(r"\bWLOG(?:D|I|W|E)\s*\(")
_WRITE_LOG_GUARD = re.compile(
    r"if\s*\(\s*!\s*isWriteLog\s*\)\s*\{?\s*return\b",
    re.IGNORECASE | re.DOTALL,
)


_STRUCTURAL_REASON_CATEGORIES = {"unit_type", "decorator", "name", "platform"}


def _structural_root_ids(entry_points: Iterable[str], details: Mapping[str, Any]) -> set[str]:
    """Keep real execution/boundary roots separate from incidental input reads.

    The shared detector intentionally over-seeds reachable analysis when a
    function merely contains an input-like call such as ``open(..., "r")``.
    That is safe for recall filtering, but it is not sufficient evidence for a
    Stage 1 *top-level* attack-chain node.  P3 therefore uses only structural
    reasons (main/handler/decorator/platform) here; explicit dataset roots and
    high semantic seeds are merged separately by ``build_reachability_context``.
    """
    output: set[str] = set()
    for function_id in entry_points:
        raw = details.get(function_id, {}) if isinstance(details, Mapping) else {}
        reasons = raw.get("reasons", []) if isinstance(raw, Mapping) else []
        if any(str(reason).split(":", 1)[0] in _STRUCTURAL_REASON_CATEGORIES for reason in reasons):
            output.add(str(function_id))
    return output


def _text(value: Any, limit: int | None = None) -> str:
    text = str(value).strip() if value is not None else ""
    return text[:limit] if limit is not None else text


_MEMBER_POINTER_TARGET = re.compile(
    r"&\s*((?:[A-Za-z_]\w*::)+[A-Za-z_]\w*)"
)


def _infer_member_pointer_targets(
    expression: Any,
    graph_functions: Mapping[str, Any],
) -> list[str]:
    """Infer exact function-pointer targets from a source expression.

    This covers the common ``std::thread(&RAM::SetRamValue, ...)`` form
    without pretending to solve arbitrary pointer analysis.  The result is
    intentionally used as a *candidate* relation: overloads, build variants,
    and template instantiations still require downstream validation.
    """
    text = _text(expression)
    if not text:
        return []
    match = _MEMBER_POINTER_TARGET.search(text)
    if not match:
        return []
    qualified = match.group(1)
    suffix = qualified.split("::")[-1]
    owner = qualified.split("::")[-2] if "::" in qualified else ""
    targets: list[str] = []
    for function_id, info in graph_functions.items():
        name = _function_name(function_id, graph_functions)
        if not name.endswith(f"::{suffix}"):
            continue
        if owner and f"::{owner}::{suffix}" not in f"::{name}":
            continue
        targets.append(function_id)
    return sorted(dict.fromkeys(targets))[:32]


def _load_entry_detector():
    """Load the shared detector without importing optional LLM dependencies."""
    module_name = "_openant_entry_point_detector_for_context"
    loaded = sys.modules.get(module_name)
    if loaded is None:
        path = (
            Path(__file__).resolve().parents[1]
            / "utilities"
            / "agentic_enhancer"
            / "entry_point_detector.py"
        )
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError("entry point detector is unavailable")
        loaded = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = loaded
        spec.loader.exec_module(loaded)
    return loaded.EntryPointDetector


def _load_graph(path: str | Path) -> Mapping[str, Any] | None:
    try:
        payload = read_json(path)
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _merge_graphs(paths: Iterable[str | Path]) -> tuple[dict, dict, dict, list[str]]:
    functions: dict[str, dict] = {}
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    versions: list[str] = []
    for raw_path in paths:
        payload = _load_graph(raw_path)
        if payload is None:
            continue
        raw_functions = payload.get("functions", {})
        if isinstance(raw_functions, Mapping):
            for function_id, info in raw_functions.items():
                if isinstance(function_id, str) and isinstance(info, Mapping):
                    functions[function_id] = dict(info)
        raw_forward = payload.get("call_graph", {})
        if isinstance(raw_forward, Mapping):
            for caller, targets in raw_forward.items():
                if not isinstance(caller, str) or not isinstance(targets, list):
                    continue
                forward.setdefault(caller, set()).update(
                    str(target) for target in targets if isinstance(target, str) and target
                )
        raw_reverse = payload.get("reverse_call_graph", {})
        if isinstance(raw_reverse, Mapping):
            for callee, callers in raw_reverse.items():
                if not isinstance(callee, str) or not isinstance(callers, list):
                    continue
                reverse.setdefault(callee, set()).update(
                    str(caller) for caller in callers if isinstance(caller, str) and caller
                )
        version = _text(payload.get("graph_version"))
        if version:
            versions.append(version)
    # Recompute reverse from forward as a consistency backstop. An old graph
    # can carry a stale reverse map; using both maps would silently lose paths.
    for caller, targets in forward.items():
        for target in targets:
            reverse.setdefault(target, set()).add(caller)
    return (
        functions,
        {key: sorted(value) for key, value in forward.items()},
        {key: sorted(value) for key, value in reverse.items()},
        sorted(set(versions)),
    )


def _node_info(
    functions: Mapping[str, Any],
    function_id: str,
    *,
    include_source: bool = False,
) -> dict[str, Any]:
    raw = functions.get(function_id, {})
    raw = raw if isinstance(raw, Mapping) else {}
    code = _text(raw.get("code"))
    info = {
        "id": function_id,
        "name": raw.get("name"),
        "file": raw.get("file_path") or raw.get("filePath"),
        "line_start": raw.get("start_line") or raw.get("startLine"),
        "line_end": raw.get("end_line") or raw.get("endLine"),
        "unit_type": raw.get("unit_type") or raw.get("unitType"),
        "source_excerpt": code[:MAX_NODE_CODE_CHARS],
    }
    if include_source:
        # ``source_excerpt`` is intentionally bounded for compact metadata.
        # The path bundle is a separate Stage-1 contract and carries the full
        # function body so the model does not have to reconstruct the chain
        # from unrelated dependency ordering in ``primary_code``.
        info["source"] = code
        info["source_length"] = len(code)
        info["source_complete"] = bool(code)
    return info


def _path_edge_record(
    caller_id: str,
    callee_id: str,
    status: str,
    callsite_contexts_by_target: Mapping[str, list[Mapping[str, Any]]],
) -> dict[str, Any]:
    """Build one auditable edge record for a displayed path.

    Native edges do not become candidate edges merely because their ledger
    record is absent.  When a ledger record is available, it is attached as
    provenance; otherwise the effective-graph status remains the authoritative
    fact and the source bodies in the path bundle remain the fallback evidence.
    """
    edge_record: dict[str, Any] = {
        "caller": caller_id,
        "callee": callee_id,
        "status": status,
    }
    contexts = [
        context
        for context in (callsite_contexts_by_target.get(callee_id, []) or [])
        if isinstance(context, Mapping)
        and _text(context.get("caller")) == caller_id
    ]
    if contexts:
        # Prefer a relation whose status agrees with the path.  This avoids
        # showing a stale candidate record when a confirmed ledger binding is
        # also available for the same caller/callee pair.
        preferred = [
            item for item in contexts
            if (
                status == "native"
                and _text(item.get("status")) == "confirmed"
            ) or (
                status == "candidate"
                and _text(item.get("status")) != "confirmed"
            )
        ]
        selected = (preferred or contexts)[0]
        for key in (
            "callsite_id", "location", "file", "line_start", "line_end",
            "expression", "call_type", "dispatch_type", "binding_status",
            "dispatch_status", "graph_status", "candidate_completeness",
            "target_set_completeness", "binding_basis", "candidate_target_ids",
            "linked_target_ids", "flow_facts", "evidence", "assumptions",
        ):
            value = selected.get(key)
            if value not in (None, "", []):
                edge_record[key] = value
        edge_record["source_evidence_present"] = bool(
            selected.get("file") and selected.get("line_start") is not None
            and (selected.get("expression") or selected.get("evidence"))
        )
    elif status == "candidate":
        edge_record["assumptions"] = ["candidate_callsite_evidence_not_indexed"]
        edge_record["source_evidence_present"] = False
    else:
        edge_record["source_evidence_present"] = False
    return edge_record


def _source_bundle_for_path(
    path: list[str],
    statuses: list[str],
    functions: Mapping[str, Any],
    callsite_contexts_by_target: Mapping[str, list[Mapping[str, Any]]],
    *,
    kind: str,
) -> dict[str, Any]:
    """Create the ordered full-source bundle used by Stage 1.

    ``source_complete`` means every displayed node has its complete indexed
    function body and the path was not cut by the presentation cap.  It does
    not claim that a candidate edge is semantically proven or that parameter
    data-flow reaches a sink.
    """
    displayed_path = list(path[:MAX_PATH_NODES])
    nodes = []
    for order, node_id in enumerate(displayed_path, 1):
        node = _node_info(functions, node_id, include_source=True)
        node["order"] = order
        nodes.append(node)
    edges = [
        _path_edge_record(
            displayed_path[index],
            displayed_path[index + 1],
            statuses[index] if index < len(statuses) else "native",
            callsite_contexts_by_target,
        )
        for index in range(max(len(displayed_path) - 1, 0))
    ]
    source_complete = bool(path) and len(displayed_path) == len(path) and all(
        bool(node.get("source_complete")) for node in nodes
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "order": "entry_to_target",
        "source_complete": source_complete,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "omitted_node_count": max(len(path) - len(displayed_path), 0),
    }


def _supporting_context_bundle(
    unit_id: str,
    raw_unit: Mapping[str, Any],
    functions: Mapping[str, Any],
    forward: Mapping[str, list[str]],
    callsite_contexts_by_target: Mapping[str, list[Mapping[str, Any]]],
) -> dict[str, Any]:
    """Collect a small, deterministic direct-downstream source bundle.

    The primary path explains entry-to-target control flow.  Direct callees
    preserve the local sink/guard context that a path alone cannot show (for
    example a wrapper calling ``popen``).  We deliberately do not re-create
    the old depth-3 all-dependency blob here; Stage 1 receives a focused,
    auditable view and Stage 2 can request deeper data-flow context.
    """
    targets = list(forward.get(unit_id, []) or [])
    if not targets:
        metadata = raw_unit.get("metadata") if isinstance(raw_unit, Mapping) else {}
        raw_targets = metadata.get("direct_calls", []) if isinstance(metadata, Mapping) else []
        if isinstance(raw_targets, list):
            targets = [str(value) for value in raw_targets if value]
    targets = list(dict.fromkeys(targets))
    displayed = targets[:MAX_SUPPORTING_CONTEXT_NODES]
    nodes = [
        _node_info(functions, target, include_source=True)
        for target in displayed
        if target in functions
    ]
    edges = [
        _path_edge_record(
            unit_id,
            node["id"],
            "native",
            callsite_contexts_by_target,
        )
        for node in nodes
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "direct_downstream",
        "source_complete": bool(nodes) and len(nodes) == len(displayed) and all(
            bool(node.get("source_complete")) for node in nodes
        ),
        "nodes": nodes,
        "edges": edges,
        "omitted_node_count": max(len(targets) - len(displayed), 0),
    }


def _path_has_source_evidence(path: list[dict[str, Any]]) -> bool:
    """Whether every recorded node has the minimum source-backed fields.

    This is deliberately only a completeness indicator.  It does not validate
    that the edge is semantically correct or that an external value reaches a
    dangerous parameter.
    """
    return bool(path) and all(
        isinstance(node, Mapping)
        and bool(node.get("file"))
        and node.get("line_start") is not None
        and bool(node.get("source_excerpt"))
        for node in path
    )


def _validate_path_record(
    path: list[str],
    functions: Mapping[str, Any],
    forward: Mapping[str, list[str]],
    statuses: list[str] | None = None,
    *,
    callsite_contexts_by_target: Mapping[str, list[Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Validate the structural facts used to present one path.

    This is intentionally narrower than semantic reachability: it checks that
    node identities, source excerpts and recorded edge provenance are
    internally consistent.  It does not prove runtime branch compatibility or
    source-to-sink data flow; those remain Stage 2 responsibilities.
    """
    issues: list[str] = []
    if not path:
        issues.append("empty_path")
    if len(path) != len(set(path)):
        issues.append("repeated_node_id")
    for node_id in path:
        if node_id not in functions:
            issues.append(f"unknown_node:{node_id}")
            continue
        node = _node_info(functions, node_id)
        if not node.get("file") or node.get("line_start") is None:
            issues.append(f"node_source_location_missing:{node_id}")
        if not node.get("source_excerpt"):
            issues.append(f"node_source_excerpt_missing:{node_id}")
    expected_edges = max(len(path) - 1, 0)
    edge_statuses = statuses if isinstance(statuses, list) else ["native"] * expected_edges
    if len(edge_statuses) != expected_edges:
        issues.append("edge_status_count_mismatch")
    for index in range(expected_edges):
        caller, callee = path[index], path[index + 1]
        status = edge_statuses[index] if index < len(edge_statuses) else ""
        if status == "native" and callee not in (forward.get(caller) or []):
            issues.append(f"native_edge_missing:{caller}->{callee}")
        elif status == "candidate":
            # A candidate edge is useful to Stage 1 only when it is tied to a
            # concrete source callsite.  Merely placing the pair in a
            # candidate adjacency (or carrying a model flag) is not enough:
            # that would turn an accidental function-name match into a path.
            contexts = (
                callsite_contexts_by_target.get(callee, [])
                if isinstance(callsite_contexts_by_target, Mapping)
                else []
            )
            matching = [
                item for item in contexts
                if isinstance(item, Mapping)
                and _text(item.get("caller")) == caller
            ]
            source_backed = []
            for item in matching:
                file_name = _text(item.get("file") or item.get("path"))
                line_start = item.get("line_start", item.get("line"))
                expression = _text(item.get("expression"))
                evidence_items = item.get("evidence")
                has_evidence_excerpt = False
                if isinstance(evidence_items, list):
                    has_evidence_excerpt = any(
                        isinstance(evidence, Mapping)
                        and _text(evidence.get("excerpt") or evidence.get("text"))
                        for evidence in evidence_items
                    )
                elif isinstance(evidence_items, Mapping):
                    has_evidence_excerpt = bool(
                        _text(evidence_items.get("excerpt") or evidence_items.get("text"))
                    )
                if file_name and line_start is not None and (
                    expression or has_evidence_excerpt
                ):
                    source_backed.append(item)
            if not matching:
                issues.append(f"candidate_callsite_missing:{caller}->{callee}")
            elif not source_backed:
                issues.append(
                    f"candidate_callsite_source_evidence_missing:{caller}->{callee}"
                )
        elif status not in {"native", "candidate"}:
            issues.append(f"unknown_edge_status:{status}")
    issues.extend(_path_control_flow_issues(path, functions))
    return {
        "valid": not issues,
        "issues": issues,
        "node_count": len(path),
        "edge_count": expected_edges,
        "source_complete": _path_has_source_evidence([
            _node_info(functions, node_id) for node_id in path
        ]),
        "edge_statuses": list(edge_statuses),
    }


def _function_name(function_id: str, functions: Mapping[str, Any]) -> str:
    raw = functions.get(function_id, {})
    if isinstance(raw, Mapping):
        value = raw.get("name")
        if isinstance(value, str) and value:
            return value
    return function_id.rsplit(":", 1)[-1]


def _function_code(function_id: str, functions: Mapping[str, Any]) -> str:
    raw = functions.get(function_id, {})
    if not isinstance(raw, Mapping):
        return ""
    value = raw.get("code")
    return value if isinstance(value, str) else ""


def _path_control_flow_issues(
    path: list[str],
    functions: Mapping[str, Any],
) -> list[str]:
    """Return obvious control-flow contradictions in a function-level path.

    The native graph is intentionally conservative and operates at function
    granularity.  One important consequence is that it can compose callsites
    that cannot execute in the same path.  SmartPerf's logging macros are a
    concrete example: ``LOGI`` expands to ``SpLog(..., false, ...)``, while
    ``SpLog`` returns before ``GetLogFilePath`` unless ``isWriteLog`` is true.
    We do not attempt full path-sensitive analysis here; we only reject this
    directly source-provable contradiction so it cannot be presented as an
    executable source-to-sink path.
    """
    issues: list[str] = []

    # Tree-sitter's function index represents callbacks/lambdas declared in a
    # method by a synthetic name such as
    # ``ProcSetCacheCommand.DnsResolvListenInternal::ProcGetCacheContent``.
    # The enclosing method is also a node.  A function-level reverse walk can
    # therefore compose ``nested-A -> enclosing -> nested-B`` even though the
    # enclosing method creates the callbacks; nested-B is not invoked by
    # nested-A merely because both share the same lexical owner.  Reject this
    # mechanically recognizable shape.  It is not a general C++ path proof;
    # it only prevents a known parser-scope artifact from being displayed as
    # an executable chain.
    def synthetic_scope(node_id: str) -> tuple[str, bool]:
        # The first colon separates the file path from the qualified symbol;
        # the ``::`` inside a C++ name must remain part of the symbol.
        suffix = node_id.split(":", 1)[1] if ":" in node_id else node_id
        if "." not in suffix:
            return suffix, False
        return suffix.split(".", 1)[0], True

    scopes = [synthetic_scope(node_id) for node_id in path]
    for middle_index, (middle_scope, middle_nested) in enumerate(scopes):
        if middle_nested:
            continue
        nested_before = any(
            nested and scope == middle_scope
            for scope, nested in scopes[:middle_index]
        )
        nested_after = any(
            nested and scope == middle_scope
            for scope, nested in scopes[middle_index + 1:]
        )
        if nested_before and nested_after:
            issues.append(
                f"{path[middle_index]} is an enclosing function between sibling "
                "synthetic callback nodes"
            )
            break

    for index in range(len(path) - 2):
        caller_id, middle_id, next_id = path[index:index + 3]
        middle_name = _function_name(middle_id, functions)
        next_name = _function_name(next_id, functions)
        if not middle_name.endswith("SpLog") or not next_name.endswith("GetLogFilePath"):
            continue
        middle_code = _function_code(middle_id, functions)
        if not _WRITE_LOG_GUARD.search(middle_code):
            continue
        caller_code = _function_code(caller_id, functions)
        if _NORMAL_LOG_MACRO.search(caller_code) and not _WRITE_LOG_MACRO.search(caller_code):
            issues.append(
                f"{caller_id} invokes a non-writing LOG* macro, but {middle_id} "
                "returns before reaching GetLogFilePath"
            )
    return issues


def _signal_summary(owner: str, raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    kind = _text(raw.get("kind"), 64)
    if kind not in {"entry_point", "external_input", "cross_process"}:
        return None
    output: dict[str, Any] = {"unit_id": owner, "kind": kind}
    for key in (
        "confidence", "boundary", "direction", "evidence_status", "seed_status",
        "seed_reason", "evidence", "evidence_excerpt", "evidence_line_start",
        "evidence_line_end",
    ):
        value = raw.get(key)
        if value not in (None, "", []):
            output[key] = value if not isinstance(value, str) else value[:800]
    return output


def _semantic_boundary_root_ids(
    units: Iterable[Mapping[str, Any]],
    candidate_ids: set[str],
) -> set[str]:
    """Select semantic roots that actually look like external boundaries.

    A model may label a worker that consumes a child-process result as
    ``external_input`` or ``cross_process(receive)``.  Such a label is useful
    for recall, but it must not terminate the source-backed path before the
    socket/event function that scheduled the worker.  Prefer explicit
    boundary evidence; when evidence is absent, retain a high-confidence
    external-input seed for compatibility with existing datasets.
    """
    boundary_roots: set[str] = set()
    output_words = (
        "loadcmd", "popen", "child process", "helper output", "command output",
        "reads command", "reads the helper", "subprocess output",
    )
    boundary_words = (
        "socket", "recv", "accept", "listen", "bind", "connect", "read(",
        "read ", "recvmsg", "parcel", "ipc", "binder", "unix socket",
        "tcp", "udp", "message", "request", "event callback", "on event",
        "inbound", "incoming", "server endpoint",
    )
    internal_name_words = (
        "thread", "async", "worker", "collect", "loadcmd", "popen",
        "parse", "itemdata",
    )
    for raw_unit in units:
        if not isinstance(raw_unit, Mapping):
            continue
        unit_id = _text(raw_unit.get("id"))
        if unit_id not in candidate_ids:
            continue
        signals = raw_unit.get("llm_reachability_signals")
        if not isinstance(signals, list):
            continue
        for signal in signals:
            if not isinstance(signal, Mapping):
                continue
            kind = _text(signal.get("kind"))
            confidence = _text(signal.get("confidence")).lower()
            if kind not in {"external_input", "cross_process"}:
                continue
            if confidence not in {"high", "medium"}:
                continue
            haystack = " ".join(
                _text(signal.get(key)).lower()
                for key in ("evidence", "evidence_excerpt", "boundary", "direction")
            ).strip()
            # When a model supplied concrete evidence, require that evidence
            # to name an inbound boundary before using the signal as a path
            # terminus.  An unlabeled helper/reader is retained only when the
            # signal has no evidence at all; this keeps legacy seed-only
            # artifacts usable without treating child output as a socket root.
            # A concrete inbound API or endpoint is required when the model
            # supplied evidence. Generic words such as "event" or
            # "message" alone describe an internal state hand-off just as
            # often as they describe an external boundary.
            concrete_boundary = any(
                word in haystack
                for word in (
                    "socket", "recv", "accept", "listen", "bind", "connect",
                    "recvmsg", "read(", "read ", "parcel", "ipc", "binder",
                    "unix socket", "tcp", "udp", "incoming", "inbound",
                    "server endpoint", "event callback", "on event",
                )
            )
            if haystack and not concrete_boundary:
                continue
            function_name = _text(raw_unit.get("name") or raw_unit.get("id")).lower()
            # A model may mark an asynchronous collector or parser as an
            # external-input seed merely because it consumes a value later.
            # Unless the same evidence names an inbound boundary, it must not
            # terminate the reverse path at that internal worker.
            if any(word in function_name for word in internal_name_words) and not concrete_boundary:
                continue
            if any(word in haystack for word in output_words) and not concrete_boundary:
                continue
            boundary_roots.add(unit_id)
            break
    return boundary_roots


def _framework_boundary_root_ids(functions: Mapping[str, Any]) -> set[str]:
    """Return conservative framework callback/receive roots for context only.

    Some OpenHarmony callbacks are registered in framework code or generated
    glue that is outside the selected repository view.  They therefore have
    no reverse caller in the local graph even though their bodies are the
    actual inbound service boundary.  Recognize only well-known *handler
    method suffixes* here; this does not add graph edges or alter reachability.
    The resulting path still has to be validated node-by-node and retains its
    framework-boundary provenance in the context.
    """
    suffixes = {
        "OnEvent", "OnEventPoll", "OnDataRecv", "OnReceiveMsg",
        "OnReceiveMessage", "OnRequest", "RecvPacket", "ServingThread",
        "HandleRecvMessage", "CmdOnRecvMessage", "ProcessMessage",
        "TypeTcp", "HandleMsg", "StartListen", "StartUnixSocketListen",
        "StartMultiVpnSocketListen",
    }
    roots: set[str] = set()
    for function_id in functions:
        if not isinstance(function_id, str):
            continue
        qualified = function_id.split(":", 1)[1] if ":" in function_id else function_id
        short = qualified.rsplit("::", 1)[-1]
        if "." in short:  # generated lambda/function suffix, not the handler
            continue
        if short in suffixes:
            roots.add(function_id)
    return roots


def _load_callsite_contexts(
    graph_paths: Iterable[str | Path],
) -> dict[str, list[dict[str, Any]]]:
    """Index ledger callsites by their possible callee.

    The effective graph contains function-level edges, while the ledger keeps
    the exact expression, file and line for a call.  Joining the two lets Stage
    1 see callsite evidence without claiming that the ledger itself proves a
    source-to-sink attack chain.  Candidate targets are retained as
    ``candidate``; only a resolved/linked target is labelled ``confirmed``.
    """
    indexed: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str, str]] = set()
    for raw_graph_path in graph_paths:
        graph_path = Path(raw_graph_path)
        graph_payload = _load_graph(graph_path)
        graph_functions = (
            graph_payload.get("functions", {})
            if isinstance(graph_payload, Mapping)
            and isinstance(graph_payload.get("functions", {}), Mapping)
            else {}
        )
        ledger = None
        for name in ("callsite_ledger.json", "call_graph_residuals.json"):
            ledger = _load_graph(graph_path.parent / name)
            if ledger is not None:
                break
        if not isinstance(ledger, Mapping):
            continue
        flow_by_site: dict[str, list[dict[str, Any]]] = {}
        flow_path = graph_path.parent / "object_flow_facts.json"
        flow_payload = _load_graph(flow_path)
        if isinstance(flow_payload, Mapping):
            for raw_fact in flow_payload.get("facts", []) or []:
                if not isinstance(raw_fact, Mapping):
                    continue
                attrs = raw_fact.get("attributes") if isinstance(raw_fact.get("attributes"), Mapping) else {}
                evidence = raw_fact.get("evidence") if isinstance(raw_fact.get("evidence"), Mapping) else {}
                site_key = _text(
                    attrs.get("call_site_id")
                    or attrs.get("callsite_id")
                    or evidence.get("site_id")
                )
                if site_key:
                    flow_by_site.setdefault(site_key, []).append(dict(raw_fact))

        # The effective graph may contain source-backed candidate facts that
        # are not present in the parser's callsite ledger (for example an
        # object-flow fact for ``profiler->ItemData()`` or a function-pointer
        # submission discovered by the semantic overlay).  Keep those facts
        # in the same callsite index used by path validation.  Otherwise the
        # graph can carry a candidate edge with a real file/line/expression,
        # while the context builder reports ``candidate_callsite_missing`` and
        # drops the only useful upstream route.
        raw_candidate_facts = (
            graph_payload.get("candidate_facts", [])
            if isinstance(graph_payload, Mapping)
            else []
        )
        if isinstance(raw_candidate_facts, list):
            for raw_fact in raw_candidate_facts:
                if not isinstance(raw_fact, Mapping):
                    continue
                if _text(raw_fact.get("status") or "candidate").lower() != "candidate":
                    continue
                caller = _text(raw_fact.get("caller_id") or raw_fact.get("caller"))
                target = _text(raw_fact.get("callee_id") or raw_fact.get("callee"))
                evidence = raw_fact.get("evidence")
                evidence = evidence if isinstance(evidence, Mapping) else {}
                file_path = _text(
                    evidence.get("file")
                    or evidence.get("path")
                    or raw_fact.get("file")
                    or raw_fact.get("path")
                )
                line_start = evidence.get(
                    "line_start",
                    evidence.get("start_line", evidence.get("line")),
                )
                line_end = evidence.get(
                    "line_end",
                    evidence.get("end_line", line_start),
                )
                expression = _text(
                    evidence.get("expression")
                    or evidence.get("relation")
                    or raw_fact.get("expression")
                )
                site_id = _text(
                    raw_fact.get("site_id")
                    or raw_fact.get("callsite_id")
                    or evidence.get("site_id")
                    or raw_fact.get("fact_id")
                )
                if not caller or not target or not file_path or line_start is None:
                    continue
                key = (target, site_id, caller)
                if key in seen:
                    continue
                seen.add(key)
                excerpt = ""
                caller_info = graph_functions.get(caller, {})
                if isinstance(caller_info, Mapping):
                    code = caller_info.get("code")
                    try:
                        start_line = int(caller_info.get("start_line", 1))
                        source_line = int(line_start)
                    except (TypeError, ValueError):
                        start_line = source_line = 0
                    if isinstance(code, str) and start_line and source_line >= start_line:
                        code_lines = code.splitlines()
                        offset = source_line - start_line
                        if 0 <= offset < len(code_lines):
                            excerpt = code_lines[offset].strip()[:600]
                evidence_excerpt = _text(evidence.get("excerpt") or evidence.get("text"))
                indexed.setdefault(target, []).append({
                    "callsite_id": site_id or None,
                    "location": f"{file_path}:{line_start}",
                    "file": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "expression": expression or None,
                    "caller": caller,
                    "callee": target,
                    "call_type": raw_fact.get("call_type") or raw_fact.get("kind"),
                    "dispatch_type": raw_fact.get("dispatch_type"),
                    "binding_status": raw_fact.get("binding_status"),
                    "dispatch_status": raw_fact.get("dispatch_status"),
                    "graph_status": raw_fact.get("graph_status"),
                    "candidate_target_ids": [target],
                    "linked_target_ids": [],
                    "candidate_completeness": raw_fact.get("candidate_completeness"),
                    "target_set_completeness": raw_fact.get(
                        "candidate_completeness", "unknown"
                    ),
                    "binding_basis": raw_fact.get("binding_basis") or "semantic_candidate_fact",
                    "status": "candidate",
                    "assumptions": ["target_binding_not_confirmed"],
                    "evidence": [{
                        "kind": "semantic_candidate_fact",
                        "file": file_path,
                        "line_start": line_start,
                        "line_end": line_end,
                        "relation": expression or evidence_excerpt or "candidate target binding",
                        "status": "candidate",
                        "excerpt": excerpt or evidence_excerpt or None,
                    }],
                    "flow_facts": flow_by_site.get(site_id, [])[:16],
                })
        sites = ledger.get("call_sites")
        if not isinstance(sites, list):
            nested = ledger.get("residual")
            sites = nested.get("call_sites") if isinstance(nested, Mapping) else None
        if not isinstance(sites, list):
            continue
        for raw_site in sites:
            if not isinstance(raw_site, Mapping):
                continue
            caller = _text(raw_site.get("caller_id") or raw_site.get("caller"))
            site_id = _text(raw_site.get("site_id") or raw_site.get("id"))
            linked = raw_site.get("linked_target_ids")
            candidates = raw_site.get("candidate_target_ids")
            linked_values = linked if isinstance(linked, list) else []
            candidate_values = candidates if isinstance(candidates, list) else []
            inferred_values = _infer_member_pointer_targets(
                raw_site.get("expression"), graph_functions
            )
            targets: list[tuple[str, str]] = []
            for target in linked_values:
                target_id = _text(target)
                if target_id:
                    targets.append((target_id, "confirmed"))
            for target in candidate_values:
                target_id = _text(target)
                if target_id and not any(existing == target_id for existing, _ in targets):
                    targets.append((target_id, "candidate"))
            for target_id in inferred_values:
                if target_id and not any(existing == target_id for existing, _ in targets):
                    # A pointer-to-member expression identifies a concrete
                    # implementation, but the surrounding template/build
                    # context may still be incomplete.  Keep it candidate so
                    # it can explain a path without silently changing the
                    # strict effective graph.
                    targets.append((target_id, "candidate"))
            for target, relation_status in targets:
                key = (target, site_id, caller)
                if key in seen:
                    continue
                seen.add(key)
                file_path = _text(raw_site.get("file") or raw_site.get("path"))
                line_start = raw_site.get("line_start", raw_site.get("line"))
                line_end = raw_site.get("line_end", line_start)
                excerpt = ""
                caller_info = graph_functions.get(caller, {})
                if isinstance(caller_info, Mapping):
                    code = caller_info.get("code")
                    try:
                        start_line = int(caller_info.get("start_line", 1))
                        source_line = int(line_start)
                    except (TypeError, ValueError):
                        start_line = source_line = 0
                    if isinstance(code, str) and start_line and source_line >= start_line:
                        code_lines = code.splitlines()
                        offset = source_line - start_line
                        if 0 <= offset < len(code_lines):
                            excerpt = code_lines[offset].strip()[:600]
                missing: list[str] = []
                if relation_status != "confirmed":
                    missing.append("target_binding_not_confirmed")
                candidate_completeness = _text(raw_site.get("candidate_completeness")).lower()
                if candidate_completeness not in {
                    "complete", "exhaustive", "closed_world"
                }:
                    missing.append("candidate_target_set_not_proven_complete")
                is_inferred_pointer = target in inferred_values and target not in {
                    _text(value) for value in candidate_values + linked_values
                }
                indexed.setdefault(target, []).append({
                    "callsite_id": site_id or None,
                    "location": f"{file_path}:{line_start}" if file_path and line_start is not None else file_path,
                    "file": file_path or None,
                    "line_start": line_start,
                    "line_end": line_end,
                    "expression": raw_site.get("expression"),
                    "caller": caller or None,
                    "callee": target,
                    "call_type": raw_site.get("call_kind") or raw_site.get("call_type"),
                    "dispatch_type": raw_site.get("dispatch_kind"),
                    "binding_status": raw_site.get("binding_status"),
                    "dispatch_status": raw_site.get("dispatch_status"),
                    "graph_status": raw_site.get("graph_status"),
                    "candidate_target_ids": [
                        _text(value) for value in candidate_values
                        if _text(value)
                    ][:32] + ([target] if is_inferred_pointer else []),
                    "linked_target_ids": [
                        _text(value) for value in linked_values
                        if _text(value)
                    ][:32],
                    "candidate_completeness": raw_site.get("candidate_completeness"),
                    "target_set_completeness": (
                        raw_site.get("candidate_completeness") or "unknown"
                    ),
                    "binding_basis": (
                        raw_site.get("binding_basis") or "function_pointer_expression"
                        if is_inferred_pointer else raw_site.get("binding_basis")
                    ),
                    "status": relation_status,
                    "assumptions": missing,
                    "evidence": [{
                        "kind": "function_pointer_expression"
                        if is_inferred_pointer else "callsite_ledger",
                        "file": file_path or None,
                        "line_start": line_start,
                        "line_end": line_end,
                        "relation": raw_site.get("expression") or "callsite target binding",
                        "status": relation_status,
                        "excerpt": excerpt or None,
                    }],
                    "flow_facts": flow_by_site.get(site_id, [])[:16],
                })
    boundary_words = (
        "socket", "recv", "accept", "handle", "process", "network", "command",
        "dispatch", "thread", "event", "ipc", "parcel", "message",
    )
    for target, values in indexed.items():
        # Prefer callsites whose owner/expression carries an explicit boundary
        # or dispatch hint, then retain stable source order.  This is only a
        # context presentation policy; it never upgrades candidate edges.
        def relevance(item: Mapping[str, Any]) -> tuple[int, int, str, str]:
            haystack = " ".join(
                _text(item.get(key)).lower()
                for key in ("caller", "file", "expression", "call_type")
            )
            score = sum(1 for word in boundary_words if word in haystack)
            return (-score, 0 if item.get("status") == "confirmed" else 1,
                    _text(item.get("file")), _text(item.get("callsite_id")))
        indexed[target] = sorted(values, key=relevance)[:24]
    return indexed


def _all_reverse_paths(
    target: str,
    reverse: Mapping[str, list[str]],
    roots: set[str],
    *,
    functions: Mapping[str, Any] | None = None,
    max_paths: int = MAX_PATHS_PER_UNIT,
    max_depth: int = MAX_PATH_DEPTH,
) -> list[list[str]]:
    if not target:
        return []
    queue: deque[tuple[str, list[str]]] = deque([(target, [target])])
    visited: set[tuple[str, ...]] = set()
    paths: list[list[str]] = []
    while queue and len(paths) < max_paths:
        current, backward = queue.popleft()
        if current in roots:
            path = list(reversed(backward))
            if not functions or not _path_control_flow_issues(path, functions):
                paths.append(path)
            # A target can itself be marked as an entry/retention root while
            # still having an upstream dispatcher, listener, or service
            # initializer.  Recording the one-node root and stopping here
            # used to hide that caller.  Keep traversing (bounded and
            # cycle-guarded) so ranking can prefer the longer, source-backed
            # route.  The one-node path remains as an explicit fallback when
            # no upstream caller exists.
        if len(backward) >= max_depth:
            continue
        for caller in reverse.get(current, []) or []:
            if not isinstance(caller, str) or not caller:
                continue
            if caller in backward:
                continue
            candidate = tuple(backward + [caller])
            if candidate in visited:
                continue
            visited.add(candidate)
            queue.append((caller, list(candidate)))
    return paths


def _candidate_reverse_paths(
    target: str,
    reverse: Mapping[str, list[str]],
    roots: set[str],
    edge_status: Mapping[tuple[str, str], str],
    *,
    functions: Mapping[str, Any] | None = None,
    max_paths: int = MAX_PATHS_PER_UNIT,
    max_depth: int = MAX_PATH_DEPTH,
) -> list[tuple[list[str], list[str]]]:
    """Find bounded paths that contain at least one unverified edge.

    ``reverse`` is the union of the effective graph and ledger relationships.
    We intentionally keep a separate search instead of treating this union as
    the effective graph: a candidate edge is useful evidence for Stage 1 but
    cannot silently become a strict reachable path.  A root reached through
    only native edges is not emitted here; traversal continues until a path
    containing a candidate edge is found or the bounded search is exhausted.
    """
    if not target:
        return []
    queue: deque[tuple[str, list[str], bool]] = deque([(target, [target], False)])
    visited: set[tuple[tuple[str, ...], bool]] = set()
    paths: list[tuple[list[str], list[str]]] = []
    expansions = 0
    while queue and len(paths) < max_paths and expansions < MAX_CANDIDATE_PATH_EXPANSIONS:
        current, backward, has_candidate = queue.popleft()
        expansions += 1
        if current in roots and has_candidate:
            path = list(reversed(backward))
            if functions and _path_control_flow_issues(path, functions):
                continue
            statuses = [
                edge_status.get((path[index], path[index + 1]), "native")
                for index in range(len(path) - 1)
            ]
            paths.append((path, statuses))
            # Do not stop at a candidate/semantic root.  Such a root may be a
            # callback or worker nested below a real socket/IPC dispatcher;
            # continuing lets the presentation layer retain the outer route
            # without upgrading any candidate edge.
        # A root that was reached without a candidate edge may itself be an
        # incidental/framework root (for example a detached worker that the
        # generic detector classified as an execution function).  For the
        # candidate view we must be able to continue through that root and
        # reach an earlier socket/IPC root where the missing edge is recorded.
        # Stop only after a candidate-bearing path reaches a root.  This does
        # not change strict reachability, and the cycle guard below keeps the
        # bounded search finite.
        # Keep traversing after a candidate-bearing root.  Semantic seeds and
        # framework handlers are often intermediate roots (for example
        # ``OnReceiveMsg`` is separately labelled as an entry signal while the
        # socket read lives in ``OnEventPoll``).  Stopping here would produce a
        # path that starts at the inner handler and hide the actual outer
        # boundary.  The bounded depth/expansion limits and simple-cycle guard
        # keep this search finite.
        if len(backward) >= max_depth:
            continue
        for caller in reverse.get(current, []) or []:
            if not isinstance(caller, str) or not caller:
                continue
            if caller in backward:
                continue
            status = edge_status.get((caller, current), "native")
            next_has_candidate = has_candidate or status == "candidate"
            next_backward = tuple(backward + [caller])
            visit_key = (next_backward, next_has_candidate)
            if visit_key in visited:
                continue
            visited.add(visit_key)
            queue.append((caller, list(next_backward), next_has_candidate))
    # Prefer paths that preserve an explicit boundary/dispatch vocabulary.  A
    # generic helper can have many candidate callers; showing only the first
    # lexical paths would otherwise hide the socket-handler candidate that is
    # most useful to Stage 1.
    boundary_words = (
        "socket", "recv", "accept", "handle", "process", "network", "thread",
        "dispatch", "udp", "tcp", "ipc", "server", "command", "message",
    )
    def relevance(record: tuple[list[str], list[str]]) -> tuple[int, int, int, tuple[str, ...]]:
        path, statuses = record
        haystack = " ".join(path).lower()
        score = sum(1 for word in boundary_words if word in haystack)
        return (-score, -sum(1 for value in statuses if value == "candidate"), len(path), tuple(path))
    return sorted(paths, key=relevance)[:max_paths]


def _owner_prefix(function_id: str, functions: Mapping[str, Any]) -> str:
    """Return the innermost class/namespace owner visible in a function name."""
    name = _function_name(function_id, functions)
    if "::" not in name:
        return ""
    return name.rsplit("::", 1)[0].split("::")[-1]


def _rank_entry_paths(
    paths: Iterable[list[str]],
    functions: Mapping[str, Any],
    *,
    max_paths: int = MAX_PATHS_PER_UNIT,
) -> list[list[str]]:
    """Prefer source-backed external-boundary paths over lexical/self paths.

    Reverse BFS is intentionally bounded and follows a set of roots.  The
    order in which callers are stored in a graph is not a semantic ranking,
    however.  This presentation-level ranking keeps Stage 1 from receiving a
    short internal helper path when a socket/process/dispatch path is also
    available.  It never turns a candidate edge into a confirmed edge.
    """
    records = [path for path in paths if isinstance(path, list) and path]
    boundary_words = (
        "socket", "recv", "accept", "listen", "handle", "process", "server",
        "thread", "dispatch", "message", "parcel", "ipc", "request", "command",
        "event", "callback", "receive", "listener", "main", "run", "start", "loop",
    )

    # A semantic seed is often the target itself (or a nearby cache/helper)
    # and can produce a perfectly valid reverse path which starts in the
    # middle of the service.  When the same target also has a path rooted at
    # an explicit listener/receiver/dispatcher, the latter is the useful
    # Stage-1 context.  Apply this as a presentation filter, never as a graph
    # or reachability rule: all paths remain available in the JSON context.
    hard_boundary_words = (
        "socket", "accept", "recv", "receive", "listen", "listener",
        "handle", "process", "dispatch", "server", "parcel", "ipc",
        "request", "message", "event", "callback", "main", "command",
        "serving", "runforclientfd", "handlerfdholder", "ondatarecv",
        "onevent", "oneventpoll", "onreceivemsg", "onrequest", "recvpacket",
        "startlisten", "startunixsocketlisten", "startmultivpnsocketlisten",
    )

    def is_explicit_boundary(path: list[str]) -> bool:
        if not path:
            return False
        # Match the callable's method/function token, not the source path or
        # owning class.  For example, every DNS helper lives in
        # ``dns_resolv_listen.cpp`` and ``DnsResolvListenInternal``; neither
        # fact makes ``ProcGetCacheSize`` a listener.
        root = _function_name(path[0], functions).rsplit("::", 1)[-1].lower()
        return any(word in root for word in hard_boundary_words)

    explicit_boundary_records = [path for path in records if is_explicit_boundary(path)]
    if explicit_boundary_records:
        records = explicit_boundary_records

    def relevance(path: list[str]) -> tuple[int, int, int, tuple[str, ...]]:
        root = path[0]
        root_name = _function_name(root, functions).lower()
        haystack = " ".join(
            (_function_name(node, functions) + " " + node).lower() for node in path
        )
        hard_boundary_score = sum(
            1 for word in ("socket", "recv", "accept", "listen", "parcel", "ipc")
            if word in root_name
        )
        event_boundary_score = 8 if any(
            root_name.endswith(suffix)
            for suffix in ("::onevent", "::oneventpoll", "::ondatarecv", "::onreceivemsg", "::recvpacket")
        ) else 0
        handler_score = sum(
            1 for word in ("handle", "process", "server", "dispatch", "message")
            if word in root_name
        )
        boundary_score = sum(1 for word in boundary_words if word in root_name)
        chain_score = sum(1 for word in boundary_words if word in haystack)
        # A one-node semantic/self path is useful only when no real upstream
        # route exists.  It should never outrank a multi-node route.
        self_penalty = 100 if len(path) == 1 else 0
        return (
            -(hard_boundary_score * 1600 + event_boundary_score * 350
              + handler_score * 350
              + boundary_score * 100 + chain_score - self_penalty),
            -len(path),
            0 if len(path) > 1 else 1,
            tuple(path),
        )

    return sorted(records, key=relevance)[:max_paths]


def _rank_candidate_paths(
    records: Iterable[tuple[list[str], list[str]]],
    functions: Mapping[str, Any],
    callsite_contexts_by_target: Mapping[str, list[Mapping[str, Any]]],
    *,
    max_paths: int = MAX_PATHS_PER_UNIT,
) -> list[tuple[list[str], list[str]]]:
    """Rank candidate paths by boundary quality and plausible target ownership.

    A broad virtual/factory candidate can create dozens of syntactically valid
    paths.  For a target such as ``FPS::GetDistr``, a candidate edge to
    ``FPS::ItemData`` is a much better explanatory path than an unrelated
    ``Power::ItemData`` path.  The path remains explicitly ``candidate``; this
    heuristic only controls which evidence is shown first.
    """
    target_records = [record for record in records if isinstance(record, tuple) and len(record) == 2]
    if not target_records:
        return []
    target_id = target_records[0][0][-1]
    target_owner = _owner_prefix(target_id, functions)
    boundary_words = (
        "socket", "recv", "accept", "listen", "handle", "process", "server",
        "thread", "dispatch", "message", "parcel", "ipc", "request", "command",
        "main", "run", "start", "loop",
    )

    # Keep candidate presentation aligned with strict presentation.  A
    # candidate path rooted at an explicit receiver/listener is more useful
    # than a path rooted at a semantic seed or an internal cache helper.  The
    # candidate status and all non-selected paths are retained unchanged.
    hard_boundary_words = (
        "socket", "accept", "recv", "receive", "listen", "listener",
        "handle", "process", "dispatch", "server", "parcel", "ipc",
        "request", "message", "event", "callback", "main", "command",
        "serving", "runforclientfd", "handlerfdholder", "ondatarecv",
        "onevent", "oneventpoll", "onreceivemsg", "onrequest", "recvpacket",
        "startlisten", "startunixsocketlisten", "startmultivpnsocketlisten",
    )

    def is_explicit_boundary(record: tuple[list[str], list[str]]) -> bool:
        path = record[0]
        if not path:
            return False
        root = _function_name(path[0], functions).rsplit("::", 1)[-1].lower()
        return any(word in root for word in hard_boundary_words)

    explicit_boundary_records = [record for record in target_records if is_explicit_boundary(record)]
    if explicit_boundary_records:
        target_records = explicit_boundary_records

    def score(record: tuple[list[str], list[str]]) -> tuple[int, int, int, int, tuple[str, ...]]:
        path, statuses = record
        names = [(_function_name(node, functions) + " " + node).lower() for node in path]
        boundary_text = " ".join(names)
        root_text = names[0] if names else ""
        hard_boundary_score = sum(
            1 for word in ("socket", "recv", "accept", "listen", "handle", "parcel", "ipc")
            if word in root_text
        )
        handler_score = sum(
            1 for word in ("handle", "process", "server", "dispatch", "message")
            if word in root_text
        )
        boundary_score = sum(1 for word in boundary_words if word in boundary_text)
        service_route_score = 0
        if hard_boundary_score or handler_score:
            service_route_score = sum(
                1 for word in ("network", "socket", "ipc", "server")
                if word in boundary_text
            ) * 90
        owner_score = 0
        broad_penalty = 0
        resolved_bonus = 0
        candidate_count = 0
        for index, status in enumerate(statuses):
            if index + 1 >= len(path):
                continue
            if status != "candidate":
                continue
            candidate_count += 1
            caller, callee = path[index], path[index + 1]
            callee_owner = _owner_prefix(callee, functions)
            if target_owner and callee_owner == target_owner:
                owner_score += 80
            contexts = callsite_contexts_by_target.get(callee, [])
            matching = [
                item for item in contexts
                if isinstance(item, Mapping) and _text(item.get("caller")) == caller
            ]
            if not matching:
                broad_penalty += 10
                continue
            best = matching[0]
            targets = best.get("candidate_target_ids")
            target_count = len(targets) if isinstance(targets, list) else 0
            broad_penalty += min(target_count, 32)
            if _text(best.get("binding_status")).lower() == "resolved":
                resolved_bonus += 8
            if _text(best.get("candidate_completeness")).lower() in {
                "complete", "exhaustive", "closed_world"
            }:
                resolved_bonus += 12
        # Fewer unresolved dispatches are preferred once owner/boundary quality
        # is accounted for.  Longer paths are retained because they expose the
        # actual call chain instead of a helper shortcut.
        # The primary objective is a plausible boundary and a small number of
        # unresolved dispatches.  A path with one direct factory candidate is
        # preferable to a longer path containing two unrelated candidates;
        # this is what keeps ``HandleMsg -> Network::ItemData`` ahead of the
        # unrelated visual-effect logging branch for LoadCmd.
        total = (
            hard_boundary_score * 1600
            + handler_score * 350
            + owner_score
            + service_route_score
            + boundary_score * 6
            + resolved_bonus
            - candidate_count * 420
            - broad_penalty * 2
        )
        return (
            -total,
            candidate_count,
            -len(path),
            0 if len(path) > 1 else 1,
            tuple(path),
        )

    return sorted(target_records, key=score)[:max_paths]


def _path_entry_role_score(path: list[str], functions: Mapping[str, Any]) -> int:
    """Score the *first* node of a path for presentation as the primary route.

    This is deliberately not a reachability or edge-validation rule.  It only
    decides which already-recorded strict/candidate path should be shown first
    to Stage 1.  A socket/message handler is a better explanation of an
    externally triggered route than an initialization helper or a detached
    worker, even when both paths are present in the graph.
    """
    if not path:
        return -10_000
    # Use the callable name only.  The stable ID contains the source path, so
    # matching words in ``dns_resolv_listen.cpp`` would incorrectly classify
    # every helper in that file as a listener.
    root = _function_name(path[0], functions).rsplit("::", 1)[-1].lower()
    score = 0
    for word, value in (
        ("socket", 900), ("accept", 850), ("recv", 800), ("listen", 880),
        ("onreceive", 820), ("onrequest", 780), ("onevent", 900),
        ("ondatarecv", 880), ("oneventpoll", 900), ("recvpacket", 860),
        ("recvmsg", 820), ("serving", 780), ("accepting", 760),
        ("runforclient", 800), ("handlerfd", 760), ("communicationloop", 700),
        ("callback", 760), ("handle", 700),
        ("process", 500), ("dispatch", 480), ("listener", 450),
        ("message", 420), ("parcel", 420), ("ipc", 420),
        ("server", 400), ("command", 360), ("main", 260),
        ("init", -180), ("start", -90), ("thread", -40),
        ("worker", -80), ("async", -80), ("itemdata", -160),
        ("loadcmd", -220), ("popen", -220),
    ):
        if word in root:
            score += value
    # For command-execution sinks, prefer a source-backed request/handler
    # route over an unrelated logging/archive/helper branch when both routes
    # share the same boundary.  This is deliberately sink-class based rather
    # than tied to one repository or function name; it only chooses the
    # presentation path and does not change edge status.
    target = _function_name(path[-1], functions).rsplit("::", 1)[-1].lower()
    sink_like = any(
        token in target for token in ("loadcmd", "popen", "system", "exec", "shell")
    )
    if sink_like:
        route_text = " ".join(
            _function_name(node, functions).lower() for node in path
        )
        score += sum(
            value for word, value in (
                ("network", 360), ("socket", 300), ("recv", 260),
                ("handle", 180), ("command", 140), ("dispatch", 120),
                ("sp log", -280), ("tar", -220), ("copy", -180),
                ("remove", -120), ("trace", -100),
            ) if word in route_text
        )
    # A path with a real upstream chain is more useful than a semantic seed
    # that consists of the target itself.  This does not alter its status.
    if len(path) > 1:
        score += min(len(path), 12) * 8
    else:
        score -= 1000
    return score


def _select_primary_entry_path(
    strict_paths: Iterable[list[str]],
    candidate_records: Iterable[tuple[list[str], list[str]]],
    functions: Mapping[str, Any],
) -> tuple[str, list[str], list[str]]:
    """Choose a display path while preserving strict/candidate provenance.

    The strict graph remains authoritative for ``entry_paths``.  A
    source-backed candidate route may nevertheless be the most relevant
    explanation of the target's external entry (for example a factory return
    followed by ``profiler->ItemData()``).  Returning ``candidate`` here makes
    that choice explicit; callers must never interpret it as a strict edge.
    """
    strict = [path for path in strict_paths if isinstance(path, list) and path]
    candidates = [
        record for record in candidate_records
        if isinstance(record, tuple) and len(record) == 2
        and isinstance(record[0], list) and record[0]
        and _path_has_source_evidence([
            _node_info(functions, node_id) for node_id in record[0]
        ])
    ]
    # A target can also be retained as a semantic/root unit.  In that case
    # reverse traversal records a valid one-node path in addition to a real
    # caller chain.  The one-node path must not win merely because the target
    # name contains words such as ``recv`` or ``handle``: Stage 1 needs the
    # outermost already-validated route when one exists.  Keep the root-only
    # path in ``entry_path_ids`` as a fallback, but exclude it from primary
    # selection whenever an upstream strict route is available.
    strict_with_upstream = [path for path in strict if len(path) > 1]
    strict_for_primary = strict_with_upstream or strict
    best_strict = max(
        strict_for_primary,
        key=lambda path: _path_entry_role_score(path, functions),
        default=None,
    )
    best_candidate = max(
        candidates,
        key=lambda record: _path_entry_role_score(record[0], functions),
        default=None,
    )
    if best_strict is None and best_candidate is None:
        return "none", [], []
    if best_strict is None:
        return "candidate", list(best_candidate[0]), list(best_candidate[1])
    if best_candidate is None:
        return "strict", list(best_strict), []
    strict_score = _path_entry_role_score(best_strict, functions)
    candidate_score = _path_entry_role_score(best_candidate[0], functions)
    # Prefer a candidate only when it is materially more boundary-like.  This
    # avoids replacing a well-established main/socket path merely because a
    # secondary callback route happens to contain the word ``process``.
    if candidate_score >= strict_score + 180:
        return "candidate", list(best_candidate[0]), list(best_candidate[1])
    return "strict", list(best_strict), []


def _build_candidate_reverse_graph(
    reverse: Mapping[str, list[str]],
    callsite_contexts_by_target: Mapping[str, list[Mapping[str, Any]]],
) -> tuple[dict[str, list[str]], dict[tuple[str, str], str]]:
    """Overlay ledger targets on the native reverse graph for diagnostics.

    Native edges are marked ``native``.  A ledger relationship that is absent
    from the native graph is marked ``candidate`` even when its binding status
    says ``resolved``: until it is projected into the effective graph, it must
    remain visibly unverified for reachability and security conclusions.
    """
    candidate_reverse = {
        str(callee): set(callers or [])
        for callee, callers in reverse.items()
    }
    edge_status: dict[tuple[str, str], str] = {}
    for callee, callers in candidate_reverse.items():
        for caller in callers:
            edge_status[(caller, callee)] = "native"
    for target, contexts in callsite_contexts_by_target.items():
        if not target:
            continue
        for context in contexts or []:
            if not isinstance(context, Mapping):
                continue
            caller = _text(context.get("caller"))
            if not caller:
                continue
            candidate_reverse.setdefault(target, set()).add(caller)
            edge_status.setdefault((caller, target), "candidate")
    return (
        {callee: sorted(callers) for callee, callers in candidate_reverse.items()},
        edge_status,
    )


def build_reachability_context(
    dataset: Mapping[str, Any],
    graph_paths: Iterable[str | Path],
    *,
    platform: str = "generic",
) -> dict[str, Any]:
    """Return an enriched dataset copy with top-level entry paths."""
    graph_paths = list(graph_paths)
    functions, forward, reverse, versions = _merge_graphs(graph_paths)
    callsite_contexts_by_target = _load_callsite_contexts(graph_paths)
    candidate_reverse, candidate_edge_status = _build_candidate_reverse_graph(
        reverse, callsite_contexts_by_target
    )
    units = dataset.get("units", []) if isinstance(dataset, Mapping) else []
    units = units if isinstance(units, list) else []

    try:
        detector_cls = _load_entry_detector()
        detector = detector_cls(
            functions,
            forward,
            platform=platform,
        )
        detector_roots = set(detector.detect_entry_points())
        details = detector.entry_point_details
        structural_roots = _structural_root_ids(detector_roots, details)
        incidental_roots = detector_roots - structural_roots
    except Exception as exc:  # context is additive; never block a scan
        structural_roots = set()
        details = {}
        detector_error = str(exc)[:300]
        incidental_roots = set()
    else:
        detector_error = None

    explicit_roots = {
        str(unit.get("id"))
        for unit in units
        if isinstance(unit, Mapping)
        and unit.get("id")
        and unit.get("is_entry_point") is True
    }
    semantic_roots = {
        str(unit.get("id"))
        for unit in units
        if isinstance(unit, Mapping)
        and unit.get("id")
        and unit.get("semantic_reachability_seed") is True
    }
    roots = (structural_roots | explicit_roots | semantic_roots) & set(functions)

    # A semantic seed is evidence that a node may be relevant, not proof that
    # it is the earliest boundary in the execution chain.  Detached workers
    # are the common failure mode: ``Network::ThreadGetHapNetwork`` can be
    # promoted by the model because it runs a command, but stopping reverse
    # traversal there hides the socket handler and the thread launcher that
    # scheduled it.  Keep semantic roots only when their own evidence actually
    # describes an external boundary (socket/event/IPC).  This preserves a
    # high-confidence socket handler as a terminus while allowing a worker
    # labelled ``external_input`` merely because it reads command output to be
    # traced back to its scheduler.  Reachability BFS still uses the original
    # ``roots`` set; this affects only context presentation.
    semantic_boundary_roots = _semantic_boundary_root_ids(units, semantic_roots)
    llm_entry_only_roots = {
        _text(raw_unit.get("id"))
        for raw_unit in units
        if isinstance(raw_unit, Mapping)
        and _text(raw_unit.get("id")) in roots
        and raw_unit.get("is_entry_point") is True
        and isinstance(raw_unit.get("llm_reachability_signals"), list)
        and raw_unit.get("llm_reachability_signals")
        and all(
            _text(signal.get("kind")) == "entry_point"
            for signal in raw_unit.get("llm_reachability_signals", [])
            if isinstance(signal, Mapping)
        )
    }
    # ``is_entry_point`` is also used by the broad reachability filter for
    # incidental input readers (for example a helper that calls ``popen`` or
    # reads a process result).  Such a unit is a valid *retention seed*, but
    # it is not a top-level external boundary for Stage 1 context.  Exclude
    # detector-known incidental roots here; otherwise a target can appear to
    # be its own root and hide the real socket/event caller.
    non_incidental_explicit_roots = (
        explicit_roots - semantic_roots - llm_entry_only_roots - incidental_roots
    )
    framework_boundary_roots = _framework_boundary_root_ids(functions)
    context_boundary_roots = (
        structural_roots
        | non_incidental_explicit_roots
        | semantic_boundary_roots
        | framework_boundary_roots
    ) & set(functions)
    # Do not fall back to every semantic seed when at least one genuine
    # structural/boundary root exists.  That fallback made a worker or the
    # target itself appear as a one-node "top-level" path and hid the actual
    # upstream socket/command handler.  If no boundary can be identified at
    # all, retain the historical root set as an explicit uncertainty fallback.
    preferred_roots = context_boundary_roots or (
        roots - incidental_roots - semantic_roots
    ) or roots

    enriched_units: list[dict[str, Any]] = []
    unit_by_id = {
        _text(unit.get("id")): unit
        for unit in units
        if isinstance(unit, Mapping) and _text(unit.get("id"))
    }
    path_count = 0
    no_path_count = 0
    for raw_unit in units:
        if not isinstance(raw_unit, Mapping):
            continue
        unit = dict(raw_unit)
        unit_id = _text(unit.get("id"))
        paths = _all_reverse_paths(
            unit_id,
            reverse,
            preferred_roots,
            functions=functions,
            # Collect more paths than we display so BFS ordering does not hide
            # a socket/dispatcher route behind a lexical helper route.
            max_paths=MAX_PATHS_PER_UNIT * 8,
        )
        paths = _rank_entry_paths(paths, functions)
        candidate_path_records = _candidate_reverse_paths(
            unit_id,
            candidate_reverse,
            preferred_roots,
            candidate_edge_status,
            functions=functions,
            # Collect a little more than the presentation cap so relevance
            # ranking can retain a boundary/dispatch path instead of an
            # arbitrary lexical candidate.
            max_paths=MAX_PATHS_PER_UNIT * 8,
        )
        # Do not fall back to every retention seed for candidate presentation.
        # A semantic worker/target seed can be useful for keeping a unit in
        # the dataset, but using it as a candidate root would manufacture a
        # plausible-looking path that never reaches a proven socket/IPC or
        # structural boundary.  If no preferred boundary reaches the target,
        # keep the candidate view empty and report the unresolved upstream
        # evidence instead of displaying that internal route as an entry.
        candidate_path_records = _rank_candidate_paths(
            candidate_path_records,
            functions,
            callsite_contexts_by_target,
            max_paths=MAX_PATHS_PER_UNIT,
        )
        # A strict path is already represented by ``entry_paths``.  The
        # candidate view intentionally contains only paths that use at least
        # one ledger relationship absent from the effective graph, so the two
        # metrics do not double-count native coverage.
        candidate_path_records = candidate_path_records[:MAX_PATHS_PER_UNIT]
        candidate_paths = [record[0] for record in candidate_path_records]
        candidate_edge_statuses = [record[1] for record in candidate_path_records]
        primary_path_kind, primary_path_ids, primary_path_statuses = (
            _select_primary_entry_path(paths, candidate_path_records, functions)
        )
        path_count += len(paths)
        if not paths:
            no_path_count += 1
        node_paths = [
            [_node_info(functions, node_id) for node_id in path[:MAX_PATH_NODES]]
            for path in paths
        ]
        candidate_node_paths = [
            [_node_info(functions, node_id) for node_id in path[:MAX_PATH_NODES]]
            for path in candidate_paths
        ]
        primary_node_path = [
            _node_info(functions, node_id)
            for node_id in primary_path_ids[:MAX_PATH_NODES]
        ]
        primary_path_source_bundle = _source_bundle_for_path(
            primary_path_ids[:MAX_PATH_NODES],
            primary_path_statuses if primary_path_kind == "candidate" else (
                ["native"] * max(len(primary_path_ids[:MAX_PATH_NODES]) - 1, 0)
            ),
            functions,
            callsite_contexts_by_target,
            kind=primary_path_kind,
        )
        supporting_context_bundle = _supporting_context_bundle(
            unit_id,
            unit,
            functions,
            forward,
            callsite_contexts_by_target,
        )
        candidate_path_edges: list[list[dict[str, Any]]] = []
        for path, statuses in zip(candidate_paths, candidate_edge_statuses):
            path_edges: list[dict[str, Any]] = []
            for index, status in enumerate(statuses):
                if index + 1 >= len(path):
                    continue
                caller_id = path[index]
                callee_id = path[index + 1]
                edge_record: dict[str, Any] = {
                    "caller": caller_id,
                    "callee": callee_id,
                    "status": status,
                }
                if status == "candidate":
                    matching = [
                        context for context in callsite_contexts_by_target.get(callee_id, [])
                        if isinstance(context, Mapping)
                        and _text(context.get("caller")) == caller_id
                    ]
                    if matching:
                        selected = matching[0]
                        for key in (
                            "callsite_id", "location", "file", "line_start", "line_end",
                            "expression", "call_type", "dispatch_type", "binding_status",
                            "dispatch_status", "graph_status", "candidate_completeness",
                            "target_set_completeness", "binding_basis", "candidate_target_ids",
                            "linked_target_ids", "flow_facts", "evidence", "assumptions",
                        ):
                            value = selected.get(key)
                            if value not in (None, "", []):
                                edge_record[key] = value
                    else:
                        edge_record["assumptions"] = ["candidate_callsite_evidence_not_indexed"]
                path_edges.append(edge_record)
            candidate_path_edges.append(path_edges)
        strict_path_validation = [
            _validate_path_record(
                path,
                functions,
                forward,
                callsite_contexts_by_target=callsite_contexts_by_target,
            )
            for path in paths
        ]
        candidate_path_validation = [
            _validate_path_record(
                path,
                functions,
                forward,
                statuses,
                callsite_contexts_by_target=callsite_contexts_by_target,
            )
            for path, statuses in zip(candidate_paths, candidate_edge_statuses)
        ]
        primary_path_validation = (
            _validate_path_record(
                primary_path_ids,
                functions,
                forward,
                primary_path_statuses if primary_path_kind == "candidate" else None,
                callsite_contexts_by_target=callsite_contexts_by_target,
            )
            if primary_path_ids else {
                "valid": False,
                "issues": ["no_primary_path"],
                "node_count": 0,
                "edge_count": 0,
                "source_complete": False,
                "edge_statuses": [],
            }
        )
        root_ids = list(dict.fromkeys(path[0] for path in paths if path))
        root_details = [
            {
                "id": root_id,
                "reason": details.get(root_id, {}).get("reasons", [])
                if isinstance(details.get(root_id), Mapping)
                else [],
                "kind": (
                    "semantic_seed"
                    if root_id in semantic_roots and root_id not in structural_roots
                    else "structural_or_explicit"
                ),
            }
            for root_id in root_ids[:MAX_PATHS_PER_UNIT]
        ]
        attack_chain = context_from_unit(unit)
        # A ledger callsite is useful evidence, but it is not yet a complete
        # attack chain: dangerous parameter binding, state/event ordering and
        # source-to-sink propagation still need a dedicated analysis.
        if attack_chain["status"] == "not_evaluated":
            ledger_callsites = callsite_contexts_by_target.get(unit_id, [])
            if ledger_callsites:
                attack_chain = normalize_attack_chain_context({
                    "status": "incomplete",
                    "complete": False,
                    "callsite_contexts": ledger_callsites,
                    "missing_evidence": [
                        "dangerous_operation_and_parameter_not_bound",
                        "source_to_sink_dataflow_not_traced",
                        "state_or_event_order_not_traced",
                    ],
                    "provenance": "callsite_ledger",
                })
        # Attach direct-caller boundary signals separately from the generic
        # path.  This is useful evidence for Stage 1 (for example a caller is
        # known to receive socket data), but it is never promoted to a proven
        # source-to-sink chain without a callsite/data-flow proof.
        boundary_signals: list[dict[str, Any]] = []
        signal_owners = list(dict.fromkeys(
            [
                _text(item.get("caller"))
                for item in attack_chain.get("callsite_contexts", [])
                if isinstance(item, Mapping) and _text(item.get("caller"))
            ]
            + [
                node_id
                for path in candidate_paths
                for node_id in path[:-1]
                if _text(node_id)
            ]
            + list(reverse.get(unit_id, []) or [])
        ))
        for owner in signal_owners[:12]:
            owner_unit = unit_by_id.get(owner)
            if not isinstance(owner_unit, Mapping):
                continue
            for raw_signal in owner_unit.get("llm_reachability_signals", []) or []:
                summary = _signal_summary(owner, raw_signal)
                if summary is not None and summary not in boundary_signals:
                    boundary_signals.append(summary)
                    if len(boundary_signals) >= 16:
                        break
            if len(boundary_signals) >= 16:
                break
        generic_source_complete = any(
            _path_has_source_evidence(path) for path in node_paths
        )
        candidate_source_complete = any(
            _path_has_source_evidence(path) for path in candidate_node_paths
        )
        candidate_missing_evidence: list[str] = []
        if candidate_paths:
            candidate_missing_evidence.extend([
                "candidate_edge_not_in_effective_graph",
                "candidate_dispatch_or_binding_not_proven",
            ])
            if not candidate_source_complete:
                candidate_missing_evidence.append("candidate_path_source_excerpt_incomplete")
        # Keep structural Stage-1 context independent from the callsite/data
        # flow contract.  A target can be admitted to Stage 1 with a strict
        # path, a candidate path, or an explicit root even when Stage 2 has
        # not yet traced a dangerous parameter to a sink.
        if paths:
            stage1_context_status = "strict"
        elif candidate_paths:
            stage1_context_status = "candidate"
        elif unit_id in roots:
            stage1_context_status = "root"
        else:
            stage1_context_status = "unknown"
        stage1_missing_evidence = (
            [] if paths else (
                candidate_missing_evidence[:8]
                if candidate_paths else (
                    [] if unit_id in roots else [
                        "external_or_structural_entry_path_not_proven"
                    ]
                )
            )
        )
        reachability_status = (
            "path_found" if paths else (
                "candidate_path_found" if candidate_paths else (
                    "root" if unit_id in roots else "unknown"
                )
            )
        )
        unit["reachability_context"] = {
            "schema_version": SCHEMA_VERSION,
            "status": reachability_status,
            "graph_versions": versions,
            "root_entry_points": root_details,
            "top_level_entry": paths[0][0] if paths and paths[0] else None,
            "entry_paths": node_paths,
            "entry_path_ids": paths,
            "path_count": len(paths),
            # ``primary_*`` is a presentation view, not a replacement for
            # the evidence-tiered fields above.  It lets Stage 1 see the most
            # plausible external route when a strict logging/initialization
            # path and a source-backed factory/dispatch candidate coexist.
            "primary_entry_path_kind": primary_path_kind,
            "primary_entry_path_ids": [primary_path_ids] if primary_path_ids else [],
            "primary_entry_path": primary_node_path,
            "primary_entry_path_edge_statuses": primary_path_statuses,
            "primary_top_level_entry": primary_path_ids[0] if primary_path_ids else None,
            "primary_entry_path_source_complete": _path_has_source_evidence(primary_node_path),
            # Full function bodies are kept in this bounded, ordered bundle so
            # Stage 1 can inspect every function on the selected entry-to-target
            # route.  The legacy excerpt fields above remain for compatibility
            # with older reports and UI consumers.
            "primary_path_source_bundle": primary_path_source_bundle,
            "primary_entry_path_full_source_complete": primary_path_source_bundle.get(
                "source_complete", False
            ),
            "supporting_context_bundle": supporting_context_bundle,
            "primary_entry_path_validation": primary_path_validation,
            "strict_entry_path_validation": strict_path_validation,
            "candidate_entry_path_validation": candidate_path_validation,
            "upstream_complete": bool(paths and len(paths[0]) < MAX_PATH_DEPTH),
            # These fields intentionally separate the graph question from the
            # callsite/data-flow question.  A generic path is not an attack
            # chain proof; when no structured callsite evidence was supplied,
            # ``complete`` remains null and the status is explicit.
            "generic_entry_path_found": bool(paths),
            "generic_entry_path_source_complete": generic_source_complete,
            "candidate_entry_path_found": bool(candidate_paths),
            "candidate_entry_path_source_complete": candidate_source_complete,
            "candidate_entry_path_ids": candidate_paths,
            "candidate_entry_paths": candidate_node_paths,
            "candidate_entry_path_edge_statuses": candidate_edge_statuses,
            "candidate_entry_path_edges": candidate_path_edges,
            "candidate_path_count": len(candidate_paths),
            "candidate_missing_evidence": candidate_missing_evidence,
            # Explicit phase ownership: these fields answer the structural
            # question used by Stage 1 admission/context construction.  They
            # do not assert source-to-sink control of a dangerous parameter.
            "stage1_context_status": stage1_context_status,
            "stage1_context_analysis_allowed": True,
            "stage1_context_missing_evidence": stage1_missing_evidence,
            "stage2_dataflow_status": attack_chain["status"],
            "stage2_dataflow_complete": attack_chain["complete"],
            "stage2_dataflow_missing_evidence": attack_chain["missing_evidence"],
            "attack_chain_context": attack_chain,
            "attack_chain_context_status": attack_chain["status"],
            "attack_chain_context_complete": attack_chain["complete"],
            "attack_chain_missing_evidence": attack_chain["missing_evidence"],
            "upstream_boundary_signals": boundary_signals,
            "missing_upstream_evidence": (
                [] if paths else (
                    candidate_missing_evidence[:8]
                    if candidate_paths else list(reverse.get(unit_id, []) or [])[:8]
                )
            ),
        }
        if detector_error:
            unit["reachability_context"]["detector_error"] = detector_error
        enriched_units.append(unit)

    result = dict(dataset)
    result["units"] = enriched_units
    metadata = dict(dataset.get("metadata") or {}) if isinstance(dataset, Mapping) else {}
    metadata["reachability_context"] = {
        "schema_version": SCHEMA_VERSION,
        "graph_versions": versions,
        "root_count": len(roots),
        "structural_root_count": len(structural_roots & set(functions)),
        "incidental_root_count": len(incidental_roots & set(functions)),
        "explicit_root_count": len(explicit_roots & set(functions)),
        "semantic_root_count": len(semantic_roots & set(functions)),
        "units_with_paths": len(enriched_units) - no_path_count,
        "units_without_paths": no_path_count,
        "units_with_generic_entry_paths": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("generic_entry_path_found") is True
        ),
        "units_with_candidate_entry_paths": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("candidate_entry_path_found") is True
        ),
        "units_with_stage1_strict_context": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("stage1_context_status") == "strict"
        ),
        "units_with_stage1_candidate_context": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("stage1_context_status") == "candidate"
        ),
        "units_with_stage1_root_context": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("stage1_context_status") == "root"
        ),
        "units_with_stage2_dataflow_pending": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("stage2_dataflow_status")
            in {"not_evaluated", "incomplete", "unknown", "blocked"}
        ),
        "candidate_entry_paths_recorded": sum(
            int(unit.get("reachability_context", {}).get("candidate_path_count", 0))
            for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
        ),
        "units_with_attack_chain_context": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("attack_chain_context_status")
            not in {None, "not_evaluated"}
        ),
        "units_attack_chain_context_not_evaluated": sum(
            1 for unit in enriched_units
            if isinstance(unit.get("reachability_context"), Mapping)
            and unit["reachability_context"].get("attack_chain_context_status")
            == "not_evaluated"
        ),
        "paths_recorded": path_count,
        "platform": platform,
    }
    result["metadata"] = metadata
    return result


def enrich_dataset_file(
    dataset_path: str | Path,
    output_path: str | Path,
    graph_paths: Iterable[str | Path],
    *,
    platform: str = "generic",
) -> dict[str, Any]:
    dataset = read_json(dataset_path)
    enriched = build_reachability_context(dataset, graph_paths, platform=platform)
    from utilities.file_io import write_json

    write_json(output_path, enriched, indent=2)
    return enriched


__all__ = [
    "SCHEMA_VERSION",
    "build_reachability_context",
    "enrich_dataset_file",
]
