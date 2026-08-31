"""Bounded, evidence-backed context for vulnerability disclosures.

The analysis pipeline keeps useful evidence in several sibling artifacts.  A
disclosure used to receive only a verdict and one source snippet, which made it
impossible for a reviewer (or the report model) to distinguish a local code
defect from a complete source-to-sink path.  This module joins those artifacts
without treating any artifact as trusted instructions and without copying an
entire repository graph into every prompt.

The public helpers deliberately return ordinary JSON-compatible dictionaries so
the pipeline schema remains backwards compatible:

``load_report_context_index(scan_dir)``
    Read known, optional artifacts from one scan directory.

``build_disclosure_context(index, route_key, finding, full_result, source_code)``
    Build a bounded context for one finding.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Mapping
from pathlib import Path


# Keep report prompts useful but bounded.  These limits apply per finding, not
# to the whole scan, so one unusually large function cannot exhaust the report
# model context or make the web UI unusable.
MAX_CONTEXT_NODES = 24
MAX_CONTEXT_EDGES = 96
MAX_FUNCTION_CODE_CHARS = 8_000
MAX_TOTAL_CODE_CHARS = 60_000
MAX_TEXT_CHARS = 8_000
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_UNRESOLVED_REFERENCES = 32


def _text(value, limit: int = MAX_TEXT_CHARS) -> str:
    """Return a bounded plain string for untrusted artifact values."""
    if isinstance(value, str):
        text = value
    elif value is None:
        return ""
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[已截断，原长度 {len(text)} 字符]"


def _list_of_strings(value, limit: int | None = None) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result = [item for item in value if isinstance(item, str) and item]
    return result[:limit] if limit is not None else result


def _source(value) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, Mapping):
        return ""
    for key in ("code", "source_code", "source", "snippet", "primary_code"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return ""


def _bounded_source(value, limit: int = MAX_FUNCTION_CODE_CHARS) -> tuple[str, bool]:
    source = _source(value)
    if len(source) <= limit:
        return source, False
    return source[:limit] + f"\n…[源码已截断，原长度 {len(source)} 字符]", True


def _read_json(path: Path):
    """Read a known optional artifact with a size guard.

    Artifact files are scan output and therefore untrusted data.  Only paths
    selected by this module are read, and an oversized/corrupt artifact simply
    becomes unavailable evidence instead of aborting report generation.
    """
    try:
        if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            return None
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _route(value) -> str:
    """Normalize route IDs from graph artifacts."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if value.startswith("function:"):
        value = value[len("function:"):]
    return value


def _route_file(route: str) -> str:
    return route.split(":", 1)[0] if ":" in route else ""


def _route_function(route: str) -> str:
    return route.split(":", 1)[1] if ":" in route else route


def _origin_to_record(origin: Mapping, source_code: str = "") -> dict:
    file_path = origin.get("file_path") or origin.get("path") or ""
    function = origin.get("function_name") or origin.get("name") or ""
    record = {
        "name": str(function) if function else "",
        "file_path": str(file_path) if file_path else "",
        "start_line": origin.get("start_line"),
        "end_line": origin.get("end_line"),
        "function_name": str(function) if function else "",
        "class_name": origin.get("class_name"),
        "unit_type": origin.get("unit_type"),
        "code": source_code,
    }
    return record


def _merge_function_record(functions: dict[str, dict], route: str, record) -> None:
    route = _route(route)
    if not route or not isinstance(record, Mapping):
        return
    existing = functions.setdefault(route, {})
    # Call-graph records normally have the best line range and source.  Dataset
    # origins fill gaps left by old/partial call-graph artifacts.
    for key in (
        "name", "file_path", "start_line", "end_line", "function_name",
        "class_name", "unit_type", "return_type", "parameters", "is_exported",
    ):
        value = record.get(key)
        if value not in (None, "", []):
            if existing.get(key) in (None, "", []):
                existing[key] = value
    code = _source(record)
    if code and not _source(existing):
        existing["code"] = code
    existing.setdefault("route_key", route)


def _merge_edges(mapping: dict[str, list[str]], payload) -> None:
    if not isinstance(payload, Mapping):
        return
    for source, targets in payload.items():
        source = _route(source)
        if not source or not isinstance(targets, (list, tuple)):
            continue
        output = mapping.setdefault(source, [])
        for target in targets:
            target = _route(target)
            if target and target not in output:
                output.append(target)


def _add_graph_functions(index: dict, payload) -> None:
    if not isinstance(payload, Mapping):
        return
    functions = payload.get("functions")
    if isinstance(functions, Mapping):
        for route, record in functions.items():
            _merge_function_record(index["functions"], route, record)
    _merge_edges(index["forward"], payload.get("call_graph"))
    _merge_edges(index["reverse"], payload.get("reverse_call_graph"))
    stats = payload.get("statistics")
    if isinstance(stats, Mapping):
        index["graph_statistics"].update({
            str(k): v for k, v in stats.items()
            if isinstance(k, str) and isinstance(v, (str, int, float, bool))
        })


def _add_dataset_units(index: dict, payload) -> None:
    if not isinstance(payload, Mapping):
        return
    units = payload.get("units")
    if not isinstance(units, list):
        return
    for unit in units:
        if not isinstance(unit, Mapping):
            continue
        route = _route(unit.get("id") or unit.get("route_key") or unit.get("unit_id"))
        if not route:
            continue
        code = unit.get("code")
        origin = code.get("primary_origin") if isinstance(code, Mapping) else None
        if isinstance(origin, Mapping):
            record = _origin_to_record(origin, _source(code))
        else:
            record = {
                "name": _route_function(route),
                "file_path": _route_file(route),
                "code": _source(code),
                "start_line": None,
                "end_line": None,
                "function_name": _route_function(route),
            }
        metadata = unit.get("metadata")
        if isinstance(metadata, Mapping):
            record.update({
                key: metadata.get(key) for key in (
                    "direct_calls", "direct_callers", "unit_type", "return_type",
                    "parameters", "is_exported",
                ) if metadata.get(key) not in (None, "", [])
            })
            _merge_edges(index["forward"], {route: metadata.get("direct_calls", [])})
            _merge_edges(index["reverse"], {route: metadata.get("direct_callers", [])})
        _merge_function_record(index["functions"], route, record)
        index["units"].setdefault(route, unit)
        agent_context = unit.get("agent_context")
        if isinstance(agent_context, Mapping):
            index["agent_context"].setdefault(route, agent_context)


def _normalise_edge(edge, *, source_key="source_id", target_key="target_id") -> dict | None:
    if not isinstance(edge, Mapping):
        return None
    source = _route(edge.get(source_key) or edge.get("source"))
    target = _route(edge.get(target_key) or edge.get("target"))
    if not source or not target:
        return None
    output = {
        "source": source,
        "target": target,
        "kind": _text(edge.get("kind"), 256),
    }
    for key in ("confidence", "resolver_version", "edge_kinds", "is_new", "selector"):
        value = edge.get(key)
        if value not in (None, "", []):
            if isinstance(value, (str, int, float, bool, list)):
                output[key] = value
    return output


def _add_semantic_edges(index: dict, payload) -> None:
    if not isinstance(payload, Mapping):
        return
    for edge in payload.get("edges", []) or []:
        normal = _normalise_edge(edge)
        if normal:
            index["semantic_edges"].append(normal)


def _add_projected_edges(index: dict, payload) -> None:
    if not isinstance(payload, Mapping):
        return
    for key in ("projected_edges", "added_edges", "retained_edges"):
        for edge in payload.get(key, []) or []:
            normal = _normalise_edge(edge)
            if normal:
                normal["kind"] = normal.get("kind") or "projected_dispatch"
                index["projected_edges"].append(normal)
    summary = payload.get("summary")
    if isinstance(summary, Mapping):
        index["recovery_summary"].update({
            str(k): v for k, v in summary.items()
            if isinstance(k, str) and isinstance(v, (str, int, float, bool))
        })


def _load_optional_call_graphs(index: dict, scan_dir: Path, payload) -> None:
    """Merge a multi-language ``call_graphs.json`` index when present."""
    if not isinstance(payload, Mapping):
        return
    entries = payload.get("graphs") or payload.get("call_graphs")
    if isinstance(entries, Mapping):
        entries = list(entries.values())
    if not isinstance(entries, list):
        return
    for item in entries[:32]:
        path_value = item.get("path") if isinstance(item, Mapping) else item
        if not isinstance(path_value, str) or not path_value:
            continue
        candidate = (scan_dir / path_value).resolve()
        try:
            candidate.relative_to(scan_dir.resolve())
        except ValueError:
            continue
        _add_graph_functions(index, _read_json(candidate))


def load_report_context_index(scan_dir: str | Path) -> dict:
    """Load known sibling scan artifacts into one bounded lookup index."""
    root = Path(scan_dir).resolve()
    index = {
        "functions": {},
        "forward": {},
        "reverse": {},
        "units": {},
        "agent_context": {},
        "semantic_edges": [],
        "projected_edges": [],
        "graph_statistics": {},
        "recovery_summary": {},
        "artifacts": [],
        "dataset_enhanced": False,
    }

    def load(name: str):
        path = root / name
        payload = _read_json(path)
        if payload is not None:
            index["artifacts"].append(name)
        return payload

    # Prefer the full native graph first; dataset origins then fill missing
    # records and preserve agentic context from enhanced datasets.
    _add_graph_functions(index, load("call_graph.json"))
    _load_optional_call_graphs(index, root, load("call_graphs.json"))
    enhanced = load("dataset_enhanced.json")
    if enhanced is not None:
        index["dataset_enhanced"] = True
    _add_dataset_units(index, enhanced)
    _add_dataset_units(index, load("dataset.json"))
    _add_semantic_edges(index, load("semantic_graph.json"))
    _add_projected_edges(index, load("dispatch_recovery_diff.json"))
    residual = load("call_graph_residuals.json")
    if isinstance(residual, Mapping):
        index["residual_summary"] = {
            "residual_site_count": len(residual.get("residual_sites", []) or []),
            "unresolved_count": len(residual.get("unresolved", []) or []),
        }
    else:
        index["residual_summary"] = {}
    return index


def _name_index(functions: Mapping) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for route, record in functions.items():
        name = _route_function(route)
        if isinstance(record, Mapping):
            name = str(record.get("function_name") or record.get("name") or name)
        if name:
            result.setdefault(name, []).append(route)
            # A qualified name often appears in evidence with a class prefix;
            # also index its final component for conservative matching.
            short = name.rsplit("::", 1)[-1]
            if short and short != name:
                result.setdefault(short, []).append(route)
    return result


def _resolve_reference(value: str, functions: Mapping, names: Mapping[str, list[str]]) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    candidate = re.split(r"\s*\(", candidate, maxsplit=1)[0].strip()
    candidate = candidate.strip("`'\".,;:")
    candidate = _route(candidate)
    if candidate in functions:
        return candidate
    exact = names.get(candidate) or []
    if len(exact) == 1:
        return exact[0]
    suffix = [route for route in functions if route.endswith(":" + candidate)]
    if len(suffix) == 1:
        return suffix[0]
    return ""


def _references_from_text(text: str, functions: Mapping, names: Mapping[str, list[str]]) -> list[str]:
    if not isinstance(text, str):
        return []
    found = []
    # Longest names first prevents ``Enable`` from winning before a qualified
    # ``MedicalSensorService::Enable`` reference.
    for name in sorted(names, key=len, reverse=True):
        if not name:
            continue
        # Do not resolve a short class/function component when the evidence
        # contains a qualified reference (``Class::Method``).  Otherwise a
        # service constructor or a short ``On`` helper can be spuriously added
        # simply because its component occurs inside a longer symbol name.
        if "::" not in name and re.search(rf"\b{re.escape(name)}\s*::", text):
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text):
            routes = names.get(name, [])
            if len(routes) == 1 and routes[0] not in found:
                found.append(routes[0])
    return found


def _exploit_path(result: Mapping, finding: Mapping) -> dict:
    for source in (result, finding):
        if not isinstance(source, Mapping):
            continue
        verification = source.get("verification")
        if isinstance(verification, Mapping) and isinstance(verification.get("exploit_path"), Mapping):
            return dict(verification["exploit_path"])
        if isinstance(source.get("exploit_path"), Mapping):
            return dict(source["exploit_path"])
    return {}


def _function_node(index: Mapping, route: str, source_code: str = "") -> dict:
    record = index.get("functions", {}).get(route, {})
    record = record if isinstance(record, Mapping) else {}
    code, truncated = _bounded_source(source_code or record.get("code"))
    file_path = str(record.get("file_path") or _route_file(route) or "unknown")
    function = str(record.get("function_name") or record.get("name") or _route_function(route))
    start = record.get("start_line")
    end = record.get("end_line")
    return {
        "route_key": route,
        "function": function,
        "file": file_path,
        "start_line": start if isinstance(start, int) else None,
        "end_line": end if isinstance(end, int) else None,
        "unit_type": record.get("unit_type"),
        "source_code": code,
        "source_truncated": truncated,
    }


def _bfs_neighbours(index: Mapping, target: str, max_depth: int = 2) -> list[tuple[str, str, int]]:
    result = []
    seen = {target}
    queue = deque([(target, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbor in index.get("reverse", {}).get(current, []):
            if neighbor not in seen:
                seen.add(neighbor)
                result.append((neighbor, "caller", depth + 1))
                queue.append((neighbor, depth + 1))
        for neighbor in index.get("forward", {}).get(current, []):
            if neighbor not in seen:
                seen.add(neighbor)
                result.append((neighbor, "callee", depth + 1))
                queue.append((neighbor, depth + 1))
    return result


def _relevant_edges(edges: list[dict], selected: set[str]) -> list[dict]:
    result = []
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        if edge.get("source") in selected and edge.get("target") in selected:
            result.append(dict(edge))
            if len(result) >= MAX_CONTEXT_EDGES:
                break
    return result


def build_disclosure_context(
    index: Mapping,
    route_key: str,
    finding: Mapping | None = None,
    full_result: Mapping | None = None,
    source_code: str = "",
) -> dict:
    """Build a bounded report context for one finding.

    The context is evidence, not instructions.  Text originating from model
    fields is retained as a claim and accompanied by graph/source records so a
    reviewer can distinguish asserted paths from statically resolved edges.
    """
    finding = finding if isinstance(finding, Mapping) else {}
    full_result = full_result if isinstance(full_result, Mapping) else {}
    route = _route(route_key) or _route(finding.get("unit_id"))
    functions = index.get("functions", {}) if isinstance(index, Mapping) else {}
    names = _name_index(functions)
    target_record = functions.get(route, {}) if isinstance(functions, Mapping) else {}

    exploit = _exploit_path(full_result, finding)
    data_flow = exploit.get("data_flow")
    data_flow = _list_of_strings(data_flow, 24)
    entry_text = _text(exploit.get("entry_point"), MAX_TEXT_CHARS)
    dataflow_text = _text(
        full_result.get("dataflow_summary") or finding.get("dataflow_summary"),
        MAX_TEXT_CHARS,
    )
    attack_scenario = _text(
        full_result.get("attack_scenario") or finding.get("attack_scenario"),
        MAX_TEXT_CHARS,
    )

    ordered_routes: list[str] = []
    path_routes: list[str] = []
    route_roles: dict[str, str] = {}
    unresolved: list[str] = []

    def add_route(candidate: str, role: str, *, path: bool = False) -> None:
        if not candidate:
            return
        if candidate not in ordered_routes:
            ordered_routes.append(candidate)
        route_roles.setdefault(candidate, role)
        if path and candidate not in path_routes:
            path_routes.append(candidate)

    # Stage-2 entry point is the strongest available source-to-sink ordering.
    if entry_text:
        for token in entry_text.split("->"):
            resolved = _resolve_reference(token, functions, names)
            if resolved:
                add_route(resolved, "entry" if not ordered_routes else "path", path=True)
            elif token.strip() and len(unresolved) < MAX_UNRESOLVED_REFERENCES:
                unresolved.append(token.strip())

    for step in data_flow:
        for resolved in _references_from_text(step, functions, names):
            add_route(resolved, "path", path=True)

    # Agentic context explicitly names downstream functions even when native
    # call-graph edges cannot cross a Binder/System Ability boundary.
    agent_context = index.get("agent_context", {}).get(route, {})
    includes = agent_context.get("include_functions", []) if isinstance(agent_context, Mapping) else []
    for item in includes:
        if not isinstance(item, Mapping):
            continue
        included_route = _resolve_reference(str(item.get("id") or ""), functions, names)
        if included_route:
            add_route(included_route, "context")

    add_route(route, "target")
    # Explicitly mark the final resolvable path function as a sink when the
    # exploit path says a sink was reached.  This is a label, not a new claim.
    if exploit.get("sink_reached") and path_routes:
        route_roles[path_routes[-1]] = "sink" if path_routes[-1] != route else "target"

    # Expand direct callers/callees around the target to expose the complete
    # local graph while keeping context bounded.
    for neighbor, relation, depth in _bfs_neighbours(index, route, max_depth=2):
        if len(ordered_routes) >= MAX_CONTEXT_NODES:
            break
        add_route(neighbor, relation)

    # Keep only routes with a function record or the target.  Unknown graph
    # references remain visible in `unresolved_references` rather than creating
    # fabricated source locations.
    selected = ordered_routes[:MAX_CONTEXT_NODES]
    omitted_nodes = max(0, len(ordered_routes) - len(selected))
    selected_set = set(selected)
    total_code = 0
    chain = []
    code_truncated = False
    for position, selected_route in enumerate(selected, 1):
        code_budget = max(0, min(MAX_FUNCTION_CODE_CHARS, MAX_TOTAL_CODE_CHARS - total_code))
        record = functions.get(selected_route, {}) if isinstance(functions, Mapping) else {}
        raw_code = source_code if selected_route == route and source_code else (record.get("code") if isinstance(record, Mapping) else "")
        node = _function_node(index, selected_route, raw_code if code_budget else "")
        if node["source_code"] and len(node["source_code"]) > code_budget:
            node["source_code"] = node["source_code"][:code_budget] + "\n…[披露上下文总源码预算已用尽]"
            node["source_truncated"] = True
        total_code += len(node["source_code"])
        code_truncated = code_truncated or bool(node["source_truncated"])
        node.update({
            "order": position,
            "role": route_roles.get(selected_route, "context"),
            "reason": "",
        })
        if selected_route == route:
            node["reason"] = "漏洞分析目标函数"
        for item in includes:
            if isinstance(item, Mapping) and _route(item.get("id")) == selected_route:
                node["reason"] = _text(item.get("reason"), 1_500)
                break
        chain.append(node)

    target = _function_node(index, route, source_code)
    selected_set.add(route)
    source_location = {
        "file": target["file"],
        "function": target["function"],
        "start_line": target["start_line"],
        "end_line": target["end_line"],
        "route_key": route,
    }

    source_sink = {
        "entry_point": entry_text,
        "ordered_steps": data_flow,
        "dataflow_summary": dataflow_text,
        "attack_scenario": attack_scenario,
        # This is the ordered chain explicitly supported by Stage 2 evidence.
        # Local caller/callee expansion below is context, not an assertion that
        # every neighboring graph node lies on the exploit path.
        "function_route_chain": path_routes or ([route] if route else []),
        "target_in_chain": route in path_routes,
        "sink_reached": exploit.get("sink_reached") if "sink_reached" in exploit else None,
        "attacker_control_at_sink": exploit.get("attacker_control_at_sink"),
        "path_broken_at": exploit.get("path_broken_at"),
    }

    # Native, semantic and projected edges are kept separate so the report can
    # state when an inter-process path is asserted by Stage 2 but absent from
    # the local native graph.
    native_edges = []
    for src in selected_set:
        for dst in index.get("forward", {}).get(src, []):
            if dst in selected_set:
                native_edges.append({"source": src, "target": dst, "kind": "native_call"})
                if len(native_edges) >= MAX_CONTEXT_EDGES:
                    break
        if len(native_edges) >= MAX_CONTEXT_EDGES:
            break
    semantic_edges = _relevant_edges(index.get("semantic_edges", []), selected_set)
    projected_edges = _relevant_edges(index.get("projected_edges", []), selected_set)
    if entry_text and not native_edges and not semantic_edges and not projected_edges:
        coverage_note = (
            "Stage 2 提供了跨进程入口到下游的路径描述，但当前本地调用图没有对应边；"
            "这不表示路径不存在，需结合 Binder/SA 注册证据复核。"
        )
    elif entry_text and (semantic_edges or projected_edges):
        coverage_note = "本地调用图与语义/恢复边均已纳入；跨进程边仍以证据和验证路径区分。"
    else:
        coverage_note = "当前上下文主要来自本地调用图；未发现可用的 Stage 2 跨进程路径。"

    return {
        "schema_version": 1,
        "target": {
            "source_location": source_location,
            "source_code": target.get("source_code", ""),
            "source_truncated": bool(target.get("source_truncated")),
        },
        "source_to_sink": source_sink,
        "call_chain": {
            "nodes": chain,
            "node_count": len(chain),
            "omitted_node_count": omitted_nodes,
            "truncated": bool(omitted_nodes or code_truncated),
            "unresolved_references": unresolved[:MAX_UNRESOLVED_REFERENCES],
        },
        "call_graph": {
            "native_edges": native_edges,
            "semantic_edges": semantic_edges,
            "projected_edges": projected_edges,
            "statistics": dict(index.get("graph_statistics", {})),
            "recovery_summary": dict(index.get("recovery_summary", {})),
            "coverage_note": coverage_note,
            "enhanced_dataset": bool(index.get("dataset_enhanced")),
        },
        "provenance": {
            "artifacts": list(index.get("artifacts", [])),
            "agentic_context": bool(includes),
            "residual_summary": dict(index.get("residual_summary", {})),
        },
    }
