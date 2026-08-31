"""OpenHarmony semantic edges used by the reachability filter.

The ordinary C/C++ call graph is deliberately kept as the source graph.  This
module only projects a small, validated subset of the OpenHarmony IPC semantic
graph onto native function IDs so that an IPC stub can reach its handler when
the generated/native call graph does not contain that edge.  When generated
stub code is absent entirely, a transaction-to-handler edge can additionally
provide a validated external IPC entry-point seed.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, Mapping, Set, Tuple


# ``interface_to_transaction`` describes an interface declaration, not a
# runtime function invocation.  It must not seed function reachability.
SEMANTIC_REACHABILITY_EDGE_KINDS = frozenset(
    {
        "proxy_to_transaction",
        "stub_to_transaction",
        "transaction_to_handler",
        # Native member-function-table dispatch is an additive semantic
        # relation.  It is accepted here only after the resolver has attached
        # exact assignment/call-site evidence to the edge.
        "native_dispatch_to_handler",
        "native_dispatch_to_service",
        # Produced only by the validated LLM recovery projection stage. The
        # projection boundary checks caller/target membership, confidence,
        # and source-backed evidence before this edge can reach BFS.
        "llm_confirmed_indirect_call",
    }
)


def _function_id(node_id: Any) -> str | None:
    """Return the native ID encoded by a semantic function node ID."""
    if not isinstance(node_id, str) or not node_id.startswith("function:"):
        return None
    function_id = node_id[len("function:") :]
    return function_id or None


def build_semantic_reachability_overlay(
    semantic_graph: Mapping[str, Any] | None,
    known_function_ids: Iterable[str],
    *,
    max_depth: int = 4,
) -> Dict[str, Any]:
    """Collapse validated semantic IPC paths into native function edges.

    Only paths whose endpoints are known native functions are returned.  The
    semantic transaction/interface nodes remain out of the reachability graph;
    they are merely the evidence used to connect the two native endpoints.
    Malformed records are ignored so semantic enrichment cannot break the
    ordinary parser pipeline.
    """
    known: Set[str] = {item for item in known_function_ids if isinstance(item, str)}
    result: Dict[str, Any] = {
        "edges": [],
        "candidate_edges": 0,
        # Native IDs reached directly from an IPC transaction.  These are
        # external roots, not synthetic call-graph edges, and are consumed by
        # the pipeline's BFS seed set.
        "entry_points": [],
        "edge_kinds": [],
        "ignored_edge_count": 0,
        "invalid_endpoint_count": 0,
        "max_depth": max_depth,
    }
    if not isinstance(semantic_graph, Mapping) or max_depth < 1 or not known:
        return result

    nodes = semantic_graph.get("nodes", [])
    declared_nodes = {
        node.get("id")
        for node in nodes
        if isinstance(node, Mapping) and isinstance(node.get("id"), str)
    }
    node_kinds = {
        node.get("id"): node.get("kind")
        for node in nodes
        if isinstance(node, Mapping) and isinstance(node.get("id"), str)
    }
    # Older/hand-written fixtures may omit ``nodes``.  In that case the edge
    # endpoints still have to carry the explicit function: prefix and be in
    # the known function set; a populated node list is validated strictly.
    strict_nodes = bool(declared_nodes)
    function_nodes = {
        node_id
        for node_id in declared_nodes
        if _function_id(node_id) in known
    }

    adjacency: Dict[str, list[Tuple[str, str]]] = {}
    used_kinds: Set[str] = set()
    for edge in semantic_graph.get("edges", []) or []:
        if not isinstance(edge, Mapping):
            result["ignored_edge_count"] += 1
            continue
        source_id = edge.get("source_id")
        target_id = edge.get("target_id")
        kind = edge.get("kind")
        if kind not in SEMANTIC_REACHABILITY_EDGE_KINDS:
            result["ignored_edge_count"] += 1
            continue
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            result["invalid_endpoint_count"] += 1
            continue
        if strict_nodes and (
            source_id not in declared_nodes or target_id not in declared_nodes
        ):
            result["invalid_endpoint_count"] += 1
            continue
        adjacency.setdefault(source_id, []).append((target_id, kind))
        used_kinds.add(kind)

    if not strict_nodes:
        # Compatibility path for compact semantic graphs that omit the node
        # table: the explicit ``function:`` endpoint IDs still provide safe
        # roots, while the known-function allowlist prevents arbitrary IDs
        # from entering the native reachability graph.
        function_nodes = {
            endpoint
            for source_id, targets in adjacency.items()
            for endpoint in [source_id, *(target for target, _ in targets)]
            if _function_id(endpoint) in known
        }

    # A source-only checkout can contain the IDL and the service implementation
    # but not the generated Stub::OnRemoteRequest source.  In that case there
    # is no native function node from which to start the usual semantic path.
    # Treat only a declared/explicit transaction -> known function edge as an
    # external entry seed.  Interface declarations never become roots because
    # traversal starts at transaction nodes and the interface_to_transaction
    # edge points in the opposite direction.
    transaction_nodes = {
        node_id
        for node_id in declared_nodes
        if node_kinds.get(node_id) == "ipc_transaction"
    }
    if not strict_nodes:
        transaction_nodes.update(
            endpoint
            for source_id, targets in adjacency.items()
            for endpoint in [source_id, *(target for target, _ in targets)]
            if isinstance(endpoint, str) and endpoint.startswith("idl:transaction:")
        )
    external_entry_points: Set[str] = set()
    for transaction_id in sorted(transaction_nodes):
        for target, kind in adjacency.get(transaction_id, []):
            if kind != "transaction_to_handler":
                continue
            target_id = _function_id(target)
            if target_id in known:
                external_entry_points.add(target_id)
    result["entry_points"] = sorted(external_entry_points)

    # Keep the chosen path deterministic when a resolver emits duplicate or
    # competing evidence for the same pair.
    selected: Dict[Tuple[str, str], Tuple[int, Tuple[str, ...]]] = {}
    for source_node in sorted(function_nodes):
        source_id = _function_id(source_node)
        if source_id is None:
            continue
        queue = deque([(source_node, tuple())])
        visited = {(source_node, tuple())}
        while queue:
            current, path_kinds = queue.popleft()
            if len(path_kinds) >= max_depth:
                continue
            for target, kind in sorted(adjacency.get(current, [])):
                next_kinds = path_kinds + (kind,)
                state = (target, next_kinds)
                if state in visited:
                    continue
                visited.add(state)
                target_id = _function_id(target)
                if target_id in known and target_id != source_id:
                    pair = (source_id, target_id)
                    candidate = (len(next_kinds), next_kinds)
                    previous = selected.get(pair)
                    if previous is None or candidate < previous:
                        selected[pair] = candidate
                    # A function endpoint is a native boundary.  Do not walk
                    # through it to invent longer, transitive semantic calls.
                    continue
                queue.append((target, next_kinds))

    overlay_edges = [
        {
            "source_id": source_id,
            "target_id": target_id,
            "edge_kinds": list(path_kinds),
        }
        for (source_id, target_id), (_, path_kinds) in sorted(selected.items())
    ]
    result["edges"] = overlay_edges
    result["candidate_edges"] = len(overlay_edges)
    result["edge_kinds"] = sorted(used_kinds)
    return result


def merge_reachability_graph(
    call_graph: Mapping[str, Iterable[str]] | None,
    reverse_call_graph: Mapping[str, Iterable[str]] | None,
    overlay: Mapping[str, Any] | None,
) -> tuple[Dict[str, list[str]], Dict[str, list[str]]]:
    """Return copies of native graphs with semantic edges appended.

    The inputs are never mutated.  Existing native edge order is preserved and
    each semantic edge is added at most once, making repeated filtering
    deterministic and idempotent.
    """
    merged_call: Dict[str, list[str]] = {
        str(source): list(targets) if isinstance(targets, (list, tuple, set)) else []
        for source, targets in (call_graph or {}).items()
    }
    merged_reverse: Dict[str, list[str]] = {
        str(target): list(callers) if isinstance(callers, (list, tuple, set)) else []
        for target, callers in (reverse_call_graph or {}).items()
    }

    for edge in (overlay or {}).get("edges", []) or []:
        if not isinstance(edge, Mapping):
            continue
        source_id = edge.get("source_id")
        target_id = edge.get("target_id")
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            continue
        if source_id == target_id:
            continue
        targets = merged_call.setdefault(source_id, [])
        if target_id not in targets:
            targets.append(target_id)
        callers = merged_reverse.setdefault(target_id, [])
        if source_id not in callers:
            callers.append(source_id)

    return merged_call, merged_reverse
