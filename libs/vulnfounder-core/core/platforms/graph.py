"""Deterministic container for platform semantic-overlay graphs.

Language parsers keep their native call graphs.  This module stores the
additional, evidence-backed nodes and edges that cross language, IPC, build,
or runtime boundaries without pretending that they are ordinary source-level
calls.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from .base import SemanticEdge, SemanticNode


SCHEMA_VERSION = 1


def _require_nonempty_string(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _require_schema_version(value: Any, *, expected: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("schema_version must be a positive integer")
    if value != expected:
        raise ValueError(
            f"semantic graph schema_version {value} does not match {expected}"
        )
    return value


def _copy_mapping(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def _copy_evidence(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ValueError("evidence must be a list of objects")
    return [dict(item) for item in value]


def _confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("confidence must be a number between 0 and 1")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError("confidence must be a number between 0 and 1")
    return result


def _stable_key(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _merge_evidence(*groups: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for group in groups:
        for evidence in group:
            item = dict(evidence)
            unique[_stable_key(item)] = item
    return [unique[key] for key in sorted(unique)]


class SemanticGraph:
    """A validated, deterministic semantic graph overlay.

    Nodes are keyed by their stable ID.  Edges with the same source, target,
    and kind are merged, preserving all independent evidence while retaining
    the highest confidence.  Unresolved relationships are stored as explicit
    ``orphans`` instead of being silently discarded.
    """

    def __init__(self, *, schema_version: int = SCHEMA_VERSION) -> None:
        self.schema_version = _require_schema_version(
            schema_version, expected=SCHEMA_VERSION
        )
        self.nodes: dict[str, SemanticNode] = {}
        self.edges: dict[tuple[str, str, str], SemanticEdge] = {}
        self.orphans: list[dict[str, Any]] = []

    def add_node(self, node: SemanticNode | Mapping[str, Any]) -> SemanticNode:
        """Add a node, rejecting conflicting definitions for one stable ID."""
        normalized = node if isinstance(node, SemanticNode) else SemanticNode.from_dict(dict(node))
        _require_schema_version(normalized.schema_version, expected=self.schema_version)
        node_id = _require_nonempty_string("node.id", normalized.id)
        kind = _require_nonempty_string("node.kind", normalized.kind)
        attributes = _copy_mapping("node.attributes", normalized.attributes)
        candidate = SemanticNode(
            schema_version=self.schema_version,
            id=node_id,
            kind=kind,
            attributes=attributes,
        )
        existing = self.nodes.get(node_id)
        if existing is not None and existing.to_dict() != candidate.to_dict():
            raise ValueError(f"conflicting semantic node definition: {node_id}")
        self.nodes[node_id] = candidate
        return candidate

    def add_edge(self, edge: SemanticEdge | Mapping[str, Any]) -> SemanticEdge:
        """Add or merge an evidence-backed edge between existing nodes."""
        normalized = edge if isinstance(edge, SemanticEdge) else SemanticEdge.from_dict(dict(edge))
        _require_schema_version(normalized.schema_version, expected=self.schema_version)
        source_id = _require_nonempty_string("edge.source_id", normalized.source_id)
        target_id = _require_nonempty_string("edge.target_id", normalized.target_id)
        kind = _require_nonempty_string("edge.kind", normalized.kind)
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError("semantic edge endpoints must already exist as nodes")
        evidence = _copy_evidence(normalized.evidence)
        confidence = _confidence(normalized.confidence)
        resolver_version = normalized.resolver_version
        if (
            isinstance(resolver_version, bool)
            or not isinstance(resolver_version, int)
            or resolver_version < 1
        ):
            raise ValueError("resolver_version must be a positive integer")
        attributes = _copy_mapping("edge.attributes", normalized.attributes)
        key = (source_id, target_id, kind)
        existing = self.edges.get(key)
        if existing is not None:
            if existing.resolver_version != resolver_version:
                raise ValueError(f"conflicting resolver versions for edge: {key}")
            merged = SemanticEdge(
                schema_version=self.schema_version,
                source_id=source_id,
                target_id=target_id,
                kind=kind,
                evidence=_merge_evidence(existing.evidence, evidence),
                confidence=max(existing.confidence, confidence),
                resolver_version=resolver_version,
                attributes={**existing.attributes, **attributes},
            )
            self.edges[key] = merged
            return merged
        candidate = SemanticEdge(
            schema_version=self.schema_version,
            source_id=source_id,
            target_id=target_id,
            kind=kind,
            evidence=_merge_evidence(evidence),
            confidence=confidence,
            resolver_version=resolver_version,
            attributes=attributes,
        )
        self.edges[key] = candidate
        return candidate

    def add_orphan(
        self,
        *,
        kind: str,
        reason: str,
        evidence: Iterable[Mapping[str, Any]] = (),
        attributes: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an unresolved relationship without inventing a graph edge."""
        item = {
            "schema_version": self.schema_version,
            "kind": _require_nonempty_string("orphan.kind", kind),
            "reason": _require_nonempty_string("orphan.reason", reason),
            "evidence": _merge_evidence(evidence),
            "attributes": _copy_mapping("orphan.attributes", attributes or {}),
        }
        if item not in self.orphans:
            self.orphans.append(item)
        return item

    def to_dict(self) -> dict[str, Any]:
        """Serialize in stable order for reports, fixtures, and hashing."""
        return {
            "schema_version": self.schema_version,
            "nodes": [
                node.to_dict() for node in sorted(self.nodes.values(), key=lambda item: item.id)
            ],
            "edges": [
                edge.to_dict()
                for edge in sorted(
                    self.edges.values(),
                    key=lambda item: (item.source_id, item.target_id, item.kind),
                )
            ],
            "orphans": sorted(
                (dict(item) for item in self.orphans),
                key=_stable_key,
            ),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SemanticGraph":
        if not isinstance(payload, Mapping):
            raise ValueError("semantic graph must be an object")
        version = _require_schema_version(payload.get("schema_version"), expected=SCHEMA_VERSION)
        graph = cls(schema_version=version)
        nodes = payload.get("nodes", [])
        edges = payload.get("edges", [])
        orphans = payload.get("orphans", [])
        if not isinstance(nodes, list) or not isinstance(edges, list) or not isinstance(orphans, list):
            raise ValueError("semantic graph nodes, edges, and orphans must be lists")
        for node in nodes:
            if not isinstance(node, Mapping):
                raise ValueError("semantic graph nodes must be objects")
            graph.add_node(node)
        for edge in edges:
            if not isinstance(edge, Mapping):
                raise ValueError("semantic graph edges must be objects")
            graph.add_edge(edge)
        for orphan in orphans:
            if not isinstance(orphan, Mapping):
                raise ValueError("semantic graph orphans must be objects")
            _require_schema_version(orphan.get("schema_version"), expected=version)
            graph.add_orphan(
                kind=orphan.get("kind", ""),
                reason=orphan.get("reason", ""),
                evidence=orphan.get("evidence", []),
                attributes=orphan.get("attributes", {}),
            )
        return graph


def merge_semantic_graphs(*graphs: Any) -> SemanticGraph | None:
    """Merge validated semantic overlays without importing language parsers.

    Projection and reporting only need the graph container; they must remain
    usable when an optional Tree-sitter grammar package is not installed.  The
    OpenHarmony native-dispatch resolver re-exports the same operation for
    compatibility, while this dependency-light location is the canonical
    implementation for scan orchestration.
    """
    merged = SemanticGraph()
    present = False
    for payload in graphs:
        if payload is None:
            continue
        graph = (
            payload
            if isinstance(payload, SemanticGraph)
            else SemanticGraph.from_dict(payload)
        )
        present = True
        for node in graph.nodes.values():
            merged.add_node(node)
        for edge in graph.edges.values():
            merged.add_edge(edge)
        for orphan in graph.orphans:
            merged.add_orphan(
                kind=orphan["kind"],
                reason=orphan["reason"],
                evidence=orphan.get("evidence", []),
                attributes=orphan.get("attributes", {}),
            )
    return merged if present else None


__all__ = ["SCHEMA_VERSION", "SemanticGraph", "merge_semantic_graphs"]
