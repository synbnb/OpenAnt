"""Contract tests for the deterministic semantic graph overlay."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.graph import SemanticGraph  # noqa: E402


def _graph() -> SemanticGraph:
    graph = SemanticGraph()
    graph.add_node(
        {
            "schema_version": 1,
            "id": "idl:transaction:OHOS.Health.IService:Enable",
            "kind": "ipc_transaction",
            "attributes": {"interface": "OHOS.Health.IService", "method": "Enable"},
        }
    )
    graph.add_node(
        {
            "schema_version": 1,
            "id": "function:service.cpp:HealthServiceStub::OnRemoteRequest",
            "kind": "function",
            "attributes": {"file": "service.cpp", "line": 42},
        }
    )
    return graph


def test_graph_merges_duplicate_edges_and_keeps_all_evidence():
    graph = _graph()
    graph.add_edge(
        {
            "schema_version": 1,
            "source_id": "function:service.cpp:HealthServiceStub::OnRemoteRequest",
            "target_id": "idl:transaction:OHOS.Health.IService:Enable",
            "kind": "stub_to_transaction",
            "confidence": 0.7,
            "evidence": [{"path": "service.cpp", "line": 42, "token": "CMD_ENABLE"}],
        }
    )
    merged = graph.add_edge(
        {
            "schema_version": 1,
            "source_id": "function:service.cpp:HealthServiceStub::OnRemoteRequest",
            "target_id": "idl:transaction:OHOS.Health.IService:Enable",
            "kind": "stub_to_transaction",
            "confidence": 0.9,
            "evidence": [{"path": "service.cpp", "line": 43, "token": "Enable"}],
        }
    )

    assert len(graph.edges) == 1
    assert merged.confidence == 0.9
    assert len(merged.evidence) == 2


def test_graph_serialization_is_sorted_and_round_trips_with_orphans():
    graph = _graph()
    graph.add_orphan(
        kind="unresolved_ipc_method",
        reason="no native handler matched",
        evidence=[{"path": "IService.idl", "line": 8}],
        attributes={"method": "Missing"},
    )
    payload = graph.to_dict()
    restored = SemanticGraph.from_dict(json.loads(json.dumps(payload)))

    assert payload == restored.to_dict()
    assert payload["nodes"][0]["id"].startswith("function:")
    assert payload["orphans"][0]["attributes"] == {"method": "Missing"}


def test_graph_rejects_dangling_edges_and_invalid_confidence():
    graph = _graph()
    with pytest.raises(ValueError, match="endpoints"):
        graph.add_edge(
            {
                "schema_version": 1,
                "source_id": "missing",
                "target_id": "idl:transaction:OHOS.Health.IService:Enable",
                "kind": "stub_to_transaction",
            }
        )

    with pytest.raises(ValueError, match="between 0 and 1"):
        graph.add_edge(
            {
                "schema_version": 1,
                "source_id": "function:service.cpp:HealthServiceStub::OnRemoteRequest",
                "target_id": "idl:transaction:OHOS.Health.IService:Enable",
                "kind": "stub_to_transaction",
                "confidence": 1.1,
            }
        )
