"""SL-02B tests for source-backed evidence and graph integrity."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    EvidenceGraphError,
    EvidenceStore,
    EvidenceStoreError,
    EvidenceValidationError,
    SearchHit,
    SearchResponse,
    SourceDocument,
    score_edge,
    score_evidence_bundle,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "opengrok" / "live_1_14_11"


def _evidence(store: EvidenceStore, *, kind: str = "literal_match", line: int = 10, symbol: str | None = None):
    return store.add_evidence(
        kind=kind,
        source_path="base/service/param.c",
        line_start=line,
        symbol=symbol,
        excerpt="PIPE_NAME",
        raw_excerpt="PIPE_NAME",
        tool_name="opengrok.search_full",
        source_mode="search",
        query_id="Q-0001",
    )


def test_same_kind_path_line_and_symbol_is_deduplicated_without_losing_first_audit_record():
    store = EvidenceStore()
    first = _evidence(store, symbol="PIPE_NAME")
    second = store.add_evidence(
        kind="literal_match",
        source_path="/base/service/param.c",
        line_start=10,
        line_end=10,
        symbol="PIPE_NAME",
        excerpt="a later query has different text",
        raw_excerpt="<b>a later query has different text</b>",
        tool_name="opengrok.search_symbol",
        source_mode="search",
        query_id="Q-0002",
    )

    assert first.evidence_id == second.evidence_id
    assert len(store.evidence) == 1
    assert store.duplicate_count(first.evidence_id) == 1
    assert store.get_evidence(first.evidence_id).query_id == "Q-0001"


def test_duplicate_trace_can_enrich_missing_target_relation_metadata():
    store = EvidenceStore()
    first = store.add_evidence(
        kind="client_connect",
        source_path="base/service/param.c",
        line_start=10,
        excerpt="connect(fd, addr, len);",
        tool_name="opengrok.search_full",
        query_id="Q-search",
    )
    second = store.add_evidence(
        kind="client_connect",
        source_path="base/service/param.c",
        line_start=10,
        excerpt="connect(fd, addr, len);",
        tool_name="opengrok.read_source",
        query_id="Q-trace",
        relation_from="/dev/unix/socket/paramservice",
        relation_to="/base/service/param.c:10",
    )

    assert first.evidence_id == second.evidence_id
    enriched = store.get_evidence(first.evidence_id)
    assert enriched.relation_from == "/dev/unix/socket/paramservice"
    assert enriched.relation_to == "/base/service/param.c:10"
    assert enriched.query_id == "Q-search"


def test_excerpt_is_bounded_and_control_characters_are_replaced():
    store = EvidenceStore()
    raw = "raw\x00\n" + ("y" * 5000)
    evidence = store.add_evidence(
        kind="symbol_reference",
        source_path="a.c",
        line_start=1,
        excerpt="before\x00\x1b[31m\r\nafter\t" + ("x" * 5000),
        raw_excerpt=raw,
        tool_name="test",
    )

    assert len(evidence.excerpt) == 4096
    assert len(evidence.raw_excerpt) <= 4096
    assert "\x00" not in evidence.excerpt
    assert "\x1b" not in evidence.excerpt
    assert "\r" not in evidence.excerpt
    assert "\n" in evidence.excerpt
    assert evidence.content_sha256 == hashlib.sha256(raw.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("path", ["", "../a.c", "https://example.invalid/a.c", "a\\b.c", "a\x00b.c"])
def test_unsafe_source_path_fails_closed(path: str):
    with pytest.raises(EvidenceValidationError):
        EvidenceStore().add_evidence(
            kind="literal_match",
            source_path=path,
            line_start=1,
            tool_name="test",
        )


def test_search_hit_requires_line_number_and_retains_raw_and_cleaned_forms():
    store = EvidenceStore()
    hit = SearchHit.from_payload(
        {"line": "#define <b>PIPE_NAME</b> &lt;x&gt;\r", "lineNumber": "80"}
    )
    evidence = store.add_search_hit(
        "/openharmony/base/startup/init/services/param/include/param_utils.h",
        hit,
        kind="macro_definition",
        symbol="PIPE_NAME",
        query_id="Q-macro",
        source_endpoint="/source/api/v1/search",
    )

    assert evidence.line_start == 80
    assert evidence.excerpt == "#define PIPE_NAME <x>\n"
    assert "<b>" in evidence.raw_excerpt
    assert evidence.source_mode == "search"
    assert evidence.source_endpoint == "/source/api/v1/search"

    with pytest.raises(EvidenceValidationError, match="有效行号"):
        store.add_search_hit("a.c", SearchHit(line="no line", line_number=""))


def test_search_response_conversion_keeps_query_provenance_for_each_file():
    response = SearchResponse(
        time_ms=2,
        result_count=2,
        start_document=0,
        end_document=1,
        results={
            "/openharmony/base/a.c": (
                SearchHit(line="socket(\u2026)", line_number="3", raw_line="socket(&lt;fd&gt;)"),
            ),
            "/openharmony/base/b.c": (
                SearchHit(line="connect(\u2026)", line_number="9"),
            ),
        },
    )
    evidence = EvidenceStore().add_search_response(response, query_id="Q-full")

    assert len(evidence) == 2
    assert {item.source_path for item in evidence} == {
        "/openharmony/base/a.c",
        "/openharmony/base/b.c",
    }
    assert all(item.query_id == "Q-full" for item in evidence)


def test_source_excerpt_hashes_full_document_but_stores_requested_lines_only():
    content = "#define PIPE_NAME \"/dev/unix/socket/paramservice\"\nint InitParamService(void)\n"
    document = SourceDocument(
        path="/openharmony/base/startup/init/services/param/param_service.c",
        content=content,
        source="raw",
        content_type="text/plain",
    )
    store = EvidenceStore()
    evidence = store.add_source_excerpt(
        document,
        line_start=1,
        line_end=2,
        kind="macro_definition",
        symbol="PIPE_NAME",
        query_id="Q-read",
        source_endpoint="/source/raw",
    )

    assert evidence.excerpt == content.rstrip("\n")
    assert evidence.line_end == 2
    assert evidence.content_sha256 == hashlib.sha256(content.encode()).hexdigest()
    with pytest.raises(EvidenceValidationError, match="超出源码范围"):
        store.add_source_excerpt(document, line_start=3)


def test_graph_rejects_dangling_reference_and_supports_reverse_lookup():
    store = EvidenceStore()
    evidence = _evidence(store, line=12)
    edge = store.add_edge(
        src="PIPE_NAME",
        relation="resolves_to",
        dst="/dev/unix/socket/paramservice",
        evidence_ids=[evidence.evidence_id],
        confidence="strong",
    )

    assert store.evidence_for_edge(edge.edge_id) == (evidence,)
    assert store.evidence_for("PIPE_NAME") == (evidence,)
    assert store.graph.evidence_for({"node_id": "/dev/unix/socket/paramservice"}) == (evidence,)
    with pytest.raises(EvidenceGraphError, match="不存在的 evidence_id"):
        store.add_edge(src="a", relation="calls", dst="b", evidence_ids=["E-missing"])
    with pytest.raises(EvidenceGraphError, match="至少需要一个"):
        store.add_edge(src="a", relation="calls", dst="b", evidence_ids=[])


def test_repeated_edge_enriches_one_edge_instead_of_inflating_graph():
    store = EvidenceStore()
    first = _evidence(store, line=1)
    second = _evidence(store, kind="symbol_reference", line=2)
    edge_a = store.add_edge(src="InitParamService", relation="registers", dst="OnIncomingConnect", evidence_ids=[first.evidence_id])
    edge_b = store.add_edge(
        src="InitParamService",
        relation="registers",
        dst="OnIncomingConnect",
        evidence_ids=[first.evidence_id, second.evidence_id],
        confidence="strong",
    )

    assert edge_a.edge_id == edge_b.edge_id
    assert len(store.edges) == 1
    assert edge_b.evidence_ids == (first.evidence_id, second.evidence_id)
    assert edge_b.confidence == "strong"
    assert score_edge(edge_a, store).evidence_count == 2


def test_json_round_trip_preserves_evidence_edges_and_duplicate_counts():
    store = EvidenceStore()
    evidence = _evidence(store, line=4)
    store.add_evidence(
        kind="literal_match",
        source_path="base/service/param.c",
        line_start=4,
        excerpt="duplicate",
        tool_name="other",
    )
    store.add_edge(src="a", relation="uses", dst="b", evidence_ids=[evidence.evidence_id])
    restored = EvidenceStore.from_dict(json.loads(store.to_json()))

    assert restored.to_dict() == store.to_dict()
    assert restored.duplicate_count(evidence.evidence_id) == 1

    bad = store.to_dict()
    bad["edges"][0]["evidence_ids"] = ["E-dangling"]
    with pytest.raises(EvidenceGraphError, match="不存在的 evidence_id"):
        EvidenceStore.from_dict(bad)


def test_paramservice_fixture_can_build_a_line_backed_registration_graph_offline():
    content = (FIXTURE_DIR / "raw_param_service_excerpt.c").read_text(encoding="utf-8")
    document = SourceDocument(
        path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        content=content,
        source="raw",
    )
    store = EvidenceStore()
    socket_use = store.add_source_excerpt(
        document,
        line_start=9,
        kind="literal_match",
        symbol="PIPE_NAME",
        query_id="Q-full",
    )
    registration = store.add_source_excerpt(
        document,
        line_start=13,
        kind="symbol_reference",
        symbol="OnIncomingConnect",
        query_id="Q-init",
    )
    edge = store.add_edge(
        src="InitParamService",
        relation="registers",
        dst="OnIncomingConnect",
        evidence_ids=[registration.evidence_id],
        confidence="strong",
    )
    store.add_edge(
        src="PIPE_NAME",
        relation="used_by",
        dst="InitParamService",
        evidence_ids=[socket_use.evidence_id],
        confidence="moderate",
    )

    assert len(store.evidence) == 2
    assert len(store.edges) == 2
    assert store.evidence_for_edge(edge.edge_id)[0].source_path.endswith("param_service.c")
    assert all(item.line_start > 0 for item in store.evidence)


def test_edge_score_deduplicates_ids_and_creator_only_is_not_confirmed_server():
    store = EvidenceStore()
    creator = _evidence(store, kind="socket_bind_listen", line=20)
    edge = store.add_edge(
        src="ParamService",
        relation="owns_socket",
        dst="PIPE_NAME",
        evidence_ids=[creator.evidence_id],
    )
    score = score_edge(edge, store)
    duplicated = score_evidence_bundle([creator, creator])

    assert score.evidence_count == 1
    assert score.score == duplicated.score
    assert score.mandatory_predicates.creator_only is True
    assert score.confirmed_server is False


def test_consumer_plus_identity_and_creator_satisfy_structural_server_predicates():
    store = EvidenceStore()
    creator = _evidence(store, kind="socket_bind_listen", line=20)
    consumer = _evidence(store, kind="socket_accept_read", line=21)
    identity = _evidence(store, kind="macro_definition", line=22, symbol="PIPE_NAME")
    edge = store.add_edge(
        src="ParamService",
        relation="handles",
        dst="OnIncomingConnect",
        evidence_ids=[creator.evidence_id, consumer.evidence_id, identity.evidence_id],
    )
    score = score_edge(edge, store)

    assert score.mandatory_predicates.has_server_creator is True
    assert score.mandatory_predicates.has_server_consumer is True
    assert score.mandatory_predicates.has_socket_identity is True
    assert score.confirmed_server is True


def test_invalid_serialization_version_fails_closed():
    with pytest.raises(EvidenceStoreError, match="不支持的证据图版本"):
        EvidenceStore.from_dict({"schema_version": "old", "evidence": [], "edges": []})
