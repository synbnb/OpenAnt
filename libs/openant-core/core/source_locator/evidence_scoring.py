"""Deterministic triage scoring for source-locator evidence.

Scores help order follow-up work; they are not a vulnerability verdict and
cannot replace mandatory server/client predicates.  In particular, a socket
creator without a consumer is deliberately reported as ``creator_only`` and
never as a confirmed server.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .evidence_store import Evidence, EvidenceEdge, EvidenceStore


_KIND_WEIGHTS: Mapping[str, tuple[int, str]] = {
    "literal_match": (12, "目标字面量命中"),
    "macro_definition": (22, "宏定义直接证据"),
    "constant_definition": (18, "常量定义证据"),
    "symbol_reference": (10, "符号引用证据"),
    "service_config": (18, "服务配置证据"),
    "executable_build": (12, "可执行文件/构建证据"),
    "socket_server_registration": (26, "服务端注册结构或创建包装证据"),
    "socket_acquire": (14, "创建或获取 socket 证据"),
    "socket_bind_listen": (28, "bind/listen 服务端证据"),
    "socket_accept_read": (30, "accept/read 服务端消费证据"),
    "protocol_dispatch": (28, "协议分派证据"),
    "client_endpoint": (10, "客户端端点证据"),
    "client_connect": (12, "客户端 connect 证据"),
    "protocol_construction": (10, "协议构造证据"),
    "client_send": (10, "客户端发送证据"),
    "manifest_mapping": (16, "Manifest 映射证据"),
    "post_clone_verification": (20, "拉取后复核证据"),
}
_SERVER_CREATOR_KINDS = frozenset({"socket_bind_listen", "socket_server_registration"})
_SERVER_CONSUMER_KINDS = frozenset({"socket_accept_read", "protocol_dispatch"})
_IDENTITY_KINDS = frozenset({"literal_match", "macro_definition", "constant_definition", "service_config"})
_MAPPING_KINDS = frozenset({"manifest_mapping", "executable_build", "service_config"})


@dataclass(frozen=True)
class ScoreFeature:
    """One transparent contribution to an evidence score."""

    code: str
    label: str
    weight: int

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "label": self.label, "weight": self.weight}


@dataclass(frozen=True)
class MandatoryPredicates:
    """Structural predicates kept separate from the numerical triage score."""

    has_server_creator: bool
    has_server_consumer: bool
    has_socket_identity: bool
    has_service_mapping: bool
    creator_only: bool
    confirmed_server: bool

    def to_dict(self) -> dict[str, bool]:
        return {
            "has_server_creator": self.has_server_creator,
            "has_server_consumer": self.has_server_consumer,
            "has_socket_identity": self.has_socket_identity,
            "has_service_mapping": self.has_service_mapping,
            "creator_only": self.creator_only,
            "confirmed_server": self.confirmed_server,
        }


@dataclass(frozen=True)
class EvidenceScore:
    """Score and audit details for a unique evidence bundle."""

    score: int
    evidence_count: int
    evidence_ids: tuple[str, ...]
    features: tuple[ScoreFeature, ...]
    mandatory_predicates: MandatoryPredicates

    @property
    def confirmed_server(self) -> bool:
        return self.mandatory_predicates.confirmed_server

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "evidence_count": self.evidence_count,
            "evidence_ids": list(self.evidence_ids),
            "features": [feature.to_dict() for feature in self.features],
            "mandatory_predicates": self.mandatory_predicates.to_dict(),
        }


def _individual_score(evidence: Evidence) -> tuple[int, tuple[ScoreFeature, ...]]:
    base_weight, base_label = _KIND_WEIGHTS.get(evidence.kind, (0, "未分类证据"))
    features: list[ScoreFeature] = [
        ScoreFeature(f"kind:{evidence.kind}", base_label, base_weight),
    ]
    if evidence.line_start > 0:
        features.append(ScoreFeature("source_line", "存在明确源码行号", 5))
    if evidence.excerpt.strip():
        features.append(ScoreFeature("excerpt", "存在源码片段", 5))
    if evidence.content_sha256:
        features.append(ScoreFeature("content_hash", "来源内容可校验", 5))
    return min(50, sum(feature.weight for feature in features)), tuple(features)


def evaluate_mandatory_predicates(evidence: Iterable[Evidence]) -> MandatoryPredicates:
    items = tuple(evidence)
    kinds = {item.kind for item in items}
    has_creator = bool(kinds & _SERVER_CREATOR_KINDS)
    has_consumer = bool(kinds & _SERVER_CONSUMER_KINDS)
    has_identity = bool(kinds & _IDENTITY_KINDS)
    has_mapping = bool(kinds & _MAPPING_KINDS)
    creator_only = has_creator and not has_consumer
    # The numerical score is intentionally not consulted here.  A server is
    # only structurally confirmed after both sides of the receive path exist,
    # plus either identity or service mapping evidence.
    confirmed_server = has_creator and has_consumer and (has_identity or has_mapping)
    return MandatoryPredicates(
        has_server_creator=has_creator,
        has_server_consumer=has_consumer,
        has_socket_identity=has_identity,
        has_service_mapping=has_mapping,
        creator_only=creator_only,
        confirmed_server=confirmed_server,
    )


def score_evidence(evidence: Evidence) -> EvidenceScore:
    """Score one evidence object without any duplicate-reference multiplier."""

    if not isinstance(evidence, Evidence):
        raise ValueError("evidence 必须是 Evidence")
    score, features = _individual_score(evidence)
    return EvidenceScore(
        score=score,
        evidence_count=1,
        evidence_ids=(evidence.evidence_id,),
        features=features,
        mandatory_predicates=evaluate_mandatory_predicates((evidence,)),
    )


def score_evidence_bundle(evidence: Iterable[Evidence]) -> EvidenceScore:
    """Aggregate unique evidence items and evaluate structural predicates."""

    unique: list[Evidence] = []
    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, Evidence):
            raise ValueError("evidence 序列只能包含 Evidence")
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        unique.append(item)
    feature_values: list[ScoreFeature] = []
    total = 0
    for item in unique:
        item_score, item_features = _individual_score(item)
        total += item_score
        feature_values.extend(item_features)
    return EvidenceScore(
        score=min(100, total),
        evidence_count=len(unique),
        evidence_ids=tuple(item.evidence_id for item in unique),
        features=tuple(feature_values),
        mandatory_predicates=evaluate_mandatory_predicates(unique),
    )


def score_edge(edge: EvidenceEdge, store: EvidenceStore) -> EvidenceScore:
    """Resolve an edge's IDs and score only unique, source-backed evidence."""

    if not isinstance(edge, EvidenceEdge):
        raise ValueError("edge 必须是 EvidenceEdge")
    if not isinstance(store, EvidenceStore):
        raise ValueError("store 必须是 EvidenceStore")
    stored_edge = store.get_edge(edge.edge_id)
    if (stored_edge.src, stored_edge.relation, stored_edge.dst) != (edge.src, edge.relation, edge.dst):
        raise ValueError("edge 不属于给定的 EvidenceStore")
    # The store may have enriched an edge after the caller retained an older
    # immutable snapshot.  Score the canonical current edge so newly attached
    # evidence is visible while the endpoint identity is still checked above.
    return score_evidence_bundle(store.evidence_for_edge(stored_edge.edge_id))


# Name used by future attribution code; keep it as an explicit alias so the
# scoring contract remains discoverable without coupling this slice to it.
score_edge_evidence = score_edge
