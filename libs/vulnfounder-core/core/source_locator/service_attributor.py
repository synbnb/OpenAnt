"""Deterministic server-side attribution for OpenHarmony socket evidence.

OpenGrok can find a socket creator, an init configuration entry, and the real
service implementation in different files or repositories.  This module
keeps those roles separate and only calls a candidate a confirmed server when
the required source-backed predicates are present.  It intentionally has no
LLM, network, Git, or filesystem dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .evidence_store import Evidence, EvidenceStore
from .manifest_resolver import RepositoryMapping
from .opengrok_client import normalize_source_path
from .path_classifier import classify_path


_SCHEMA_VERSION = "openant.source-locator.server-attribution.v1"
_MAX_TEXT = 512
_MAX_EVIDENCE_IDS = 256
_ROLES = frozenset(
    {
        "socket_creator",
        "service_owner",
        "server_consumer",
        "server_handler",
        "client_transport",
        "client_protocol",
        "client_sender",
    }
)
_STATUSES = frozenset({"HIGH", "PARTIAL", "UNRESOLVED"})

_IDENTITY_KINDS = frozenset(
    {"literal_match", "macro_definition", "constant_definition", "symbol_reference"}
)
# OpenHarmony commonly declares a named socket only in an init ``.cfg``/JSON
# record (``socket.name``).  That record is an identity anchor even when the
# service obtains an already-created descriptor with ``GetControlSocket`` and
# therefore never repeats the full path in C/C++.
_CONFIG_IDENTITY_KINDS = frozenset({"service_config"})
_CREATOR_KINDS = frozenset({"service_config", "socket_server_registration", "socket_acquire"})
_OWNER_KINDS = frozenset({"socket_server_registration", "socket_acquire", "socket_bind_listen"})
_CONSUMER_KINDS = frozenset({"socket_accept_read"})
_HANDLER_KINDS = frozenset({"protocol_dispatch"})
_SERVER_KINDS = (
    _IDENTITY_KINDS
    | _CREATOR_KINDS
    | _OWNER_KINDS
    | _CONSUMER_KINDS
    | _HANDLER_KINDS
    | {"service_config", "executable_build", "manifest_mapping"}
)
_KIND_WEIGHTS: Mapping[str, int] = {
    "literal_match": 15,
    "macro_definition": 15,
    "constant_definition": 15,
    "symbol_reference": 8,
    "service_config": 15,
    "executable_build": 10,
    "socket_server_registration": 30,
    "socket_acquire": 25,
    "socket_bind_listen": 25,
    "socket_accept_read": 25,
    "protocol_dispatch": 10,
    "manifest_mapping": 10,
}


class ServiceAttributionError(ValueError):
    """Raised when the attribution API receives an invalid typed value."""


def _clean(value: Any, *, limit: int = _MAX_TEXT) -> str:
    return " ".join(str(value).split())[:limit]


def _evidence_items(value: EvidenceStore | Iterable[Evidence]) -> tuple[Evidence, ...]:
    if isinstance(value, EvidenceStore):
        items = value.evidence
    else:
        if isinstance(value, (str, bytes)):
            raise ServiceAttributionError("evidence 必须是 EvidenceStore 或 Evidence 序列")
        try:
            items = tuple(value)
        except TypeError as exc:
            raise ServiceAttributionError("evidence 必须是 EvidenceStore 或 Evidence 序列") from exc
    unique: list[Evidence] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Evidence):
            raise ServiceAttributionError("evidence 序列只能包含 Evidence")
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        unique.append(item)
    return tuple(unique)


def partition_attribution_evidence(
    value: EvidenceStore | Iterable[Evidence],
) -> tuple[tuple[Evidence, ...], tuple[str, ...]]:
    """Split evidence into role-eligible and test/fuzz-only records.

    Search evidence is intentionally append-only and can contain useful clues
    from tests or fuzzers.  Those records remain in the evidence graph, but
    they must not satisfy service/client attribution predicates.  All other
    path scopes (kernel, third-party, generated, build, and so on) stay
    eligible and are left for semantic role attribution.
    """

    items = _evidence_items(value)
    eligible: list[Evidence] = []
    excluded: list[str] = []
    for item in items:
        try:
            allowed = classify_path(item.source_path).attribution_eligible
        except (TypeError, ValueError):
            # Evidence paths are validated at storage time, but fail closed if
            # an older checkpoint contains a path the classifier cannot parse.
            allowed = False
        if allowed:
            eligible.append(item)
        else:
            excluded.append(item.evidence_id)
    return tuple(eligible), tuple(excluded)


def _mapping_is_resolved(mapping: RepositoryMapping | None) -> bool:
    return isinstance(mapping, RepositoryMapping) and mapping.is_resolved


def _mapping_evidence_present(items: Iterable[Evidence]) -> bool:
    return any(item.kind == "manifest_mapping" for item in items)


@dataclass(frozen=True)
class SourceLocation:
    """A bounded source location copied from one evidence item."""

    source_path: str
    line_start: int
    line_end: int
    symbol: str | None = None

    def __post_init__(self) -> None:
        try:
            normalized = normalize_source_path(self.source_path)
        except (TypeError, ValueError) as exc:
            raise ServiceAttributionError(f"source_path 无效：{exc}") from exc
        if isinstance(self.line_start, bool) or not isinstance(self.line_start, int) or self.line_start < 1:
            raise ServiceAttributionError("line_start 必须是正整数")
        if isinstance(self.line_end, bool) or not isinstance(self.line_end, int) or self.line_end < self.line_start:
            raise ServiceAttributionError("line_end 必须不小于 line_start")
        if self.symbol is not None:
            if not isinstance(self.symbol, str) or not self.symbol.strip() or len(self.symbol.strip()) > _MAX_TEXT:
                raise ServiceAttributionError("symbol 为空或过长")
            object.__setattr__(self, "symbol", self.symbol.strip())
        object.__setattr__(self, "source_path", normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class AttributionCandidate:
    """One role candidate and the evidence that supports it."""

    role: str
    subject: str
    source_locations: tuple[SourceLocation, ...]
    evidence_ids: tuple[str, ...]
    score: int
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.role not in _ROLES:
            raise ServiceAttributionError("候选角色无效")
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise ServiceAttributionError("候选 subject 不能为空")
        if len(self.subject.strip()) > _MAX_TEXT:
            raise ServiceAttributionError("候选 subject 过长")
        locations = tuple(self.source_locations)
        if not locations or any(not isinstance(item, SourceLocation) for item in locations):
            raise ServiceAttributionError("候选必须包含源码位置")
        ids = tuple(dict.fromkeys(self.evidence_ids))
        if not ids or any(not isinstance(item, str) or not item.startswith("E-") for item in ids):
            raise ServiceAttributionError("候选 evidence_ids 无效")
        if len(ids) > _MAX_EVIDENCE_IDS:
            raise ServiceAttributionError("候选 evidence_ids 超过数量上限")
        if isinstance(self.score, bool) or not isinstance(self.score, int) or self.score < 0:
            raise ServiceAttributionError("候选 score 无效")
        object.__setattr__(self, "subject", self.subject.strip())
        object.__setattr__(self, "source_locations", locations)
        object.__setattr__(self, "evidence_ids", ids)
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "subject": self.subject,
            "source_locations": [item.to_dict() for item in self.source_locations],
            "evidence_ids": list(self.evidence_ids),
            "score": self.score,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class ServerAttributionResult:
    """Auditable server attribution with structural predicates and triage status.

    The predicates determine the attribution status and remain visible to the
    reviewer.  The worker may use an incomplete result as an advisory
    confirmation candidate after a resolved repository mapping is available;
    they are not a hidden permission to clone.
    """

    status: str
    confirmed: bool
    score: int
    predicates: Mapping[str, bool]
    candidates: tuple[AttributionCandidate, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    mapping: RepositoryMapping | None = None
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION
    excluded_evidence_ids: tuple[str, ...] = ()
    semantic_decision: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ServiceAttributionError("服务端归因 status 无效")
        if not isinstance(self.confirmed, bool) or self.confirmed != (self.status == "HIGH"):
            raise ServiceAttributionError("confirmed 必须与 HIGH 状态一致")
        if isinstance(self.score, bool) or not isinstance(self.score, int) or not 0 <= self.score <= 100:
            raise ServiceAttributionError("服务端归因 score 无效")
        if not isinstance(self.predicates, Mapping):
            raise ServiceAttributionError("predicates 必须是映射")
        if any(not isinstance(value, bool) for value in self.predicates.values()):
            raise ServiceAttributionError("predicates 的值必须是布尔值")
        object.__setattr__(self, "predicates", {str(key): value for key, value in self.predicates.items()})
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "evidence_ids", tuple(dict.fromkeys(self.evidence_ids)))
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_clean(item) for item in self.warnings))
        excluded = tuple(dict.fromkeys(self.excluded_evidence_ids))
        if any(not isinstance(item, str) or not item.startswith("E-") for item in excluded):
            raise ServiceAttributionError("excluded_evidence_ids 无效")
        object.__setattr__(self, "excluded_evidence_ids", excluded)
        if self.semantic_decision is not None and not isinstance(self.semantic_decision, Mapping):
            raise ServiceAttributionError("semantic_decision 必须是 JSON 对象或 null")
        object.__setattr__(self, "semantic_decision", dict(self.semantic_decision) if self.semantic_decision else None)

    @property
    def roles(self) -> dict[str, tuple[AttributionCandidate, ...]]:
        grouped: dict[str, list[AttributionCandidate]] = {role: [] for role in _ROLES}
        for candidate in self.candidates:
            grouped[candidate.role].append(candidate)
        return {role: tuple(items) for role, items in grouped.items()}

    @property
    def server_repo(self) -> str | None:
        return self.mapping.project_name if self.mapping and self.mapping.is_resolved else None

    @property
    def best_candidate(self) -> AttributionCandidate | None:
        """Return the highest-scoring source-backed candidate.

        ``status`` answers whether the complete server receive chain has been
        proven.  It is intentionally not reused for candidate selection: a
        useful ``.cfg socket.name`` mapping can be the best repository answer
        while the later ``GetControlSocket``/consumer edge is still missing.
        Ties are resolved deterministically so a resumed session produces the
        same result.
        """

        if not self.candidates:
            return None
        # A confirmed, evidence-backed LLM decision is the semantic owner
        # decision for this target.  Do not let a later noisy repository
        # mapping hide that candidate merely because the mapping was built
        # from basename/API hits.  Repository selection is separately scored
        # with the same semantic evidence; this override keeps
        # ``server_attribution.json`` and ``confirmation_summary.json``
        # consistent while retaining all deterministic candidates for audit.
        if isinstance(self.semantic_decision, Mapping) and self.semantic_decision.get("status") == "confirmed":
            semantic_ids = {
                item
                for item in self.semantic_decision.get("evidence_ids", ())
                if isinstance(item, str)
            }
            semantic_candidates = [
                item
                for item in self.candidates
                if item.role == "service_owner"
                and bool(semantic_ids.intersection(item.evidence_ids))
            ]
            if semantic_candidates:
                return max(
                    semantic_candidates,
                    key=lambda item: (item.score, item.subject, item.evidence_ids),
                )
        # Older/hand-built mappings may not carry evidence_ids.  Treat an
        # empty list as "linkage unknown" rather than as proof that the config
        # row is unrelated; populated mappings are checked strictly.
        mapping_ids = (
            set(self.mapping.evidence_ids)
            if self.mapping is not None and self.mapping.evidence_ids
            else None
        )
        return min(
            self.candidates,
            key=lambda item: (
                # When a mapping is available, prefer a role whose evidence
                # is actually part of that mapping.  The evidence store can
                # contain several repositories with the same basename or
                # generic ``bind``/``recv`` calls; an unrelated high-score
                # candidate must not displace the mapped ``socket.name``
                # owner merely because it has more communication hits.
                0 if mapping_ids is None or bool(mapping_ids.intersection(item.evidence_ids)) else 1,
                -item.score,
                item.role,
                item.subject,
                item.evidence_ids,
            ),
        )

    @property
    def _has_config_identity(self) -> bool:
        """Whether a candidate is explicitly backed by a service config row."""

        mapping_ids = (
            set(self.mapping.evidence_ids)
            if self.mapping is not None and self.mapping.evidence_ids
            else None
        )
        return any(
            (mapping_ids is None or bool(mapping_ids.intersection(candidate.evidence_ids)))
            and any(
                reason.startswith("service_config：") or reason.startswith("service_config:")
                for reason in candidate.reasons
            )
            for candidate in self.candidates
        )

    @property
    def repository_confidence(self) -> str:
        """Confidence of the repository choice, independent of chain completeness.

        This is an explainable triage label, not a calibrated probability.  A
        resolved Manifest mapping joined to ``socket.name`` is the strongest
        practical ownership anchor for named OpenHarmony sockets.  It is
        therefore HIGH even when the service-side consumer was not recovered.
        """

        if self.mapping is None or not self.mapping.is_resolved:
            return "UNKNOWN"
        if self._has_config_identity:
            return "HIGH"
        if self.predicates.get("socket_identity") and self.predicates.get("service_relation"):
            return "HIGH"
        if self.predicates.get("socket_identity"):
            return "MEDIUM"
        if self.candidates:
            return "LOW"
        return "UNKNOWN"

    @property
    def selection_confidence_score(self) -> int:
        """Return a bounded, explainable score for the selected candidate."""

        score = self.score
        candidate = self.best_candidate
        if candidate is not None:
            score = max(score, min(100, candidate.score))
        score += {"HIGH": 20, "MEDIUM": 10, "LOW": 0, "UNKNOWN": 0}[self.repository_confidence]
        return min(100, max(0, score))

    @property
    def selection_reasons(self) -> tuple[str, ...]:
        """Explain why the current repository candidate was preferred."""

        reasons: list[str] = []
        if self.mapping is not None and self.mapping.is_resolved:
            reasons.append("Manifest 已解析仓库映射")
        if self._has_config_identity:
            reasons.append("发现 init 配置 socket.name 身份锚点")
        elif self.predicates.get("socket_identity"):
            reasons.append("发现源码中的 socket 字面量/宏/常量身份锚点")
        if self.predicates.get("socket_acquire_or_bind"):
            reasons.append("发现服务端获取 descriptor 或 bind/listen 线索")
        if self.predicates.get("server_consumer"):
            reasons.append("发现服务端 accept/read/recv 或协议分派线索")
        missing = [
            key
            for key in ("socket_identity", "socket_acquire_or_bind", "server_consumer", "manifest_mapping")
            if not self.predicates.get(key, False)
        ]
        if missing:
            reasons.append("仍缺少：" + "、".join(missing))
        return tuple(dict.fromkeys(reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "confirmed": self.confirmed,
            "score": self.score,
            "predicates": dict(self.predicates),
            "candidates": [item.to_dict() for item in self.candidates],
            "roles": {
                role: [item.to_dict() for item in items] for role, items in self.roles.items()
            },
            "evidence_ids": list(self.evidence_ids),
            "mapping": self.mapping.to_dict() if self.mapping else None,
            "server_repo": self.server_repo,
            "chain_status": self.status,
            "best_candidate": self.best_candidate.to_dict() if self.best_candidate else None,
            "repository_confidence": self.repository_confidence,
            "selection_confidence_score": self.selection_confidence_score,
            "selection_reasons": list(self.selection_reasons),
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "excluded_evidence_ids": list(self.excluded_evidence_ids),
            "semantic_decision": dict(self.semantic_decision) if self.semantic_decision else None,
        }


def _candidate_subject(item: Evidence) -> str:
    return _clean(item.relation_to or item.symbol or f"{item.source_path}:{item.line_start}")


def _candidate_locations(items: Iterable[Evidence]) -> tuple[SourceLocation, ...]:
    locations: list[SourceLocation] = []
    seen: set[tuple[str, int, int, str | None]] = set()
    for item in items:
        location = SourceLocation(item.source_path, item.line_start, item.line_end, item.symbol)
        key = (location.source_path, location.line_start, location.line_end, location.symbol)
        if key not in seen:
            seen.add(key)
            locations.append(location)
    return tuple(locations)


def _build_candidates(items: tuple[Evidence, ...], role: str, kinds: frozenset[str]) -> tuple[AttributionCandidate, ...]:
    # Search evidence often has no relation_to and historically every row was
    # assigned the requested socket name as ``symbol``.  Grouping only by that
    # name merged unrelated repositories (for example ``hisysevent`` and
    # ``paramservice``) into one candidate.  Keep the human-facing subject,
    # but scope symbol-only rows to their source path.  Explicit traced
    # relation_to values already identify a function/location and keep their
    # previous grouping behavior.
    groups: dict[tuple[str, str | None], list[Evidence]] = {}
    for item in items:
        if item.kind in kinds:
            subject = _candidate_subject(item)
            scope = None if item.relation_to else item.source_path
            groups.setdefault((subject, scope), []).append(item)
    candidates: list[AttributionCandidate] = []
    for (subject, _scope), group in groups.items():
        # A broad socket.name/basename query can produce hundreds of records
        # with the same relation_to (for example, ``paramservice``).  The
        # candidate schema deliberately bounds evidence references, but an
        # overfull group must be reduced here rather than making the whole
        # attribution stage fail.  Prefer communication evidence over weaker
        # identity/configuration repetitions, while retaining input order for
        # deterministic replay.
        ranked_group = sorted(
            enumerate(group),
            key=lambda pair: (-_KIND_WEIGHTS.get(pair[1].kind, 0), pair[0]),
        )
        selected = tuple(item for _, item in ranked_group[:_MAX_EVIDENCE_IDS])
        ids = tuple(item.evidence_id for item in selected)
        score = min(100, sum(_KIND_WEIGHTS.get(item.kind, 0) for item in selected))
        reasons_list = list(dict.fromkeys(
            f"{item.kind}：{item.source_path}:{item.line_start}" for item in selected
        ))
        if len(group) > len(selected):
            reasons_list.append(
                f"证据过多：从 {len(group)} 条候选中按证据类型权重保留 {len(selected)} 条"
            )
        reasons = tuple(reasons_list)
        candidates.append(
            AttributionCandidate(
                role=role,
                subject=subject,
                source_locations=_candidate_locations(selected),
                evidence_ids=ids,
                score=score,
                reasons=reasons,
            )
        )
    return tuple(sorted(candidates, key=lambda item: (-item.score, item.subject, item.evidence_ids)))


def _predicate_score(predicates: Mapping[str, bool]) -> int:
    weights = {
        "socket_identity": 15,
        "service_relation": 15,
        "socket_acquire_or_bind": 25,
        "server_consumer": 25,
        "protocol_dispatch": 10,
        "manifest_mapping": 10,
    }
    return min(100, sum(weight for key, weight in weights.items() if predicates.get(key, False)))


class ServiceAttributor:
    """Build server candidates from source-backed evidence."""

    def __init__(self, *, mapping: RepositoryMapping | None = None) -> None:
        if mapping is not None and not isinstance(mapping, RepositoryMapping):
            raise ServiceAttributionError("mapping 必须是 RepositoryMapping 或 null")
        self.mapping = mapping

    def attribute(
        self,
        evidence: EvidenceStore | Iterable[Evidence],
        *,
        mapping: RepositoryMapping | None = None,
    ) -> ServerAttributionResult:
        items, excluded_evidence_ids = partition_attribution_evidence(evidence)
        active_mapping = mapping if mapping is not None else self.mapping
        if active_mapping is not None and not isinstance(active_mapping, RepositoryMapping):
            raise ServiceAttributionError("mapping 必须是 RepositoryMapping 或 null")

        creator_candidates = _build_candidates(items, "socket_creator", _CREATOR_KINDS)
        owner_candidates = _build_candidates(items, "service_owner", _OWNER_KINDS)
        consumer_candidates = _build_candidates(items, "server_consumer", _CONSUMER_KINDS)
        handler_candidates = _build_candidates(items, "server_handler", _HANDLER_KINDS)
        candidates = creator_candidates + owner_candidates + consumer_candidates + handler_candidates

        has_identity = any(item.kind in (_IDENTITY_KINDS | _CONFIG_IDENTITY_KINDS) for item in items)
        has_service_relation = any(item.kind in {"service_config", "executable_build"} for item in items)
        has_acquire_or_bind = any(
            item.kind in {"socket_server_registration", "socket_acquire", "socket_bind_listen"}
            for item in items
        )
        has_consumer = bool(consumer_candidates or handler_candidates)
        has_dispatch = bool(handler_candidates)
        has_mapping = (
            _mapping_is_resolved(active_mapping)
            if active_mapping is not None
            else _mapping_evidence_present(items)
        )
        predicates = {
            "socket_identity": has_identity,
            "service_relation": has_service_relation,
            "socket_acquire_or_bind": has_acquire_or_bind,
            "server_consumer": has_consumer,
            "protocol_dispatch": has_dispatch,
            "manifest_mapping": has_mapping,
            "creator_only": has_acquire_or_bind and not has_consumer,
        }
        confirmed = has_identity and has_acquire_or_bind and has_consumer and has_mapping
        status = "HIGH" if confirmed else ("PARTIAL" if any(item.kind in _SERVER_KINDS for item in items) else "UNRESOLVED")
        reasons: list[str] = []
        if not has_identity:
            reasons.append("缺少 socket identity（字面量、宏、常量或符号证据）")
        if not has_acquire_or_bind:
            reasons.append("缺少服务端获取 fd 或 bind/listen 证据")
        if not has_consumer:
            reasons.append("缺少 accept/read/recv 或协议分派证据")
        if not has_mapping:
            reasons.append("缺少已解析的 Manifest 仓库映射")
        if predicates["creator_only"]:
            reasons.append("当前只有创建/绑定线索，不能把 creator 当作服务端")
        warnings: list[str] = []
        if has_service_relation is False and candidates:
            warnings.append("未发现 service/config/executable 归属线索，候选归因仍需复核")
        evidence_ids = tuple(item.evidence_id for item in items if item.kind in _SERVER_KINDS)
        return ServerAttributionResult(
            status=status,
            confirmed=confirmed,
            score=_predicate_score(predicates),
            predicates=predicates,
            candidates=candidates,
            evidence_ids=evidence_ids,
            mapping=active_mapping,
            reasons=tuple(dict.fromkeys(reasons)),
            warnings=tuple(dict.fromkeys(warnings)),
            excluded_evidence_ids=excluded_evidence_ids,
        )


@dataclass(frozen=True)
class OverallAttributionResult:
    """Combined server/client status used by later orchestration stages."""

    status: str
    server_status: str
    client_status: str
    reasons: tuple[str, ...] = ()
    schema_version: str = "openant.source-locator.attribution.v1"

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ServiceAttributionError("overall attribution status 无效")
        if self.server_status not in _STATUSES or self.client_status not in _STATUSES:
            raise ServiceAttributionError("server/client status 无效")
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "server_status": self.server_status,
            "client_status": self.client_status,
            "reasons": list(self.reasons),
        }


def combine_attributions(
    server: ServerAttributionResult,
    client: Any | None = None,
) -> OverallAttributionResult:
    """Combine server/client statuses without laundering unresolved evidence."""

    if not isinstance(server, ServerAttributionResult):
        raise ServiceAttributionError("server 必须是 ServerAttributionResult")
    client_status = getattr(client, "status", "UNRESOLVED")
    if client is not None and client_status not in _STATUSES:
        raise ServiceAttributionError("client status 无效")
    if server.status == "HIGH" and client_status == "HIGH":
        status = "HIGH"
    elif server.status == "UNRESOLVED" and client_status == "UNRESOLVED":
        status = "UNRESOLVED"
    else:
        status = "PARTIAL"
    reasons: list[str] = []
    if server.status != "HIGH":
        reasons.append(f"服务端状态为 {server.status}，不能视为完整确认")
    if client_status != "HIGH":
        reasons.append(f"客户端状态为 {client_status}，整体结果保持 {status}")
    return OverallAttributionResult(
        status=status,
        server_status=server.status,
        client_status=client_status,
        reasons=tuple(reasons),
    )


__all__ = [
    "AttributionCandidate",
    "OverallAttributionResult",
    "ServerAttributionResult",
    "ServiceAttributionError",
    "ServiceAttributor",
    "SourceLocation",
    "partition_attribution_evidence",
    "combine_attributions",
]
