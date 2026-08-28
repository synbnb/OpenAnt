"""Deterministic client communication boundary detection.

The locator stops at the transport/protocol layer.  Once endpoint, connect,
request construction, send, and repository mapping are proven, searching all
business callers would add noise and enlarge the scope without improving the
socket-service attribution.  The completed result therefore explicitly blocks
the ``find_business_callers`` action.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .evidence_store import Evidence, EvidenceStore
from .manifest_resolver import RepositoryMapping
from .service_attributor import (
    AttributionCandidate,
    OverallAttributionResult,
    ServiceAttributionError,
    SourceLocation,
    _clean,
    _evidence_items,
    _mapping_evidence_present,
    _mapping_is_resolved,
    combine_attributions,
)


_SCHEMA_VERSION = "openant.source-locator.client-attribution.v1"
_STATUSES = frozenset({"HIGH", "PARTIAL", "UNRESOLVED"})
_CLIENT_ROLES = frozenset({"client_transport", "client_protocol", "client_sender"})
_CLIENT_KINDS = frozenset(
    {
        "client_endpoint",
        "client_connect",
        "protocol_construction",
        "client_send",
        "literal_match",
        "macro_definition",
        "constant_definition",
        "symbol_reference",
        "service_config",
        "manifest_mapping",
    }
)
_IDENTITY_KINDS = frozenset(
    {"literal_match", "macro_definition", "constant_definition", "symbol_reference"}
)
_KIND_WEIGHTS: Mapping[str, int] = {
    "client_endpoint": 20,
    "client_connect": 25,
    "protocol_construction": 20,
    "client_send": 25,
    "literal_match": 20,
    "macro_definition": 20,
    "constant_definition": 20,
    "symbol_reference": 10,
    "manifest_mapping": 10,
}


class ClientLocatorError(ValueError):
    """Raised when client locator input or action is invalid."""


def _mapping_is_valid(mapping: RepositoryMapping | None) -> bool:
    return _mapping_is_resolved(mapping)


def _client_subject(item: Evidence) -> str:
    return _clean(item.relation_to or item.symbol or f"{item.source_path}:{item.line_start}")


def _locations(items: Iterable[Evidence]) -> tuple[SourceLocation, ...]:
    result: list[SourceLocation] = []
    seen: set[tuple[str, int, int, str | None]] = set()
    for item in items:
        location = SourceLocation(item.source_path, item.line_start, item.line_end, item.symbol)
        key = (location.source_path, location.line_start, location.line_end, location.symbol)
        if key not in seen:
            seen.add(key)
            result.append(location)
    return tuple(result)


def _client_candidates(items: tuple[Evidence, ...]) -> tuple[AttributionCandidate, ...]:
    role_kinds = {
        "client_transport": frozenset({"client_endpoint", "client_connect"}),
        "client_protocol": frozenset({"protocol_construction"}),
        "client_sender": frozenset({"client_send"}),
    }
    candidates: list[AttributionCandidate] = []
    for role, kinds in role_kinds.items():
        groups: dict[str, list[Evidence]] = {}
        for item in items:
            if item.kind in kinds:
                groups.setdefault(_client_subject(item), []).append(item)
        for subject, group in groups.items():
            candidates.append(
                AttributionCandidate(
                    role=role,
                    subject=subject,
                    source_locations=_locations(group),
                    evidence_ids=tuple(item.evidence_id for item in group),
                    score=min(100, sum(_KIND_WEIGHTS.get(item.kind, 0) for item in group)),
                    reasons=tuple(
                        dict.fromkeys(f"{item.kind}：{item.source_path}:{item.line_start}" for item in group)
                    ),
                )
            )
    return tuple(sorted(candidates, key=lambda item: (-item.score, item.role, item.subject)))


@dataclass(frozen=True)
class ClientAttributionResult:
    """Auditable client communication result."""

    status: str
    completed: bool
    score: int
    predicates: Mapping[str, bool]
    candidates: tuple[AttributionCandidate, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    mapping: RepositoryMapping | None = None
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    forbidden_actions: tuple[str, ...] = ("find_business_callers",)
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ClientLocatorError("客户端归因 status 无效")
        if not isinstance(self.completed, bool) or self.completed != (self.status == "HIGH"):
            raise ClientLocatorError("completed 必须与 HIGH 状态一致")
        if isinstance(self.score, bool) or not isinstance(self.score, int) or not 0 <= self.score <= 100:
            raise ClientLocatorError("客户端归因 score 无效")
        if not isinstance(self.predicates, Mapping):
            raise ClientLocatorError("predicates 必须是映射")
        if any(not isinstance(value, bool) for value in self.predicates.values()):
            raise ClientLocatorError("predicates 的值必须是布尔值")
        object.__setattr__(self, "predicates", {str(key): value for key, value in self.predicates.items()})
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "evidence_ids", tuple(dict.fromkeys(self.evidence_ids)))
        actions = tuple(dict.fromkeys(self.forbidden_actions))
        if any(not isinstance(item, str) or not item.strip() for item in actions):
            raise ClientLocatorError("forbidden_actions 无效")
        object.__setattr__(self, "forbidden_actions", actions)
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_clean(item) for item in self.warnings))

    @property
    def roles(self) -> dict[str, tuple[AttributionCandidate, ...]]:
        grouped: dict[str, list[AttributionCandidate]] = {role: [] for role in _CLIENT_ROLES}
        for candidate in self.candidates:
            grouped[candidate.role].append(candidate)
        return {role: tuple(items) for role, items in grouped.items()}

    @property
    def client_repo(self) -> str | None:
        return self.mapping.project_name if self.mapping and self.mapping.is_resolved else None

    @property
    def business_caller_search_allowed(self) -> bool:
        return not (self.completed and "find_business_callers" in self.forbidden_actions)

    def allows_action(self, action: str) -> bool:
        if not isinstance(action, str) or not action.strip():
            raise ClientLocatorError("action 必须是非空字符串")
        return not (
            self.completed
            and action.strip() in self.forbidden_actions
        )

    def assert_action_allowed(self, action: str) -> None:
        if not self.allows_action(action):
            raise ClientLocatorError(
                f"客户端通信层已完成，禁止继续执行 {action.strip()}；不追踪业务 caller"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "completed": self.completed,
            "score": self.score,
            "predicates": dict(self.predicates),
            "candidates": [item.to_dict() for item in self.candidates],
            "roles": {
                role: [item.to_dict() for item in items] for role, items in self.roles.items()
            },
            "evidence_ids": list(self.evidence_ids),
            "mapping": self.mapping.to_dict() if self.mapping else None,
            "client_repo": self.client_repo,
            "business_caller_search_allowed": self.business_caller_search_allowed,
            "forbidden_actions": list(self.forbidden_actions),
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


class ClientLocator:
    """Locate the client transport/protocol boundary and stop there."""

    def __init__(self, *, mapping: RepositoryMapping | None = None) -> None:
        if mapping is not None and not isinstance(mapping, RepositoryMapping):
            raise ClientLocatorError("mapping 必须是 RepositoryMapping 或 null")
        self.mapping = mapping

    def locate(
        self,
        evidence: EvidenceStore | Iterable[Evidence],
        *,
        mapping: RepositoryMapping | None = None,
    ) -> ClientAttributionResult:
        items = _evidence_items(evidence)
        active_mapping = mapping if mapping is not None else self.mapping
        if active_mapping is not None and not isinstance(active_mapping, RepositoryMapping):
            raise ClientLocatorError("mapping 必须是 RepositoryMapping 或 null")
        candidates = _client_candidates(items)
        has_target_relation = any(
            item.kind == "client_endpoint"
            or (
                item.kind in {"client_connect", *_IDENTITY_KINDS}
                and item.relation_from
            )
            for item in items
        )
        has_connect = any(item.kind == "client_connect" for item in items)
        has_protocol = any(item.kind == "protocol_construction" for item in items)
        has_send = any(item.kind == "client_send" for item in items)
        has_mapping = (
            _mapping_is_valid(active_mapping)
            if active_mapping is not None
            else _mapping_evidence_present(items)
        )
        predicates = {
            "target_relation": has_target_relation,
            "endpoint_or_connect": has_connect or any(item.kind == "client_endpoint" for item in items),
            "client_connect": has_connect,
            "protocol_construction": has_protocol,
            "client_send": has_send,
            "manifest_mapping": has_mapping,
        }
        completed = (
            has_target_relation
            and predicates["endpoint_or_connect"]
            and has_protocol
            and has_send
            and has_mapping
        )
        status = "HIGH" if completed else ("PARTIAL" if any(item.kind in _CLIENT_KINDS for item in items) else "UNRESOLVED")
        score = min(
            100,
            (20 if has_target_relation else 0)
            + (25 if has_connect else 0)
            + (20 if has_protocol else 0)
            + (25 if has_send else 0)
            + (10 if has_mapping else 0),
        )
        reasons: list[str] = []
        if not has_target_relation:
            reasons.append("缺少目标 socket/service 关系")
        if not predicates["endpoint_or_connect"]:
            reasons.append("缺少客户端 endpoint、connect 或等价连接证据")
        if not has_protocol:
            reasons.append("缺少请求/协议构造证据")
        if not has_send:
            reasons.append("缺少 send/write/request 发送证据")
        if not has_mapping:
            reasons.append("缺少已解析的 Manifest 仓库映射")
        warnings = ("客户端定位完成后不继续搜索业务 caller",) if completed else ()
        evidence_ids = tuple(item.evidence_id for item in items if item.kind in _CLIENT_KINDS)
        return ClientAttributionResult(
            status=status,
            completed=completed,
            score=score,
            predicates=predicates,
            candidates=candidates,
            evidence_ids=evidence_ids,
            mapping=active_mapping,
            reasons=tuple(dict.fromkeys(reasons)),
            warnings=warnings,
        )

    @staticmethod
    def combine(
        server: Any,
        client: ClientAttributionResult,
    ) -> OverallAttributionResult:
        if not isinstance(client, ClientAttributionResult):
            raise ClientLocatorError("client 必须是 ClientAttributionResult")
        try:
            return combine_attributions(server, client)
        except ServiceAttributionError as exc:
            raise ClientLocatorError(str(exc)) from exc


__all__ = [
    "ClientAttributionResult",
    "ClientLocator",
    "ClientLocatorError",
]
