"""Evidence-constrained LLM attribution for OpenHarmony socket roles.

The deterministic attribution code is intentionally conservative: it is good
at recognizing explicit ``bind/listen/accept`` and ``connect/send`` evidence,
but a large OpenHarmony tree may express the same boundary through wrappers,
registration helpers, generated code, or a cross-repository service layer.
This module lets a model adjudicate the *role* of already-collected evidence
without allowing it to invent a path, a repository, or a call edge.

Only source evidence supplied by the caller enters the prompt.  Test and fuzz
paths are removed by :func:`partition_attribution_evidence` before this module
is called.  The returned JSON is strictly validated and contains no raw model
response or hidden reasoning trace.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Iterable, Mapping

from .evidence_store import Evidence, EvidenceStore
from .path_classifier import classify_path
from .service_attributor import partition_attribution_evidence
from .target_normalizer import TargetSpec


ROLE_ATTRIBUTION_SCHEMA_VERSION = "openant.source-locator.llm-role-attribution.v1"
ROLE_ATTRIBUTION_PROMPT_VERSION = "openant.source-locator.llm-role-prompt.v1"
ROLE_ATTRIBUTION_SYSTEM = (
    "你是 OpenHarmony 源码审计中的服务端/客户端角色复核器。"
    "只能依据用户提供的结构化源码证据作出判断；Unix socket 和 TCP/UDP 端点都适用。"
    "网络目标中端口、地址和进程名只是线索，必须结合源码中的 bind/listen/accept/recvfrom 方向判断服务端；"
    "connect/send 只能支持客户端角色。必须严格返回 JSON，不能输出思维链。"
)
_STATUSES = frozenset({"confirmed", "possible", "unresolved"})
_CONFIDENCES = frozenset({"high", "medium", "low"})
_ROLES = ("server", "client")
_EVIDENCE_ID_RE = re.compile(r"^E-[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_EVIDENCE = 64
_MAX_ROLE_EVIDENCE = 16
_MAX_SUBJECT = 256
_MAX_REASON = 768
_MAX_EXCERPT = 640
_MAX_PROMPT_CHARS = 32_000


class LLMRoleAttributionError(ValueError):
    """Raised when the model response or attribution input is invalid."""


def _clean(value: Any, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise LLMRoleAttributionError(f"{name} 必须是字符串")
    value = " ".join(value.split()).strip()
    if not value and not allow_empty:
        raise LLMRoleAttributionError(f"{name} 不能为空")
    if len(value) > limit:
        raise LLMRoleAttributionError(f"{name} 超过长度上限 {limit}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise LLMRoleAttributionError(f"{name} 包含控制字符")
    return value


def _target_payload(target: TargetSpec | Mapping[str, Any] | None) -> dict[str, Any]:
    if isinstance(target, TargetSpec):
        return {
            "target_type": target.target_type,
            "socket_path": target.socket_path,
            "basename": target.basename,
            "service_hint": target.service_hint,
            "macro_hint": target.macro_hint,
            "transport": target.transport,
            "address": target.address,
            "port": target.port,
            "process_hint": target.process_hint,
            "target_revision": target.target_revision,
        }
    if target is None:
        return {}
    if not isinstance(target, Mapping):
        raise LLMRoleAttributionError("target 必须是 TargetSpec、JSON 对象或 null")
    # Do not echo arbitrary nested user data into the prompt.
    allowed = {
        "target_type",
        "socket_path",
        "basename",
        "service_hint",
        "macro_hint",
        "transport",
        "address",
        "port",
        "process_hint",
        "target_revision",
    }
    return {str(key): value for key, value in target.items() if str(key) in allowed}


def _evidence_items(value: EvidenceStore | Iterable[Evidence]) -> tuple[Evidence, ...]:
    if isinstance(value, EvidenceStore):
        items = value.evidence
    else:
        if isinstance(value, (str, bytes)):
            raise LLMRoleAttributionError("evidence 必须是 EvidenceStore 或 Evidence 序列")
        try:
            items = tuple(value)
        except TypeError as exc:
            raise LLMRoleAttributionError("evidence 必须是 EvidenceStore 或 Evidence 序列") from exc
    result: list[Evidence] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Evidence):
            raise LLMRoleAttributionError("evidence 序列只能包含 Evidence")
        if item.evidence_id not in seen:
            seen.add(item.evidence_id)
            result.append(item)
    return tuple(result)


def _extract_json(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        raise LLMRoleAttributionError("模型返回必须是 JSON 对象或 JSON 文本")
    text = value.strip()
    # Providers sometimes wrap structured output in a markdown code fence.
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, count=1, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text, count=1)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMRoleAttributionError("模型返回不是合法 JSON") from exc
    if not isinstance(payload, Mapping):
        raise LLMRoleAttributionError("模型返回顶层必须是 JSON 对象")
    return payload


@dataclass(frozen=True)
class LLMRoleDecision:
    """One validated model decision for either server or client role."""

    role: str
    status: str
    confidence: str
    subject: str
    evidence_ids: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        if self.role not in _ROLES:
            raise LLMRoleAttributionError("role 必须是 server 或 client")
        if self.status not in _STATUSES:
            raise LLMRoleAttributionError("status 必须是 confirmed、possible 或 unresolved")
        if self.confidence not in _CONFIDENCES:
            raise LLMRoleAttributionError("confidence 无效")
        object.__setattr__(self, "subject", _clean(self.subject, name="subject", limit=_MAX_SUBJECT, allow_empty=True))
        object.__setattr__(self, "reason", _clean(self.reason, name="reason", limit=_MAX_REASON))
        try:
            ids = tuple(dict.fromkeys(self.evidence_ids))
        except (TypeError, ValueError) as exc:
            raise LLMRoleAttributionError("evidence_ids 无效或包含不可哈希值") from exc
        if len(ids) > _MAX_ROLE_EVIDENCE or any(
            not isinstance(item, str) or not _EVIDENCE_ID_RE.fullmatch(item)
            for item in ids
        ):
            raise LLMRoleAttributionError("evidence_ids 无效或超过数量上限")
        if self.status == "confirmed" and not ids:
            raise LLMRoleAttributionError("confirmed 决策必须引用至少一个 evidence_id")
        object.__setattr__(self, "evidence_ids", ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "status": self.status,
            "confidence": self.confidence,
            "subject": self.subject,
            "evidence_ids": list(self.evidence_ids),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class LLMRoleAttributionResult:
    """Validated, bounded result of one role-attribution model call."""

    server: LLMRoleDecision
    client: LLMRoleDecision
    model_calls: int = 1
    prompt_version: str = ROLE_ATTRIBUTION_PROMPT_VERSION
    schema_version: str = ROLE_ATTRIBUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.server.role != "server" or self.client.role != "client":
            raise LLMRoleAttributionError("server/client 决策角色不匹配")
        if isinstance(self.model_calls, bool) or not isinstance(self.model_calls, int) or not 1 <= self.model_calls <= 2:
            raise LLMRoleAttributionError("model_calls 必须是 1 或 2")

    @property
    def status(self) -> str:
        if self.server.status == "confirmed" or self.client.status == "confirmed":
            return "READY"
        if self.server.status == "possible" or self.client.status == "possible":
            return "PARTIAL"
        return "UNRESOLVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "prompt_version": self.prompt_version,
            "status": self.status,
            "model_calls": self.model_calls,
            "server": self.server.to_dict(),
            "client": self.client.to_dict(),
        }


def build_role_attribution_prompt(
    *,
    target: TargetSpec | Mapping[str, Any] | None,
    evidence: EvidenceStore | Iterable[Evidence],
    excluded_evidence_ids: Iterable[str] = (),
    max_prompt_chars: int = _MAX_PROMPT_CHARS,
) -> str:
    """Build the only prompt sent to the role model.

    The prompt deliberately describes ``CreateSocket`` as neutral.  A model
    must cite surrounding bind/listen/accept/register or connect/send/protocol
    evidence rather than relying on a function-name rule.
    """

    items, partition_excluded = partition_attribution_evidence(evidence)
    if len(items) > _MAX_EVIDENCE:
        items = items[:_MAX_EVIDENCE]
    if isinstance(excluded_evidence_ids, (str, bytes)):
        raise LLMRoleAttributionError("excluded_evidence_ids 必须是 ID 序列")
    try:
        explicit_excluded = tuple(excluded_evidence_ids)
    except TypeError as exc:
        raise LLMRoleAttributionError("excluded_evidence_ids 必须是 ID 序列") from exc
    if any(not isinstance(item, str) or not _EVIDENCE_ID_RE.fullmatch(item) for item in explicit_excluded):
        raise LLMRoleAttributionError("excluded_evidence_ids 包含无效 ID")
    excluded = tuple(dict.fromkeys((*partition_excluded, *explicit_excluded)))
    rows: list[dict[str, Any]] = []
    for item in items:
        try:
            classification = classify_path(item.source_path, target=target if isinstance(target, TargetSpec) else None)
            path_role = classification.role
            path_signals = list(classification.path_signals)
        except Exception:
            path_role = "unknown"
            path_signals = []
        rows.append(
            {
                "evidence_id": item.evidence_id,
                "kind": item.kind,
                "source_path": item.source_path,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "symbol": item.symbol,
                "relation_from": item.relation_from,
                "relation_to": item.relation_to,
                "excerpt": item.excerpt[:_MAX_EXCERPT],
                "path_role": path_role,
                "path_signals": path_signals,
            }
        )
    payload = {
        "prompt_version": ROLE_ATTRIBUTION_PROMPT_VERSION,
        "task": "判断 OpenHarmony Unix socket 或 TCP/UDP endpoint 相关源码证据中的服务端和客户端角色",
        "target": _target_payload(target),
        "evidence": rows,
        "excluded_test_or_fuzz_evidence_count": len(excluded),
        "rules": {
            "evidence_only": True,
            "cite_only_given_evidence_ids": True,
            "test_or_fuzz_paths_are_non_authoritative": True,
            "create_socket_alone_is_neutral": True,
            "server_signals": ["bind", "listen", "accept", "recv/recvfrom/read", "socket registration", "protocol dispatch"],
            "client_signals": ["connect", "request/protocol construction", "send/write"],
            "kernel_third_party_generated_build_paths_are_not_automatically_excluded": True,
        },
        "output_schema": {
            "server": {
                "status": "confirmed|possible|unresolved",
                "confidence": "high|medium|low",
                "subject": "short function/class/service name or empty string",
                "evidence_ids": ["only IDs from evidence"],
                "reason": "short Chinese explanation",
            },
            "client": {
                "status": "confirmed|possible|unresolved",
                "confidence": "high|medium|low",
                "subject": "short function/class/client name or empty string",
                "evidence_ids": ["only IDs from evidence"],
                "reason": "short Chinese explanation",
            },
        },
        "instruction": "只输出一个 JSON 对象，不要输出 Markdown、思维链、仓库 URL 或未提供的证据。服务端和客户端都可以是 unresolved。",
    }
    prompt = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(prompt) > max_prompt_chars:
        raise LLMRoleAttributionError("角色判定 prompt 超过长度上限")
    return prompt


class LLMRoleAttributor:
    """Call and validate one bounded model decision for both roles."""

    def __init__(
        self,
        *,
        model_call: Callable[[str], Any],
        max_prompt_chars: int = _MAX_PROMPT_CHARS,
    ) -> None:
        if not callable(model_call):
            raise LLMRoleAttributionError("model_call 必须是可调用对象")
        if isinstance(max_prompt_chars, bool) or not isinstance(max_prompt_chars, int) or not 4096 <= max_prompt_chars <= 128_000:
            raise LLMRoleAttributionError("max_prompt_chars 超出安全范围")
        self.model_call = model_call
        self.max_prompt_chars = max_prompt_chars
        self.model_calls = 0

    @staticmethod
    def _decision(role: str, raw: Any, allowed_ids: set[str]) -> LLMRoleDecision:
        if not isinstance(raw, Mapping):
            raise LLMRoleAttributionError(f"{role} 决策必须是 JSON 对象")
        unknown = set(raw) - {"status", "confidence", "subject", "evidence_ids", "reason"}
        if unknown:
            raise LLMRoleAttributionError(f"{role} 决策包含未知字段：{', '.join(sorted(str(item) for item in unknown))}")
        status = _clean(raw.get("status"), name=f"{role}.status", limit=32)
        confidence = _clean(raw.get("confidence"), name=f"{role}.confidence", limit=32)
        subject = raw.get("subject", "")
        reason = _clean(raw.get("reason"), name=f"{role}.reason", limit=_MAX_REASON)
        raw_ids = raw.get("evidence_ids", [])
        if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, Iterable):
            raise LLMRoleAttributionError(f"{role}.evidence_ids 必须是数组")
        try:
            ids = tuple(dict.fromkeys(raw_ids))
        except (TypeError, ValueError) as exc:
            raise LLMRoleAttributionError(f"{role}.evidence_ids 包含不可哈希值") from exc
        if any(item not in allowed_ids for item in ids):
            raise LLMRoleAttributionError(f"{role} 引用了未提供或被排除的 evidence_id")
        return LLMRoleDecision(
            role=role,
            status=status,
            confidence=confidence,
            subject=subject,
            evidence_ids=ids,
            reason=reason,
        )

    def attribute(
        self,
        *,
        target: TargetSpec | Mapping[str, Any] | None,
        evidence: EvidenceStore | Iterable[Evidence],
        excluded_evidence_ids: Iterable[str] = (),
    ) -> LLMRoleAttributionResult:
        eligible, partition_excluded = partition_attribution_evidence(evidence)
        allowed_ids = {item.evidence_id for item in eligible}
        # Explicitly reject a caller that tries to mark an eligible ID as
        # excluded; this prevents a stale artifact from silently changing the
        # model's evidence universe.
        if isinstance(excluded_evidence_ids, (str, bytes)):
            raise LLMRoleAttributionError("excluded_evidence_ids 必须是 ID 序列")
        try:
            explicit_excluded = tuple(excluded_evidence_ids)
        except TypeError as exc:
            raise LLMRoleAttributionError("excluded_evidence_ids 必须是 ID 序列") from exc
        if any(not isinstance(item, str) or not _EVIDENCE_ID_RE.fullmatch(item) for item in explicit_excluded):
            raise LLMRoleAttributionError("excluded_evidence_ids 包含无效 ID")
        if set(explicit_excluded) & allowed_ids:
            raise LLMRoleAttributionError("excluded_evidence_ids 与可用证据重叠")
        prompt = build_role_attribution_prompt(
            target=target,
            evidence=eligible,
            excluded_evidence_ids=(*partition_excluded, *explicit_excluded),
            max_prompt_chars=self.max_prompt_chars,
        )
        self.model_calls += 1
        raw = self.model_call(prompt)
        payload = _extract_json(raw)
        if set(payload) != {"server", "client"}:
            raise LLMRoleAttributionError("模型返回必须且只能包含 server、client 两个顶层字段")
        server = self._decision("server", payload["server"], allowed_ids)
        client = self._decision("client", payload["client"], allowed_ids)
        return LLMRoleAttributionResult(
            server=server,
            client=client,
            model_calls=1,
        )


__all__ = [
    "LLMRoleAttributionError",
    "LLMRoleAttributionResult",
    "LLMRoleAttributor",
    "LLMRoleDecision",
    "ROLE_ATTRIBUTION_PROMPT_VERSION",
    "ROLE_ATTRIBUTION_SCHEMA_VERSION",
    "ROLE_ATTRIBUTION_SYSTEM",
    "build_role_attribution_prompt",
]
