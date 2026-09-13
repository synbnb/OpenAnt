"""Evidence-constrained repository candidate adjudication.

The deterministic manifest/role score is useful for ordering candidates, but
it cannot reliably distinguish a service implementation from a client copy or
an executable's split source tree.  This module adds one small, optional LLM
review step.  The model may only choose among the candidates and evidence
rows supplied by the worker; it cannot invent a repository, URL, path, or
source fact.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Iterable, Mapping


CANDIDATE_REVIEW_SCHEMA_VERSION = "openant.source-locator.candidate-review.v1"
CANDIDATE_REVIEW_PROMPT_VERSION = "openant.source-locator.candidate-review-prompt.v1"
CANDIDATE_REVIEW_SYSTEM = (
    "你是 OpenHarmony 源码仓库归属复核器。"
    "只能依据提示中的候选仓库和源码证据作出最终 PK；不得创建新仓库、URL、路径或证据。"
    "需要综合进程/构建归属、目标 socket 的服务端实现、客户端或控制端实现、"
    "以及重复源码或拆分源码关系。若目标包含进程名，构建目标与该进程名的直接对应关系"
    "优先于只出现相同 socket 文本的镜像；若没有进程线索，则优先真实服务端接收链。"
    "必须只返回一个 JSON 对象，不输出思维链。"
)
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_EVIDENCE_RE = re.compile(r"^E-[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONFIDENCES = frozenset({"high", "medium", "low"})
_ROLES = frozenset({"process_owner", "server_implementation", "client_controller", "duplicate_or_split_source", "unknown"})
# Models often use a short natural-language role for a related repository
# (for example ``client`` or ``mirror``) even though the primary role is
# returned correctly.  Related rows are advisory, so normalize the common
# spellings instead of discarding an otherwise valid primary decision.
_RELATED_ROLE_ALIASES = {
    "process owner": "process_owner",
    "owner": "process_owner",
    "server": "server_implementation",
    "server implementation": "server_implementation",
    "service": "server_implementation",
    "client": "client_controller",
    "client implementation": "client_controller",
    "controller": "client_controller",
    "copy": "duplicate_or_split_source",
    "duplicate": "duplicate_or_split_source",
    "mirror": "duplicate_or_split_source",
    "split source": "duplicate_or_split_source",
    "duplicate or split source": "duplicate_or_split_source",
}
_MAX_PROMPT_CHARS = 32_000
_MAX_REASON_CHARS = 1_024
_MAX_EVIDENCE_IDS = 24


class CandidateReviewError(ValueError):
    """Raised when a candidate review input or response is invalid."""


def _clean(value: Any, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CandidateReviewError(f"{name} 必须是字符串")
    value = " ".join(value.split()).strip()
    if not value and not allow_empty:
        raise CandidateReviewError(f"{name} 不能为空")
    if len(value) > limit:
        raise CandidateReviewError(f"{name} 超过长度上限 {limit}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise CandidateReviewError(f"{name} 包含控制字符")
    return value


def _normalize_related_role(value: Any) -> str:
    """Normalize a model's advisory related-repository role.

    The primary role remains strict.  A malformed related role must not make
    the whole PK unusable because related repositories are explanatory
    metadata, not the repository-selection authority.
    """

    if not isinstance(value, str):
        return "unknown"
    role = " ".join(value.split()).strip().casefold()
    if role in _ROLES:
        return role
    return _RELATED_ROLE_ALIASES.get(role, "unknown")


def _extract_json(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str):
        raise CandidateReviewError("模型返回必须是 JSON 对象或 JSON 文本")
    text = value.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, count=1, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text, count=1)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CandidateReviewError("模型返回不是合法 JSON") from exc
    if not isinstance(payload, Mapping):
        raise CandidateReviewError("模型返回顶层必须是 JSON 对象")
    return payload


@dataclass(frozen=True)
class CandidateReviewResult:
    """Validated final choice among already resolved repository candidates."""

    primary_repository: str
    primary_role: str
    confidence: str
    reason: str
    evidence_ids: tuple[str, ...]
    related_repositories: tuple[dict[str, Any], ...] = ()
    model_calls: int = 1
    schema_version: str = CANDIDATE_REVIEW_SCHEMA_VERSION
    prompt_version: str = CANDIDATE_REVIEW_PROMPT_VERSION

    def __post_init__(self) -> None:
        if not _PROJECT_RE.fullmatch(self.primary_repository):
            raise CandidateReviewError("primary_repository 不是合法候选项目名")
        if self.primary_role not in _ROLES:
            raise CandidateReviewError("primary_role 无效")
        if self.confidence not in _CONFIDENCES:
            raise CandidateReviewError("confidence 无效")
        object.__setattr__(self, "reason", _clean(self.reason, name="reason", limit=_MAX_REASON_CHARS))
        ids = tuple(dict.fromkeys(self.evidence_ids))
        if len(ids) > _MAX_EVIDENCE_IDS or any(not isinstance(item, str) or not _EVIDENCE_RE.fullmatch(item) for item in ids):
            raise CandidateReviewError("evidence_ids 无效或超过数量上限")
        object.__setattr__(self, "evidence_ids", ids)
        if isinstance(self.related_repositories, (str, bytes)):
            raise CandidateReviewError("related_repositories 必须是数组")
        related: list[dict[str, Any]] = []
        for item in self.related_repositories:
            if not isinstance(item, Mapping):
                raise CandidateReviewError("related_repositories 条目必须是对象")
            project = _clean(item.get("project_name"), name="related_repositories.project_name", limit=128)
            role = _clean(item.get("role", "unknown"), name="related_repositories.role", limit=64)
            if role not in _ROLES:
                raise CandidateReviewError("related_repositories.role 无效")
            raw_ids = item.get("evidence_ids", [])
            if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, Iterable):
                raise CandidateReviewError("related_repositories.evidence_ids 必须是数组")
            ids = tuple(dict.fromkeys(raw_ids))
            if len(ids) > _MAX_EVIDENCE_IDS or any(not isinstance(value, str) or not _EVIDENCE_RE.fullmatch(value) for value in ids):
                raise CandidateReviewError("related_repositories.evidence_ids 无效")
            related.append({"project_name": project, "role": role, "evidence_ids": list(ids)})
        object.__setattr__(self, "related_repositories", tuple(related))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "prompt_version": self.prompt_version,
            "primary_repository": self.primary_repository,
            "primary_role": self.primary_role,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "related_repositories": list(self.related_repositories),
            "model_calls": self.model_calls,
        }


def build_candidate_review_prompt(
    *,
    target: Mapping[str, Any],
    candidates: Iterable[Mapping[str, Any]],
    max_prompt_chars: int = _MAX_PROMPT_CHARS,
) -> str:
    """Build a bounded prompt from candidate rows and source-backed facts."""

    if not isinstance(target, Mapping):
        raise CandidateReviewError("target 必须是 JSON 对象")
    rows: list[dict[str, Any]] = []
    for raw in candidates:
        if not isinstance(raw, Mapping):
            raise CandidateReviewError("candidates 条目必须是对象")
        project = _clean(raw.get("project_name"), name="candidate.project_name", limit=128)
        if not _PROJECT_RE.fullmatch(project):
            raise CandidateReviewError("candidate.project_name 不是合法项目名")
        raw_ids = raw.get("evidence_ids", [])
        if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, Iterable):
            raise CandidateReviewError("candidate.evidence_ids 必须是数组")
        evidence_ids = tuple(dict.fromkeys(raw_ids))
        if any(not isinstance(item, str) or not _EVIDENCE_RE.fullmatch(item) for item in evidence_ids):
            raise CandidateReviewError("candidate.evidence_ids 包含无效 ID")
        rows.append({
            "project_name": project,
            "source_root": _clean(raw.get("source_root", ""), name="candidate.source_root", limit=256, allow_empty=True),
            "source_path": _clean(raw.get("source_path", ""), name="candidate.source_path", limit=512, allow_empty=True),
            "repo_url": _clean(raw.get("repo_url", ""), name="candidate.repo_url", limit=512, allow_empty=True),
            "ranking_score": raw.get("ranking_score", 0),
            "role_evidence_counts": dict(raw.get("role_evidence_counts", {})) if isinstance(raw.get("role_evidence_counts", {}), Mapping) else {},
            "evidence_ids": list(evidence_ids[:_MAX_EVIDENCE_IDS]),
            "source_facts": list(raw.get("source_facts", []))[:12] if isinstance(raw.get("source_facts", []), list) else [],
        })
    if len(rows) < 2:
        raise CandidateReviewError("候选仓库至少需要两个")
    payload = {
        "schema_version": CANDIDATE_REVIEW_SCHEMA_VERSION,
        "prompt_version": CANDIDATE_REVIEW_PROMPT_VERSION,
        "task": "在已有候选仓库中选择最可能的源码归属，并说明其他候选是客户端、控制端或重复/拆分源码",
        "target": dict(target),
        "candidates": rows,
        "rules": {
            "choose_only_given_project_names": True,
            "cite_only_given_evidence_ids": True,
            "process_build_ownership_matters": True,
            "server_implementation_matters": True,
            "client_controller_is_related_not_automatically_primary": True,
            "duplicate_or_split_source_must_be_explicit": True,
        },
        "output_schema": {
            "primary_repository": "one supplied project_name",
            "primary_role": "process_owner|server_implementation|client_controller|duplicate_or_split_source|unknown",
            "confidence": "high|medium|low",
            "reason": "short Chinese explanation",
            "evidence_ids": ["only supplied evidence IDs"],
            "related_repositories": [{"project_name": "one supplied project_name", "role": "...", "evidence_ids": ["only supplied IDs"]}],
        },
        "instruction": "只输出一个 JSON 对象；不确定时降低 confidence，但仍从候选中选择概率最高者。",
    }
    prompt = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(prompt) > max_prompt_chars:
        raise CandidateReviewError("候选 PK prompt 超过长度上限")
    return prompt


class LLMCandidateReviewer:
    """Call and validate one optional candidate PK review."""

    def __init__(self, *, model_call: Callable[[str], Any], max_prompt_chars: int = _MAX_PROMPT_CHARS) -> None:
        if not callable(model_call):
            raise CandidateReviewError("model_call 必须是可调用对象")
        self.model_call = model_call
        self.max_prompt_chars = max_prompt_chars
        self.model_calls = 0

    def review(self, *, target: Mapping[str, Any], candidates: Iterable[Mapping[str, Any]]) -> CandidateReviewResult:
        candidate_rows = tuple(candidates)
        prompt = build_candidate_review_prompt(
            target=target,
            candidates=candidate_rows,
            max_prompt_chars=self.max_prompt_chars,
        )
        allowed_projects = {
            str(item.get("project_name"))
            for item in candidate_rows
            if isinstance(item, Mapping)
        }
        allowed_ids = {
            item
            for raw in candidate_rows
            if isinstance(raw, Mapping)
            for item in raw.get("evidence_ids", ())
            if isinstance(item, str)
        }
        self.model_calls += 1
        payload = _extract_json(self.model_call(prompt))
        allowed_fields = {"primary_repository", "primary_role", "confidence", "reason", "evidence_ids", "related_repositories"}
        unknown = set(payload) - allowed_fields
        if unknown or set(payload) - {"primary_repository", "primary_role", "confidence", "reason", "evidence_ids", "related_repositories"}:
            raise CandidateReviewError("模型返回包含未知字段或缺少必需字段")
        primary = _clean(payload.get("primary_repository"), name="primary_repository", limit=128)
        if primary not in allowed_projects:
            raise CandidateReviewError("primary_repository 不在候选集合中")
        raw_ids = payload.get("evidence_ids", [])
        if isinstance(raw_ids, (str, bytes)) or not isinstance(raw_ids, Iterable):
            raise CandidateReviewError("evidence_ids 必须是数组")
        evidence_ids = tuple(dict.fromkeys(raw_ids))
        if any(item not in allowed_ids for item in evidence_ids):
            raise CandidateReviewError("模型引用了候选集合之外的 evidence_id")
        related_raw = payload.get("related_repositories", [])
        if not isinstance(related_raw, list):
            raise CandidateReviewError("related_repositories 必须是数组")
        for item in related_raw:
            if not isinstance(item, Mapping) or item.get("project_name") not in allowed_projects:
                raise CandidateReviewError("related_repositories 引用了未知候选")
            for evidence_id in item.get("evidence_ids", []):
                if evidence_id not in allowed_ids:
                    raise CandidateReviewError("related_repositories 引用了未知 evidence_id")
        # Normalize only the advisory related rows.  Unknown role wording is
        # retained as ``unknown``; it no longer invalidates a valid primary
        # repository decision.
        normalized_related = []
        for item in related_raw:
            normalized_related.append(
                {
                    "project_name": item["project_name"],
                    "role": _normalize_related_role(item.get("role", "unknown")),
                    "evidence_ids": list(dict.fromkeys(item.get("evidence_ids", []))),
                }
            )
        return CandidateReviewResult(
            primary_repository=primary,
            primary_role=_clean(payload.get("primary_role"), name="primary_role", limit=64),
            confidence=_clean(payload.get("confidence"), name="confidence", limit=32),
            reason=_clean(payload.get("reason"), name="reason", limit=_MAX_REASON_CHARS),
            evidence_ids=evidence_ids,
            related_repositories=tuple(normalized_related),
        )


__all__ = [
    "CANDIDATE_REVIEW_PROMPT_VERSION",
    "CANDIDATE_REVIEW_SCHEMA_VERSION",
    "CANDIDATE_REVIEW_SYSTEM",
    "CandidateReviewError",
    "CandidateReviewResult",
    "LLMCandidateReviewer",
    "build_candidate_review_prompt",
]
