"""受限的 LLM 源码检索动作规划器。

该模块只负责：

* 把已有的、可审计证据投影成有限上下文；
* 校验模型返回的单个结构化动作；
* 施加动作种类、路径、证据引用、重复查询、格式修复和预算门禁。

它不会执行 OpenGrok、Git、shell 或本地文件读取。真正的执行器必须在后续
状态机中把 ``LLMSearchAction`` 再转换成确定性的白名单操作。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import re
import unicodedata
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from .evidence_store import Evidence, EvidenceStore
from .opengrok_client import normalize_source_path
from .prompts import build_search_planner_prompt, build_search_planner_repair_prompt
from .target_normalizer import LocatorQuery, TargetSpec


_SCHEMA_VERSION = "openant.source-locator.llm-search-action.v1"
_RESULT_SCHEMA_VERSION = "openant.source-locator.llm-search-result.v1"
_MAX_JUSTIFICATION = 512
_MAX_RELATION = 128
_MAX_PHASE = 64
_MAX_EVIDENCE_SUMMARY = 512
_EVIDENCE_ID_RE = re.compile(r"^E-[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_LOCAL_PATH_ROOTS = frozenset(
    {
        "home",
        "library",
        "opt",
        "private",
        "system",
        "users",
        "usr",
        "var",
        "volumes",
    }
)
_DANGEROUS_QUERY_CHARS = frozenset({"\x00", "\r", "\n", "`", "$", ";", "|", "&"})
_ALLOWED_PURPOSES = frozenset({"normal", "repair", "recovery"})

ALLOWED_ACTION_KINDS = frozenset(
    {
        "search_full",
        "search_definition",
        "search_symbol",
        "search_path",
        "read_file",
    }
)
FORBIDDEN_ACTION_KINDS = frozenset(
    {
        "clone",
        "checkout",
        "exec_shell",
        "read_arbitrary_local_path",
        "generate_repo_url",
        "find_business_callers",
    }
)
_SEARCH_KIND_TO_QUERY_KIND = {
    "search_full": "full",
    "search_definition": "definition",
    "search_symbol": "symbol",
    "search_path": "path",
}
_ACTION_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "query",
        "justification",
        "expected_relation",
        "purpose",
        "evidence_used",
    }
)
_STATUSES = frozenset({"READY", "REPEATED", "PARTIAL", "NEEDS_REVIEW"})


class LLMSearchPlannerError(ValueError):
    """Raised when a planner input violates its typed contract."""


def _clean_text(value: Any, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise LLMSearchPlannerError(f"{name} 必须是字符串")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized and not allow_empty:
        raise LLMSearchPlannerError(f"{name} 不能为空")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized):
        raise LLMSearchPlannerError(f"{name} 包含控制字符")
    if len(normalized) > limit:
        raise LLMSearchPlannerError(f"{name} 超过长度上限 {limit}")
    return normalized


def _validate_evidence_id(value: Any) -> str:
    if not isinstance(value, str) or not _EVIDENCE_ID_RE.fullmatch(value.strip()):
        raise LLMSearchPlannerError("evidence_used 只能包含格式正确的 evidence_id")
    return value.strip()


def _is_local_path(path: str) -> bool:
    first = path.lstrip("/").split("/", 1)[0].lower()
    return first in _LOCAL_PATH_ROOTS or path.startswith("~")


def _validate_search_query(value: Any, *, max_length: int, path_query: bool = False) -> str:
    query = _clean_text(value, name="query", limit=max_length)
    if any(char in query for char in _DANGEROUS_QUERY_CHARS):
        raise LLMSearchPlannerError("query 包含命令或控制字符")
    try:
        parsed = urlsplit(query)
    except ValueError as exc:
        raise LLMSearchPlannerError("query 不是合法的源码检索词") from exc
    if parsed.scheme or parsed.netloc or "?" in query or "#" in query:
        raise LLMSearchPlannerError("query 不能是 URL、查询串或片段")
    if "\\" in query or any(part == ".." for part in query.split("/")):
        raise LLMSearchPlannerError("query 包含路径穿越或反斜杠")
    if path_query and query.startswith("/") and _is_local_path(query):
        raise LLMSearchPlannerError("search_path 不能指向本机路径")
    return query


def _validate_read_path(value: Any, *, max_length: int) -> str:
    query = _validate_search_query(value, max_length=max_length, path_query=True)
    try:
        normalized = normalize_source_path(query)
    except (TypeError, ValueError) as exc:
        raise LLMSearchPlannerError(f"read_file 路径无效：{exc}") from exc
    if _is_local_path(normalized):
        raise LLMSearchPlannerError("read_file 只允许 OpenGrok 源路径，拒绝本机路径")
    return normalized


def _validate_context_evidence(
    evidence: EvidenceStore | Iterable[Evidence],
) -> tuple[Evidence, ...]:
    if isinstance(evidence, EvidenceStore):
        items = evidence.evidence
    else:
        if isinstance(evidence, (str, bytes)):
            raise LLMSearchPlannerError("evidence 必须是 EvidenceStore 或 Evidence 序列")
        try:
            items = tuple(evidence)
        except TypeError as exc:
            raise LLMSearchPlannerError("evidence 必须是 EvidenceStore 或 Evidence 序列") from exc
    result: list[Evidence] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Evidence):
            raise LLMSearchPlannerError("evidence 序列只能包含 Evidence")
        if item.evidence_id not in seen:
            seen.add(item.evidence_id)
            result.append(item)
    return tuple(result)


def _canonical_action_key(kind: str, query: str) -> str:
    return f"{kind}:{query}"


def _normalize_executed_action(value: Any) -> str:
    if isinstance(value, Mapping):
        kind = value.get("kind")
        query = value.get("query")
        if isinstance(kind, str) and isinstance(query, str):
            return _canonical_action_key(kind.strip(), query.strip())
    if isinstance(value, (tuple, list)) and len(value) == 2:
        kind, query = value
        if isinstance(kind, str) and isinstance(query, str):
            return _canonical_action_key(kind.strip(), query.strip())
    return _clean_text(value, name="executed_actions item", limit=768)


@dataclass(frozen=True)
class PlannerBudget:
    """一次定位 session 的硬预算；所有限制都在模型调用前检查。"""

    max_actions: int = 8
    max_query_length: int = 512
    max_evidence_ids: int = 16
    max_prompt_chars: int = 12_000
    max_repair_attempts: int = 1
    max_model_calls: int = 2

    def __post_init__(self) -> None:
        integer_fields = (
            ("max_actions", self.max_actions, 0, 128),
            ("max_query_length", self.max_query_length, 1, 4096),
            ("max_evidence_ids", self.max_evidence_ids, 1, 64),
            ("max_prompt_chars", self.max_prompt_chars, 512, 128_000),
            ("max_repair_attempts", self.max_repair_attempts, 0, 1),
            ("max_model_calls", self.max_model_calls, 0, 32),
        )
        for name, value, lower, upper in integer_fields:
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise LLMSearchPlannerError(f"{name} 必须是 {lower} 到 {upper} 之间的整数")


@dataclass(frozen=True)
class LLMSearchPlannerContext:
    """提供给规划器的最小、可审计上下文。

    ``evidence`` 可以是 :class:`EvidenceStore` 或 Evidence 序列。为了支持从
    持久化事件恢复，也允许只传 ``evidence_ids``；这种情况下模型只能引用这些
    ID，不会凭空得到源码片段。
    """

    target: TargetSpec | Mapping[str, Any] | None = None
    evidence: EvidenceStore | Iterable[Evidence] = ()
    evidence_ids: tuple[str, ...] | None = None
    executed_actions: tuple[Any, ...] = ()
    client_completed: bool = False
    phase: str = "trace"
    missing_predicates: tuple[str, ...] = ()
    candidate_paths: tuple[str, ...] = ()
    last_feedback: str = ""

    def __post_init__(self) -> None:
        items = _validate_context_evidence(self.evidence)
        object.__setattr__(self, "evidence", items)
        if self.target is not None and not isinstance(self.target, (TargetSpec, Mapping)):
            raise LLMSearchPlannerError("target 必须是 TargetSpec、映射或 null")
        if not isinstance(self.client_completed, bool):
            raise LLMSearchPlannerError("client_completed 必须是布尔值")
        phase = _clean_text(self.phase, name="phase", limit=_MAX_PHASE)
        object.__setattr__(self, "phase", phase)
        if isinstance(self.missing_predicates, (str, bytes)):
            raise LLMSearchPlannerError("missing_predicates 必须是字符串序列")
        try:
            predicates = tuple(
                dict.fromkeys(
                    _clean_text(item, name="missing_predicates item", limit=128)
                    for item in self.missing_predicates
                )
            )
        except TypeError as exc:
            raise LLMSearchPlannerError("missing_predicates 必须是可迭代对象") from exc
        if len(predicates) > 32:
            raise LLMSearchPlannerError("missing_predicates 超过数量上限 32")
        object.__setattr__(self, "missing_predicates", predicates)
        if isinstance(self.candidate_paths, (str, bytes)):
            raise LLMSearchPlannerError("candidate_paths 必须是路径序列")
        try:
            paths = tuple(
                dict.fromkeys(
                    normalize_source_path(
                        _clean_text(item, name="candidate_paths item", limit=2048)
                    )
                    for item in self.candidate_paths
                )
            )
        except (TypeError, ValueError) as exc:
            raise LLMSearchPlannerError("candidate_paths 必须是安全源码路径序列") from exc
        if len(paths) > 32:
            raise LLMSearchPlannerError("candidate_paths 超过数量上限 32")
        object.__setattr__(self, "candidate_paths", paths)
        feedback = _clean_text(self.last_feedback, name="last_feedback", limit=512, allow_empty=True)
        object.__setattr__(self, "last_feedback", feedback)
        explicit_ids = self.evidence_ids
        if explicit_ids is None:
            ids = tuple(item.evidence_id for item in items)
        else:
            if isinstance(explicit_ids, (str, bytes)):
                raise LLMSearchPlannerError("evidence_ids 必须是 ID 序列")
            ids = tuple(dict.fromkeys(_validate_evidence_id(item) for item in explicit_ids))
        item_ids = {item.evidence_id for item in items}
        if item_ids and not item_ids.issubset(set(ids)):
            ids = tuple(dict.fromkeys((*ids, *(item.evidence_id for item in items))))
        object.__setattr__(self, "evidence_ids", ids)
        if isinstance(self.executed_actions, (str, bytes)):
            raise LLMSearchPlannerError("executed_actions 必须是序列")
        try:
            actions = tuple(_normalize_executed_action(item) for item in self.executed_actions)
        except TypeError as exc:
            raise LLMSearchPlannerError("executed_actions 必须是可迭代对象") from exc
        object.__setattr__(self, "executed_actions", tuple(dict.fromkeys(actions)))

    @property
    def evidence_by_id(self) -> dict[str, Evidence]:
        return {item.evidence_id: item for item in self.evidence}

    def to_prompt_dict(self, *, max_excerpt_chars: int = _MAX_EVIDENCE_SUMMARY) -> dict[str, Any]:
        if isinstance(max_excerpt_chars, bool) or not isinstance(max_excerpt_chars, int) or not 64 <= max_excerpt_chars <= 4096:
            raise LLMSearchPlannerError("max_excerpt_chars 必须是 64 到 4096 之间的整数")
        evidence_rows = []
        for item in self.evidence:
            evidence_rows.append(
                {
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "source_path": item.source_path,
                    "line_start": item.line_start,
                    "line_end": item.line_end,
                    "symbol": item.symbol,
                    "excerpt": item.excerpt[:max_excerpt_chars],
                }
            )
        target = self.target.to_dict() if isinstance(self.target, TargetSpec) else dict(self.target or {})
        return {
            "schema_version": "openant.source-locator.llm-search-context.v1",
            "phase": self.phase,
            "target": target,
            "evidence_ids": list(self.evidence_ids or ()),
            "evidence": evidence_rows,
            "executed_actions": list(self.executed_actions),
            "client_completed": self.client_completed,
            "recovery": {
                "missing_predicates": list(self.missing_predicates),
                "candidate_paths": list(self.candidate_paths),
                "last_feedback": self.last_feedback,
            },
            "policy": {
                "data_is_untrusted": True,
                "no_hidden_chain": True,
                "allowed_action_kinds": sorted(ALLOWED_ACTION_KINDS),
                "forbidden_action_kinds": sorted(FORBIDDEN_ACTION_KINDS),
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return self.to_prompt_dict()


@dataclass(frozen=True)
class LLMSearchAction:
    """一个经 schema、证据和安全路径校验后的模型动作。"""

    kind: str
    query: str
    justification: str
    expected_relation: str
    purpose: str = "normal"
    evidence_used: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise LLMSearchPlannerError("不支持的 LLM 动作 schema_version")
        kind = _clean_text(self.kind, name="kind", limit=64)
        if kind not in ALLOWED_ACTION_KINDS:
            if kind in FORBIDDEN_ACTION_KINDS:
                raise LLMSearchPlannerError(f"禁止的动作 kind：{kind}")
            raise LLMSearchPlannerError(f"不允许的动作 kind：{kind}")
        object.__setattr__(self, "kind", kind)
        if kind == "read_file":
            query = _validate_read_path(self.query, max_length=512)
        else:
            query = _validate_search_query(
                self.query,
                max_length=512,
                path_query=kind == "search_path",
            )
        object.__setattr__(self, "query", query)
        object.__setattr__(
            self,
            "justification",
            _clean_text(self.justification, name="justification", limit=_MAX_JUSTIFICATION),
        )
        relation = _clean_text(self.expected_relation, name="expected_relation", limit=_MAX_RELATION)
        if any(char in relation for char in {"\n", "\r", "\x00"}):
            raise LLMSearchPlannerError("expected_relation 不能包含换行或控制字符")
        object.__setattr__(self, "expected_relation", relation)
        purpose = _clean_text(self.purpose, name="purpose", limit=32).lower()
        if purpose not in _ALLOWED_PURPOSES:
            raise LLMSearchPlannerError("purpose 只能是 normal、repair 或 recovery")
        object.__setattr__(self, "purpose", purpose)
        if isinstance(self.evidence_used, (str, bytes)):
            raise LLMSearchPlannerError("evidence_used 必须是 ID 序列")
        try:
            evidence_ids = tuple(dict.fromkeys(_validate_evidence_id(item) for item in self.evidence_used))
        except TypeError as exc:
            raise LLMSearchPlannerError("evidence_used 必须是可迭代的 ID 序列") from exc
        if not evidence_ids:
            raise LLMSearchPlannerError("evidence_used 不能为空")
        object.__setattr__(self, "evidence_used", evidence_ids)

    @property
    def action_key(self) -> str:
        return _canonical_action_key(self.kind, self.query)

    @property
    def is_search(self) -> bool:
        return self.kind in _SEARCH_KIND_TO_QUERY_KIND

    def to_locator_query(self, *, query_id: str, file_type: str = "c") -> LocatorQuery:
        """将搜索动作转换成现有确定性 SearchPlanner 能识别的查询。"""

        if not self.is_search:
            raise LLMSearchPlannerError("read_file 动作不能转换成 LocatorQuery")
        try:
            return LocatorQuery(
                query_id=query_id,
                kind=_SEARCH_KIND_TO_QUERY_KIND[self.kind],
                value=self.query,
                file_type=file_type,
                reason=self.justification,
            )
        except (TypeError, ValueError) as exc:
            raise LLMSearchPlannerError(f"动作无法转换为 LocatorQuery：{exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "query": self.query,
            "justification": self.justification,
            "expected_relation": self.expected_relation,
            "purpose": self.purpose,
            "evidence_used": list(self.evidence_used),
        }


@dataclass(frozen=True)
class LLMSearchPlanResult:
    """一次规划尝试的可序列化结果，不包含原始响应或隐藏思维链。"""

    status: str
    action: LLMSearchAction | None = None
    reason_code: str = ""
    reason: str = ""
    repair_attempted: bool = False
    model_calls: int = 0
    remaining_actions: int = 0
    warnings: tuple[str, ...] = ()
    rejected_action_key: str = ""
    schema_version: str = _RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _RESULT_SCHEMA_VERSION:
            raise LLMSearchPlannerError("不支持的规划结果 schema_version")
        if self.status not in _STATUSES:
            raise LLMSearchPlannerError("规划结果 status 无效")
        if self.action is not None and not isinstance(self.action, LLMSearchAction):
            raise LLMSearchPlannerError("action 必须是 LLMSearchAction 或 null")
        if self.status == "READY" and self.action is None:
            raise LLMSearchPlannerError("READY 结果必须包含 action")
        if self.status != "READY" and self.action is not None:
            raise LLMSearchPlannerError("非 READY 结果不能包含 action")
        if not isinstance(self.repair_attempted, bool):
            raise LLMSearchPlannerError("repair_attempted 必须是布尔值")
        for name, value in (("model_calls", self.model_calls), ("remaining_actions", self.remaining_actions)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LLMSearchPlannerError(f"{name} 必须是非负整数")
        object.__setattr__(self, "reason", " ".join(str(self.reason).split())[:512])
        object.__setattr__(self, "reason_code", " ".join(str(self.reason_code).split())[:64])
        object.__setattr__(self, "warnings", tuple(" ".join(str(item).split())[:512] for item in self.warnings))
        object.__setattr__(self, "rejected_action_key", " ".join(str(self.rejected_action_key).split())[:768])

    @property
    def accepted(self) -> bool:
        return self.status == "READY" and self.action is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "action": self.action.to_dict() if self.action is not None else None,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "repair_attempted": self.repair_attempted,
            "model_calls": self.model_calls,
            "remaining_actions": self.remaining_actions,
            "warnings": list(self.warnings),
            "rejected_action_key": self.rejected_action_key,
        }


ModelCall = Callable[[str], Any]


class LLMSearchPlanner:
    """对 LLM 建议施加硬门禁的单步 planner。

    ``model_call`` 是一个窄接口：接收完整提示词并返回 JSON 对象或 JSON 字符串。
    真实适配器由上层注入；没有适配器时返回 PARTIAL，不会自行寻找密钥或网络。
    """

    def __init__(
        self,
        *,
        model_call: ModelCall | None = None,
        repair_call: ModelCall | None = None,
        budget: PlannerBudget | None = None,
    ) -> None:
        if model_call is not None and not callable(model_call):
            raise LLMSearchPlannerError("model_call 必须是可调用对象或 null")
        if repair_call is not None and not callable(repair_call):
            raise LLMSearchPlannerError("repair_call 必须是可调用对象或 null")
        if budget is not None and not isinstance(budget, PlannerBudget):
            raise LLMSearchPlannerError("budget 必须是 PlannerBudget 或 null")
        self.model_call = model_call
        self.repair_call = repair_call
        self.budget = budget or PlannerBudget()
        self._executed_keys: set[str] = set()
        self._actions_used = 0
        self._repair_attempts = 0
        self._model_calls = 0

    @property
    def actions_used(self) -> int:
        return self._actions_used

    @property
    def model_calls(self) -> int:
        return self._model_calls

    @property
    def repair_attempts(self) -> int:
        return self._repair_attempts

    @staticmethod
    def _prompt_context_variants(context: LLMSearchPlannerContext):
        """Yield progressively smaller, still auditable prompt projections.

        OpenGrok can return hundreds of line-backed facts and a single source
        path can itself be long.  Passing a fixed number of rows to the model
        is therefore not a real prompt-size guarantee.  Keep the evidence
        graph intact on disk, but project a prefix of the caller's already
        ranked evidence and shorten excerpts until the planner's explicit
        prompt budget can be met.  The projected ``evidence_ids`` always match
        the visible rows, so the model cannot cite an omitted fact by accident.
        """

        items = tuple(context.evidence)
        counts: list[int] = []
        for count in (len(items), 32, 16, 12, 8, 6, 4, 2, 1):
            bounded = min(len(items), count)
            if bounded and bounded not in counts:
                counts.append(bounded)
        # ``context`` normally has evidence because ``suggest`` checks it,
        # but keep this helper total for direct prompt callers and tests.
        if not counts:
            counts.append(0)
        for count in counts:
            subset = items[:count]
            projected = replace(
                context,
                evidence=subset,
                evidence_ids=tuple(item.evidence_id for item in subset),
            )
            for excerpt_chars in (512, 384, 256, 192, 128, 96, 64):
                yield projected.to_prompt_dict(max_excerpt_chars=excerpt_chars)

    def build_prompt(self, context: LLMSearchPlannerContext) -> str:
        if not isinstance(context, LLMSearchPlannerContext):
            raise LLMSearchPlannerError("context 必须是 LLMSearchPlannerContext")
        last_error: ValueError | None = None
        for payload in self._prompt_context_variants(context):
            try:
                return build_search_planner_prompt(
                    payload,
                    max_chars=self.budget.max_prompt_chars,
                )
            except ValueError as exc:
                last_error = exc
        raise LLMSearchPlannerError(str(last_error or "规划提示词长度预算不足"))

    def _build_repair_prompt(self, context: LLMSearchPlannerContext, *, validation_error: str) -> str:
        """Build a repair prompt using the same bounded projection as normal calls."""

        last_error: ValueError | None = None
        for payload in self._prompt_context_variants(context):
            try:
                return build_search_planner_repair_prompt(
                    payload,
                    validation_error=validation_error,
                    max_chars=self.budget.max_prompt_chars,
                )
            except ValueError as exc:
                last_error = exc
        raise LLMSearchPlannerError(str(last_error or "修复提示词长度预算不足"))

    def _result(
        self,
        status: str,
        *,
        action: LLMSearchAction | None = None,
        reason_code: str,
        reason: str,
        repair_attempted: bool = False,
        warnings: tuple[str, ...] = (),
        rejected_action_key: str = "",
    ) -> LLMSearchPlanResult:
        return LLMSearchPlanResult(
            status=status,
            action=action,
            reason_code=reason_code,
            reason=reason,
            repair_attempted=repair_attempted,
            model_calls=self._model_calls,
            remaining_actions=max(0, self.budget.max_actions - self._actions_used),
            warnings=warnings,
            rejected_action_key=rejected_action_key,
        )

    @staticmethod
    def _decode_response(response: Any) -> Mapping[str, Any]:
        if isinstance(response, Mapping):
            payload: Any = dict(response)
        elif isinstance(response, str):
            text = response.strip()
            if len(text) > 16_384:
                raise LLMSearchPlannerError("模型响应超过长度上限")
            if text.startswith("```") and text.endswith("```"):
                lines = text.splitlines()
                if len(lines) < 3:
                    raise LLMSearchPlannerError("代码围栏中的 JSON 不完整")
                text = "\n".join(lines[1:-1]).strip()
                if text.lower().startswith("json\n"):
                    text = text[5:]
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise LLMSearchPlannerError("模型响应不是合法 JSON 对象") from exc
        else:
            raise LLMSearchPlannerError("模型响应必须是 JSON 对象或 JSON 字符串")
        if not isinstance(payload, Mapping):
            raise LLMSearchPlannerError("模型响应顶层必须是 JSON 对象")
        if set(payload) == {"action"}:
            payload = payload["action"]
            if not isinstance(payload, Mapping):
                raise LLMSearchPlannerError("action 字段必须是 JSON 对象")
        unknown = set(payload) - _ACTION_FIELDS
        if unknown:
            raise LLMSearchPlannerError("模型响应包含未允许字段")
        return payload

    @classmethod
    def parse_action(
        cls,
        response: Any,
        *,
        context: LLMSearchPlannerContext,
        budget: PlannerBudget | None = None,
    ) -> LLMSearchAction:
        """解析并校验单个动作，但不改变 planner 状态。"""

        if not isinstance(context, LLMSearchPlannerContext):
            raise LLMSearchPlannerError("context 必须是 LLMSearchPlannerContext")
        if budget is None:
            active_budget = PlannerBudget()
        elif isinstance(budget, PlannerBudget):
            active_budget = budget
        else:
            raise LLMSearchPlannerError("budget 必须是 PlannerBudget 或 null")
        payload = cls._decode_response(response)
        try:
            kind = payload["kind"]
            query = payload["query"]
            justification = payload["justification"]
            expected_relation = payload["expected_relation"]
            purpose = payload.get("purpose", "normal")
            evidence_used = payload["evidence_used"]
        except KeyError as exc:
            raise LLMSearchPlannerError(f"动作缺少字段：{exc.args[0]}") from exc
        if kind == "find_business_callers" and context.client_completed:
            raise LLMSearchPlannerError("客户端通信层已完成，禁止继续查找业务 caller")
        action = LLMSearchAction(
            kind=kind,
            query=query,
            justification=justification,
            expected_relation=expected_relation,
            purpose=purpose,
            evidence_used=evidence_used,
            schema_version=payload.get("schema_version", _SCHEMA_VERSION),
        )
        if len(action.query) > active_budget.max_query_length:
            raise LLMSearchPlannerError("query 超过当前 planner 预算")
        if len(action.evidence_used) > active_budget.max_evidence_ids:
            raise LLMSearchPlannerError("evidence_used 超过当前 planner 预算")
        known_ids = set(context.evidence_ids or ())
        unknown_ids = [item for item in action.evidence_used if item not in known_ids]
        if unknown_ids:
            raise LLMSearchPlannerError("action 引用了上下文不存在的 evidence_id")
        return action

    def validate_response(
        self,
        response: Any,
        context: LLMSearchPlannerContext,
        *,
        repair_response: Any | None = None,
    ) -> LLMSearchPlanResult:
        """验证响应；repair_response 最多被消费一次。"""

        if not isinstance(context, LLMSearchPlannerContext):
            raise LLMSearchPlannerError("context 必须是 LLMSearchPlannerContext")
        if not context.evidence_ids:
            return self._result(
                "PARTIAL",
                reason_code="DETERMINISTIC_ONLY",
                reason="当前没有可引用的代码证据，保持固定初始查询路径",
            )
        if self._actions_used >= self.budget.max_actions:
            return self._result(
                "PARTIAL",
                reason_code="ACTION_BUDGET_EXHAUSTED",
                reason="LLM 检索动作预算已耗尽",
            )
        repair_attempted = False
        try:
            action = self.parse_action(response, context=context, budget=self.budget)
        except LLMSearchPlannerError as first_error:
            if repair_response is None or self._repair_attempts >= self.budget.max_repair_attempts:
                return self._result(
                    "NEEDS_REVIEW",
                    reason_code="SCHEMA_INVALID",
                    reason=str(first_error),
                )
            self._repair_attempts += 1
            repair_attempted = True
            try:
                action = self.parse_action(repair_response, context=context, budget=self.budget)
            except LLMSearchPlannerError as second_error:
                return self._result(
                    "NEEDS_REVIEW",
                    reason_code="SCHEMA_INVALID_AFTER_REPAIR",
                    reason=str(second_error),
                    repair_attempted=True,
                )
        if action.action_key in self._executed_keys or action.action_key in set(context.executed_actions):
            return self._result(
                "REPEATED",
                reason_code="DUPLICATE_ACTION",
                reason="该检索动作已经执行过，请选择尚未执行且能补足缺失证据的动作",
                repair_attempted=repair_attempted,
                rejected_action_key=action.action_key,
            )
        self._executed_keys.add(action.action_key)
        self._actions_used += 1
        return self._result(
            "READY",
            action=action,
            reason_code="ACTION_ACCEPTED",
            reason="动作通过 schema、证据引用、路径和预算校验",
            repair_attempted=repair_attempted,
        )

    def _invoke(self, provider: ModelCall, prompt: str) -> tuple[Any | None, str | None]:
        if self._model_calls >= self.budget.max_model_calls:
            return None, "模型调用预算已耗尽"
        self._model_calls += 1
        try:
            return provider(prompt), None
        except Exception as exc:  # 适配器边界：不让模型/网络异常打断定位状态机
            return None, "模型调用失败：" + " ".join(str(exc).split())[:256]

    def suggest(
        self,
        context: LLMSearchPlannerContext,
        *,
        model_call: ModelCall | None = None,
        repair_call: ModelCall | None = None,
    ) -> LLMSearchPlanResult:
        """调用一次模型并在需要时进行唯一一次格式修复。"""

        if not isinstance(context, LLMSearchPlannerContext):
            raise LLMSearchPlannerError("context 必须是 LLMSearchPlannerContext")
        if not context.evidence_ids:
            return self._result(
                "PARTIAL",
                reason_code="DETERMINISTIC_ONLY",
                reason="当前没有可引用的代码证据，跳过 LLM，保持固定初始查询路径",
            )
        provider = model_call or self.model_call
        if provider is None:
            return self._result(
                "PARTIAL",
                reason_code="NO_MODEL_ADAPTER",
                reason="未配置可调用的模型适配器，保留确定性检索结果",
            )
        try:
            prompt = self.build_prompt(context)
        except LLMSearchPlannerError as exc:
            return self._result(
                "NEEDS_REVIEW",
                reason_code="PROMPT_TOO_LARGE",
                reason=str(exc),
            )
        first_response, call_error = self._invoke(provider, prompt)
        if call_error is not None:
            return self._result("PARTIAL", reason_code="MODEL_UNAVAILABLE", reason=call_error)
        first_result = self.validate_response(first_response, context)
        if first_result.status != "NEEDS_REVIEW":
            return first_result
        if self._repair_attempts >= self.budget.max_repair_attempts:
            return first_result
        repair_provider = repair_call or self.repair_call or provider
        try:
            repair_prompt = self._build_repair_prompt(
                context,
                validation_error=first_result.reason,
            )
        except LLMSearchPlannerError as exc:
            return self._result("NEEDS_REVIEW", reason_code="PROMPT_TOO_LARGE", reason=str(exc))
        self._repair_attempts += 1
        repaired_response, call_error = self._invoke(repair_provider, repair_prompt)
        if call_error is not None:
            return self._result(
                "NEEDS_REVIEW",
                reason_code="SCHEMA_REPAIR_UNAVAILABLE",
                reason=call_error,
                repair_attempted=True,
            )
        repaired_result = self.validate_response(repaired_response, context, repair_response=None)
        if repaired_result.status == "NEEDS_REVIEW":
            repaired_result = replace(repaired_result, reason_code="SCHEMA_INVALID_AFTER_REPAIR")
        return replace(repaired_result, repair_attempted=True)

    def plan(
        self,
        context: LLMSearchPlannerContext,
        *,
        model_call: ModelCall | None = None,
        repair_call: ModelCall | None = None,
    ) -> LLMSearchPlanResult:
        """``suggest`` 的语义别名，便于状态机把 planner 当作一步计划器调用。"""

        return self.suggest(context, model_call=model_call, repair_call=repair_call)


__all__ = [
    "ALLOWED_ACTION_KINDS",
    "FORBIDDEN_ACTION_KINDS",
    "LLMSearchAction",
    "LLMSearchPlanResult",
    "LLMSearchPlanner",
    "LLMSearchPlannerContext",
    "LLMSearchPlannerError",
    "ModelCall",
    "PlannerBudget",
]
