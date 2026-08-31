"""持久化的 OpenHarmony source-locator 状态机。

状态机只负责顺序、用户决策和恢复，不负责调用网络或 Git。具体查询、证据
提取、Manifest 解析和 clone 由后续 worker 注入。这样可以在没有模型/网络的
测试中验证安全边界，也避免 Web 进程直接把用户输入当成命令。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from typing import Any, Iterable, Mapping

from .events import LocatorEvent, LocatorEventError, LocatorEventLog
from .opengrok_client import normalize_source_path


SESSION_SCHEMA_VERSION = "openant.source-locator.session.v1"
SESSION_FILENAME = "session.json"
_SESSION_ID_RE = re.compile(r"^loc_[A-Za-z0-9_-]{8,64}$")
_EVIDENCE_ID_RE = re.compile(r"^E-[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+~-]{0,127}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._+@=-]+(?:/[A-Za-z0-9._+@=-]+)*$")

# Detailed states are used on disk so the UI can explain which operation is in
# progress.  The shorter names in the design document correspond to these
# groups: NORMALIZE, SEARCH, TRACE, SERVER, CLIENT, RESOLVE and VERIFY.
FLOW_STATES = (
    "INTAKE",
    "NORMALIZE_TARGET",
    "PROBE_OPENGROK",
    "SEARCH_INITIAL",
    "TRACE_EVIDENCE",
    "ATTRIBUTION_SERVER",
    "LOCATE_CLIENT_COMM",
    "RESOLVE_REPOSITORIES",
    "VERIFY_EVIDENCE",
    "RECOVER_EVIDENCE",
    "AWAIT_USER_CONFIRMATION",
    "APPLY_FEEDBACK",
    "CLONE",
    "POST_CLONE_VERIFY",
    "HANDOFF",
    "DONE",
)
TERMINAL_STATES = frozenset(
    {
        "DONE",
        "PARTIAL",
        "NEEDS_REVIEW",
        "OPENGROK_UNAVAILABLE",
        "VERSION_MISMATCH",
        "CLONE_FAILED",
        "POST_CLONE_VERIFY_FAILED",
        "CANCELLED",
        "FAILED",
    }
)
ACTIVE_STATES = frozenset(FLOW_STATES) - {"DONE"}
ALL_STATES = frozenset((*FLOW_STATES, *TERMINAL_STATES))

_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "INTAKE": frozenset({"NORMALIZE_TARGET", "CANCELLED", "FAILED"}),
    "NORMALIZE_TARGET": frozenset({"PROBE_OPENGROK", "NEEDS_REVIEW", "FAILED", "CANCELLED"}),
    "PROBE_OPENGROK": frozenset({"SEARCH_INITIAL", "OPENGROK_UNAVAILABLE", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "SEARCH_INITIAL": frozenset({"TRACE_EVIDENCE", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "TRACE_EVIDENCE": frozenset({"ATTRIBUTION_SERVER", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "ATTRIBUTION_SERVER": frozenset({"LOCATE_CLIENT_COMM", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "LOCATE_CLIENT_COMM": frozenset({"RESOLVE_REPOSITORIES", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "RESOLVE_REPOSITORIES": frozenset({"VERIFY_EVIDENCE", "VERSION_MISMATCH", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "VERIFY_EVIDENCE": frozenset({"AWAIT_USER_CONFIRMATION", "RECOVER_EVIDENCE", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "RECOVER_EVIDENCE": frozenset({"TRACE_EVIDENCE", "VERIFY_EVIDENCE", "PARTIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "AWAIT_USER_CONFIRMATION": frozenset({"APPLY_FEEDBACK", "CLONE", "CANCELLED", "NEEDS_REVIEW"}),
    "APPLY_FEEDBACK": frozenset({"SEARCH_INITIAL", "NEEDS_REVIEW", "CANCELLED"}),
    "CLONE": frozenset({"POST_CLONE_VERIFY", "CLONE_FAILED", "PARTIAL", "CANCELLED"}),
    "POST_CLONE_VERIFY": frozenset({"HANDOFF", "POST_CLONE_VERIFY_FAILED", "PARTIAL", "CANCELLED"}),
    "HANDOFF": frozenset({"DONE", "FAILED", "CANCELLED"}),
}


class LocatorStateError(ValueError):
    """Raised for an illegal state transition or unsafe session data."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise LocatorStateError(f"{name} 必须是字符串")
    value = value.strip()
    if not value and not allow_empty:
        raise LocatorStateError(f"{name} 不能为空")
    if len(value) > limit:
        raise LocatorStateError(f"{name} 超过长度上限 {limit}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise LocatorStateError(f"{name} 包含控制字符")
    return value


def _session_id(value: Any) -> str:
    if not isinstance(value, str) or not _SESSION_ID_RE.fullmatch(value):
        raise LocatorStateError("session_id 不是安全标识")
    return value


def _state(value: Any) -> str:
    if not isinstance(value, str) or value not in ALL_STATES:
        raise LocatorStateError(f"不支持的 session state：{value!r}")
    return value


def _safe_tuple(value: Any, *, name: str, limit: int, pattern: re.Pattern[str] | None = None) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise LocatorStateError(f"{name} 必须是序列")
    try:
        values = tuple(value)
    except TypeError as exc:
        raise LocatorStateError(f"{name} 必须是可迭代序列") from exc
    if len(values) > limit:
        raise LocatorStateError(f"{name} 超过数量上限 {limit}")
    result: list[str] = []
    for item in values:
        normalized = _text(item, name=f"{name} item", limit=768)
        if pattern is not None and not pattern.fullmatch(normalized):
            raise LocatorStateError(f"{name} 包含不安全值")
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _safe_mapping(value: Any, *, name: str, max_bytes: int = 64 * 1024) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise LocatorStateError(f"{name} 必须是 JSON 对象或 null")
    result = dict(value)
    if any(not isinstance(key, str) or not key or len(key) > 128 for key in result):
        raise LocatorStateError(f"{name} 包含无效字段名")
    try:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise LocatorStateError(f"{name} 必须是可序列化 JSON") from exc
    if len(encoded.encode("utf-8")) > max_bytes:
        raise LocatorStateError(f"{name} 超过大小上限")
    return result


def _safe_artifacts(value: Any) -> dict[str, str]:
    raw = _safe_mapping(value or {}, name="artifacts", max_bytes=16 * 1024) or {}
    result: dict[str, str] = {}
    for key, item in raw.items():
        path = _text(key, name="artifact key", limit=512)
        if path.startswith("/") or "\\" in path or any(part in {".", ".."} for part in path.split("/")):
            raise LocatorStateError("artifact key 必须是 session 内相对路径")
        result[path] = _text(item, name="artifact value", limit=2048)
    return result


def _safe_excluded_paths(value: Any) -> tuple[str, ...]:
    """Normalize feedback paths before storing them as constraints."""

    if isinstance(value, (str, bytes)):
        raise LocatorStateError("excluded_paths 必须是路径序列")
    try:
        values = tuple(value)
    except TypeError as exc:
        raise LocatorStateError("excluded_paths 必须是可迭代序列") from exc
    if len(values) > 256:
        raise LocatorStateError("excluded_paths 超过数量上限 256")
    result: list[str] = []
    for item in values:
        try:
            normalized = normalize_source_path(_text(item, name="excluded_path", limit=2048))
        except (TypeError, ValueError) as exc:
            raise LocatorStateError("excluded_path 不是安全源码路径") from exc
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


@dataclass(frozen=True)
class LocatorSession:
    """Serializable checkpoint for a locator session."""

    session_id: str
    raw_target: str
    state: str = "INTAKE"
    target_revision: str | None = None
    target: Mapping[str, Any] | None = None
    evidence_ids: tuple[str, ...] = ()
    evidence_graph: Mapping[str, Any] | None = None
    executed_queries: tuple[str, ...] = ()
    executed_actions: tuple[str, ...] = ()
    server_attribution: Mapping[str, Any] | None = None
    client_attribution: Mapping[str, Any] | None = None
    repository_mappings: Mapping[str, Any] | None = None
    handoff: Mapping[str, Any] | None = None
    artifacts: Mapping[str, str] = field(default_factory=dict)
    excluded_paths: tuple[str, ...] = ()
    excluded_repos: tuple[str, ...] = ()
    required_role: str | None = None
    feedback_round: int = 0
    budget: Mapping[str, Any] = field(default_factory=dict)
    metrics: Mapping[str, Any] = field(default_factory=dict)
    last_error: str | None = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    schema_version: str = SESSION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _session_id(self.session_id)
        object.__setattr__(self, "raw_target", _text(self.raw_target, name="raw_target", limit=4096))
        object.__setattr__(self, "state", _state(self.state))
        if self.target_revision is not None:
            revision = _text(self.target_revision, name="target_revision", limit=128)
            if revision != "unknown" and not _REVISION_RE.fullmatch(revision):
                raise LocatorStateError("target_revision 不是安全 revision")
            object.__setattr__(self, "target_revision", revision)
        object.__setattr__(self, "target", _safe_mapping(self.target, name="target"))
        object.__setattr__(self, "evidence_ids", _safe_tuple(self.evidence_ids, name="evidence_ids", limit=4096, pattern=_EVIDENCE_ID_RE))
        object.__setattr__(self, "evidence_graph", _safe_mapping(self.evidence_graph, name="evidence_graph"))
        object.__setattr__(self, "executed_queries", _safe_tuple(self.executed_queries, name="executed_queries", limit=256))
        object.__setattr__(self, "executed_actions", _safe_tuple(self.executed_actions, name="executed_actions", limit=256))
        object.__setattr__(self, "server_attribution", _safe_mapping(self.server_attribution, name="server_attribution"))
        object.__setattr__(self, "client_attribution", _safe_mapping(self.client_attribution, name="client_attribution"))
        object.__setattr__(self, "repository_mappings", _safe_mapping(self.repository_mappings, name="repository_mappings"))
        object.__setattr__(self, "handoff", _safe_mapping(self.handoff, name="handoff"))
        object.__setattr__(self, "artifacts", _safe_artifacts(self.artifacts))
        object.__setattr__(self, "excluded_paths", _safe_excluded_paths(self.excluded_paths))
        object.__setattr__(self, "excluded_repos", _safe_tuple(self.excluded_repos, name="excluded_repos", limit=256, pattern=_PROJECT_RE))
        if self.required_role is not None:
            object.__setattr__(self, "required_role", _text(self.required_role, name="required_role", limit=64))
        if isinstance(self.feedback_round, bool) or not isinstance(self.feedback_round, int) or not 0 <= self.feedback_round <= 3:
            raise LocatorStateError("feedback_round 必须是 0 到 3 的整数")
        object.__setattr__(self, "budget", _safe_mapping(self.budget, name="budget", max_bytes=16 * 1024) or {})
        object.__setattr__(self, "metrics", _safe_mapping(self.metrics, name="metrics", max_bytes=16 * 1024) or {})
        if self.last_error is not None:
            object.__setattr__(self, "last_error", _text(self.last_error, name="last_error", limit=1024))
        object.__setattr__(self, "created_at", _text(self.created_at, name="created_at", limit=64))
        object.__setattr__(self, "updated_at", _text(self.updated_at, name="updated_at", limit=64))
        if self.schema_version != SESSION_SCHEMA_VERSION:
            raise LocatorStateError("不支持的 session schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "raw_target": self.raw_target,
            "state": self.state,
            "target_revision": self.target_revision,
            "target": dict(self.target) if self.target else None,
            "evidence_ids": list(self.evidence_ids),
            "evidence_graph": dict(self.evidence_graph) if self.evidence_graph else None,
            "executed_queries": list(self.executed_queries),
            "executed_actions": list(self.executed_actions),
            "server_attribution": dict(self.server_attribution) if self.server_attribution else None,
            "client_attribution": dict(self.client_attribution) if self.client_attribution else None,
            "repository_mappings": dict(self.repository_mappings) if self.repository_mappings else None,
            "handoff": dict(self.handoff) if self.handoff else None,
            "artifacts": dict(self.artifacts),
            "excluded_paths": list(self.excluded_paths),
            "excluded_repos": list(self.excluded_repos),
            "required_role": self.required_role,
            "feedback_round": self.feedback_round,
            "budget": dict(self.budget),
            "metrics": dict(self.metrics),
            "last_error": self.last_error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "LocatorSession":
        if not isinstance(payload, Mapping):
            raise LocatorStateError("session checkpoint 必须是 JSON 对象")
        data = dict(payload)
        if data.get("schema_version") != SESSION_SCHEMA_VERSION:
            raise LocatorStateError("不支持的 session checkpoint 版本")
        data.pop("schema_version", None)
        try:
            return cls(**data)
        except TypeError as exc:
            raise LocatorStateError("session checkpoint 字段不完整或类型错误") from exc


class LocatorSessionStore:
    """Store session checkpoints below one explicitly selected root."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        raw_root = Path(root).expanduser()
        if raw_root.exists() and raw_root.is_symlink():
            raise LocatorStateError("session root 不能是符号链接")
        self.root = raw_root.resolve(strict=False)
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.root.is_dir() or self.root.is_symlink():
            raise LocatorStateError("session root 必须是非符号链接目录")

    @staticmethod
    def _new_id() -> str:
        return "loc_" + secrets.token_urlsafe(12).replace("-", "_")

    def _validate_id(self, session_id: str) -> str:
        return _session_id(session_id)

    def session_dir(self, session_id: str) -> Path:
        safe_id = self._validate_id(session_id)
        path = self.root / safe_id
        if not _within(path, self.root):
            raise LocatorStateError("session 路径越界")
        return path

    def ensure_session_dir(self, session_id: str) -> Path:
        path = self.session_dir(session_id)
        if path.exists():
            if not path.is_dir() or path.is_symlink():
                raise LocatorStateError("session 目录冲突或是符号链接")
        else:
            path.mkdir(mode=0o700)
        return path

    def create(
        self,
        raw_target: str,
        *,
        target_revision: str | None = None,
        budget: Mapping[str, Any] | None = None,
        session_id: str | None = None,
    ) -> "SourceLocatorStateMachine":
        chosen_id = self._new_id() if session_id is None else self._validate_id(session_id)
        path = self.ensure_session_dir(chosen_id)
        if (path / SESSION_FILENAME).exists() or (path / "events.jsonl").exists():
            raise LocatorStateError("session_id 已经存在，不覆盖旧 session")
        session = LocatorSession(
            session_id=chosen_id,
            raw_target=raw_target,
            target_revision=target_revision,
            budget=budget or {},
        )
        machine = SourceLocatorStateMachine(self, session)
        machine._append_event(
            event_type="session.created",
            state=session.state,
            summary_zh="已创建源码定位 session，等待标准化目标",
        )
        self.save(session)
        return machine

    def save(self, session: LocatorSession) -> None:
        path = self.ensure_session_dir(session.session_id) / SESSION_FILENAME
        payload = json.dumps(session.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
        if len(payload) > 256 * 1024:
            raise LocatorStateError("session checkpoint 超过大小上限")
        fd, temporary = tempfile.mkstemp(prefix=".session-", suffix=".tmp", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def load(self, session_id: str) -> "SourceLocatorStateMachine":
        directory = self.session_dir(session_id)
        path = directory / SESSION_FILENAME
        if not path.exists() or path.is_symlink() or not path.is_file():
            raise LocatorStateError("session checkpoint 不存在或不是普通文件")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocatorStateError("session checkpoint 无法读取") from exc
        return SourceLocatorStateMachine(self, LocatorSession.from_dict(payload))

    def delete(self, session_id: str) -> bool:
        """删除一个明确指定的 session 目录及其定位产物。

        该方法只操作 ``session root/<validated-id>``，不会触碰项目源码仓库
        或 ``source_code_base``。根目录和 session 目录均拒绝符号链接，避免
        清理动作越出持久化边界；内部文件由 ``shutil.rmtree`` 安全移除。
        """

        path = self.session_dir(session_id)
        if not path.exists():
            raise LocatorStateError("session 不存在")
        if path.is_symlink() or not path.is_dir():
            raise LocatorStateError("session 目录不是安全的普通目录")
        resolved = path.resolve(strict=False)
        if not _within(resolved, self.root) or resolved == self.root:
            raise LocatorStateError("session 路径越界")
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise LocatorStateError(f"删除 session 失败：{exc}") from exc
        if path.exists():
            raise LocatorStateError("删除 session 后目录仍然存在")
        return True

    def events(self, session_id: str) -> LocatorEventLog:
        directory = self.session_dir(session_id)
        if not directory.exists() or not directory.is_dir():
            raise LocatorStateError("session 目录不存在")
        return LocatorEventLog(directory, session_id=self._validate_id(session_id))

    def list_sessions(self) -> tuple[LocatorSession, ...]:
        sessions: list[LocatorSession] = []
        for entry in self.root.iterdir():
            if not entry.is_dir() or entry.is_symlink() or not _SESSION_ID_RE.fullmatch(entry.name):
                continue
            try:
                sessions.append(self.load(entry.name).session)
            except LocatorStateError:
                continue
        return tuple(sorted(sessions, key=lambda item: item.updated_at, reverse=True))


def _within(child: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((str(child), str(parent))) == str(parent)
    except ValueError:
        return False


@dataclass(frozen=True)
class StageResult:
    """Output contract for one injected deterministic stage handler."""

    next_state: str
    summary_zh: str
    updates: Mapping[str, Any] = field(default_factory=dict)
    event_type: str = "state.changed"
    evidence_ids: tuple[str, ...] = ()


class SourceLocatorStateMachine:
    """Strict transition façade over one persisted :class:`LocatorSession`."""

    _UPDATE_FIELDS = frozenset(
        {
            "target_revision",
            "target",
            "evidence_ids",
            "evidence_graph",
            "executed_queries",
            "executed_actions",
            "server_attribution",
            "client_attribution",
            "repository_mappings",
            "handoff",
            "artifacts",
            "excluded_paths",
            "excluded_repos",
            "required_role",
            "feedback_round",
            "budget",
            "metrics",
            "last_error",
        }
    )

    def __init__(self, store: LocatorSessionStore, session: LocatorSession) -> None:
        if not isinstance(store, LocatorSessionStore):
            raise LocatorStateError("store 必须是 LocatorSessionStore")
        if not isinstance(session, LocatorSession):
            raise LocatorStateError("session 必须是 LocatorSession")
        self.store = store
        self.session = session

    @classmethod
    def create(
        cls,
        root: str | os.PathLike[str],
        raw_target: str,
        *,
        target_revision: str | None = None,
        budget: Mapping[str, Any] | None = None,
        session_id: str | None = None,
    ) -> "SourceLocatorStateMachine":
        return LocatorSessionStore(root).create(
            raw_target,
            target_revision=target_revision,
            budget=budget,
            session_id=session_id,
        )

    def _append_event(self, **kwargs: Any) -> LocatorEvent:
        try:
            return self.store.events(self.session.session_id).append(**kwargs)
        except LocatorStateError:
            # During creation the session directory exists but no checkpoint;
            # ``events`` itself raises only for a missing directory.  Re-raise
            # other state errors unchanged.
            raise
        except LocatorEventError as exc:
            raise LocatorStateError(str(exc)) from exc

    def _updated_session(self, *, state: str | None = None, updates: Mapping[str, Any] | None = None) -> LocatorSession:
        patch = dict(updates or {})
        unknown = set(patch) - self._UPDATE_FIELDS
        if unknown:
            raise LocatorStateError("不允许更新 session 字段：" + ", ".join(sorted(unknown)))
        if state is not None:
            patch["state"] = state
        patch["updated_at"] = _now()
        try:
            return replace(self.session, **patch)
        except TypeError as exc:
            raise LocatorStateError("session 更新字段无效") from exc

    def transition(
        self,
        next_state: str,
        *,
        summary_zh: str,
        event_type: str = "state.changed",
        updates: Mapping[str, Any] | None = None,
        evidence_ids: Iterable[str] = (),
        details: Mapping[str, Any] | None = None,
    ) -> LocatorSession:
        next_state = _state(next_state)
        if self.session.state in TERMINAL_STATES:
            raise LocatorStateError(f"终态 {self.session.state} 不允许继续转换")
        if next_state not in _ALLOWED_TRANSITIONS.get(self.session.state, frozenset()):
            raise LocatorStateError(f"非法状态转换：{self.session.state} -> {next_state}")
        candidate = self._updated_session(state=next_state, updates=updates)
        merged_details = dict(details or {})
        merged_details.setdefault("from_state", self.session.state)
        merged_details.setdefault("to_state", next_state)
        # Event first, checkpoint second.  On restart the event stream makes
        # the last attempted transition visible even if the process died while
        # replacing session.json.
        self._append_event(
            event_type=event_type,
            state=next_state,
            summary_zh=summary_zh,
            evidence_ids=tuple(evidence_ids),
            details=merged_details,
        )
        self.store.save(candidate)
        self.session = candidate
        return candidate

    def record_event(
        self,
        *,
        event_type: str,
        summary_zh: str,
        updates: Mapping[str, Any] | None = None,
        evidence_ids: Iterable[str] = (),
        details: Mapping[str, Any] | None = None,
    ) -> LocatorSession:
        """Record an action/evidence event without changing the state."""

        if self.session.state in TERMINAL_STATES:
            raise LocatorStateError(f"终态 {self.session.state} 不允许记录新事件")
        candidate = self._updated_session(updates=updates)
        self._append_event(
            event_type=event_type,
            state=self.session.state,
            summary_zh=summary_zh,
            evidence_ids=tuple(evidence_ids),
            details=details or {},
        )
        self.store.save(candidate)
        self.session = candidate
        return candidate

    def record_query(self, query_key: str, *, action_key: str | None = None) -> str:
        """Record one query once, enforcing the session query budget.

        Returns ``accepted``, ``repeated`` or ``budget_exhausted``.  A rejected
        query never reaches an external OpenGrok executor.
        """

        query = _text(query_key, name="query_key", limit=768)
        if query in self.session.executed_queries:
            self.record_event(
                event_type="action.skipped_duplicate",
                summary_zh="跳过已经执行过的重复查询",
                details={"query_key": query},
            )
            return "repeated"
        raw_limit = self.session.budget.get("max_queries", 50)
        if isinstance(raw_limit, bool) or not isinstance(raw_limit, int) or raw_limit < 0:
            raise LocatorStateError("budget.max_queries 必须是非负整数")
        if len(self.session.executed_queries) >= raw_limit:
            self.transition(
                "PARTIAL",
                summary_zh="查询预算已耗尽，暂停等待人工复核",
                event_type="budget.exhausted",
                details={"budget": "max_queries", "limit": raw_limit},
            )
            return "budget_exhausted"
        updates = {"executed_queries": (*self.session.executed_queries, query)}
        if action_key is not None:
            updates["executed_actions"] = (*self.session.executed_actions, _text(action_key, name="action_key", limit=768))
        self.record_event(
            event_type="query.accepted",
            summary_zh="已登记新的确定性检索动作",
            updates=updates,
            details={"query_key": query},
        )
        return "accepted"

    def confirm(self, *, confirmation_id: str | None = None) -> LocatorSession:
        if self.session.state != "AWAIT_USER_CONFIRMATION":
            raise LocatorStateError("只有等待用户确认时才能接受仓库候选")
        details = {"decision": "accepted"}
        if confirmation_id:
            details["confirmation_id"] = _text(confirmation_id, name="confirmation_id", limit=256)
        return self.transition("CLONE", summary_zh="用户已确认候选仓库，允许进入拉取阶段", event_type="user.confirmed", details=details)

    def reject(
        self,
        reason: str,
        *,
        excluded_paths: Iterable[str] = (),
        excluded_repos: Iterable[str] = (),
        required_role: str | None = None,
    ) -> LocatorSession:
        if self.session.state != "AWAIT_USER_CONFIRMATION":
            raise LocatorStateError("只有等待用户确认时才能拒绝候选")
        reason = _text(reason, name="拒绝理由", limit=1024)
        next_round = self.session.feedback_round + 1
        if next_round > 3:
            return self.transition(
                "NEEDS_REVIEW",
                summary_zh="用户拒绝次数超过上限，暂停人工复核",
                event_type="user.rejected.limit",
                updates={"feedback_round": 3, "last_error": "用户拒绝反馈超过 3 轮"},
                details={"reason": reason, "feedback_round": next_round},
            )
        paths = tuple(dict.fromkeys((*self.session.excluded_paths, *_safe_excluded_paths(excluded_paths))))
        repos = tuple(dict.fromkeys((*self.session.excluded_repos, *_safe_tuple(excluded_repos, name="excluded_repos", limit=256, pattern=_PROJECT_RE))))
        role = required_role if required_role is not None else self.session.required_role
        updates = {
            "feedback_round": next_round,
            "excluded_paths": paths,
            "excluded_repos": repos,
            "required_role": role,
            # Deliberately do not modify evidence_graph/evidence_ids.
            "last_error": reason,
        }
        return self.transition(
            "APPLY_FEEDBACK",
            summary_zh="已保留旧证据并登记用户拒绝约束，等待重新检索",
            event_type="user.rejected",
            updates=updates,
            details={"reason": reason, "feedback_round": next_round},
        )

    def resume_after_feedback(self) -> LocatorSession:
        if self.session.state != "APPLY_FEEDBACK":
            raise LocatorStateError("当前不是等待应用用户反馈的状态")
        return self.transition("SEARCH_INITIAL", summary_zh="已应用用户反馈，重新执行受限初始检索", event_type="feedback.applied")

    def cancel(self, *, reason: str = "用户取消定位") -> LocatorSession:
        if self.session.state in TERMINAL_STATES:
            return self.session
        return self.transition("CANCELLED", summary_zh="定位 session 已取消", event_type="session.cancelled", details={"reason": _text(reason, name="reason", limit=512)})

    def fail(self, reason: str, *, state: str = "FAILED") -> LocatorSession:
        if state not in {"FAILED", "NEEDS_REVIEW", "PARTIAL", "OPENGROK_UNAVAILABLE", "VERSION_MISMATCH", "CLONE_FAILED", "POST_CLONE_VERIFY_FAILED"}:
            raise LocatorStateError("fail state 不是允许的异常状态")
        return self.transition(state, summary_zh=_text(reason, name="reason", limit=512), event_type="session.failed", updates={"last_error": reason})


__all__ = [
    "ACTIVE_STATES",
    "ALL_STATES",
    "FLOW_STATES",
    "LocatorSession",
    "LocatorSessionStore",
    "LocatorStateError",
    "SourceLocatorStateMachine",
    "StageResult",
    "TERMINAL_STATES",
]
