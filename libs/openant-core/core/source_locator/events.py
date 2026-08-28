"""Source-locator session events and append-only persistence.

事件是 Web/SSE、CLI worker 和恢复逻辑共享的最小审计单位。事件只保存动作
摘要、状态、artifact 引用和 evidence ID，不保存模型原文、思维链、源码全文或
凭据。写入采用追加 + flush + fsync；checkpoint 由 :mod:`state_machine` 以
临时文件 + ``os.replace`` 写入。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping


EVENT_SCHEMA_VERSION = "openant.source-locator.event.v1"
EVENTS_FILENAME = "events.jsonl"
MAX_EVENT_BYTES = 64 * 1024
_SESSION_ID_RE = re.compile(r"^loc_[A-Za-z0-9_-]{8,64}$")
_EVIDENCE_ID_RE = re.compile(r"^E-[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_STATE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class LocatorEventError(ValueError):
    """Raised when an event is malformed or cannot be persisted safely."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise LocatorEventError(f"{name} 必须是字符串")
    normalized = " ".join(value.split())
    if not normalized and not allow_empty:
        raise LocatorEventError(f"{name} 不能为空")
    if len(normalized) > limit:
        raise LocatorEventError(f"{name} 超过长度上限 {limit}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value if char not in {"\n", "\t"}):
        raise LocatorEventError(f"{name} 包含控制字符")
    return normalized


def _session_id(value: Any) -> str:
    if not isinstance(value, str) or not _SESSION_ID_RE.fullmatch(value):
        raise LocatorEventError("session_id 不是安全的定位 session 标识")
    return value


def _state(value: Any) -> str:
    if not isinstance(value, str) or not _STATE_RE.fullmatch(value):
        raise LocatorEventError("event state 不是安全的状态名")
    return value


def _artifact(value: Any) -> str | None:
    if value is None:
        return None
    result = _text(value, name="artifact", limit=512)
    if result.startswith("/") or "\\" in result or "\x00" in result:
        raise LocatorEventError("artifact 必须是 session 内的相对路径")
    parts = [part for part in result.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        raise LocatorEventError("artifact 包含路径穿越片段")
    return "/".join(parts)


def _details(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise LocatorEventError("details 必须是 JSON 对象")
    result = dict(value)
    try:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise LocatorEventError("details 必须是可序列化的 JSON 数据") from exc
    if len(encoded.encode("utf-8")) > 16 * 1024:
        raise LocatorEventError("details 超过 16 KiB 上限")
    return result


@dataclass(frozen=True)
class LocatorEvent:
    """One append-only, safe-to-display locator event."""

    seq: int
    session_id: str
    type: str
    state: str
    summary_zh: str
    artifact: str | None = None
    evidence_ids: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 1:
            raise LocatorEventError("seq 必须是正整数")
        _session_id(self.session_id)
        if not isinstance(self.type, str) or not _TYPE_RE.fullmatch(self.type):
            raise LocatorEventError("event type 不是安全的事件类型")
        _state(self.state)
        object.__setattr__(self, "summary_zh", _text(self.summary_zh, name="summary_zh", limit=512))
        object.__setattr__(self, "artifact", _artifact(self.artifact))
        if isinstance(self.evidence_ids, (str, bytes)):
            raise LocatorEventError("evidence_ids 必须是 ID 序列")
        try:
            ids = tuple(dict.fromkeys(self.evidence_ids))
        except TypeError as exc:
            raise LocatorEventError("evidence_ids 必须是可迭代序列") from exc
        if len(ids) > 256 or any(not isinstance(item, str) or not _EVIDENCE_ID_RE.fullmatch(item) for item in ids):
            raise LocatorEventError("evidence_ids 包含无效或过多的 ID")
        object.__setattr__(self, "evidence_ids", ids)
        object.__setattr__(self, "details", _details(self.details))
        object.__setattr__(self, "created_at", _text(self.created_at, name="created_at", limit=64))
        if self.schema_version != EVENT_SCHEMA_VERSION:
            raise LocatorEventError("不支持的 event schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "seq": self.seq,
            "session_id": self.session_id,
            "type": self.type,
            "state": self.state,
            "summary_zh": self.summary_zh,
            "artifact": self.artifact,
            "evidence_ids": list(self.evidence_ids),
            "details": dict(self.details),
            "created_at": self.created_at,
        }


class LocatorEventLog:
    """Append-only JSONL log for one session."""

    def __init__(self, session_dir: str | os.PathLike[str], *, session_id: str) -> None:
        self.session_dir = Path(session_dir)
        self.session_id = _session_id(session_id)
        if not self.session_dir.exists() or not self.session_dir.is_dir():
            raise LocatorEventError("session 目录不存在或不是目录")
        if self.session_dir.is_symlink():
            raise LocatorEventError("session 目录不能是符号链接")
        self.path = self.session_dir / EVENTS_FILENAME
        if self.path.exists() and self.path.is_symlink():
            raise LocatorEventError("events.jsonl 不能是符号链接")

    def load(self) -> tuple[LocatorEvent, ...]:
        if not self.path.exists():
            return ()
        if not self.path.is_file():
            raise LocatorEventError("events.jsonl 不是普通文件")
        events: list[LocatorEvent] = []
        with self.path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if len(raw_line) > MAX_EVENT_BYTES:
                    raise LocatorEventError(f"events.jsonl 第 {line_number} 行超过大小上限")
                if not raw_line.strip():
                    continue
                try:
                    payload = json.loads(raw_line.decode("utf-8"))
                    event = LocatorEvent(**payload)
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, LocatorEventError) as exc:
                    raise LocatorEventError(f"events.jsonl 第 {line_number} 行无效") from exc
                if event.session_id != self.session_id:
                    raise LocatorEventError("events.jsonl 包含其他 session 的事件")
                expected_seq = len(events) + 1
                if event.seq != expected_seq:
                    raise LocatorEventError("events.jsonl seq 不连续")
                events.append(event)
        return tuple(events)

    def append(
        self,
        *,
        event_type: str,
        state: str,
        summary_zh: str,
        artifact: str | None = None,
        evidence_ids: tuple[str, ...] = (),
        details: Mapping[str, Any] | None = None,
    ) -> LocatorEvent:
        events = self.load()
        event = LocatorEvent(
            seq=len(events) + 1,
            session_id=self.session_id,
            type=event_type,
            state=state,
            summary_zh=summary_zh,
            artifact=artifact,
            evidence_ids=evidence_ids,
            details=details or {},
        )
        encoded = (json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_EVENT_BYTES:
            raise LocatorEventError("事件超过大小上限")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        try:
            with os.fdopen(fd, "ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            # fdopen closes fd on all normal/error paths.
            raise
        return event

    def after(self, last_seq: int = 0) -> tuple[LocatorEvent, ...]:
        if isinstance(last_seq, bool) or not isinstance(last_seq, int) or last_seq < 0:
            raise LocatorEventError("last_seq 必须是非负整数")
        return tuple(event for event in self.load() if event.seq > last_seq)


__all__ = [
    "EVENT_SCHEMA_VERSION",
    "EVENTS_FILENAME",
    "LocatorEvent",
    "LocatorEventError",
    "LocatorEventLog",
]
