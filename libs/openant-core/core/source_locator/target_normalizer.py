"""Deterministic normalization of a user's OpenHarmony service target.

This module deliberately does not call an LLM or OpenGrok.  It extracts a
small, auditable target description from natural language and produces a
bounded initial query plan.  Later stages may ask an LLM to suggest more
queries, but they must start from (and remain within) these validated values.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import unicodedata
from typing import Any, Mapping


class TargetNormalizationError(ValueError):
    """Raised when an input cannot be safely converted into a target."""


_SCHEMA_VERSION = "openant.source-locator.target.v1"
_MAX_INPUT_LENGTH = 4096
_MAX_PATH_LENGTH = 512
_MAX_QUERY_LENGTH = 512
_MAX_QUERIES = 32
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:[A-Za-z0-9._+@=-]+/)+[A-Za-z0-9._+@=-]+"
)
_ASSIGNMENT_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?"
    r"(/(?:[A-Za-z0-9._+@=-]+/)+[A-Za-z0-9._+@=-]+)"
)
_IDENTIFIER_SCAN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,127}")
_LOCAL_ROOTS = frozenset(
    {
        "applications",
        "home",
        "library",
        "opt",
        "private",
        "system",
        "users",
        "usr",
        "volumes",
    }
)
_STOPWORDS = frozenset(
    {
        "analyze",
        "analysis",
        "code",
        "find",
        "for",
        "service",
        "socket",
        "source",
        "the",
        "want",
        "with",
        "我",
        "想",
        "分析",
        "查看",
        "服务",
        "源码",
        "套接字",
    }
)


def _validate_revision(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TargetNormalizationError("target_revision 必须是非空字符串")
    value = value.strip()
    if not _REVISION_RE.fullmatch(value):
        raise TargetNormalizationError("target_revision 不是安全的 Git revision")
    if ".." in value or "//" in value or value.endswith(".") or value.endswith(".lock"):
        raise TargetNormalizationError("target_revision 包含不允许的 Git ref 片段")
    return value


def _validate_identifier(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise TargetNormalizationError(f"{name} 不是安全的标识符")
    return value


def _clean_path(value: str, *, notes: list[str]) -> str:
    if not isinstance(value, str):
        raise TargetNormalizationError("socket 路径必须是字符串")
    original = value
    value = value.strip().strip("\"'`“”‘’「」『』《》")
    value = value.rstrip("，。；：！？、,.;:!?)]}>")
    if not value.startswith("/"):
        raise TargetNormalizationError("socket 路径必须以 / 开头")
    if len(value) > _MAX_PATH_LENGTH:
        raise TargetNormalizationError(f"socket 路径过长（上限 {_MAX_PATH_LENGTH} 个字符）")
    if "\\" in value or "\x00" in value or "?" in value or "#" in value:
        raise TargetNormalizationError("socket 路径包含禁止字符")
    parts = value.split("/")
    if any(part in {".", ".."} for part in parts):
        raise TargetNormalizationError("socket 路径包含路径穿越片段")
    clean_parts = [part for part in parts if part]
    if len(clean_parts) < 2 or any(not re.fullmatch(r"[A-Za-z0-9._+@=-]+", part) for part in clean_parts):
        raise TargetNormalizationError("socket 路径包含不支持的路径组件")
    normalized = "/" + "/".join(clean_parts)
    if normalized != original.strip():
        notes.append("已去除引号、中文标点或重复斜杠")
    return normalized


def _looks_like_local_path(path: str) -> bool:
    parts = path.lstrip("/").split("/")
    first = parts[0].lower() if parts else ""
    if first in _LOCAL_ROOTS:
        return True
    if len(parts) >= 2 and first == "var" and parts[1].lower() in {"folders", "db", "log"}:
        return True
    markers = {"openant", "source_code_base", "openharmony_source_code", ".git"}
    return any(part.lower() in markers for part in parts)


def _extract_path_and_macro(text: str, notes: list[str]) -> tuple[str | None, str | None]:
    assignment = _ASSIGNMENT_RE.search(text)
    paths = _PATH_RE.findall(text)
    if not paths:
        return None, assignment.group(1) if assignment else None
    # An assignment is stronger evidence than an incidental path mentioned in
    # prose.  The last path is useful for sentences containing an example and
    # a trailing explanation, while preserving deterministic behaviour.
    raw_path = assignment.group(2) if assignment else paths[-1]
    macro = assignment.group(1) if assignment else None
    if macro:
        macro = _validate_identifier(macro, name="macro_hint")
        notes.append(f"识别到宏或常量赋值：{macro}")
    return _clean_path(raw_path, notes=notes), macro


def _extract_identifier(text: str, *, macro_hint: str | None) -> str | None:
    candidates = [
        token
        for token in _IDENTIFIER_SCAN_RE.findall(text)
        if token.lower() not in _STOPWORDS and token.lower() not in {"http", "https"}
    ]
    if macro_hint:
        return macro_hint
    if not candidates:
        return None
    # Prefer an all-caps macro-like token, then the last meaningful service
    # token.  This does not claim semantic certainty; it only seeds queries.
    for token in reversed(candidates):
        if token.isupper() and "_" in token:
            return token
    return candidates[-1]


@dataclass(frozen=True)
class TargetSpec:
    """Validated target description shared by locator stages."""

    raw_input: str
    target_type: str
    socket_path: str | None = None
    basename: str | None = None
    service_hint: str | None = None
    macro_hint: str | None = None
    target_revision: str = "unknown"
    path_components: tuple[str, ...] = ()
    normalization_notes: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.raw_input, str) or not self.raw_input:
            raise TargetNormalizationError("raw_input 不能为空")
        if self.target_type not in {"unix_socket", "service_name", "macro"}:
            raise TargetNormalizationError("target_type 不是支持的目标类型")
        if self.target_revision != "unknown":
            _validate_revision(self.target_revision)
        if self.socket_path is not None:
            _clean_path(self.socket_path, notes=[])
        for value, name in ((self.basename, "basename"), (self.service_hint, "service_hint"), (self.macro_hint, "macro_hint")):
            if value is not None:
                _validate_identifier(value, name=name)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["path_components"] = list(self.path_components)
        result["normalization_notes"] = list(self.normalization_notes)
        return result


@dataclass(frozen=True)
class LocatorQuery:
    """One bounded OpenGrok query in the initial deterministic plan."""

    query_id: str
    kind: str
    value: str
    file_type: str
    reason: str

    def __post_init__(self) -> None:
        if self.kind not in {"definition", "symbol", "path", "full"}:
            raise TargetNormalizationError("查询 kind 无效")
        if self.file_type not in {"c", "cxx"}:
            raise TargetNormalizationError("查询 file_type 只能是 c 或 cxx")
        if not self.value or len(self.value) > _MAX_QUERY_LENGTH:
            raise TargetNormalizationError("查询值为空或超出长度上限")

    @property
    def params(self) -> dict[str, str]:
        key = {"definition": "def", "symbol": "symbol", "path": "path", "full": "full"}[self.kind]
        return {key: self.value, "file_type": self.file_type}

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "kind": self.kind,
            "value": self.value,
            "file_type": self.file_type,
            "reason": self.reason,
            "params": self.params,
        }


def normalize_target(raw_input: str, *, target_revision: str | None = None) -> TargetSpec:
    """Convert a natural-language target into a validated :class:`TargetSpec`.

    A local checkout path is rejected instead of being treated as a remote
    Unix socket.  Callers that want to scan an existing checkout should keep
    using the existing direct local-path scan entry point.
    """

    if not isinstance(raw_input, str) or not raw_input.strip():
        raise TargetNormalizationError("目标描述不能为空")
    if len(raw_input) > _MAX_INPUT_LENGTH:
        raise TargetNormalizationError(f"目标描述过长（上限 {_MAX_INPUT_LENGTH} 个字符）")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw_input):
        raise TargetNormalizationError("目标描述包含控制字符")
    if re.search(r"(?:https?|file)://", raw_input, flags=re.IGNORECASE):
        raise TargetNormalizationError("目标描述不能包含 URL；请提供服务名或 Unix socket 路径")

    text = unicodedata.normalize("NFKC", raw_input).strip()
    notes: list[str] = []
    if text != raw_input.strip():
        notes.append("已进行 Unicode 全角字符和首尾空白标准化")
    socket_path, macro_hint = _extract_path_and_macro(text, notes)
    if socket_path is not None:
        if _looks_like_local_path(socket_path):
            raise TargetNormalizationError(
                "输入看起来是本地源码/工程路径，不会把它误当成远程 Unix socket；"
                "请使用直接扫描入口或提供 /dev、/run、/tmp 等服务 socket 路径"
            )
        basename = socket_path.rsplit("/", 1)[-1]
        service_hint = basename
        if macro_hint is not None:
            target_type = "unix_socket"
        else:
            target_type = "unix_socket"
        revision = "unknown" if target_revision is None else _validate_revision(target_revision)
        return TargetSpec(
            raw_input=raw_input,
            target_type=target_type,
            socket_path=socket_path,
            basename=_validate_identifier(basename, name="basename"),
            service_hint=_validate_identifier(service_hint, name="service_hint"),
            macro_hint=macro_hint,
            target_revision=revision,
            path_components=tuple(part for part in socket_path.split("/") if part),
            normalization_notes=tuple(notes),
        )

    identifier = _extract_identifier(text, macro_hint=macro_hint)
    if identifier is None:
        raise TargetNormalizationError(
            "未识别出 Unix socket 路径、服务名或宏名；示例：/dev/unix/socket/paramservice"
        )
    identifier = _validate_identifier(identifier, name="service_hint")
    target_type = "macro" if identifier.isupper() and "_" in identifier else "service_name"
    revision = "unknown" if target_revision is None else _validate_revision(target_revision)
    if target_type == "macro":
        notes.append("输入被作为宏/常量候选处理，后续需要源码证据确认其值")
    else:
        notes.append("输入被作为服务名候选处理，尚未推断其仓库归属")
    return TargetSpec(
        raw_input=raw_input,
        target_type=target_type,
        basename=identifier,
        service_hint=identifier,
        macro_hint=identifier if target_type == "macro" else None,
        target_revision=revision,
        normalization_notes=tuple(notes),
    )


def build_initial_queries(target: TargetSpec, *, max_queries: int = 12) -> tuple[LocatorQuery, ...]:
    """Build a stable, deduplicated and bounded first-pass query sequence."""

    if not isinstance(target, TargetSpec):
        raise TargetNormalizationError("target 必须是 TargetSpec")
    if isinstance(max_queries, bool) or not isinstance(max_queries, int) or not 1 <= max_queries <= _MAX_QUERIES:
        raise TargetNormalizationError(f"max_queries 必须是 1 到 {_MAX_QUERIES} 之间的整数")

    candidates: list[tuple[str, str, str, str]] = []

    def add(kind: str, value: str | None, reason: str) -> None:
        if not value:
            return
        value = value.strip()
        if not value or len(value) > _MAX_QUERY_LENGTH:
            return
        for file_type in ("c", "cxx"):
            item = (kind, value, file_type, reason)
            if item not in candidates:
                candidates.append(item)

    symbol = target.macro_hint or target.service_hint or target.basename
    if symbol:
        add("definition", symbol, "先查找服务名或宏名的定义")
        add("symbol", symbol, "再查找服务名或宏名的符号引用")
    if target.socket_path:
        add("path", target.basename, "按 socket basename 限定源码路径")
        add("full", target.socket_path, "检索完整 socket 路径及其配置/宏引用")
        add("full", target.socket_path.lstrip("/"), "去掉首斜杠后再次检索 OpenGrok 分词结果")
    elif target.service_hint:
        add("path", target.service_hint, "按服务名检索可能的实现文件")
        add("full", target.service_hint, "全文检索服务名作为兜底召回")

    queries: list[LocatorQuery] = []
    for index, (kind, value, file_type, reason) in enumerate(candidates[:max_queries], start=1):
        queries.append(
            LocatorQuery(
                query_id=f"Q-{index:04d}",
                kind=kind,
                value=value,
                file_type=file_type,
                reason=reason,
            )
        )
    return tuple(queries)


def normalize_and_plan(
    raw_input: str,
    *,
    target_revision: str | None = None,
    max_queries: int = 12,
) -> tuple[TargetSpec, tuple[LocatorQuery, ...]]:
    """Convenience function used by a future worker and deterministic tests."""

    target = normalize_target(raw_input, target_revision=target_revision)
    return target, build_initial_queries(target, max_queries=max_queries)
