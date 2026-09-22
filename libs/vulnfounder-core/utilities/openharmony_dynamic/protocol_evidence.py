"""从当前路由源码中提取通用协议证据。

这里故意不维护服务名、端口或样本白名单。输入只包含当前 finding 已经
限定的源码文件，输出的是给描述符合成 Agent 使用的证据候选，而不是可直接
发送的协议契约。真正的帧、字段和守卫仍必须由源码/设备证据核验。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


_SOURCE_REF_RE = re.compile(r"^(?P<path>.+?)(?::\d+(?:-\d+)?)?$")
_UNIX_RE = re.compile(r"/dev/(?:unix/)?socket/[A-Za-z0-9_.-]+")
_ENDPOINT_RE = re.compile(r"(?:(?:127\.0\.0\.1|0\.0\.0\.0|localhost):\d{1,5})")
_PORT_RE = re.compile(r"\b(?:htons|ntohs)\s*\(\s*(\d{1,5})\s*\)")

# 名称是语义类别，不是服务类型。表达式只用于定位行，最终关系仍需 Agent
# 结合类型/注册对象/命令值核对。
_TRANSPORT_PATTERNS = (
    ("receive", re.compile(r"\b(?:recvfrom|recvmsg|recv|accept|read|readv)\s*\(")),
    ("send", re.compile(r"\b(?:sendto|sendmsg|send|write|writev)\s*\(")),
    ("bind_or_listen", re.compile(r"\b(?:bind|listen|connect|socket)\s*\(")),
)
_FRAMING_PATTERNS = (
    ("delimiter", re.compile(r"(?:SplitMsg|split|strtok|strsep|delimiter|separator)", re.I)),
    ("substring", re.compile(r"\b(?:find|substr|substring|memchr|strstr)\s*\(")),
    ("serialization", re.compile(r"\b(?:Parcel|Serialize|Deserialize|Encode|Decode|json|protobuf|TLV)\b", re.I)),
    ("literal_separator", re.compile(r"(?:\"::\"|\"\\n\"|\"\\r\\n\"|\"\\t\"|\"\|\"|\",\")")),
)
_DISPATCH_PATTERNS = (
    ("switch", re.compile(r"\bswitch\s*\(")),
    ("case", re.compile(r"\bcase\s+[^:]+:")),
    ("message_map", re.compile(r"(?:message[_ ]?map|command[_ ]?map|handler[_ ]?map|unordered_map|map<)", re.I)),
    ("callback_or_event", re.compile(r"(?:register|subscribe|callback|listener|event|dispatch|handle)", re.I)),
)
_GUARD_PATTERNS = (
    ("permission", re.compile(r"(?:permission|authorize|authorization|token|uid|gid|access[_ ]?check|Verify)", re.I)),
    ("validation", re.compile(r"(?:validate|invalid|range|length|size|bounds|saniti[sz])", re.I)),
)


@dataclass(frozen=True)
class ProtocolEvidenceItem:
    category: str
    signal: str
    path: str
    line: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "signal": self.signal,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass
class ProtocolEvidence:
    status: str = "insufficient"
    source_paths: list[str] = field(default_factory=list)
    transport: list[ProtocolEvidenceItem] = field(default_factory=list)
    endpoints: list[ProtocolEvidenceItem] = field(default_factory=list)
    framing: list[ProtocolEvidenceItem] = field(default_factory=list)
    dispatch: list[ProtocolEvidenceItem] = field(default_factory=list)
    guards: list[ProtocolEvidenceItem] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "source_paths": list(self.source_paths),
            "transport": [item.to_dict() for item in self.transport],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "framing": [item.to_dict() for item in self.framing],
            "dispatch": [item.to_dict() for item in self.dispatch],
            "guards": [item.to_dict() for item in self.guards],
            "missing_evidence": list(self.missing_evidence),
            "counts": {
                "transport": len(self.transport),
                "endpoints": len(self.endpoints),
                "framing": len(self.framing),
                "dispatch": len(self.dispatch),
                "guards": len(self.guards),
            },
        }


def _strip_source_ref(value: str) -> str:
    text = str(value or "").strip()
    match = _SOURCE_REF_RE.match(text)
    return match.group("path") if match else text


def _resolve_paths(source_paths: Iterable[str], repo_root: Path) -> list[Path]:
    resolved: list[Path] = []
    seen: set[Path] = set()
    for raw in source_paths:
        path_text = _strip_source_ref(str(raw))
        if not path_text:
            continue
        candidate = Path(path_text)
        if not candidate.is_absolute():
            candidate = repo_root / candidate
        try:
            candidate = candidate.resolve()
        except OSError:
            continue
        if not candidate.is_file() or candidate in seen:
            continue
        try:
            candidate.relative_to(repo_root.resolve())
        except ValueError:
            # 当前 bundle 只能读取仓库内证据；外部文件不被偷偷纳入。
            continue
        seen.add(candidate)
        resolved.append(candidate)
    return resolved[:16]


def _item(category: str, signal: str, path: Path, repo_root: Path, line_no: int, line: str) -> ProtocolEvidenceItem:
    try:
        rel = path.relative_to(repo_root).as_posix()
    except ValueError:
        rel = str(path)
    snippet = " ".join(line.strip().split())[:400]
    return ProtocolEvidenceItem(category=category, signal=signal, path=rel, line=line_no, snippet=snippet)


def _append_unique(target: list[ProtocolEvidenceItem], item: ProtocolEvidenceItem, seen: set[tuple[str, str, str, int]]) -> None:
    key = (item.category, item.signal, item.path, item.line)
    if key not in seen:
        seen.add(key)
        target.append(item)


def infer_protocol_evidence(
    source_paths: Iterable[str], *, repo_root: str | Path, route_context: dict[str, Any] | None = None,
) -> ProtocolEvidence:
    """读取当前 route bundle，提取协议结构候选及缺口。

    ``route_context`` 只用于把 handler/sink 文本作为审计元数据保存；不会扩大
    读取范围，也不会把函数名直接当作入口证据。
    """
    root = Path(repo_root).resolve()
    paths = _resolve_paths(source_paths, root)
    result = ProtocolEvidence(source_paths=[p.relative_to(root).as_posix() for p in paths])
    seen: dict[str, set[tuple[str, str, str, int]]] = {
        key: set() for key in ("transport", "endpoints", "framing", "dispatch", "guards")
    }
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for signal, pattern in _TRANSPORT_PATTERNS:
                if pattern.search(line):
                    _append_unique(result.transport, _item("transport", signal, path, root, line_no, line), seen["transport"])
            for match in _UNIX_RE.finditer(line):
                _append_unique(result.endpoints, _item("endpoint", match.group(0), path, root, line_no, line), seen["endpoints"])
            for match in _ENDPOINT_RE.finditer(line):
                _append_unique(result.endpoints, _item("endpoint", match.group(0), path, root, line_no, line), seen["endpoints"])
            for match in _PORT_RE.finditer(line):
                _append_unique(result.endpoints, _item("port_literal", match.group(1), path, root, line_no, line), seen["endpoints"])
            for signal, pattern in _FRAMING_PATTERNS:
                if pattern.search(line):
                    _append_unique(result.framing, _item("framing", signal, path, root, line_no, line), seen["framing"])
            for signal, pattern in _DISPATCH_PATTERNS:
                if pattern.search(line):
                    _append_unique(result.dispatch, _item("dispatch", signal, path, root, line_no, line), seen["dispatch"])
            for signal, pattern in _GUARD_PATTERNS:
                if pattern.search(line):
                    _append_unique(result.guards, _item("guard", signal, path, root, line_no, line), seen["guards"])

    if not result.transport:
        result.missing_evidence.append("未找到接收/发送/绑定调用证据")
    if not result.endpoints:
        result.missing_evidence.append("未找到端点、Unix socket 名称或端口常量")
    if not result.framing:
        result.missing_evidence.append("未找到分帧、字段分隔或序列化线索")
    if not result.dispatch:
        result.missing_evidence.append("未找到命令/消息/回调分派线索")
    result.status = "complete" if not result.missing_evidence else "partial"
    return result


__all__ = ["ProtocolEvidence", "ProtocolEvidenceItem", "infer_protocol_evidence"]
