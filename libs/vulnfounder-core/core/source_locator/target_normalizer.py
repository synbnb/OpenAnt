"""Deterministic normalization of a user's OpenHarmony service target.

This module deliberately does not call an LLM or OpenGrok.  It extracts a
small, auditable target description from natural language and produces a
bounded initial query plan.  Later stages may ask an LLM to suggest more
queries, but they must start from (and remain within) these validated values.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
import re
import unicodedata
from typing import Any, Mapping


class TargetNormalizationError(ValueError):
    """Raised when an input cannot be safely converted into a target."""


_SCHEMA_VERSION = "openant.source-locator.target.v2"
_MAX_INPUT_LENGTH = 4096
_MAX_PATH_LENGTH = 512
_MAX_QUERY_LENGTH = 512
_MAX_QUERIES = 32
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SERVICE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_NETWORK_PROTOCOL_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(TCP|UDP)(?![A-Za-z0-9_])")
_NETWORK_ENDPOINT_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:\[(?P<bracketed>[0-9A-Fa-f:.%]+)\]|(?P<ipv4>(?:\d{1,3}\.){3}\d{1,3}))"
    r":(?P<port>\d{1,5})(?!\d)"
)
_NETWORK_IDENTIFIER_SCAN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}")
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
        "address",
        "endpoint",
        "ipv4",
        "ipv6",
        "port",
        "tcp",
        "udp",
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
_NETWORK_STOPWORDS = _STOPWORDS | frozenset(
    {
        "af_inet",
        "af_inet6",
        "dgram",
        "domain",
        "inet",
        "stream",
        "sock_dgram",
        "sock_stream",
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


def _validate_service_identifier(value: str, *, name: str) -> str:
    """Validate a service/socket basename without weakening macro checks.

    OpenHarmony service names legitimately contain dots and hyphens (for
    example ``faultloggerd.crash.server``).  C/C++ macro names continue to use
    the stricter identifier validator above; only user-facing service/socket
    names use this grammar.
    """

    if not isinstance(value, str) or not _SERVICE_IDENTIFIER_RE.fullmatch(value):
        raise TargetNormalizationError(f"{name} 不是安全的服务标识符")
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


def _parse_network_target(
    text: str,
    *,
    raw_input: str,
    target_revision: str | None,
    notes: list[str],
) -> "TargetSpec | None":
    """Parse a TCP/UDP endpoint without falling back to a false service name.

    Before network targets were modelled explicitly, an input such as
    ``SP_daemon UDP 127.0.0.1:8283`` was reduced to a service named ``UDP``.
    Network parsing therefore runs before the ordinary identifier fallback and
    fails closed when a protocol or endpoint is present but incomplete.
    """

    protocols = [match.group(1).upper() for match in _NETWORK_PROTOCOL_RE.finditer(text)]
    endpoints = list(_NETWORK_ENDPOINT_RE.finditer(text))
    network_markers = bool(protocols or endpoints or re.search(r"(?i)\b(?:TCP|UDP)\s*/\s*(?:TCP|UDP)\b", text))
    if not network_markers:
        return None
    if len(protocols) != 1:
        raise TargetNormalizationError("网络 Socket 必须明确且只包含一个 TCP 或 UDP 协议")
    if len(endpoints) != 1:
        raise TargetNormalizationError("网络 Socket 必须包含一个 IP:端口端点，例如 UDP 127.0.0.1:8283")

    endpoint_match = endpoints[0]
    address_text = endpoint_match.group("bracketed") or endpoint_match.group("ipv4")
    try:
        # IPv6 zone identifiers are device-local metadata.  They are accepted
        # in input but removed from the canonical source-search address.
        address = ipaddress.ip_address(address_text.split("%", 1)[0])
    except ValueError as exc:
        raise TargetNormalizationError("网络 Socket 的地址不是合法 IPv4/IPv6 地址") from exc
    normalized_address = str(address)
    if normalized_address != address_text:
        notes.append("已将网络地址标准化为规范 IPv4/IPv6 文本")
    try:
        port = int(endpoint_match.group("port"))
    except (TypeError, ValueError) as exc:
        raise TargetNormalizationError("网络 Socket 端口必须是十进制整数") from exc
    if not 1 <= port <= 65535:
        raise TargetNormalizationError("网络 Socket 端口必须在 1 到 65535 之间")

    endpoint_text = endpoint_match.group(0)
    process_text = text.replace(endpoint_text, " ")
    process_text = _NETWORK_PROTOCOL_RE.sub(" ", process_text)
    process_candidates = [
        token
        for token in _NETWORK_IDENTIFIER_SCAN_RE.findall(process_text)
        if token.casefold() not in _NETWORK_STOPWORDS
        and token.casefold() not in {"tcp", "udp", "socket", "service"}
    ]
    process_hint: str | None = None
    if process_candidates:
        # Prefer tokens that look like a real process/service identifier.  A
        # single safe identifier from a natural-language sentence remains a
        # useful hint, but it is never treated as proof of repository owner.
        process_candidates.sort(
            key=lambda token: (
                not any(marker in token for marker in ("_", ".", "-")),
                not any(char.isupper() for char in token),
                token,
            )
        )
        process_hint = _validate_service_identifier(process_candidates[0], name="process_hint")

    revision = "unknown" if target_revision is None else _validate_revision(target_revision)
    endpoint_display = (
        f"[{normalized_address}]:{port}" if address.version == 6 else f"{normalized_address}:{port}"
    )
    notes.append(f"识别到 {protocols[0]} 网络 Socket 端点：{endpoint_display}")
    if process_hint:
        notes.append(f"识别到关联进程提示：{process_hint}")
    return TargetSpec(
        raw_input=raw_input,
        target_type="network_socket",
        basename=process_hint,
        service_hint=process_hint,
        process_hint=process_hint,
        transport=protocols[0],
        address=normalized_address,
        port=port,
        target_revision=revision,
        normalization_notes=tuple(notes),
    )


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
    # Network fields are appended after the original positional fields so
    # older integrations constructing TargetSpec positionally keep working.
    transport: str | None = None
    address: str | None = None
    port: int | None = None
    process_hint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.raw_input, str) or not self.raw_input:
            raise TargetNormalizationError("raw_input 不能为空")
        if self.target_type not in {"unix_socket", "network_socket", "service_name", "macro"}:
            raise TargetNormalizationError("target_type 不是支持的目标类型")
        if self.target_revision != "unknown":
            _validate_revision(self.target_revision)
        if self.socket_path is not None:
            _clean_path(self.socket_path, notes=[])
        for value, name in (
            (self.basename, "basename"),
            (self.service_hint, "service_hint"),
            (self.process_hint, "process_hint"),
        ):
            if value is not None:
                _validate_service_identifier(value, name=name)
        if self.macro_hint is not None:
            _validate_identifier(self.macro_hint, name="macro_hint")
        if self.target_type == "network_socket":
            if self.socket_path is not None or self.macro_hint is not None:
                raise TargetNormalizationError("网络 Socket 不能同时包含 Unix 路径或宏提示")
            if self.transport not in {"TCP", "UDP"}:
                raise TargetNormalizationError("网络 Socket transport 必须是 TCP 或 UDP")
            if not isinstance(self.address, str) or not self.address.strip():
                raise TargetNormalizationError("网络 Socket address 必须是非空 IP 地址")
            try:
                ipaddress.ip_address(self.address)
            except ValueError as exc:
                raise TargetNormalizationError("网络 Socket address 不是合法 IP 地址") from exc
            if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
                raise TargetNormalizationError("网络 Socket port 必须是 1 到 65535 的整数")
            if self.process_hint is not None and self.service_hint not in {None, self.process_hint}:
                raise TargetNormalizationError("process_hint 与 service_hint 不一致")
        elif any(value is not None for value in (self.transport, self.address, self.port, self.process_hint)):
            raise TargetNormalizationError("只有 network_socket 目标可以包含网络字段")

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
        if self.file_type not in {"c", "cxx", "all"}:
            raise TargetNormalizationError("查询 file_type 只能是 c、cxx 或 all")
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
        raise TargetNormalizationError("目标描述不能包含 URL；请提供服务名、Unix socket 路径或 TCP/UDP 端点")

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
            basename=_validate_service_identifier(basename, name="basename"),
            service_hint=_validate_service_identifier(service_hint, name="service_hint"),
            macro_hint=macro_hint,
            target_revision=revision,
            path_components=tuple(part for part in socket_path.split("/") if part),
            normalization_notes=tuple(notes),
        )

    network_target = _parse_network_target(
        text,
        raw_input=raw_input,
        target_revision=target_revision,
        notes=notes,
    )
    if network_target is not None:
        return network_target

    identifier = _extract_identifier(text, macro_hint=macro_hint)
    if identifier is None:
        raise TargetNormalizationError(
            "未识别出 Unix socket 路径、服务名、宏名或 TCP/UDP 端点；"
            "示例：/dev/unix/socket/paramservice 或 UDP 127.0.0.1:8283"
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

    def add(
        kind: str,
        value: str | None,
        reason: str,
        *,
        file_types: tuple[str, ...] = ("c", "cxx"),
    ) -> None:
        if not value:
            return
        value = value.strip()
        if not value or len(value) > _MAX_QUERY_LENGTH:
            return
        for file_type in file_types:
            item = (kind, value, file_type, reason)
            if item not in candidates:
                candidates.append(item)

    if target.target_type == "network_socket":
        # Network source almost never contains the observed endpoint as one
        # literal.  Keep the port and byte-order form first, then use the
        # process hint and protocol primitives to find the implementation.
        # The generic API queries are deliberately bounded and are only used
        # to obtain candidate files; trace_evidence later requires a nearby
        # target-bearing line before it promotes an API call to evidence.
        endpoint = network_endpoint(target)
        # Network implementations in OpenHarmony are split between C, C++,
        # headers and (for service registration) ``.cfg``/JSON/GN metadata.
        # Use the explicit ``all`` spelling for each semantic probe rather
        # than issuing separate C and C++ requests: it preserves the bounded
        # query budget while allowing one target to recover both a C++
        # ``SpServerSocket`` listener and its configuration/build anchors.
        # Worker-side evidence gating rejects unrelated text/API hits, so the
        # wider file set improves recall without turning every numeric match
        # into ownership evidence.
        network_file_types = ("all",)
        add(
            "full",
            str(target.port) if target.port is not None else None,
            "优先检索十进制端口常量、结构体初始化和端口比较",
            file_types=network_file_types,
        )
        if target.port is not None:
            add("full", f"htons({target.port})", "检索网络字节序端口写法", file_types=network_file_types)
        add("full", endpoint, "补充检索完整 TCP/UDP 端点文本", file_types=network_file_types)
        add("full", "sin_port", "检索 sockaddr 端口字段赋值", file_types=network_file_types)
        add(
            "full",
            "SOCK_DGRAM" if target.transport == "UDP" else "SOCK_STREAM",
            "按 TCP/UDP 传输类型检索 socket 初始化",
            file_types=network_file_types,
        )
        add(
            "full",
            "AF_INET6" if target.address and ":" in target.address else "AF_INET",
            "检索目标地址族初始化",
            file_types=network_file_types,
        )
        add(
            "full",
            "recvfrom" if target.transport == "UDP" else "accept",
            "检索网络服务端入站接收 API，供端口命中邻域追踪",
            file_types=network_file_types,
        )
        if target.process_hint:
            add("full", target.process_hint, "全文检索关联进程、服务类和线程实现", file_types=network_file_types)
        add("path", "BUILD.gn", "按文件名检索 BUILD.gn 中的可执行目标归属", file_types=("all",))
        add("path", "bundle.json", "按文件名检索 bundle 元数据中的组件归属", file_types=("all",))
        # SmartPerf and similar OpenHarmony daemons commonly hide the POSIX
        # calls behind ``SpServerSocket``/``SpThreadSocket`` wrappers.  These
        # are bounded semantic probes (not ownership facts by themselves),
        # and are especially useful when the port is kept in a header while
        # the listener/dispatcher lives in a sibling implementation file.
        add("full", "ServerSocket", "检索服务端 socket 包装类", file_types=network_file_types)
        add("full", "ThreadSocket", "检索 socket 收包线程包装类", file_types=network_file_types)
        add("full", "HandleMsg", "检索消息接收后的协议分派函数", file_types=network_file_types)
        # The endpoint may be represented by a loopback macro or an address
        # conversion call rather than the literal IPv4/IPv6 text.  Keep these
        # after the first high-value probes so the default bounded plan still
        # starts with port -> socket -> bind -> receive; normal sessions with
        # a larger budget also recover the address half of sockaddr setup.
        add("full", target.address, "检索源码中的监听地址或地址常量", file_types=network_file_types)
        if target.address in {"127.0.0.1", "::1"}:
            add("full", "INADDR_LOOPBACK", "检索回环地址宏", file_types=network_file_types)
        add("full", "inet_addr", "检索 IPv4 地址转换调用", file_types=network_file_types)
        add("full", "inet_pton", "检索 IPv4/IPv6 地址转换调用", file_types=network_file_types)
        add("full", "htonl", "检索网络字节序地址转换", file_types=network_file_types)

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

    # A literal Unix path is the most selective source identity.  Search it
    # before the basename/service symbol so a global name such as ``native``
    # cannot dominate the first bounded request window.  An explicitly
    # supplied macro assignment remains a special case: its definition is a
    # stronger clue than the path text and keeps the historical macro-first
    # ordering used by callers that entered ``PIPE_NAME=/dev/...``.
    if target.socket_path and target.macro_hint is None:
        # Keep the two source-language forms first for compatibility and fast
        # recall.  The third request deliberately drops the language filter:
        # OpenHarmony normally declares named sockets in init ``.cfg``/JSON
        # files, which are invisible to a C/C++-only OpenGrok query.
        add("full", target.socket_path, "优先检索完整 Unix socket 路径及其配置/宏引用")
        add("full", target.socket_path, "以不限制文件类型的方式补充检索完整路径配置", file_types=("all",))
        add("path", target.basename, "按 socket basename 检索配置、源码和构建元数据", file_types=("all",))
        # Punctuation-bearing init names (notably ``faultloggerd.server``)
        # can trigger an expensive OpenGrok parser path when sent as an
        # unquoted full-text term.  Quote the exact service token so the
        # search remains selective while still matching cfg/JSON/source
        # literals.  Plain identifiers retain the historical query form.
        basename_query = (
            f'"{target.basename}"'
            if re.search(r"[^A-Za-z0-9_]", target.basename)
            else target.basename
        )
        add("full", basename_query, "检索 init 配置 socket.name 和短名称监听/连接实现", file_types=("all",))
        # Init configuration is the strongest ownership anchor for a named
        # socket.  Place the exact ``socket.name`` form before broad API
        # probes so the default bounded plan can establish the module context
        # even when the full path never appears in the config file.
        add(
            "full",
            f'"name" : "{target.basename}"',
            "精确检索 init 配置中的 socket.name 声明（兼容 OpenHarmony 常见空格格式）",
            file_types=("all",),
        )
        # The exact ``name`` query above is sufficient for init configs.  A
        # repository-wide ``socket.name`` term is intentionally omitted: it
        # is a high-volume metadata query that can exhaust OpenGrok without
        # improving target binding.
        # The following bounded probes recover the common OpenHarmony chain:
        # config name -> descriptor wrapper -> BUILD.gn.  Repository-wide
        # ``bind``/``listen``/``recv`` searches are intentionally omitted;
        # they are not target-specific and can exhaust a large OpenGrok heap.
        # They are recall probes; worker-side context gating prevents generic
        # API hits from becoming ownership evidence for unrelated modules.
        add("full", "GetControlSocket", "追踪 init 创建 descriptor 的服务端获取接口", file_types=("all",))
        add("full", "ohos_executable", "追踪 BUILD.gn 中的可执行目标归属", file_types=("all",))
        add("path", "bundle.json", "按文件名追踪组件 bundle 元数据归属", file_types=("all",))
        add("full", "GetServerSocket", "追踪服务端 descriptor 获取封装", file_types=("all",))
        add("full", "SocketDevice", "追踪设备式 Unix socket 注册/打开封装", file_types=("all",))
    else:
        symbol = target.macro_hint or target.service_hint or target.basename
        if symbol:
            add("definition", symbol, "先查找服务名或宏名的定义")
            add("symbol", symbol, "再查找服务名或宏名的符号引用")
    if target.socket_path and target.macro_hint is not None:
        add("path", target.basename, "按 socket basename 限定源码路径", file_types=("all",))
        add("full", target.socket_path, "检索完整 socket 路径及其配置/宏引用", file_types=("all",))
        add("full", target.socket_path.lstrip("/"), "去掉首斜杠后再次检索 OpenGrok 分词结果", file_types=("all",))
        # A listener often uses the short init name (for example
        # ``GetControlSocket(\"fwmarkd\")``) rather than the full Unix path.
        # Keep a bounded basename full-text query in both C and C++ so that
        # server implementations are reachable even when the path is only in
        # a client header.
        macro_basename_query = (
            f'"{target.basename}"'
            if re.search(r"[^A-Za-z0-9_]", target.basename)
            else target.basename
        )
        add("full", macro_basename_query, "按 socket basename 全文检索短名称监听/连接实现", file_types=("all",))
        add("full", "GetControlSocket", "追踪 init 创建 descriptor 的服务端获取接口", file_types=("all",))
        add("full", "GetServerSocket", "追踪服务端 descriptor 获取封装", file_types=("all",))
        add("full", "SocketDevice", "追踪设备式 Unix socket 注册/打开封装", file_types=("all",))
    elif target.service_hint:
        add("path", target.service_hint, "按服务名检索可能的实现文件")
        service_query = (
            f'"{target.service_hint}"'
            if re.search(r"[^A-Za-z0-9_]", target.service_hint)
            else target.service_hint
        )
        add("full", service_query, "全文检索服务名作为兜底召回")

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


def network_endpoint(target: TargetSpec) -> str | None:
    """Return a canonical address/port string for a network target."""

    if not isinstance(target, TargetSpec) or target.target_type != "network_socket":
        return None
    if target.address is None or target.port is None:
        return None
    try:
        address = ipaddress.ip_address(target.address)
    except ValueError:
        return None
    return f"[{address}]:{target.port}" if address.version == 6 else f"{address}:{target.port}"


def target_identity_terms(target: TargetSpec | None) -> tuple[str, ...]:
    """Return bounded, deduplicated source identity terms for all targets."""

    if target is None:
        return ()
    values: list[str | int | None] = [
        target.socket_path,
        target.basename,
        target.service_hint,
        target.macro_hint,
        target.process_hint,
    ]
    if target.target_type == "network_socket":
        # The transport label is a search constraint, not a source identity.
        # Treating ``UDP``/``TCP`` as an identity term would make almost every
        # protocol-related file look like evidence for one particular port.
        # Keep the endpoint, address, port and optional process/service name;
        # callers that need the transport already receive it on TargetSpec.
        values.extend((network_endpoint(target), target.address, target.port))
    terms: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        key = text.casefold()
        if text and key not in seen:
            seen.add(key)
            terms.append(text)
    return tuple(terms)


def target_relation(target: TargetSpec | None) -> str | None:
    """Return the stable relation label used by evidence edges and UI."""

    if target is None:
        return None
    return target.socket_path or network_endpoint(target) or target.service_hint or target.basename or target.macro_hint


def normalize_and_plan(
    raw_input: str,
    *,
    target_revision: str | None = None,
    max_queries: int = 12,
) -> tuple[TargetSpec, tuple[LocatorQuery, ...]]:
    """Convenience function used by a future worker and deterministic tests."""

    target = normalize_target(raw_input, target_revision=target_revision)
    return target, build_initial_queries(target, max_queries=max_queries)
