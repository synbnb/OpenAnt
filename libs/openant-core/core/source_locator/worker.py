"""有界的 source-locator worker。

这个模块把已经经过单元测试的 OpenGrok、证据、Manifest、归因和 Git
组件串成一个“每次只推进一个阶段”的 worker。它不接受 shell 字符串，
不让模型生成仓库 URL；模型若要参与，只能通过受限的检索规划器和证据
约束型角色复核器提供下一步查询或服务端/客户端判定。没有
OpenGrok/Manifest 配置时会明确暂停，而不是猜测远程地址。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping

from .client_locator import ClientAttributionResult, ClientLocator
from .config import GitCodeConfig, SourceLocatorConfig, load_source_locator_config
from .evidence_store import EvidenceStore
from .manifest_resolver import (
    ManifestDocument,
    ManifestResolver,
    RepositoryMapping,
    load_manifest,
)
from .llm_search_planner import (
    LLMSearchPlanner,
    LLMSearchPlannerContext,
    LLMSearchPlannerError,
)
from .llm_role_attributor import (
    LLMRoleAttributionError,
    LLMRoleAttributionResult,
    LLMRoleAttributor,
    LLMRoleDecision,
)
from .opengrok_client import (
    OpenGrokClient,
    OpenGrokError,
    OpenGrokHTTPError,
    ProbeResult,
    SearchResponse,
    SourceDocument,
    normalize_source_path,
)
from .path_classifier import classify_path, rank_paths
from .post_clone_verifier import (
    PostCloneVerificationRequest,
    PostCloneVerifier,
)
from .repository_manager import (
    RepositoryAcquisitionResult,
    RepositoryManager,
)
from .repository_versions import discover_repository_versions
from .service_attributor import (
    AttributionCandidate,
    ServerAttributionResult,
    ServiceAttributor,
    SourceLocation,
    partition_attribution_evidence,
)
from .state_machine import (
    LocatorSession,
    LocatorStateError,
    SourceLocatorStateMachine,
)
from .target_normalizer import LocatorQuery, TargetSpec, build_initial_queries, normalize_target


class SourceLocatorWorkerError(ValueError):
    """Raised when a worker stage cannot be executed safely."""


_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_MAX_PATHS = 32
_MAX_HITS_PER_PATH = 8
_TRACE_CONTEXT_LINES = 64
_MAX_STAGE_BYTES = 8 * 1024 * 1024
_MAX_EVENT_EVIDENCE_IDS = 256
_MAX_TRACE_EVIDENCE_PER_PATH = 128
_MAX_SEARCH_EVIDENCE = 1024
_MAX_SEARCH_ARTIFACT_PATHS_PER_EXECUTION = 32
_MAX_SEARCH_ARTIFACT_HITS_PER_PATH = 4
_MAX_SEARCH_LINE_CHARS = 2048
_MAX_ATTRIBUTION_CANDIDATES = 64
_MAX_ATTRIBUTION_EVIDENCE_IDS = 256
_MAX_CONFIRMATION_ROLES = 8
_MAX_CONFIRMATION_EVIDENCE = 12
_MAX_CONFIRMATION_LOCATIONS = 3
_MAX_CONFIRMATION_REASONS = 3
_MAX_CONFIRMATION_TEXT = 512
_MAX_LLM_CONTEXT_EVIDENCE = 64
_MAX_LLM_EVENT_EVIDENCE_IDS = 64
_MAX_LLM_EVENT_PATHS = 16
_MAX_LLM_EVENT_HITS_PER_PATH = 3
_MAX_LLM_EVENT_LINE_CHARS = 320
_REQUIRED_SERVER_PREDICATES = (
    "socket_identity",
    "socket_acquire_or_bind",
    "server_consumer",
    "manifest_mapping",
)
_NON_TRACE_ROLES = frozenset(
    {
        "test",
        "fuzz",
    }
)
_SOCKET_WORD_RE = re.compile(r"(?i)(?:socket|sock|pipe|endpoint|service)")
_MACRO_DEFINITION_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b(?:\s+(.*))?$")
_CONSTANT_DEFINITION_RE = re.compile(
    r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\s*(?:=|\{)"
)
_MACRO_NAME_RE = re.compile(
    r"^(?=[A-Z0-9_]{3,128}$)[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"
)
_LLM_EVIDENCE_KINDS = frozenset(
    {
        "literal_match",
        "macro_definition",
        "constant_definition",
        "symbol_reference",
        "service_config",
        "socket_server_registration",
        "executable_build",
        "socket_acquire",
        "socket_bind_listen",
        "socket_accept_read",
        "protocol_dispatch",
        "client_endpoint",
        "client_connect",
        "protocol_construction",
        "client_send",
    }
)


@dataclass(frozen=True)
class SourceLocatorRuntime:
    """外部依赖由调用者注入，便于离线测试和后续 Web worker 托管。"""

    client: OpenGrokClient | Any | None = None
    manifest: ManifestDocument | None = None
    project_root: str | os.PathLike[str] | None = None
    gitcode: GitCodeConfig = GitCodeConfig()
    target_revision: str | None = None
    max_paths: int = _MAX_PATHS
    max_source_bytes: int = 32 * 1024
    # Optional, caller-injected semantic planner.  The default remains None so
    # a locator run never discovers credentials or makes an implicit LLM call.
    llm_planner: LLMSearchPlanner | None = None
    # Optional role adjudicator.  It is deliberately separate from the search
    # planner so existing deterministic/search-only callers do not gain an
    # unexpected extra model call.  The CLI wires it only when --llm-search is
    # explicitly enabled.
    llm_role_attributor: LLMRoleAttributor | None = None
    # Optional fixed Git command adapter.  Production leaves this unset so
    # the manager uses its non-shell runner; tests and offline callers can
    # inject a deterministic adapter without touching the network.
    git_runner: Any | None = None

    def __post_init__(self) -> None:
        if self.client is not None and not callable(getattr(self.client, "search", None)):
            raise SourceLocatorWorkerError("runtime.client 必须提供 search 方法")
        if self.manifest is not None and not isinstance(self.manifest, ManifestDocument):
            raise SourceLocatorWorkerError("runtime.manifest 必须是 ManifestDocument 或 null")
        if not isinstance(self.gitcode, GitCodeConfig):
            raise SourceLocatorWorkerError("runtime.gitcode 必须是 GitCodeConfig")
        if self.llm_planner is not None and not isinstance(self.llm_planner, LLMSearchPlanner):
            raise SourceLocatorWorkerError("runtime.llm_planner 必须是 LLMSearchPlanner 或 null")
        if self.llm_role_attributor is not None and not isinstance(self.llm_role_attributor, LLMRoleAttributor):
            raise SourceLocatorWorkerError("runtime.llm_role_attributor 必须是 LLMRoleAttributor 或 null")
        if self.git_runner is not None and not callable(self.git_runner):
            raise SourceLocatorWorkerError("runtime.git_runner 必须是可调用对象或 null")
        if self.project_root is not None:
            root = Path(self.project_root).expanduser()
            if root.exists() and root.is_symlink():
                raise SourceLocatorWorkerError("runtime.project_root 不能是符号链接")
        if isinstance(self.max_paths, bool) or not 1 <= self.max_paths <= _MAX_PATHS:
            raise SourceLocatorWorkerError(f"max_paths 必须是 1 到 {_MAX_PATHS} 之间的整数")
        if isinstance(self.max_source_bytes, bool) or not 1 <= self.max_source_bytes <= 16 * 1024 * 1024:
            raise SourceLocatorWorkerError("max_source_bytes 超出安全范围")


def _manifest_document_from_config(config: SourceLocatorConfig, project_root: str | os.PathLike[str] | None) -> ManifestDocument | None:
    """Load only an explicitly configured local Manifest.

    Remote Manifest fetching is intentionally not hidden inside a locator
    request.  A caller may fetch it out-of-band, review the bytes, and pass a
    local path on the next invocation.  This keeps the source locator
    deterministic and prevents a model-controlled URL from becoming a
    network/Git side effect.
    """

    manifest_config = config.manifest
    if manifest_config is None or manifest_config.path is None:
        return None
    raw_root = Path(project_root or os.getcwd()).expanduser().resolve()
    path = raw_root / manifest_config.path
    if path.is_dir():
        filename = manifest_config.manifest_file or "default.xml"
        path = path / filename
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise SourceLocatorWorkerError(f"Manifest 路径不可用：{path}")
    return load_manifest(path)


def runtime_from_config(
    config_path: str | os.PathLike[str],
    *,
    project_root: str | os.PathLike[str] | None = None,
    transport: Any = None,
    client: Any = None,
    llm_planner: LLMSearchPlanner | None = None,
    llm_role_attributor: LLMRoleAttributor | None = None,
    max_paths: int = _MAX_PATHS,
    max_source_bytes: int | None = None,
) -> SourceLocatorRuntime:
    """Build a worker runtime from one explicit, credential-safe config file."""

    try:
        config = load_source_locator_config(config_path, required=True)
        if config is None or not config.enabled:
            raise SourceLocatorWorkerError("source_locator 未启用")
        opengrok = config.require_opengrok()
        runtime_root = project_root
        manifest = _manifest_document_from_config(config, runtime_root)
        gitcode = config.gitcode or GitCodeConfig()
        built_client = opengrok.build_client(transport=transport, client=client)
        return SourceLocatorRuntime(
            client=built_client,
            manifest=manifest,
            project_root=runtime_root,
            gitcode=gitcode,
            target_revision=config.target_revision,
            max_paths=max_paths,
            max_source_bytes=(
                opengrok.max_source_bytes
                if max_source_bytes is None
                else max_source_bytes
            ),
            llm_planner=llm_planner,
            llm_role_attributor=llm_role_attributor,
        )
    except SourceLocatorWorkerError:
        raise
    except Exception as exc:
        raise SourceLocatorWorkerError(f"无法构建 source-locator runtime：{_compact(exc)}") from exc


def _compact(value: Any, limit: int = 512) -> str:
    return " ".join(str(value).split())[:limit]


def _budget_int(
    budget: Mapping[str, Any],
    key: str,
    *,
    default: int,
    maximum: int,
    minimum: int = 1,
) -> int:
    """读取 session budget；非法值采用有界默认值而不是让 worker 崩溃。"""

    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0 or minimum > maximum:
        raise SourceLocatorWorkerError("budget minimum 不合法")
    value = budget.get(key, default)
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return max(minimum, min(maximum, parsed))


def _query_key(kind: str, value: str, file_type: str) -> str:
    """Return the stable key used to deduplicate a query across worker calls."""

    return f"{kind}:{file_type}:{value}"


_SEARCH_ACTION_TO_QUERY_KIND: Mapping[str, str] = {
    "search_full": "full",
    "search_definition": "definition",
    "search_symbol": "symbol",
    "search_path": "path",
}


def _planner_action_history(actions: Iterable[str]) -> tuple[str, ...]:
    """Project deterministic query keys into the planner's action-key form.

    Persisted deterministic queries use ``kind:file_type:value`` while the
    planner deduplicates ``search_kind:value``.  Supplying both forms in its
    context lets the planner reject a semantic duplicate before consuming an
    effective-action slot, while retaining the original keys for auditability.
    """

    result: list[str] = []
    reverse = {value: key for key, value in _SEARCH_ACTION_TO_QUERY_KIND.items()}
    for raw in actions:
        if not isinstance(raw, str):
            continue
        if raw not in result:
            result.append(raw)
        prefix, separator, value = raw.partition(":")
        if separator and prefix in reverse:
            # ``value`` still contains the file type and query for the
            # deterministic form (``c:foo``).  Only emit the planner form
            # when that shape is intact.
            file_type, type_separator, query = value.partition(":")
            if type_separator and file_type in {"c", "cxx"}:
                planner_key = f"{reverse[prefix]}:{query}"
                if planner_key not in result:
                    result.append(planner_key)
    return tuple(result)


def _mapping_contains_path(path: str, mapping: RepositoryMapping) -> bool:
    """Whether an OpenGrok path belongs to one resolved Manifest project."""

    if not mapping.source_root:
        return False
    normalized = path.strip().lstrip("/")
    if normalized.lower().startswith("openharmony/"):
        normalized = normalized.split("/", 1)[1]
    if normalized.lower().startswith("ohos/"):
        normalized = normalized.split("/", 1)[1]
    root = mapping.source_root.strip("/")
    return normalized == root or normalized.startswith(root + "/")


def _excluded_source_path(path: str, excluded_paths: Iterable[str]) -> bool:
    """Apply user-provided path exclusions without broad substring matching."""

    try:
        normalized = normalize_source_path(path)
    except (TypeError, ValueError):
        return True
    for excluded in excluded_paths:
        try:
            candidate = normalize_source_path(excluded)
        except (TypeError, ValueError):
            continue
        if normalized == candidate or normalized.startswith(candidate.rstrip("/") + "/"):
            return True
    return False


def _llm_read_candidates(path: str, store: EvidenceStore, client: Any) -> tuple[str, ...]:
    """Return safe OpenGrok path spellings for one model-selected read.

    Search results in the deployed OpenGrok instance include the project name
    (``/openharmony/base/...``), while a model may naturally copy the source
    tree-relative spelling (``/base/...``).  Prefer an exact evidence-backed
    suffix match, then try the configured project prefix.  We never invent a
    path from arbitrary model text: every candidate still passed through the
    normal path validator and a prefix is used only when the client exposes a
    simple project name.
    """

    normalized = normalize_source_path(path)
    candidates: list[str] = [normalized]
    suffix_matches = sorted(
        {
            item.source_path
            for item in store.evidence
            if item.source_path != normalized
            and item.source_path.rstrip("/").endswith(normalized)
        }
    )
    if len(suffix_matches) == 1:
        candidates.append(suffix_matches[0])
    project = str(getattr(client, "project", "") or "").strip("/")
    if project and "/" not in project and not normalized.lstrip("/").startswith(project + "/"):
        candidates.append(normalize_source_path(f"/{project}{normalized}"))
    return tuple(dict.fromkeys(candidates))


def _artifact_name(name: str) -> str:
    if not isinstance(name, str) or not _ARTIFACT_NAME_RE.fullmatch(name):
        raise SourceLocatorWorkerError("artifact 名称不安全")
    if name.startswith("/") or any(part in {".", ".."} for part in name.split("/")):
        raise SourceLocatorWorkerError("artifact 路径不能穿越 session 目录")
    return name


def _within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def _safe_write(path: Path, payload: bytes) -> None:
    if len(payload) > _MAX_STAGE_BYTES:
        raise SourceLocatorWorkerError("阶段产物超过大小上限")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SourceLocatorWorkerError("阶段产物不能是符号链接")
    fd, temporary = tempfile.mkstemp(prefix=".locator-", suffix=".tmp", dir=str(path.parent))
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


def _json_write(path: Path, value: Any) -> None:
    try:
        payload = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        raise SourceLocatorWorkerError(f"阶段产物无法序列化：{exc}") from exc
    _safe_write(path, payload)


def _read_json(path: Path) -> Any:
    try:
        if path.is_symlink() or path.stat().st_size > _MAX_STAGE_BYTES:
            raise SourceLocatorWorkerError("阶段产物不存在、是符号链接或超过大小上限")
        return json.loads(path.read_text(encoding="utf-8"))
    except SourceLocatorWorkerError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceLocatorWorkerError(f"无法读取阶段产物 {path.name}：{exc}") from exc


def _target(session: LocatorSession) -> TargetSpec:
    raw = session.target
    if not isinstance(raw, Mapping):
        raise SourceLocatorWorkerError("session 尚未完成目标标准化")
    try:
        return normalize_target(
            session.raw_target,
            target_revision=session.target_revision,
        )
    except Exception as exc:
        raise SourceLocatorWorkerError(f"目标标准化结果无效：{_compact(exc)}") from exc


def _session_dir(machine: SourceLocatorStateMachine) -> Path:
    path = machine.store.session_dir(machine.session.session_id)
    if path.is_symlink() or not path.is_dir():
        raise SourceLocatorWorkerError("session 目录不是安全目录")
    return path


def _save_artifact(machine: SourceLocatorStateMachine, name: str, value: Any, description: str) -> dict[str, str]:
    safe_name = _artifact_name(name)
    path = _session_dir(machine) / safe_name
    if not _within(path.resolve(strict=False), _session_dir(machine).resolve(strict=True)):
        raise SourceLocatorWorkerError("artifact 路径越出 session 目录")
    _json_write(path, value)
    artifacts = dict(machine.session.artifacts)
    artifacts[safe_name] = _compact(description, 2048)
    return artifacts


def _save_text_artifact(machine: SourceLocatorStateMachine, name: str, text: str, description: str) -> dict[str, str]:
    safe_name = _artifact_name(name)
    path = _session_dir(machine) / safe_name
    _safe_write(path, text.encode("utf-8"))
    artifacts = dict(machine.session.artifacts)
    artifacts[safe_name] = _compact(description, 2048)
    return artifacts


def _load_evidence(machine: SourceLocatorStateMachine) -> EvidenceStore:
    path = _session_dir(machine) / "evidence.json"
    if not path.exists():
        return EvidenceStore()
    return EvidenceStore.from_dict(_read_json(path))


def _load_llm_rounds(machine: SourceLocatorStateMachine) -> list[dict[str, Any]]:
    """Load the bounded semantic-round audit from an existing checkpoint.

    Older sessions stored a single round at the top level.  Normalize that
    shape here so recovery can append rounds without replacing the original
    audit trail or changing readers that still consume ``plan``/``execution``.
    """

    path = _session_dir(machine) / "llm_search.json"
    if not path.exists():
        return []
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        return []
    rounds = payload.get("rounds")
    if isinstance(rounds, list):
        return [dict(item) for item in rounds if isinstance(item, Mapping)]
    if payload.get("plan") is not None or payload.get("context") is not None:
        return [dict(payload)]
    return []


def _save_llm_rounds(
    machine: SourceLocatorStateMachine,
    audits: Iterable[Mapping[str, Any]],
    *,
    phase: str,
) -> dict[str, str]:
    """Append semantic audits while retaining a backwards-compatible shape."""

    previous = _load_llm_rounds(machine)
    combined = [*previous, *(dict(item) for item in audits if isinstance(item, Mapping))]
    if not combined:
        return dict(machine.session.artifacts)
    first = dict(combined[0])
    first["rounds"] = combined
    first["round_count"] = len(combined)
    first["last_phase"] = phase
    return _save_artifact(
        machine,
        "llm_search.json",
        first,
        "有界语义规划器的多轮结构化动作、重复动作反馈、工具结果和恢复阶段；不保存模型原始响应或隐藏思维链。",
    )


def _line_kind(
    line: str,
    target: TargetSpec,
    *,
    query_kind: str | None = None,
    query_value: str | None = None,
) -> str:
    lower = line.lower()
    identity_terms = [
        term.lower()
        for term in (
            target.socket_path,
            target.basename,
            target.service_hint,
            target.macro_hint,
            query_value,
        )
        if term
    ]
    identity = any(term in lower for term in identity_terms)
    # OpenHarmony commonly receives an init-created descriptor through
    # GetControlSocket rather than calling bind() in the service itself.  The
    # operation is only considered relevant when the queried symbol/target is
    # present in the line (or the line is already in the bounded context
    # window), so a generic helper definition does not become a service hit.
    if re.search(r"\b(?:getcontrolsocket|getsocket|socketpair)\s*\(", lower):
        return "socket_acquire"
    if _is_server_registration_line(lower):
        return "socket_server_registration"
    if re.search(r"\b(bind|listen)\s*\(", lower):
        return "socket_bind_listen"
    if re.search(r"\b(accept|recv|recvfrom|read|readv)\s*\(", lower):
        return "socket_accept_read"
    # Besides POSIX send/write calls, OpenHarmony wrappers such as
    # PollSendData and SendVpnInterfaceFdToClient carry the same direction.
    if re.search(r"\b(?:connect|send|sendto|write|writev)\s*\(", lower) or re.search(
        r"\b\w*(?:send|write)\w*\s*\(", lower
    ):
        return "client_connect" if re.search(r"\bconnect\s*\(", lower) else "client_send"
    # Do not use a bare ``handler``/``dispatch`` substring here.  Generated
    # dependency files commonly contain names such as ``check_deps_handler``
    # and ``case`` appears in unrelated paths.  A dispatch fact needs a
    # source-level construct: an IPC entry point, a switch/case statement, or
    # a call to a function whose name explicitly contains dispatch.
    if (
        "onremoterequest" in lower
        or re.search(r"\bswitch\s*\(", lower)
        or re.search(r"\bcase\s+[^:]{1,160}:", lower)
        or re.search(r"\b\w*dispatch\w*\s*\(", lower)
    ):
        return "protocol_dispatch"
    # A service/socket assignment is a useful, source-backed ownership
    # relation (for example ``info.server = PIPE_NAME`` or an init
    # ``service_name = ...`` line).  It is deliberately narrower than a raw
    # identity hit, so a random comment containing the basename cannot satisfy
    # the server attribution predicate.
    if identity and re.search(r"\b(?:service|server|socket|endpoint)(?:[_-](?:name|path|id))?\s*[:=]", lower):
        return "service_config"
    if identity and query_kind == "definition":
        return "macro_definition" if target.macro_hint else "symbol_reference"
    if identity:
        return "literal_match"
    return "symbol_reference" if query_kind in {"definition", "symbol"} else "literal_match"


def _is_server_registration_line(line: str) -> bool:
    """Recognize generic server-registration data-flow shapes.

    OpenHarmony services often put a socket path/macro in a ``server`` or
    ``endpoint`` field and pass that structure to a project-specific factory.
    This intentionally matches naming/data-flow conventions instead of one
    repository API such as ``ParamServerCreate``.  Final attribution still
    requires independent consumer and dispatch evidence.
    """

    normalized = str(line).lower()
    field_assignment = re.search(
        r"(?:\.|->)\s*(?:server|socket|endpoint|listener|stream|pipe|address|path)"
        r"[a-z0-9_]*\s*=\s*(?!(?:null|nullptr|false|0)\b)"
        r"(?:[a-z_][a-z0-9_]*|[A-Z_][A-Z0-9_]*|\"[^\"\n]{1,256}\")",
        normalized,
    )
    factory_call = re.search(
        r"\b(?:[a-z0-9_]*(?:server|socket|listener|stream|endpoint|channel)"
        r"(?:create|init|start|open|register|setup|listen|bind)[a-z0-9_]*|"
        r"(?:create|init|start|open|register|setup|make)[a-z0-9_]*"
        r"(?:server|socket|listener|stream|endpoint|channel)[a-z0-9_]*)\s*\(",
        normalized,
    )
    return bool(field_assignment or factory_call)


def _client_kind(line: str, target: TargetSpec) -> str | None:
    lower = line.lower()
    identity_terms = [term.lower() for term in (target.socket_path, target.basename, target.service_hint, target.macro_hint) if term]
    if not any(term in lower for term in identity_terms):
        return None
    if re.search(r"\bconnect\s*\(", lower):
        return "client_connect"
    if re.search(r"\b(send|sendto|write|writev)\s*\(", lower):
        return "client_send"
    if any(token in lower for token in ("serialize", "parcel", "request", "message", "payload")):
        return "protocol_construction"
    if "endpoint" in lower or "socket" in lower or "path" in lower:
        return "client_endpoint"
    return None


def _infer_related_macros(
    result_executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
    *,
    limit: int = 8,
) -> tuple[str, ...]:
    """Infer a small set of source-defined aliases for a target.

    OpenHarmony frequently registers a socket under an init/service name while
    the implementation uses a second macro (for example
    ``DNS_SOCKET_PATH`` -> ``DNS_SOCKET_NAME``).  This helper only considers
    identifiers present in bounded OpenGrok hit lines.  A macro is accepted if
    its value contains the target identity, its name is clearly socket/service
    related, or it is adjacent to a stronger target-bearing macro in the same
    result file.  It never parses arbitrary local files or accepts model text.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 32:
        raise SourceLocatorWorkerError("macro 推断数量必须是 1 到 32 之间的整数")
    identity_terms = tuple(
        term.lower()
        for term in (target.socket_path, target.basename, target.service_hint, target.macro_hint)
        if term
    )
    candidates: list[str] = []
    # Keep path-local rows so a service macro in one header cannot make an
    # unrelated macro from another result file look relevant.
    by_path: dict[str, list[tuple[int, str, str, str]]] = {}
    for execution in result_executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        response = execution.get("response")
        if not isinstance(response, Mapping):
            continue
        results = response.get("results")
        if not isinstance(results, Mapping):
            continue
        for path, raw_hits in results.items():
            if not isinstance(path, str) or not isinstance(raw_hits, list):
                continue
            rows = by_path.setdefault(path, [])
            for hit in raw_hits:
                if not isinstance(hit, Mapping):
                    continue
                line = hit.get("line")
                if not isinstance(line, str):
                    continue
                try:
                    line_no = int(hit.get("line_number", hit.get("lineNumber", 0)))
                except (TypeError, ValueError):
                    line_no = 0
                match = _MACRO_DEFINITION_RE.match(line)
                if match is not None:
                    name = match.group(1)
                    rhs = (match.group(2) or "").strip()
                else:
                    # Some OpenHarmony headers use a static/constexpr
                    # sockaddr or string constant instead of ``#define``;
                    # e.g. ``FWMARK_SERVER_PATH = {...}``.  Capture only a
                    # clearly macro-shaped constant immediately before an
                    # assignment/initializer.
                    constant = _CONSTANT_DEFINITION_RE.search(line)
                    if constant is None:
                        continue
                    name = constant.group(1)
                    rhs = line[constant.end():].strip()
                if not _MACRO_NAME_RE.fullmatch(name):
                    continue
                rows.append((line_no, name, rhs, line.lower()))

    # First pass: direct identity-bearing definitions are strongest.
    strong_rows: list[tuple[str, int, str, str]] = []
    for path, rows in by_path.items():
        for line_no, name, rhs, line in rows:
            if any(term in line or term in rhs.lower() for term in identity_terms):
                strong_rows.append((path, line_no, name, "direct_identity"))
                if name not in candidates:
                    candidates.append(name)
    # Second pass: service/socket-shaped aliases near a strong definition.
    strong_paths = {path for path, _line_no, _name, _reason in strong_rows}
    for path, rows in by_path.items():
        if path not in strong_paths:
            continue
        strong_lines = [line_no for row_path, line_no, _name, _reason in strong_rows if row_path == path]
        for line_no, name, _rhs, _line in rows:
            if name in candidates or not any(abs(line_no - anchor) <= 4 for anchor in strong_lines):
                continue
            if _SOCKET_WORD_RE.search(name):
                candidates.append(name)
    # Third pass: a service-shaped macro can be useful even when OpenGrok
    # returned only the macro definition itself and not a neighbouring path.
    for _path, rows in by_path.items():
        for _line_no, name, _rhs, _line in rows:
            if name not in candidates and _SOCKET_WORD_RE.search(name):
                candidates.append(name)
    excluded = {
        value.upper()
        for value in (target.basename, target.service_hint, target.macro_hint)
        if value
    }
    return tuple(name for name in candidates if name.upper() not in excluded)[:limit]


def _macro_queries(
    names: Iterable[str],
    *,
    max_queries: int,
    start_index: int,
) -> tuple[Any, ...]:
    """Build deterministic, file-type-aware follow-up queries for aliases."""

    # C++ is first because OpenHarmony's service implementations commonly use
    # a C++ listener while the macro is declared in a C header.  A C query is
    # still retained for mixed C/C++ repositories.
    queries: list[Any] = []
    index = start_index
    for name in names:
        for file_type in ("cxx", "c"):
            if len(queries) >= max_queries:
                return tuple(queries)
            queries.append(
                LocatorQuery(
                    query_id=f"Q-MACRO-{index:04d}",
                    kind="full",
                    value=name,
                    file_type=file_type,
                    reason="由带目标身份的宏定义推断，继续追踪服务实现和监听调用",
                )
            )
            index += 1
    return tuple(queries)


def _evidence_for_path(store: EvidenceStore, path: str) -> tuple[str, ...]:
    return tuple(item.evidence_id for item in store.evidence if item.source_path == path)


def _compact_attribution_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Bound the UI/session copy of a potentially noisy attribution result.

    The evidence store remains complete (subject to the trace budget), while
    candidate lists are a presentation/index artifact.  Keeping a bounded
    top slice prevents generic names such as ``AppSpawn`` from exceeding the
    session's 64 KiB mapping contract or making Web responses unbounded.
    """

    payload = dict(value)
    raw_candidates = payload.get("candidates", ())
    candidates: list[dict[str, Any]] = []
    if isinstance(raw_candidates, (list, tuple)):
        for raw in raw_candidates[:_MAX_ATTRIBUTION_CANDIDATES]:
            if not isinstance(raw, Mapping):
                continue
            candidate = dict(raw)
            locations = candidate.get("source_locations")
            if isinstance(locations, list):
                candidate["source_locations"] = [dict(item) for item in locations[:8] if isinstance(item, Mapping)]
            ids = candidate.get("evidence_ids")
            if isinstance(ids, list):
                candidate["evidence_ids"] = ids[:16]
            reasons = candidate.get("reasons")
            if isinstance(reasons, list):
                candidate["reasons"] = reasons[:8]
            candidates.append(candidate)
    payload["candidates"] = candidates
    roles = payload.get("roles")
    if isinstance(roles, Mapping):
        compact_roles: dict[str, list[dict[str, Any]]] = {}
        for role, entries in roles.items():
            if not isinstance(entries, list):
                compact_roles[str(role)] = []
                continue
            compact_roles[str(role)] = [
                dict(item)
                for item in entries[:16]
                if isinstance(item, Mapping)
            ]
            for item in compact_roles[str(role)]:
                if isinstance(item.get("source_locations"), list):
                    item["source_locations"] = item["source_locations"][:8]
                if isinstance(item.get("evidence_ids"), list):
                    item["evidence_ids"] = item["evidence_ids"][:16]
                if isinstance(item.get("reasons"), list):
                    item["reasons"] = item["reasons"][:8]
        payload["roles"] = compact_roles
    evidence_ids = payload.get("evidence_ids")
    if isinstance(evidence_ids, list):
        payload["evidence_ids"] = evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]
    if isinstance(raw_candidates, (list, tuple)) and len(raw_candidates) > len(candidates):
        payload["truncated"] = True
        payload["truncated_candidate_count"] = len(raw_candidates) - len(candidates)
    return payload


def _llm_role_candidate(
    decision: LLMRoleDecision,
    store: EvidenceStore,
) -> AttributionCandidate | None:
    """Turn a validated model decision into a source-backed candidate.

    A model is never allowed to create a candidate without citing an evidence
    row that the worker already stored.  ``unresolved`` therefore produces no
    synthetic candidate, while ``possible`` remains visible with a lower
    score for human review.
    """

    if decision.status == "unresolved" or not decision.evidence_ids:
        return None
    by_id = {item.evidence_id: item for item in store.evidence}
    items = [by_id[item] for item in decision.evidence_ids if item in by_id]
    if not items:
        return None
    locations: list[SourceLocation] = []
    seen: set[tuple[str, int, int, str | None]] = set()
    for item in items:
        location = SourceLocation(item.source_path, item.line_start, item.line_end, item.symbol)
        key = (location.source_path, location.line_start, location.line_end, location.symbol)
        if key not in seen:
            seen.add(key)
            locations.append(location)
    if not locations:
        return None
    role = "service_owner" if decision.role == "server" else "client_transport"
    score = 90 if decision.status == "confirmed" else 55
    return AttributionCandidate(
        role=role,
        subject=decision.subject or ("模型确认的服务端" if decision.role == "server" else "模型确认的客户端"),
        source_locations=tuple(locations),
        evidence_ids=tuple(item.evidence_id for item in items),
        score=score,
        reasons=("LLM 语义角色判定：" + decision.reason,),
    )


def _merge_server_semantic(
    result: ServerAttributionResult,
    decision: LLMRoleDecision,
    store: EvidenceStore,
) -> ServerAttributionResult:
    """Merge an evidence-validated server decision without erasing facts."""

    predicates = dict(result.predicates)
    predicates["llm_role_validated"] = True
    predicates["llm_server_confirmed"] = decision.status == "confirmed"
    predicates["llm_server_possible"] = decision.status == "possible"
    status = result.status
    if decision.status == "confirmed":
        status = "HIGH"
    elif decision.status == "possible" and status == "UNRESOLVED":
        status = "PARTIAL"
    # An unresolved model answer does not silently downgrade deterministic
    # source evidence; it remains visible in semantic_decision/warnings.
    warnings = list(result.warnings)
    if decision.status == "possible":
        warnings.append("LLM 认为服务端角色可能成立，仍需人工复核")
    elif decision.status == "unresolved":
        warnings.append("LLM 未能确认服务端角色，保留确定性证据结果")
    candidate = _llm_role_candidate(decision, store)
    candidates = list(result.candidates)
    if candidate is not None and not any(
        set(item.evidence_ids) == set(candidate.evidence_ids) and item.role == candidate.role
        for item in candidates
    ):
        candidates.append(candidate)
    evidence_ids = tuple(dict.fromkeys((*result.evidence_ids, *decision.evidence_ids)))
    reasons = list(result.reasons)
    reasons.append("LLM 语义角色判定：" + decision.reason)
    return replace(
        result,
        status=status,
        confirmed=status == "HIGH",
        score=max(result.score, 90 if decision.status == "confirmed" else 55),
        predicates=predicates,
        candidates=tuple(candidates),
        evidence_ids=evidence_ids,
        reasons=tuple(dict.fromkeys(reasons)),
        warnings=tuple(dict.fromkeys(warnings)),
        semantic_decision=decision.to_dict(),
    )


def _merge_client_semantic(
    result: ClientAttributionResult,
    decision: LLMRoleDecision,
    store: EvidenceStore,
) -> ClientAttributionResult:
    """Merge an evidence-validated client decision without inventing callers."""

    predicates = dict(result.predicates)
    predicates["llm_role_validated"] = True
    predicates["llm_client_confirmed"] = decision.status == "confirmed"
    predicates["llm_client_possible"] = decision.status == "possible"
    status = result.status
    if decision.status == "confirmed":
        status = "HIGH"
    elif decision.status == "possible" and status == "UNRESOLVED":
        status = "PARTIAL"
    warnings = list(result.warnings)
    if decision.status == "possible":
        warnings.append("LLM 认为客户端边界可能成立，仍需人工复核")
    elif decision.status == "unresolved":
        warnings.append("LLM 未能确认客户端角色，保留确定性证据结果")
    candidate = _llm_role_candidate(decision, store)
    candidates = list(result.candidates)
    if candidate is not None and not any(
        set(item.evidence_ids) == set(candidate.evidence_ids) and item.role == candidate.role
        for item in candidates
    ):
        candidates.append(candidate)
    evidence_ids = tuple(dict.fromkeys((*result.evidence_ids, *decision.evidence_ids)))
    reasons = list(result.reasons)
    reasons.append("LLM 语义角色判定：" + decision.reason)
    return replace(
        result,
        status=status,
        completed=status == "HIGH",
        score=max(result.score, 90 if decision.status == "confirmed" else 55),
        predicates=predicates,
        candidates=tuple(candidates),
        evidence_ids=evidence_ids,
        reasons=tuple(dict.fromkeys(reasons)),
        warnings=tuple(dict.fromkeys(warnings)),
        semantic_decision=decision.to_dict(),
    )


def _load_llm_role_result(
    machine: SourceLocatorStateMachine,
    *,
    allowed_evidence_ids: Iterable[str] | None = None,
) -> LLMRoleAttributionResult | None:
    path = _session_dir(machine) / "llm_role_attribution.json"
    if not path.exists():
        return None
    try:
        payload = _read_json(path)
        if not isinstance(payload, Mapping):
            return None
        server = payload.get("server")
        client = payload.get("client")
        if not isinstance(server, Mapping) or not isinstance(client, Mapping):
            return None
        allowed = None if allowed_evidence_ids is None else set(allowed_evidence_ids)
        if allowed is not None:
            candidate_ids = tuple(
                dict.fromkeys(
                    item
                    for role_payload in (server, client)
                    for item in role_payload.get("evidence_ids", ())
                    if isinstance(item, str)
                )
            )
            if any(item not in allowed for item in candidate_ids):
                return None
        return LLMRoleAttributionResult(
            server=LLMRoleDecision(
                role="server",
                status=server.get("status"),
                confidence=server.get("confidence"),
                subject=server.get("subject", ""),
                evidence_ids=tuple(server.get("evidence_ids", ())),
                reason=server.get("reason"),
            ),
            client=LLMRoleDecision(
                role="client",
                status=client.get("status"),
                confidence=client.get("confidence"),
                subject=client.get("subject", ""),
                evidence_ids=tuple(client.get("evidence_ids", ())),
                reason=client.get("reason"),
            ),
            model_calls=int(payload.get("model_calls", 1)),
        )
    except (TypeError, ValueError, KeyError, LLMRoleAttributionError):
        return None


def _save_llm_role_result(
    machine: SourceLocatorStateMachine,
    result: LLMRoleAttributionResult,
    *,
    eligible_count: int,
    excluded_evidence_ids: Iterable[str],
) -> dict[str, str]:
    payload = result.to_dict()
    payload["eligible_evidence_count"] = eligible_count
    payload["excluded_evidence_ids"] = list(dict.fromkeys(
        item for item in excluded_evidence_ids if isinstance(item, str)
    ))[:_MAX_ATTRIBUTION_EVIDENCE_IDS]
    return _save_artifact(
        machine,
        "llm_role_attribution.json",
        payload,
        "LLM 对服务端/客户端角色的证据约束判定；只保存结构化决策和 evidence_id，不保存原始响应或隐藏思维链。",
    )


def _compact_search_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Bound OpenGrok snippets before persisting a search artifact.

    OpenGrok may return very long highlighted lines for generated or macro
    files.  The worker still uses the typed response to build evidence, but
    the checkpoint keeps a bounded copy sufficient to replay path/line
    selection and explicitly marks any omitted rows.
    """

    payload = dict(value)
    executions = payload.get("executions")
    if not isinstance(executions, list):
        return payload
    artifact_executions: list[dict[str, Any]] = []
    truncated = False
    for raw_execution in executions:
        if not isinstance(raw_execution, Mapping):
            continue
        execution = dict(raw_execution)
        response = execution.get("response")
        if not isinstance(response, Mapping):
            artifact_executions.append(execution)
            continue
        response_copy = dict(response)
        raw_results = response.get("results")
        compact_results: dict[str, list[dict[str, Any]]] = {}
        if isinstance(raw_results, Mapping):
            for path_index, (path, raw_hits) in enumerate(raw_results.items()):
                if path_index >= _MAX_SEARCH_ARTIFACT_PATHS_PER_EXECUTION:
                    truncated = True
                    break
                if not isinstance(path, str) or not isinstance(raw_hits, list):
                    continue
                compact_hits: list[dict[str, Any]] = []
                for hit_index, raw_hit in enumerate(raw_hits):
                    if hit_index >= _MAX_SEARCH_ARTIFACT_HITS_PER_PATH:
                        truncated = True
                        break
                    if not isinstance(raw_hit, Mapping):
                        continue
                    hit = dict(raw_hit)
                    for key in ("line", "raw_line"):
                        text = hit.get(key)
                        if isinstance(text, str) and len(text) > _MAX_SEARCH_LINE_CHARS:
                            hit[key] = text[:_MAX_SEARCH_LINE_CHARS] + "…"
                            truncated = True
                    compact_hits.append(hit)
                compact_results[path] = compact_hits
        response_copy["results"] = compact_results
        execution["response"] = response_copy
        artifact_executions.append(execution)
    payload["executions"] = artifact_executions
    if truncated:
        payload["truncated"] = True
        payload["truncation_note"] = "为保证 checkpoint 大小，仅保留每次查询前 32 个文件、每文件前 4 个命中和每行前 2048 个字符；evidence.json 保存已接受的有界证据。"
    return payload


def _compact_llm_audit(value: Mapping[str, Any]) -> dict[str, Any]:
    """Bound one semantic-round audit before it is copied into a checkpoint."""

    payload = dict(value)
    execution = payload.get("execution")
    if isinstance(execution, Mapping) and isinstance(execution.get("response"), Mapping):
        compact = _compact_search_payload({"executions": [dict(execution)]})
        executions = compact.get("executions")
        if isinstance(executions, list) and executions:
            payload["execution"] = executions[0]
        if compact.get("truncated"):
            payload["truncated"] = True
            payload["truncation_note"] = compact.get("truncation_note", "LLM 工具响应已做有界摘要")
    return payload


def _bounded_text(value: Any, limit: int = 512) -> str | None:
    """Return a short display-safe string, omitting null/non-text values."""

    if not isinstance(value, str):
        return None
    return _compact(value, limit)


def _bounded_event_ids(value: Any, *, limit: int = _MAX_LLM_EVENT_EVIDENCE_IDS) -> list[str]:
    """Keep only schema-shaped evidence IDs in a live event payload."""

    if isinstance(value, (str, bytes)):
        return []
    try:
        values = tuple(value or ())
    except TypeError:
        return []
    result: list[str] = []
    for item in values:
        if not isinstance(item, str) or not re.fullmatch(r"E-[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", item):
            continue
        if item not in result:
            result.append(item)
        if len(result) >= limit:
            break
    return result


def _llm_event_details(audit: Mapping[str, Any], round_index: int) -> dict[str, Any]:
    """Project one LLM audit into a bounded, browser-friendly event.

    The complete (still bounded) audit is persisted in ``llm_search.json``.
    Events intentionally contain only the structured plan, tool parameters,
    result summary and evidence references; raw model responses, prompts and
    hidden chain-of-thought are never copied into the event stream.
    """

    context_raw = audit.get("context")
    context_view: dict[str, Any] | None = None
    if isinstance(context_raw, Mapping):
        context_view = {
            "phase": _bounded_text(context_raw.get("phase"), 64) or "search",
            "evidence_count": context_raw.get("evidence_count", 0),
            "visible_evidence_ids": _bounded_event_ids(context_raw.get("visible_evidence_ids")),
            "executed_action_count": context_raw.get("executed_action_count", 0),
        }
        missing = context_raw.get("missing_predicates")
        if isinstance(missing, (list, tuple)):
            context_view["missing_predicates"] = [
                _compact(item, 128) for item in missing[:16] if isinstance(item, str)
            ]
        paths = context_raw.get("candidate_paths")
        if isinstance(paths, (list, tuple)):
            context_view["candidate_paths"] = [
                _compact(item, 1024) for item in paths[:16] if isinstance(item, str)
            ]
        feedback = context_raw.get("last_feedback")
        if isinstance(feedback, str) and feedback.strip():
            context_view["last_feedback"] = _compact(feedback, 512)
        planner_budget = context_raw.get("planner_budget")
        if isinstance(planner_budget, Mapping):
            context_view["planner_budget"] = {
                _compact(key, 64): value
                for key, value in list(planner_budget.items())[:12]
                if isinstance(key, str) and isinstance(value, (str, int, float, bool))
            }

    plan_raw = audit.get("plan")
    plan = dict(plan_raw) if isinstance(plan_raw, Mapping) else {}
    action_raw = plan.get("action")
    action = dict(action_raw) if isinstance(action_raw, Mapping) else None
    plan_view: dict[str, Any] = {
        "status": plan.get("status", audit.get("status", "UNKNOWN")),
        "reason_code": plan.get("reason_code", audit.get("reason_code", "")),
        "reason": _bounded_text(plan.get("reason", audit.get("reason"))) or "",
        "repair_attempted": bool(plan.get("repair_attempted", audit.get("repair_attempted", False))),
        "model_calls": plan.get("model_calls", 0),
        "remaining_actions": plan.get("remaining_actions", 0),
    }
    rejected_action_key = plan.get("rejected_action_key")
    if isinstance(rejected_action_key, str) and rejected_action_key.strip():
        plan_view["rejected_action_key"] = _compact(rejected_action_key, 768)
    if action is not None:
        plan_view["action"] = {
            "kind": _bounded_text(action.get("kind"), 64) or "",
            "query": _bounded_text(action.get("query"), 1024) or "",
            "justification": _bounded_text(action.get("justification"), 512) or "",
            "expected_relation": _bounded_text(action.get("expected_relation"), 128) or "",
            "purpose": _bounded_text(action.get("purpose"), 32) or "normal",
            "evidence_used": _bounded_event_ids(action.get("evidence_used")),
        }

    execution_raw = audit.get("execution")
    execution_view: dict[str, Any] | None = None
    if isinstance(execution_raw, Mapping):
        execution_view = {}
        for key in (
            "status", "kind", "query_id", "path", "requested_path", "source", "truncated",
            "error_type", "error_message", "attempted_paths",
        ):
            value = execution_raw.get(key)
            if key == "attempted_paths":
                if isinstance(value, (list, tuple)):
                    execution_view[key] = [_compact(item, 1024) for item in value[:8] if isinstance(item, str)]
                continue
            if key == "truncated":
                if isinstance(value, bool):
                    execution_view[key] = value
                continue
            if value is not None:
                execution_view[key] = _compact(value, 1024) if isinstance(value, str) else value

        query_raw = execution_raw.get("query")
        if isinstance(query_raw, Mapping):
            query_view: dict[str, Any] = {}
            for key in ("query_id", "kind", "value", "file_type", "reason"):
                value = query_raw.get(key)
                if value is not None:
                    query_view[key] = _compact(value, 1024) if isinstance(value, str) else value
            params = query_raw.get("params")
            if isinstance(params, Mapping):
                query_view["params"] = {
                    _compact(key, 128): _compact(value, 1024) if isinstance(value, str) else value
                    for key, value in list(params.items())[:16]
                    if isinstance(key, str)
                }
            if query_view:
                execution_view["query"] = query_view

        evidence_ids = _bounded_event_ids(execution_raw.get("evidence_ids"))
        if evidence_ids:
            execution_view["evidence_ids"] = evidence_ids

        response = execution_raw.get("response")
        if isinstance(response, Mapping):
            response_view: dict[str, Any] = {}
            for key in ("time", "resultCount", "startDocument", "endDocument"):
                if response.get(key) is not None:
                    response_view[key] = response[key]
            results = response.get("results")
            if isinstance(results, Mapping):
                result_view: list[dict[str, Any]] = []
                for path, hits in list(results.items())[:_MAX_LLM_EVENT_PATHS]:
                    if not isinstance(path, str):
                        continue
                    path_item: dict[str, Any] = {"path": _compact(path, 1024)}
                    if isinstance(hits, (list, tuple)):
                        path_item["hit_count"] = len(hits)
                        hit_view: list[dict[str, Any]] = []
                        for hit in hits[:_MAX_LLM_EVENT_HITS_PER_PATH]:
                            if not isinstance(hit, Mapping):
                                continue
                            item: dict[str, Any] = {}
                            if hit.get("line_number") is not None:
                                item["line_number"] = hit["line_number"]
                            line = hit.get("line") or hit.get("raw_line")
                            if isinstance(line, str):
                                item["line"] = _compact(line, _MAX_LLM_EVENT_LINE_CHARS)
                            if item:
                                hit_view.append(item)
                        if hit_view:
                            path_item["hits"] = hit_view
                    result_view.append(path_item)
                if result_view:
                    response_view["results"] = result_view
            if response_view:
                execution_view["response_summary"] = response_view

    details: dict[str, Any] = {
        "round": round_index,
        "plan": plan_view,
    }
    if context_view is not None:
        details["context"] = context_view
    if execution_view is not None:
        details["execution"] = execution_view
    ids = _bounded_event_ids(
        [
            *(plan_view.get("action", {}).get("evidence_used", []) if isinstance(plan_view.get("action"), Mapping) else []),
            *(execution_view.get("evidence_ids", []) if execution_view else []),
        ]
    )
    if ids:
        details["evidence_ids"] = ids
    # Keep details safely below LocatorEvent's 16 KiB cap even when a remote
    # response contains unusually long paths or line snippets.
    try:
        encoded_size = len(json.dumps(details, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return {"round": round_index, "plan": {"status": plan_view["status"], "reason_code": plan_view["reason_code"]}}
    if encoded_size > 15 * 1024:
        execution = details.get("execution")
        if isinstance(execution, dict):
            response_summary = execution.get("response_summary")
            if isinstance(response_summary, dict):
                response_summary.pop("results", None)
    return details


def _llm_event_summary(audit: Mapping[str, Any], round_index: int) -> str:
    plan = audit.get("plan")
    plan = plan if isinstance(plan, Mapping) else {}
    action = plan.get("action")
    if isinstance(action, Mapping):
        kind = _bounded_text(action.get("kind"), 64) or "未知动作"
        query = _bounded_text(action.get("query"), 160) or ""
        execution = audit.get("execution")
        status = execution.get("status") if isinstance(execution, Mapping) else None
        suffix = f"，工具结果：{status}" if status else ""
        return f"LLM 第 {round_index} 轮：选择 {kind}，目标 {query}{suffix}"
    reason = _bounded_text(plan.get("reason", audit.get("reason")), 240) or "没有可执行动作"
    return f"LLM 第 {round_index} 轮结束：{reason}"


def _llm_context_evidence(store: EvidenceStore, target: TargetSpec) -> tuple[Any, ...]:
    """Project a noisy evidence graph into a bounded semantic context.

    The complete graph remains on disk.  The model receives the most relevant
    identity/communication rows and the newest rows from read-file actions so
    a generic target cannot make the prompt exceed the planner budget.
    """

    items = tuple(store.evidence)
    if len(items) <= _MAX_LLM_CONTEXT_EVIDENCE:
        return items
    terms = tuple(
        term.lower()
        for term in (target.socket_path, target.basename, target.service_hint, target.macro_hint)
        if term
    )
    strong_kinds = {
        "macro_definition",
        "constant_definition",
        "service_config",
        "socket_server_registration",
        "socket_acquire",
        "socket_bind_listen",
        "socket_accept_read",
        "protocol_dispatch",
        "client_endpoint",
        "client_connect",
        "protocol_construction",
        "client_send",
    }
    ranked: list[tuple[int, int, Any]] = []
    for index, item in enumerate(items):
        text = f"{item.source_path} {item.excerpt}".lower()
        score = 0
        if item.kind in strong_kinds:
            score += 3
        if any(term in text for term in terms):
            score += 4
        # ``SourceDocument.source`` is the transport actually used by the
        # client (for example ``raw``, ``api_file_content`` or
        # ``local_corpus``), not the tool name.  Keep all read-file evidence
        # above noisy search hits regardless of which safe transport won.
        if (
            item.tool_name.startswith("opengrok.read_source")
            or item.tool_name.endswith(".read_file")
            or item.source_mode in {
                "read",
                "raw",
                "api_file_content",
                "local_corpus",
                "fixture",
                "opengrok.read_source",
            }
        ):
            score += 2
        # Keep stable ordering for equal scores while preferring newer facts.
        ranked.append((score, index, item))
    ranked.sort(key=lambda row: (-row[0], -row[1]))
    selected = [item for _score, _index, item in ranked[:_MAX_LLM_CONTEXT_EVIDENCE]]
    return tuple(selected)


def _mapping_from_dict(value: Mapping[str, Any]) -> RepositoryMapping:
    allowed = {
        "project_name", "source_root", "remote_name", "remote_fetch", "repo_url", "revision",
        "resolution_method", "evidence_ids", "source_path", "manifest_path", "matched_prefix",
        "match_method", "verified", "warnings", "status", "content_sha256", "requested_revision",
    }
    data = {key: value.get(key) for key in allowed if key in value}
    return RepositoryMapping(**data)


_MAPPING_ROLE_WEIGHTS: Mapping[str, int] = {
    "socket_server_registration": 100,
    "socket_acquire": 90,
    "socket_bind_listen": 90,
    "socket_accept_read": 70,
    "protocol_dispatch": 50,
    "service_config": 60,
    "executable_build": 35,
    "client_connect": 8,
    "client_send": 5,
    "client_endpoint": 3,
    "protocol_construction": 3,
    "macro_definition": 20,
    "constant_definition": 16,
    "symbol_reference": 3,
    # A basename-only hit is retained for auditability but must not outweigh
    # one real server-role fact merely because it appears in many files.
    "literal_match": 0,
}


def _mapping_role_score(
    mapping: RepositoryMapping,
    store: EvidenceStore,
    *,
    target: TargetSpec | None = None,
    semantic_server_evidence_ids: Iterable[str] = (),
) -> tuple[int, dict[str, int]]:
    """Score one repository mapping by source role, not raw hit volume.

    Full-text socket searches often return hundreds of ordinary parameter
    names from unrelated clients/tests.  Strong server-side operations are
    therefore weighted heavily.  An optional, evidence-constrained LLM server
    decision can add a small anchor bonus, while generated/test/third-party
    paths are still kept visible.  The score only orders already
    Manifest-resolved candidates; it never creates a Git URL or bypasses the
    final confirmation gate.
    """

    ids = set(mapping.evidence_ids)
    semantic_ids = {
        item for item in semantic_server_evidence_ids
        if isinstance(item, str) and item.startswith("E-")
    }
    counts: dict[str, int] = {}
    score = 0
    for item in store.evidence:
        if item.evidence_id not in ids:
            continue
        try:
            classification = classify_path(item.source_path)
        except Exception:
            classification = None
        # Test/fuzz rows remain in evidence.json for auditability, but cannot
        # add positive mapping weight or satisfy an attribution anchor.  Other
        # path scopes (kernel, third_party, generated, out, build, etc.) stay
        # in the score and are left for semantic server/client adjudication.
        if classification is not None and not classification.attribution_eligible:
            counts["excluded_test_or_fuzz"] = counts.get("excluded_test_or_fuzz", 0) + 1
            continue
        counts[item.kind] = counts.get(item.kind, 0) + 1
        score += _MAPPING_ROLE_WEIGHTS.get(item.kind, 0)
        if item.evidence_id in semantic_ids:
            counts["llm_server_evidence"] = counts.get("llm_server_evidence", 0) + 1
            score += 30
        role = classification.role if classification is not None else "unknown"
        if role in {"generated", "build", "third_party", "kernel", "log", "selinux"}:
            score -= 30
        elif role == "production" and item.kind not in {"literal_match", "symbol_reference"}:
            score += 8
    # A generic ``SocketServer*`` helper can occur in many repositories after
    # a broad basename search.  Without an identity-bearing row in the same
    # mapping, those registrations are not evidence that this repository owns
    # the requested endpoint.  Keep such candidates visible for audit/review,
    # but cap their ranking so an identity-backed service wins even when it
    # has fewer raw hits.  Identity rows also receive a small anchor bonus.
    identity_count = sum(
        counts.get(kind, 0)
        for kind in ("literal_match", "macro_definition", "constant_definition", "symbol_reference")
    )
    service_anchor_count = counts.get("service_config", 0) + counts.get("executable_build", 0)
    target_anchor_count = 0
    if target is not None:
        target_terms = tuple(
            term.casefold()
            for term in (target.socket_path, target.macro_hint)
            if isinstance(term, str) and term
        )
        for item in store.evidence:
            if item.evidence_id not in ids:
                continue
            try:
                if not classify_path(item.source_path).attribution_eligible:
                    continue
            except Exception:
                continue
            excerpt = item.excerpt.casefold()
            if any(term in excerpt for term in target_terms):
                target_anchor_count += 1
        counts["target_identity_anchor"] = target_anchor_count
    identity_anchor_missing = target is not None and target_anchor_count == 0
    if (identity_count == 0 and service_anchor_count == 0) or identity_anchor_missing:
        score = min(score, 180)
    else:
        score += min(200, (target_anchor_count or identity_count) * 8)
    # A mapping whose own source root contains the server implementation is
    # preferable to a repository represented only by cross-repo references.
    if mapping.source_path and mapping.source_root:
        normalized = mapping.source_path.lstrip("/")
        if normalized.startswith(mapping.source_root.rstrip("/") + "/"):
            score += 10
    return max(0, score), counts


def _mapping_payload(
    mapping: RepositoryMapping,
    store: EvidenceStore,
    *,
    target: TargetSpec | None = None,
    semantic_server_evidence_ids: Iterable[str] = (),
) -> dict[str, Any]:
    payload = mapping.to_dict()
    score, counts = _mapping_role_score(
        mapping,
        store,
        target=target,
        semantic_server_evidence_ids=semantic_server_evidence_ids,
    )
    payload["ranking_score"] = score
    payload["role_evidence_counts"] = counts
    return payload


def _confirmation_role_payload(result: Any, *, limit: int) -> list[dict[str, Any]]:
    """Return a small, UI-safe slice of attribution candidates.

    The complete candidate list remains available in the attribution
    artifacts.  The confirmation view only needs enough source-backed roles
    for a human to understand why the selected repository is being proposed.
    """

    try:
        raw = result.to_dict()
    except (AttributeError, TypeError, ValueError):
        return []
    candidates = raw.get("candidates", [])
    if not isinstance(candidates, list):
        return []
    compact: list[dict[str, Any]] = []
    for candidate in candidates[:limit]:
        if not isinstance(candidate, Mapping):
            continue
        locations = candidate.get("source_locations", [])
        compact_locations = [
            {
                "source_path": item.get("source_path"),
                "line_start": item.get("line_start"),
                "line_end": item.get("line_end"),
                "symbol": item.get("symbol"),
            }
            for item in locations[:_MAX_CONFIRMATION_LOCATIONS]
            if isinstance(item, Mapping)
        ] if isinstance(locations, list) else []
        evidence_ids = candidate.get("evidence_ids", [])
        reasons = candidate.get("reasons", [])
        compact.append(
            {
                "role": candidate.get("role"),
                "subject": _compact(candidate.get("subject", ""), _MAX_CONFIRMATION_TEXT),
                "score": candidate.get("score", 0),
                "source_locations": compact_locations,
                "evidence_ids": [
                    item for item in evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]
                    if isinstance(item, str)
                ] if isinstance(evidence_ids, list) else [],
                "reasons": [
                    _compact(item, _MAX_CONFIRMATION_TEXT)
                    for item in reasons[:_MAX_CONFIRMATION_REASONS]
                ] if isinstance(reasons, list) else [],
            }
        )
    return compact


def _confirmation_evidence_payload(
    store: EvidenceStore,
    evidence_ids: Iterable[str],
) -> list[dict[str, Any]]:
    """Select bounded source excerpts in the order used by attribution."""

    by_id = {item.evidence_id: item for item in store.evidence}
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or evidence_id in seen:
            continue
        item = by_id.get(evidence_id)
        if item is None:
            continue
        seen.add(evidence_id)
        selected.append(
            {
                "evidence_id": item.evidence_id,
                "kind": item.kind,
                "source_path": item.source_path,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "symbol": item.symbol,
                "excerpt": item.excerpt[:_MAX_CONFIRMATION_TEXT],
                "relation_from": item.relation_from,
                "relation_to": item.relation_to,
            }
        )
        if len(selected) >= _MAX_CONFIRMATION_EVIDENCE:
            break
    return selected


def _confirmation_summary_payload(
    *,
    target: TargetSpec,
    mapping: RepositoryMapping,
    store: EvidenceStore,
    server: Any,
    client: Any,
    project_root: str | os.PathLike[str] | None,
    gitcode: GitCodeConfig,
    semantic_server_evidence_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the compact, human-facing payload shown before Git fetch.

    This is deliberately derived from typed attribution/mapping results.  It
    does not infer a repository URL or copy unbounded model/OpenGrok output.
    """

    mapping_payload = _mapping_payload(
        mapping,
        store,
        target=target,
        semantic_server_evidence_ids=semantic_server_evidence_ids,
    )
    server_payload = _compact_attribution_payload(server.to_dict())
    client_payload = _compact_attribution_payload(client.to_dict())
    referenced_ids = tuple(
        dict.fromkeys(
            (
                *server.evidence_ids,
                *client.evidence_ids,
                *mapping.evidence_ids,
            )
        )
    )
    project_name = mapping.project_name
    destination = (
        f"{gitcode.destination_root.rstrip('/')}/{project_name}"
        if project_name
        else gitcode.destination_root
    )
    if project_root is not None and project_name:
        destination = str(
            Path(project_root).expanduser() / gitcode.destination_root / project_name
        )
    warnings = tuple(
        dict.fromkeys(
            (
                *server.warnings,
                *client.warnings,
                *mapping.warnings,
            )
        )
    )
    missing_server_predicates = tuple(
        name
        for name in _REQUIRED_SERVER_PREDICATES
        if not bool(server.predicates.get(name, False))
    )
    if missing_server_predicates:
        warnings = tuple(
            dict.fromkeys(
                (
                    "服务端证据仍缺少：" + ", ".join(missing_server_predicates),
                    *warnings,
                )
            )
        )
    return {
        "schema_version": "openant.source-locator.confirmation-summary.v1",
        "action": {
            "operation": "git_clone",
            "requires_confirmation": True,
        },
        "target": {
            "raw_input": target.raw_input,
            "target_type": target.target_type,
            "socket_path": target.socket_path,
            "basename": target.basename,
            "service_hint": target.service_hint,
            "macro_hint": target.macro_hint,
            "target_revision": target.target_revision,
        },
        "repository": {
            "project_name": mapping.project_name,
            "source_root": mapping.source_root,
            "source_path": mapping.source_path,
            "matched_prefix": mapping.matched_prefix,
            "repo_url": mapping.repo_url,
            "revision": mapping.revision,
            "requested_revision": mapping.requested_revision,
            "destination_root": gitcode.destination_root,
            "destination": destination,
            "status": mapping.status,
            "verified": mapping.verified,
            "ranking_score": mapping_payload.get("ranking_score", 0),
            "role_evidence_counts": mapping_payload.get("role_evidence_counts", {}),
            "evidence_ids": list(mapping.evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]),
        },
        "server": {
            "status": server.status,
            "confirmed": server.confirmed,
            "score": server.score,
            "predicates": dict(server.predicates),
            "missing_predicates": list(missing_server_predicates),
            # The structural predicates remain an auditable signal.  They are
            # advisory at this point: an explicit user decision is still
            # required before any repository operation is attempted.
            "predicate_gate": "advisory" if missing_server_predicates else "satisfied",
            "roles": _confirmation_role_payload(server, limit=_MAX_CONFIRMATION_ROLES),
            "evidence_ids": list(server.evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]),
            "reasons": list(server.reasons[:_MAX_CONFIRMATION_REASONS]),
            "warnings": list(server.warnings[:_MAX_CONFIRMATION_REASONS]),
            "excluded_evidence_ids": list(server.excluded_evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]),
            "semantic_decision": dict(server.semantic_decision) if server.semantic_decision else None,
        },
        "client": {
            "status": client.status,
            "completed": client.completed,
            "score": client.score,
            "predicates": dict(client.predicates),
            "roles": _confirmation_role_payload(client, limit=_MAX_CONFIRMATION_ROLES),
            "evidence_ids": list(client.evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]),
            "reasons": list(client.reasons[:_MAX_CONFIRMATION_REASONS]),
            "warnings": list(client.warnings[:_MAX_CONFIRMATION_REASONS]),
            "excluded_evidence_ids": list(client.excluded_evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]),
            "semantic_decision": dict(client.semantic_decision) if client.semantic_decision else None,
        },
        "evidence_total": len(referenced_ids),
        "evidence": _confirmation_evidence_payload(store, referenced_ids),
        "warnings": list(warnings[:_MAX_CONFIRMATION_REASONS]),
    }


class SourceLocatorWorker:
    """推进一个持久化 session 的单阶段 worker。"""

    def __init__(self, machine: SourceLocatorStateMachine, runtime: SourceLocatorRuntime | None = None) -> None:
        if not isinstance(machine, SourceLocatorStateMachine):
            raise SourceLocatorWorkerError("machine 必须是 SourceLocatorStateMachine")
        self.machine = machine
        self.runtime = runtime or SourceLocatorRuntime()

    @property
    def session(self) -> LocatorSession:
        return self.machine.session

    def _semantic_server_evidence_ids(self, store: EvidenceStore) -> tuple[str, ...]:
        """Return current-session LLM server anchors after ID validation."""

        semantic = _load_llm_role_result(
            self.machine,
            allowed_evidence_ids=(item.evidence_id for item in store.evidence),
        )
        if semantic is None or semantic.server.status not in {"confirmed", "possible"}:
            return ()
        return semantic.server.evidence_ids

    def _mapping_score(
        self,
        mapping: RepositoryMapping,
        store: EvidenceStore,
        *,
        target: TargetSpec | None = None,
    ) -> tuple[int, dict[str, int]]:
        return _mapping_role_score(
            mapping,
            store,
            target=target,
            semantic_server_evidence_ids=self._semantic_server_evidence_ids(store),
        )

    def _run_llm_role_attribution(
        self,
        store: EvidenceStore,
    ) -> tuple[LLMRoleAttributionResult | None, dict[str, str]]:
        """Run the optional role model once and persist a bounded audit.

        The search planner and role adjudicator are separate injections.  This
        keeps deterministic/unit-test runs free of implicit model calls while
        allowing the CLI's explicit ``--llm-search`` mode to use both.
        """

        role_artifact_path = _session_dir(self.machine) / "llm_role_attribution.json"
        attributor = self.runtime.llm_role_attributor
        if attributor is None:
            return _load_llm_role_result(
                self.machine,
                allowed_evidence_ids=(item.evidence_id for item in store.evidence),
            ), dict(self.session.artifacts)
        # The server stage is the owner of this one-call artifact.  When the
        # client stage runs immediately afterwards (or a session is resumed),
        # reuse it instead of spending a second model call.
        if role_artifact_path.exists():
            return _load_llm_role_result(
                self.machine,
                allowed_evidence_ids=(item.evidence_id for item in store.evidence),
            ), dict(self.session.artifacts)
        target = _target(self.session)
        eligible, excluded = partition_attribution_evidence(store)
        if not eligible:
            artifacts = _save_artifact(
                self.machine,
                "llm_role_attribution.json",
                {
                    "schema_version": "openant.source-locator.llm-role-attribution.v1",
                    "status": "SKIPPED_NO_ELIGIBLE_EVIDENCE",
                    "eligible_evidence_count": 0,
                    "excluded_evidence_ids": list(excluded)[:_MAX_ATTRIBUTION_EVIDENCE_IDS],
                },
                "没有可供语义判定的非测试/fuzz证据，未发起额外模型调用。",
            )
            return None, artifacts
        try:
            result = attributor.attribute(
                target=target,
                evidence=eligible,
                excluded_evidence_ids=excluded,
            )
        except Exception as exc:  # optional semantic aid must not block attribution
            artifacts = _save_artifact(
                self.machine,
                "llm_role_attribution.json",
                {
                    "schema_version": "openant.source-locator.llm-role-attribution.v1",
                    "status": "ERROR",
                    "error": _compact(exc),
                    "eligible_evidence_count": len(eligible),
                    "excluded_evidence_ids": list(excluded)[:_MAX_ATTRIBUTION_EVIDENCE_IDS],
                },
                "LLM 角色判定失败的结构化错误摘要；确定性归因结果仍然有效。",
            )
            return None, artifacts
        artifacts = _save_llm_role_result(
            self.machine,
            result,
            eligible_count=len(eligible),
            excluded_evidence_ids=excluded,
        )
        return result, artifacts

    def _transition(
        self,
        state: str,
        summary: str,
        *,
        updates: Mapping[str, Any] | None = None,
        event_type: str = "state.changed",
        evidence_ids: Iterable[str] = (),
        details: Mapping[str, Any] | None = None,
    ) -> LocatorSession:
        try:
            # Event payloads are intentionally smaller than the persisted
            # evidence graph.  Large basename matches (for example AppSpawn)
            # can produce hundreds of source excerpts; retain the first
            # bounded slice in the append-only event while keeping every ID in
            # session.json/evidence.json.
            event_evidence_ids = tuple(dict.fromkeys(evidence_ids))[:_MAX_EVENT_EVIDENCE_IDS]
            return self.machine.transition(
                state,
                summary_zh=summary,
                updates=updates,
                event_type=event_type,
                evidence_ids=event_evidence_ids,
                details=details,
            )
        except LocatorStateError as exc:
            raise SourceLocatorWorkerError(str(exc)) from exc

    def _advance_intake(self) -> LocatorSession:
        return self._transition("NORMALIZE_TARGET", "已进入目标标准化阶段")

    def _advance_normalize(self) -> LocatorSession:
        try:
            target = normalize_target(self.session.raw_target, target_revision=self.session.target_revision)
        except Exception as exc:
            return self._transition(
                "NEEDS_REVIEW",
                "目标描述无法安全标准化，等待人工修正",
                updates={"last_error": _compact(exc)},
                event_type="normalize.failed",
            )
        artifacts = _save_artifact(
            self.machine,
            "target.json",
            target.to_dict(),
            "用户输入经过安全标准化后的目标规格；不代表已经确认仓库归属。",
        )
        return self._transition(
            "PROBE_OPENGROK",
            "已将用户描述标准化为受限目标规格，准备探测 OpenGrok",
            updates={"target": target.to_dict(), "artifacts": artifacts},
            event_type="target.normalized",
        )

    def _advance_probe(self) -> LocatorSession:
        client = self.runtime.client
        if client is None:
            return self._transition(
                "OPENGROK_UNAVAILABLE",
                "未配置 OpenGrok 客户端，暂停定位而不猜测远程地址",
                updates={"last_error": "未配置 source_locator.opengrok"},
                event_type="opengrok.missing_config",
            )
        target = _target(self.session)
        try:
            result = client.probe(probe_path=target.socket_path)
        except (OpenGrokError, ValueError) as exc:
            return self._transition(
                "OPENGROK_UNAVAILABLE",
                "OpenGrok 探测失败，等待检查地址、认证或网络配置",
                updates={"last_error": _compact(exc)},
                event_type="opengrok.probe.failed",
            )
        if not isinstance(result, ProbeResult):
            raise SourceLocatorWorkerError("OpenGrok probe 返回类型无效")
        artifacts = _save_artifact(
            self.machine,
            "probe.json",
            result.to_dict(),
            "OpenGrok 能力探测结果，包括搜索、源码读取、raw 和索引时间；不保存凭据。",
        )
        search_available = result.capabilities.get("search")
        if not result.reachable or search_available is None or not search_available.available:
            return self._transition(
                "OPENGROK_UNAVAILABLE",
                "OpenGrok 可达性或搜索接口未通过，暂停而不把错误页当作源码",
                updates={"artifacts": artifacts, "last_error": "搜索接口不可用"},
                event_type="opengrok.probe.unavailable",
            )
        return self._transition(
            "SEARCH_INITIAL",
            "OpenGrok 探测通过，开始执行有界初始检索",
            updates={"artifacts": artifacts},
            event_type="opengrok.probe.ok",
        )

    @staticmethod
    def _llm_evidence_kind(expected_relation: str, line: str, target: TargetSpec) -> str:
        """Map a model's relation hint to a closed evidence-kind vocabulary.

        The hint is never used as an arbitrary kind or as a filesystem
        instruction.  A concrete source line can still refine a generic hint
        (for example a ``bind`` line is recorded as ``socket_bind_listen``).
        """

        relation = str(expected_relation).strip().lower()
        detected = _line_kind(line, target)
        # Preserve an explicit bind/read/connect/dispatch classification from
        # the source line.  The model hint is only a fallback for a generic
        # identity line, never a way to relabel a concrete operation.
        if detected not in {"literal_match", "symbol_reference"}:
            kind = detected
        elif relation in _LLM_EVIDENCE_KINDS:
            kind = relation
        else:
            kind = detected
        if kind not in _LLM_EVIDENCE_KINDS:
            return "symbol_reference"
        return kind

    @staticmethod
    def _llm_query_id(action_key: str) -> str:
        return "Q-LLM-" + hashlib.sha256(action_key.encode("utf-8", "replace")).hexdigest()[:12]

    def _execute_llm_action(
        self,
        *,
        planner: LLMSearchPlanner,
        target: TargetSpec,
        store: EvidenceStore,
        search_payload: dict[str, Any],
        executed_actions: Iterable[str] = (),
        phase: str = "search",
        missing_predicates: Iterable[str] = (),
        candidate_paths: Iterable[str] = (),
        planner_feedback: str = "",
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Ask the optional planner for one action and execute it safely.

        Returns ``(audit_payload, executed_action_key)``.  Model text is only
        persisted through the planner's bounded structured result; raw model
        responses are never written to a session artifact.
        """

        context = LLMSearchPlannerContext(
            target=target,
            evidence=_llm_context_evidence(store, target),
            executed_actions=_planner_action_history(
                dict.fromkeys((*self.session.executed_actions, *tuple(executed_actions)))
            ),
            phase=phase,
            missing_predicates=tuple(missing_predicates),
            candidate_paths=tuple(candidate_paths),
            last_feedback=planner_feedback,
        )
        try:
            planned = planner.plan(context)
        except (LLMSearchPlannerError, TypeError, ValueError) as exc:
            return {
                "status": "NEEDS_REVIEW",
                "reason_code": "PLANNER_EXCEPTION",
                "reason": _compact(exc),
            }, None
        audit: dict[str, Any] = {
            "context": {
                "phase": context.phase,
                "evidence_count": len(context.evidence),
                "visible_evidence_ids": list(context.evidence_ids or ())[:_MAX_LLM_EVENT_EVIDENCE_IDS],
                "executed_action_count": len(context.executed_actions),
                "planner_budget": {
                    "max_actions": planner.budget.max_actions,
                    "max_model_calls": planner.budget.max_model_calls,
                    "max_prompt_chars": planner.budget.max_prompt_chars,
                    "max_query_length": planner.budget.max_query_length,
                    "max_evidence_ids": planner.budget.max_evidence_ids,
                },
                "missing_predicates": list(context.missing_predicates),
                "candidate_paths": list(context.candidate_paths),
                "last_feedback": context.last_feedback,
            },
            "plan": planned.to_dict(),
        }
        if not planned.accepted or planned.action is None:
            return audit, None
        action = planned.action
        action_key = action.action_key
        # A deterministic query history uses ``kind:file_type:value`` while
        # the planner uses ``kind:value``.  Treat only the same semantic action
        # as a duplicate: ``search_full(foo)`` and ``search_definition(foo)``
        # can legitimately answer different questions.  Reading the exact
        # same file twice remains redundant.  For old checkpoints that have no
        # action history, retain the value-only fallback so a restart cannot
        # unexpectedly replay an already consumed read/search.
        executed_actions = set(self.session.executed_actions)
        deterministic_kind = _SEARCH_ACTION_TO_QUERY_KIND.get(action.kind)
        semantic_keys = set()
        if deterministic_kind is not None:
            semantic_keys.update(
                {
                    _query_key(deterministic_kind, action.query, "c"),
                    _query_key(deterministic_kind, action.query, "cxx"),
                }
            )
        duplicate = action_key in executed_actions or bool(semantic_keys & executed_actions)
        if action.kind == "read_file" and action.query in self.session.executed_queries:
            duplicate = True
        elif not executed_actions and action.query in self.session.executed_queries:
            # Backward-compatible guard for sessions written before
            # ``executed_actions`` was introduced.
            duplicate = True
        if duplicate:
            audit["execution"] = {"status": "skipped_duplicate", "action_key": action_key}
            return audit, action_key
        query_id = self._llm_query_id(action_key)
        budget = self.session.budget
        max_results = _budget_int(budget, "max_results", default=50, maximum=1000)
        max_hits = _budget_int(budget, "max_hits_per_file", default=3, maximum=1000)
        if action.is_search:
            from .search_planner import SearchPlanner

            query = action.to_locator_query(query_id=query_id, file_type="c")
            try:
                result = SearchPlanner(
                    self.runtime.client,
                    max_results=max_results,
                    max_hits_per_file=max_hits,
                    max_queries=1,
                ).execute((query,), target=target)
            except (OpenGrokError, TypeError, ValueError) as exc:
                audit["execution"] = {
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error_message": _compact(exc),
                }
                return audit, action_key
            execution = result.executions[0]
            audit["execution"] = execution.to_dict()
            if execution.status == "ok" and execution.response is not None:
                for path, hits in execution.response.results.items():
                    if _excluded_source_path(path, self.session.excluded_paths):
                        continue
                    for hit in hits:
                        try:
                            # The model's relation is only a hypothesis.  A
                            # concrete hit is classified from its source line
                            # first, so a model cannot turn an arbitrary search
                            # result into a ``bind``/``dispatch`` fact merely
                            # by changing ``expected_relation``.
                            kind = self._llm_evidence_kind(
                                action.expected_relation,
                                hit.line,
                                target,
                            )
                            store.add_search_hit(
                                path,
                                hit,
                                kind=kind,
                                symbol=target.service_hint,
                                query_id=query_id,
                                source_endpoint="opengrok.search.llm",
                            )
                        except ValueError:
                            continue
                # Make this bounded execution visible to the normal trace
                # stage, which will read the returned paths and classify nearby
                # bind/read/dispatch lines from source, not from model prose.
                search_payload.setdefault("executions", []).append(execution.to_dict())
            return audit, action_key

        # ``read_file`` is still an OpenGrok path, validated by the planner;
        # it never becomes a local filesystem path.  Add only a few target-
        # relevant lines to the evidence graph and keep the full source out of
        # the artifact/log stream.
        requested_path = action.query
        document: SourceDocument | None = None
        last_error: Exception | None = None
        attempted_paths: list[str] = []
        try:
            read_candidates = _llm_read_candidates(
                requested_path,
                store,
                self.runtime.client,
            )
        except (TypeError, ValueError) as exc:
            audit["execution"] = {
                "status": "error",
                "error_type": type(exc).__name__,
                "error_message": _compact(exc),
            }
            return audit, action_key
        for candidate in read_candidates:
            attempted_paths.append(candidate)
            try:
                document = self.runtime.client.read_source(
                    candidate,
                    max_bytes=self.runtime.max_source_bytes,
                )
                break
            except OpenGrokHTTPError as exc:
                last_error = exc
                # A project-prefix alias is useful only for a missing path.  A
                # 401/403, timeout or protocol error must not be hidden by a
                # second request with a different spelling.
                if exc.status_code != 404:
                    break
            except (OpenGrokError, TypeError, ValueError) as exc:
                last_error = exc
                break
        if document is None:
            exc = last_error or SourceLocatorWorkerError("read_source 未返回源码文档")
            execution_error: dict[str, Any] = {
                "status": "error",
                "error_type": type(exc).__name__,
                "error_message": _compact(exc),
            }
            if len(attempted_paths) > 1:
                execution_error["attempted_paths"] = attempted_paths
            audit["execution"] = execution_error
            return audit, action_key
        if not isinstance(document, SourceDocument):
            audit["execution"] = {"status": "error", "error_message": "read_source 返回类型无效"}
            return audit, action_key
        lines = document.content.splitlines()
        identity_terms = tuple(
            term.lower()
            for term in (target.socket_path, target.basename, target.service_hint, target.macro_hint)
            if term
        )
        selected_lines = [
            index
            for index, line in enumerate(lines, 1)
            if any(term in line.lower() for term in identity_terms)
            or re.search(r"\b(bind|listen|accept|recv|read|connect|send|write|dispatch)\s*\(", line.lower())
            or _is_server_registration_line(line)
        ][: _MAX_HITS_PER_PATH]
        if not selected_lines:
            selected_lines = list(range(1, min(len(lines), _MAX_HITS_PER_PATH) + 1))
        evidence_ids: list[str] = []
        for line_no in selected_lines:
            try:
                evidence = store.add_source_excerpt(
                    document,
                    line_start=line_no,
                    kind=self._llm_evidence_kind(action.expected_relation, lines[line_no - 1], target),
                    symbol=target.service_hint,
                    query_id=query_id,
                    source_endpoint="opengrok.read_source.llm",
                    relation_from=target.socket_path or target.service_hint,
                    relation_to=f"{document.path}:{line_no}",
                )
            except ValueError:
                continue
            evidence_ids.append(evidence.evidence_id)
        audit["execution"] = {
            "status": "ok",
            "kind": "read_file",
            "path": document.path,
            "requested_path": requested_path,
            "source": document.source,
            "truncated": document.truncated,
            "evidence_ids": evidence_ids,
        }
        # Treat a model-selected read as a normal, bounded trace input too.
        # Without this checkpoint entry the evidence is present in
        # ``evidence.json`` but the next TRACE_EVIDENCE stage only sees search
        # response paths and may skip re-reading this file.  Keep only the
        # selected source lines (never the complete document) so the artifact
        # remains replayable and within the same size budget as search hits.
        search_payload.setdefault("executions", []).append(
            {
                "query": {
                    "query_id": query_id,
                    "kind": "read_file",
                    "value": requested_path,
                    "file_type": "source",
                    "reason": action.justification,
                },
                "status": "ok",
                "kind": "read_file",
                "path": document.path,
                "requested_path": requested_path,
                "source": document.source,
                "truncated": document.truncated,
                "response": {
                    "results": {
                        document.path: [
                            {
                                "line": lines[line_no - 1],
                                "line_number": str(line_no),
                            }
                            for line_no in selected_lines
                        ]
                    }
                },
            }
        )
        return audit, action_key

    @staticmethod
    def _persisted_llm_action_count(actions: Iterable[str]) -> int:
        """Count accepted semantic actions across worker process restarts."""

        return sum(
            1
            for value in actions
            if isinstance(value, str) and (value.startswith("search_") or value.startswith("read_file:"))
        )

    def _run_llm_actions(
        self,
        *,
        target: TargetSpec,
        store: EvidenceStore,
        search_payload: dict[str, Any],
        phase: str = "search",
        missing_predicates: Iterable[str] = (),
        candidate_paths: Iterable[str] = (),
        round_offset: int = 0,
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """Run a bounded semantic loop and retry duplicate model proposals.

        ``max_llm_actions`` counts accepted novel tool actions, not model
        attempts.  Duplicate proposals consume the model-call budget and are
        fed back to the next prompt, with a small consecutive-repeat guard to
        prevent an uncooperative model from spinning forever.
        """

        planner = self.runtime.llm_planner
        if planner is None:
            return [], [], []
        missing_predicates = tuple(missing_predicates)
        candidate_paths = tuple(candidate_paths)
        if isinstance(round_offset, bool) or not isinstance(round_offset, int) or round_offset < 0:
            raise SourceLocatorWorkerError("round_offset 必须是非负整数")
        budget = self.session.budget
        max_actions = _budget_int(budget, "max_llm_actions", default=20, maximum=20, minimum=0)
        accepted_before = self._persisted_llm_action_count(self.session.executed_actions)
        remaining_actions = max(0, max_actions - accepted_before)
        if remaining_actions <= 0:
            return [], [], []

        local_actions = list(self.session.executed_actions)
        audits: list[dict[str, Any]] = []
        action_keys: list[str] = []
        action_queries: list[str] = []
        planner_feedback = ""
        duplicate_streak = 0
        round_index = 0
        while len(action_keys) < remaining_actions and planner.model_calls < planner.budget.max_model_calls:
            llm_audit, llm_action_key = self._execute_llm_action(
                planner=planner,
                target=target,
                store=store,
                search_payload=search_payload,
                executed_actions=local_actions,
                phase=phase,
                missing_predicates=missing_predicates,
                candidate_paths=candidate_paths,
                planner_feedback=planner_feedback,
            )
            round_index += 1
            if llm_audit is None:
                break
            audit = _compact_llm_audit(llm_audit)
            audit["round"] = round_offset + round_index
            audits.append(audit)
            event_details = _llm_event_details(audit, round_offset + round_index)
            event_ids = event_details.get("evidence_ids", ())
            self.machine.record_event(
                event_type="llm.search.round",
                summary_zh=_llm_event_summary(audit, round_offset + round_index),
                evidence_ids=event_ids if isinstance(event_ids, list) else (),
                details=event_details,
            )

            execution = audit.get("execution")
            if isinstance(execution, Mapping) and execution.get("status") == "skipped_duplicate":
                duplicate_streak += 1
                rejected = execution.get("action_key") or "未记录"
                planner_feedback = (
                    f"上一动作 {rejected} 已执行过，禁止重复；"
                    "请改选不同的 kind 或 query，并优先补足缺失证据。"
                )
                if duplicate_streak >= 3:
                    self.machine.record_event(
                        event_type="llm.search.retry_exhausted",
                        summary_zh="连续重复检索达到上限，结束本轮语义检索",
                        details={"duplicate_streak": duplicate_streak, "phase": phase},
                    )
                    break
                continue

            if not llm_action_key:
                plan = audit.get("plan")
                plan_status = plan.get("status") if isinstance(plan, Mapping) else None
                if plan_status == "REPEATED":
                    duplicate_streak += 1
                    rejected = plan.get("rejected_action_key") if isinstance(plan, Mapping) else None
                    planner_feedback = (
                        f"上一动作 {rejected or '未记录'} 已执行过，禁止重复；"
                        "请改选不同的 kind 或 query，并优先补足缺失证据。"
                    )
                    if duplicate_streak >= 3:
                        self.machine.record_event(
                            event_type="llm.search.retry_exhausted",
                            summary_zh="连续重复检索达到上限，结束本轮语义检索",
                            details={"duplicate_streak": duplicate_streak, "phase": phase},
                        )
                        break
                    continue
                break
            if llm_action_key in local_actions:
                duplicate_streak += 1
                planner_feedback = (
                    f"上一动作 {llm_action_key} 已执行过，禁止重复；"
                    "请改选不同的 kind 或 query，并优先补足缺失证据。"
                )
                if duplicate_streak >= 3:
                    self.machine.record_event(
                        event_type="llm.search.retry_exhausted",
                        summary_zh="连续重复检索达到上限，结束本轮语义检索",
                        details={"duplicate_streak": duplicate_streak, "phase": phase},
                    )
                    break
                continue

            duplicate_streak = 0
            planner_feedback = ""
            local_actions.append(llm_action_key)
            action_keys.append(llm_action_key)
            plan = audit.get("plan")
            if isinstance(plan, Mapping):
                action_payload = plan.get("action")
                query = action_payload.get("query") if isinstance(action_payload, Mapping) else None
                if isinstance(query, str):
                    action_queries.append(query)
            if isinstance(execution, Mapping) and execution.get("status") not in {"ok", "skipped_duplicate"}:
                break
        return audits, action_keys, action_queries

    def _advance_search(self) -> LocatorSession:
        client = self.runtime.client
        if client is None:
            return self._transition("OPENGROK_UNAVAILABLE", "没有可用的 OpenGrok 客户端，无法检索", updates={"last_error": "未配置 OpenGrok 客户端"})
        target = _target(self.session)
        from .search_planner import SearchPlanResult, SearchPlanner

        budget = self.session.budget
        session_query_limit = _budget_int(
            budget,
            "max_queries",
            default=50,
            maximum=256,
            minimum=0,
        )
        # ``executed_queries`` predates file-type-aware actions and deduplicates
        # values such as the C and C++ forms of one query.  New sessions use
        # ``executed_actions`` as the authoritative budget counter; old
        # checkpoints fall back to the value history for compatibility.
        consumed_queries = len(self.session.executed_actions) or len(self.session.executed_queries)
        if consumed_queries >= session_query_limit:
            return self._transition(
                "PARTIAL",
                "本 session 的检索预算已耗尽，保留已有证据等待人工复核",
                updates={"last_error": "查询预算已耗尽"},
                event_type="search.budget_exhausted",
            )
        # SearchPlanner has a tighter per-call cap.  Filter queries already
        # executed by this persisted session before touching OpenGrok.  The
        # value-only history is retained for backward compatibility, while
        # executed_actions carries a kind/file-type-aware key for new runs.
        initial_queries = build_initial_queries(
            target,
            max_queries=min(32, max(1, session_query_limit - consumed_queries)),
        )
        executed_values = set(self.session.executed_queries)
        executed_actions = set(self.session.executed_actions)
        queries = tuple(
            query
            for query in initial_queries
            if query.value not in executed_values
            and _query_key(query.kind, query.value, query.file_type) not in executed_actions
        )
        if not queries:
            return self._transition(
                "PARTIAL",
                "初始查询此前已经执行过，没有新的确定性检索动作",
                updates={"last_error": "没有新的检索查询"},
                event_type="search.initial.repeated",
            )
        planner = SearchPlanner(
            client,
            max_results=_budget_int(budget, "max_results", default=50, maximum=1000),
            max_hits_per_file=_budget_int(budget, "max_hits_per_file", default=3, maximum=1000),
            max_queries=min(32, len(queries)),
        )
        try:
            result = planner.execute(queries, target=target)
        except (OpenGrokError, ValueError, TypeError) as exc:
            return self._transition("PARTIAL", "初始检索无法完成，保留失败原因供人工复核", updates={"last_error": _compact(exc)}, event_type="search.initial.failed")

        # A path hit often reveals a second macro that is not present in the
        # user's description.  For example, ``DNS_SOCKET_PATH`` and
        # ``DNS_SOCKET_NAME`` are declared together, while the C++ listener
        # only calls ``GetControlSocket(DNS_SOCKET_NAME)``.  Perform one
        # deterministic, budgeted follow-up pass over aliases extracted from
        # the first response.  This is intentionally source-driven; no model
        # is needed and no arbitrary identifier is accepted.
        initial_payload = tuple(execution.to_dict() for execution in result.executions)
        related_macros = _infer_related_macros(initial_payload, target)
        consumed_after_initial = consumed_queries + len(result.executions)
        macro_budget = max(0, session_query_limit - consumed_after_initial)
        macro_queries = _macro_queries(
            related_macros,
            max_queries=min(32, macro_budget),
            start_index=len(result.executions) + 1,
        )
        macro_queries = tuple(
            query
            for query in macro_queries
            if query.value not in executed_values
            and _query_key(query.kind, query.value, query.file_type) not in executed_actions
            and all(query.value != initial.value or query.file_type != initial.file_type for initial in queries)
        )
        all_executions = list(result.executions)
        if macro_queries:
            macro_planner = SearchPlanner(
                client,
                max_results=_budget_int(budget, "max_results", default=50, maximum=1000),
                max_hits_per_file=_budget_int(budget, "max_hits_per_file", default=3, maximum=1000),
                max_queries=min(32, len(macro_queries)),
            )
            try:
                macro_result = macro_planner.execute(macro_queries, target=target)
            except (OpenGrokError, ValueError, TypeError) as exc:
                # Keep the successful first pass and expose the follow-up
                # failure in the normal search artifact instead of discarding
                # all evidence.
                macro_result = None
                macro_error = _compact(exc)
            else:
                macro_error = None
            if macro_result is not None:
                all_executions.extend(macro_result.executions)
        search_result = SearchPlanResult(tuple(all_executions), target=target)

        # Keep the evidence graph append-only across user feedback rounds.  A
        # new search may add stronger evidence, but must never erase the old
        # evidence that justified the previous candidate.
        store = _load_evidence(self.machine)
        for execution in search_result.executions:
            if execution.status != "ok" or execution.response is None:
                continue
            for path, hits in execution.response.results.items():
                for hit in hits:
                    if len(store.evidence) >= _MAX_SEARCH_EVIDENCE:
                        break
                    try:
                        store.add_search_hit(
                            path,
                            hit,
                            kind="macro_definition" if execution.query.kind == "definition" and target.macro_hint else (
                                "symbol_reference" if execution.query.kind in {"definition", "symbol"} else "literal_match"
                            ),
                            symbol=target.service_hint,
                            query_id=execution.query.query_id,
                            source_endpoint="opengrok.search",
                        )
                    except ValueError:
                        # A malformed line from one upstream hit must not erase
                        # valid hits from the same bounded response.
                        continue
                if len(store.evidence) >= _MAX_SEARCH_EVIDENCE:
                    break
            if len(store.evidence) >= _MAX_SEARCH_EVIDENCE:
                break
        # An injected semantic planner may add a small, explicitly budgeted
        # sequence of fully validated search/read actions after deterministic
        # search. Each tool result is written to ``store`` and becomes part of
        # the next planner context. It can improve macro/constant and
        # cross-file recall, but it cannot choose a repository or run a
        # command. The regular trace stage consumes all added search paths.
        search_payload = search_result.to_dict()
        if macro_queries and macro_error is not None:
            search_payload.setdefault("follow_up", {})["status"] = "error"
            search_payload["follow_up"]["error_message"] = macro_error
        elif related_macros:
            search_payload.setdefault("follow_up", {})["status"] = "ok"
            search_payload["follow_up"]["related_macros"] = list(related_macros)
        llm_audits, llm_action_keys, llm_action_queries = self._run_llm_actions(
            target=target,
            store=store,
            search_payload=search_payload,
            phase="search",
        )
        search_payload = _compact_search_payload(search_payload)
        artifacts = _save_artifact(self.machine, "search_plan.json", search_payload, "初始检索的查询顺序、参数、响应和失败原因；若启用语义规划器也包含其经过校验的搜索响应。")
        if llm_audits:
            artifacts = _save_llm_rounds(self.machine, llm_audits, phase="search")
        _json_write(_session_dir(self.machine) / "evidence.json", store.to_dict())
        artifacts["evidence.json"] = "由 OpenGrok 搜索命中生成的、带源码行号和哈希的初始证据集合。"
        result_paths: list[str] = []
        for execution in search_payload.get("executions", []):
            response = execution.get("response") or {}
            for path in response.get("results", {}):
                if path not in result_paths:
                    result_paths.append(path)
        for llm_audit in llm_audits:
            llm_execution = llm_audit.get("execution") or {}
            llm_path = llm_execution.get("path")
            if isinstance(llm_path, str) and llm_path not in result_paths:
                result_paths.append(llm_path)
        if not result_paths:
            return self._transition(
                "PARTIAL",
                "初始检索没有返回候选文件，保留查询记录等待人工或模型补充目标",
                updates={"artifacts": artifacts, "last_error": "没有 OpenGrok 候选文件"},
                event_type="search.initial.empty",
            )
        executed_values_update = tuple(
            dict.fromkeys(
                (
                    *self.session.executed_queries,
                    *(item.query.value for item in search_result.executions),
                    *llm_action_queries,
                )
            )
        )
        executed_action_update = tuple(
            dict.fromkeys(
                (
                    *self.session.executed_actions,
                    *(
                        _query_key(item.query.kind, item.query.value, item.query.file_type)
                        for item in search_result.executions
                    ),
                    *llm_action_keys,
                )
            )
        )
        query_updates = {
            "executed_queries": executed_values_update,
            "executed_actions": executed_action_update,
        }
        return self._transition(
            "TRACE_EVIDENCE",
            f"初始检索完成，发现 {len(result_paths)} 个候选文件，开始读取证据",
            updates={"artifacts": artifacts, **query_updates},
            event_type="search.initial.completed",
        )

    def _advance_trace(self) -> LocatorSession:
        client = self.runtime.client
        if client is None:
            return self._transition("PARTIAL", "没有 OpenGrok 客户端，无法读取候选源码", updates={"last_error": "未配置 OpenGrok 客户端"})
        target = _target(self.session)
        store = _load_evidence(self.machine)
        search_payload = _read_json(_session_dir(self.machine) / "search_plan.json")
        paths: list[str] = []
        for execution in search_payload.get("executions", []):
            response = execution.get("response") or {}
            for path in response.get("results", {}):
                if path not in paths:
                    paths.append(path)
        paths = [
            path for path in paths
            if not _excluded_source_path(path, self.session.excluded_paths)
        ]
        ranked = rank_paths(paths, target=target)[: self.runtime.max_paths]
        classifications = [item.to_dict() for item in ranked]
        for classification in ranked:
            # Search results intentionally retain every path in
            # ``path_classification.json`` for auditability.  Only explicit
            # test/fuzz signals are excluded from source tracing; generated,
            # kernel, third-party, build and unknown paths remain available so
            # the semantic role adjudicator can decide whether they are real
            # service/client implementations or merely references.
            # Only explicit test/fuzz signals are hard-excluded.  The
            # classification carries all path signals because a self-test may
            # have a primary role such as ``kernel`` or ``third_party``.
            # Kernel, generated, build and third-party paths remain available
            # for semantic attribution; they are merely ranked separately.
            if not classification.attribution_eligible:
                continue
            path = classification.path
            try:
                document = client.read_source(path, max_bytes=self.runtime.max_source_bytes)
            except (OpenGrokError, ValueError):
                continue
            if not isinstance(document, SourceDocument):
                continue
            trace_keys: set[tuple[int, str]] = set()
            # Use every bounded search hit for this file, then inspect nearby
            # lines so bind/accept/connect/dispatch evidence remains line-backed.
            raw_hits = []
            for execution in search_payload.get("executions", []):
                response = execution.get("response") or {}
                if path in response.get("results", {}):
                    raw_hits.extend((execution.get("query", {}), hit) for hit in response["results"][path])
            for query, hit in raw_hits[:_MAX_HITS_PER_PATH]:
                try:
                    # SearchHit serializes its Python field as ``line_number``;
                    # ``lineNumber`` is accepted as a compatibility fallback
                    # for captured OpenGrok JSON.
                    line = int(hit.get("line_number", hit.get("lineNumber", 0)))
                except (TypeError, ValueError):
                    continue
                if line < 1 or line > len(document.content.splitlines()):
                    continue
                lines = document.content.splitlines()
                start = max(1, line - _TRACE_CONTEXT_LINES)
                end = min(len(lines), line + _TRACE_CONTEXT_LINES)
                for line_no in range(start, end + 1):
                    excerpt = lines[line_no - 1]
                    query_kind = query.get("kind") if isinstance(query, Mapping) else None
                    query_value = query.get("value") if isinstance(query, Mapping) else None
                    kind = _line_kind(
                        excerpt,
                        target,
                        query_kind=query_kind,
                        query_value=query_value,
                    )
                    client_kind = _client_kind(excerpt, target)
                    if client_kind is not None and kind in {"literal_match", "symbol_reference"}:
                        kind = client_kind
                    identity_terms = tuple(
                        term.lower()
                        for term in (target.socket_path, target.basename, target.service_hint, target.macro_hint, query_value)
                        if term
                    )
                    # Keep the exact hit, identity-bearing context, and
                    # concrete communication operations.  A 129-line window
                    # is useful for OpenHarmony's init-created descriptor and
                    # switch-based handlers, but retaining every line would
                    # turn comments and unrelated helpers into evidence.
                    if (
                        line_no != line
                        and not any(term in excerpt.lower() for term in identity_terms)
                        and kind
                        not in {
                            "socket_acquire",
                            "socket_bind_listen",
                            "socket_accept_read",
                            "protocol_dispatch",
                            "client_connect",
                            "client_send",
                        }
                    ):
                        continue
                    trace_key = (line_no, kind)
                    if trace_key not in trace_keys:
                        if len(trace_keys) >= _MAX_TRACE_EVIDENCE_PER_PATH:
                            continue
                        trace_keys.add(trace_key)
                    try:
                        evidence = store.add_source_excerpt(
                            document,
                            line_start=line_no,
                            kind=kind,
                            symbol=target.service_hint,
                            query_id=query.get("query_id"),
                            source_endpoint="opengrok.read_source",
                            relation_from=target.socket_path or target.service_hint,
                            relation_to=f"{path}:{line_no}",
                        )
                        # Attach the target relation for attribution and client
                        # completion without making a claim about business callers.
                        if target.service_hint:
                            try:
                                store.add_edge(
                                    src=target.service_hint,
                                    relation="candidate_source",
                                    dst=f"{path}:{line_no}",
                                    evidence_ids=(evidence.evidence_id,),
                                    confidence="moderate" if kind not in {"literal_match", "symbol_reference"} else "weak",
                                )
                            except ValueError:
                                pass
                    except ValueError:
                        continue
        _json_write(_session_dir(self.machine) / "evidence.json", store.to_dict())
        artifacts = dict(self.session.artifacts)
        artifacts["evidence.json"] = "经过源码读取和 bind/accept/connect/dispatch 分类后的带行号证据图。"
        artifacts = _save_artifact(self.machine, "path_classification.json", classifications, "候选路径的主角色、全部路径信号、是否允许参与服务端/客户端归因以及可解释排序分数；仅明确测试和 fuzz 路径不参与归因。")
        # _save_artifact starts from the current session map, so preserve the
        # evidence description added above.
        artifacts["evidence.json"] = "经过源码读取和 bind/accept/connect/dispatch 分类后的带行号证据图。"
        return self._transition(
            "ATTRIBUTION_SERVER",
            f"已读取 {len(ranked)} 个候选文件并生成证据图，开始区分服务端角色",
            updates={"artifacts": artifacts, "evidence_ids": tuple(item.evidence_id for item in store.evidence)},
            event_type="evidence.traced",
            evidence_ids=tuple(item.evidence_id for item in store.evidence),
        )

    def _advance_server(self) -> LocatorSession:
        store = _load_evidence(self.machine)
        result = ServiceAttributor().attribute(store)
        semantic, role_artifacts = self._run_llm_role_attribution(store)
        if semantic is not None:
            result = _merge_server_semantic(result, semantic.server, store)
        result_payload = _compact_attribution_payload(result.to_dict())
        artifacts = _save_artifact(self.machine, "server_attribution.json", result_payload, "服务端候选角色、结构性谓词、LLM 语义判定、证据和未满足条件；候选列表过大时保留高分有界摘要，完整行证据仍在 evidence.json。")
        artifacts.update(role_artifacts)
        return self._transition(
            "LOCATE_CLIENT_COMM",
            f"服务端归因完成：{result.status}" + ("（包含 LLM 语义复核）" if semantic else "") + "，继续定位客户端通信边界",
            updates={"server_attribution": result_payload, "artifacts": artifacts},
            event_type="attribution.server.completed",
            evidence_ids=result.evidence_ids,
            details={
                "semantic_review": semantic.server.to_dict() if semantic else None,
                "excluded_evidence_count": len(result.excluded_evidence_ids),
            },
        )

    def _advance_client(self) -> LocatorSession:
        store = _load_evidence(self.machine)
        result = ClientLocator().locate(store)
        semantic, role_artifacts = self._run_llm_role_attribution(store)
        if semantic is not None:
            result = _merge_client_semantic(result, semantic.client, store)
        result_payload = _compact_attribution_payload(result.to_dict())
        artifacts = _save_artifact(self.machine, "client_attribution.json", result_payload, "客户端 endpoint/connect/协议构造/send 证据、LLM 语义判定；完成后不继续追踪业务 caller；候选列表过大时保留有界摘要。")
        artifacts.update(role_artifacts)
        return self._transition(
            "RESOLVE_REPOSITORIES",
            f"客户端通信边界分析完成：{result.status}" + ("（包含 LLM 语义复核）" if semantic else "") + "，开始解析 Manifest 仓库映射",
            updates={"client_attribution": result_payload, "artifacts": artifacts},
            event_type="attribution.client.completed",
            evidence_ids=result.evidence_ids,
            details={
                "semantic_review": semantic.client.to_dict() if semantic else None,
                "excluded_evidence_count": len(result.excluded_evidence_ids),
            },
        )

    def _advance_repositories(self) -> LocatorSession:
        if self.runtime.manifest is None:
            return self._transition(
                "NEEDS_REVIEW",
                "没有 Manifest 配置，保留代码证据但不猜测 GitCode 仓库",
                updates={"last_error": "未配置可验证的 Manifest"},
                event_type="repository.mapping.missing_manifest",
            )
        store = _load_evidence(self.machine)
        target = _target(self.session)
        semantic_server_evidence_ids = self._semantic_server_evidence_ids(store)
        resolver = ManifestResolver(self.runtime.manifest, target_revision=self.runtime.target_revision or self.session.target_revision)
        source_paths = tuple(dict.fromkeys(item.source_path for item in store.evidence))
        mappings: list[RepositoryMapping] = []
        for path in source_paths:
            try:
                mapping = resolver.resolve(path, requested_revision=self.runtime.target_revision or self.session.target_revision, evidence_ids=_evidence_for_path(store, path))
            except ValueError:
                continue
            # A service's literal/macro often lives in a header while its
            # registration and consumer live in a sibling implementation
            # file.  Attach all evidence under the resolved Manifest project
            # to each project mapping before ranking; otherwise a noisy file
            # with many basename hits can outrank the actual owner simply
            # because the identity header was mapped separately.
            project_evidence_ids = tuple(
                item.evidence_id
                for item in store.evidence
                if _mapping_contains_path(item.source_path, mapping)
            )
            if project_evidence_ids:
                mapping = replace(
                    mapping,
                    evidence_ids=tuple(dict.fromkeys((*mapping.evidence_ids, *project_evidence_ids))),
                )
            mappings.append(mapping)
        # Keep one mapping per project and prefer the one with the strongest
        # source-role evidence.  Raw evidence counts are intentionally not
        # used: a noisy client/test repository can contain more copies of the
        # socket basename than the actual server implementation.
        unique: dict[tuple[str | None, str | None], RepositoryMapping] = {}
        for mapping in mappings:
            if mapping.project_name and mapping.project_name in self.session.excluded_repos:
                continue
            key = (mapping.project_name, mapping.repo_url)
            previous = unique.get(key)
            current_score = self._mapping_score(mapping, store, target=target)[0]
            previous_score = self._mapping_score(previous, store, target=target)[0] if previous is not None else -1
            if previous is None or current_score > previous_score or (
                current_score == previous_score and len(mapping.evidence_ids) > len(previous.evidence_ids)
            ):
                unique[key] = mapping
        mappings = list(unique.values())
        mappings.sort(
            key=lambda item: (
                -self._mapping_score(item, store, target=target)[0],
                -(1 if item.status == "resolved" else 0),
                item.project_name or "",
            )
        )
        artifacts = _save_artifact(
            self.machine,
            "repository_resolutions.json",
            {
                "mappings": [
                    _mapping_payload(
                        item,
                        store,
                        target=target,
                        semantic_server_evidence_ids=semantic_server_evidence_ids,
                    )
                    for item in mappings
                ]
            },
            "通过 Manifest 最长路径前缀和服务端角色证据得到的 GitCode 映射；候选按源码角色加权排序，未通过策略的映射仍保留但不可 clone。",
        )
        if not mappings:
            return self._transition("NEEDS_REVIEW", "Manifest 没有匹配任何证据路径，等待人工选择版本或补充 Manifest", updates={"artifacts": artifacts, "last_error": "没有 Manifest 路径匹配"}, event_type="repository.mapping.empty")
        if any(item.status == "version_mismatch" for item in mappings):
            return self._transition("VERSION_MISMATCH", "Manifest revision 与目标版本不一致，禁止自动拉取", updates={"repository_mappings": {"mappings": [item.to_dict() for item in mappings]}, "artifacts": artifacts, "last_error": "Manifest revision 与目标 revision 不一致"}, event_type="repository.mapping.version_mismatch")
        resolved = [item for item in mappings if item.is_resolved]
        if not resolved:
            return self._transition("NEEDS_REVIEW", "候选路径存在但没有可验证的 GitCode 映射，等待人工复核", updates={"repository_mappings": {"mappings": [item.to_dict() for item in mappings]}, "artifacts": artifacts, "last_error": "没有 resolved repository mapping"}, event_type="repository.mapping.needs_review")
        return self._transition(
            "VERIFY_EVIDENCE",
            f"已得到 {len(resolved)} 个可验证仓库映射，执行服务端强制谓词复核",
            updates={"repository_mappings": {"mappings": [item.to_dict() for item in mappings]}, "artifacts": artifacts},
            event_type="repository.mapping.resolved",
        )

    def _advance_verify(self) -> LocatorSession:
        store = _load_evidence(self.machine)
        target = _target(self.session)
        mapping_data = self.session.repository_mappings or {}
        mappings = mapping_data.get("mappings", []) if isinstance(mapping_data, Mapping) else []
        resolved = [_mapping_from_dict(item) for item in mappings if isinstance(item, Mapping) and item.get("status") == "resolved"]
        if not resolved:
            return self._transition("NEEDS_REVIEW", "没有可供确认的 resolved 仓库映射", updates={"last_error": "VERIFY_EVIDENCE 缺少 resolved mapping"}, event_type="verification.missing_mapping")
        mapping = max(resolved, key=lambda item: self._mapping_score(item, store, target=target)[0])
        server = ServiceAttributor(mapping=mapping).attribute(store, mapping=mapping)
        client = ClientLocator(mapping=mapping).locate(store, mapping=mapping)
        semantic = _load_llm_role_result(
            self.machine,
            allowed_evidence_ids=(item.evidence_id for item in store.evidence),
        )
        if semantic is not None:
            server = _merge_server_semantic(server, semantic.server, store)
            client = _merge_client_semantic(client, semantic.client, store)
        missing_predicates = tuple(
            name for name in _REQUIRED_SERVER_PREDICATES
            if not bool(server.predicates.get(name, False))
        )
        payload = {
            "server": _compact_attribution_payload(server.to_dict()),
            "client": _compact_attribution_payload(client.to_dict()),
            "mapping": mapping.to_dict(),
            "missing_server_predicates": list(missing_predicates),
            "predicate_gate": "advisory" if missing_predicates else "satisfied",
            "semantic_review": semantic.to_dict() if semantic else None,
        }
        artifacts = _save_artifact(self.machine, "verification.json", payload, "进入人工确认前的结构性谓词、服务端/客户端状态和主仓库候选。")
        confirmation_summary = _confirmation_summary_payload(
            target=target,
            mapping=mapping,
            store=store,
            server=server,
            client=client,
            project_root=self.runtime.project_root,
            gitcode=self.runtime.gitcode,
            semantic_server_evidence_ids=self._semantic_server_evidence_ids(store),
        )
        artifacts = _save_artifact(
            self.machine,
            "confirmation_summary.json",
            confirmation_summary,
            "确认前摘要：将拉取的 GitCode 仓库、版本、落盘位置、服务端判定和关键源码证据。",
        )
        if not server.confirmed:
            # An incomplete source graph is recoverable.  The semantic
            # planner receives the exact missing predicates and candidate
            # paths instead of being asked to rediscover the whole target.
            # Recovery is bounded by a session counter and by the planner's
            # existing action/call caps.  Once recovery is exhausted, the
            # predicates remain advisory and the resolved mapping is still
            # presented for explicit user confirmation.
            budget = dict(self.session.budget)
            recovery_runs = _budget_int(
                budget,
                "llm_recovery_runs",
                default=0,
                maximum=2,
                minimum=0,
            )
            max_recovery_runs = _budget_int(
                budget,
                "max_llm_recovery_runs",
                default=1,
                maximum=2,
                minimum=0,
            )
            max_actions = _budget_int(
                budget,
                "max_llm_actions",
                default=20,
                maximum=20,
                minimum=0,
            )
            accepted_actions = self._persisted_llm_action_count(self.session.executed_actions)
            if (
                missing_predicates
                and self.runtime.llm_planner is not None
                and recovery_runs < max_recovery_runs
                and accepted_actions < max_actions
            ):
                budget["llm_recovery_runs"] = recovery_runs + 1
                budget["llm_recovery_missing_predicates"] = list(missing_predicates)
                return self._transition(
                    "RECOVER_EVIDENCE",
                    "服务端证据尚不完整，进入有界语义补证阶段",
                    updates={
                        "server_attribution": payload["server"],
                        "client_attribution": payload["client"],
                        "artifacts": artifacts,
                        "budget": budget,
                        "last_error": "待补充服务端谓词：" + ", ".join(missing_predicates),
                    },
                    event_type="verification.recovery.requested",
                    evidence_ids=server.evidence_ids,
                    details={
                        "missing_predicates": list(missing_predicates),
                        "recovery_run": recovery_runs + 1,
                        "max_recovery_runs": max_recovery_runs,
                        "accepted_llm_actions": accepted_actions,
                        "max_llm_actions": max_actions,
                        "mapping_project": mapping.project_name,
                    },
                )
            # A resolved mapping is enough to present a candidate to the user.
            # Missing predicates must remain visible as a warning, but they
            # are not a terminal gate: the user is the authority who decides
            # whether this uncertain candidate should be fetched.  This keeps
            # the deterministic attribution useful without turning one
            # incomplete source trace into a false dead end.
            reason = "服务端证据仍不完整，保留缺失谓词提示并进入仓库确认"
            if missing_predicates:
                reason += "；缺失：" + ", ".join(missing_predicates)
            return self._transition(
                "AWAIT_USER_CONFIRMATION",
                reason,
                updates={
                    "server_attribution": payload["server"],
                    "client_attribution": payload["client"],
                    "artifacts": artifacts,
                    # Recovery may have recorded a transient error-like
                    # message.  The flow is now waiting for an explicit user
                    # decision, so do not leave the checkpoint in an error
                    # state; the warning is preserved in the event details
                    # and confirmation_summary.json.
                    "last_error": None,
                },
                event_type="verification.await_confirmation",
                evidence_ids=server.evidence_ids,
                details={
                    "missing_predicates": list(missing_predicates),
                    "recovery_runs": recovery_runs,
                    "max_recovery_runs": max_recovery_runs,
                    "llm_available": self.runtime.llm_planner is not None,
                    "predicate_gate": "advisory",
                    "server_confirmed": bool(server.confirmed),
                },
            )
        return self._transition(
            "AWAIT_USER_CONFIRMATION",
            "证据和仓库映射已完成校验，请用户确认是否拉取主仓库",
            updates={"server_attribution": payload["server"], "client_attribution": payload["client"], "artifacts": artifacts},
            event_type="verification.await_confirmation",
            evidence_ids=server.evidence_ids,
        )

    def _advance_recover(self) -> LocatorSession:
        """Use one bounded semantic loop to fill predicates missed by tracing.

        This stage deliberately returns to the normal TRACE → ATTRIBUTION
        path.  It never promotes a model claim directly to a server fact: all
        selected files are still read through OpenGrok and classified by the
        deterministic evidence/attribution code on the next pass.
        """

        if self.runtime.llm_planner is None:
            return self._transition(
                "VERIFY_EVIDENCE",
                "未配置语义规划器，回到最终校验并把缺失证据交给人工确认",
                updates={"last_error": None},
                event_type="verification.recovery.unavailable",
            )
        client = self.runtime.client
        if client is None:
            return self._transition(
                "VERIFY_EVIDENCE",
                "没有 OpenGrok 客户端，回到最终校验并把缺失证据交给人工确认",
                updates={"last_error": None},
                event_type="verification.recovery.unavailable",
            )
        target = _target(self.session)
        store = _load_evidence(self.machine)
        mapping_data = self.session.repository_mappings or {}
        raw_mappings = mapping_data.get("mappings", []) if isinstance(mapping_data, Mapping) else []
        resolved = [
            _mapping_from_dict(item)
            for item in raw_mappings
            if isinstance(item, Mapping) and item.get("status") == "resolved"
        ]
        if not resolved:
            return self._transition(
                "NEEDS_REVIEW",
                "补证阶段缺少可验证仓库映射，等待人工复核",
                updates={"last_error": "RECOVER_EVIDENCE 缺少 resolved mapping"},
                event_type="verification.recovery.missing_mapping",
            )
        mapping = max(resolved, key=lambda item: self._mapping_score(item, store, target=target)[0])
        server = ServiceAttributor(mapping=mapping).attribute(store, mapping=mapping)
        missing_predicates = tuple(
            name for name in _REQUIRED_SERVER_PREDICATES
            if not bool(server.predicates.get(name, False))
        )
        if not missing_predicates:
            return self._transition(
                "VERIFY_EVIDENCE",
                "现有证据已满足服务端强制谓词，重新执行最终校验",
                updates={"server_attribution": _compact_attribution_payload(server.to_dict())},
                event_type="verification.recovery.already_satisfied",
                evidence_ids=server.evidence_ids,
            )

        # Give the model the most useful source paths first: current server
        # candidates, the mapping's primary source path, then identity and
        # communication evidence.  Paths are still normalized and bounded by
        # the context schema before entering a prompt.
        candidate_paths: list[str] = []
        for candidate in server.candidates:
            for location in candidate.source_locations:
                if location.source_path not in candidate_paths:
                    candidate_paths.append(location.source_path)
        if mapping.source_path and mapping.source_path not in candidate_paths:
            candidate_paths.append(mapping.source_path)
        for item in store.evidence:
            if item.source_path not in candidate_paths:
                candidate_paths.append(item.source_path)
            if len(candidate_paths) >= 32:
                break
        search_path = _session_dir(self.machine) / "search_plan.json"
        search_payload = _read_json(search_path) if search_path.exists() else {"executions": []}
        if not isinstance(search_payload, dict):
            search_payload = {"executions": []}
        previous_rounds = _load_llm_rounds(self.machine)
        round_offset = len(previous_rounds)
        audits, action_keys, action_queries = self._run_llm_actions(
            target=target,
            store=store,
            search_payload=search_payload,
            phase="verification_recovery",
            missing_predicates=missing_predicates,
            candidate_paths=candidate_paths[:32],
            round_offset=round_offset,
        )
        search_payload = _compact_search_payload(search_payload)
        artifacts = _save_artifact(
            self.machine,
            "search_plan.json",
            search_payload,
            "初始检索和服务端补证阶段的查询、响应与有界动作记录。",
        )
        if audits:
            artifacts = _save_llm_rounds(self.machine, audits, phase="verification_recovery")
        _json_write(_session_dir(self.machine) / "evidence.json", store.to_dict())
        artifacts["evidence.json"] = "追加语义补证动作得到的源码行证据；下一阶段仍会重新读取和分类。"
        recovery_payload = {
            "phase": "verification_recovery",
            "missing_predicates": list(missing_predicates),
            "candidate_paths": candidate_paths[:32],
            "accepted_action_keys": action_keys,
            "accepted_action_count": len(action_keys),
            "rounds_added": len(audits),
            "evidence_count_after": len(store.evidence),
        }
        artifacts = _save_artifact(
            self.machine,
            "evidence_recovery.json",
            recovery_payload,
            "服务端谓词缺口、候选源码路径和补证动作摘要；模型结果不会直接绕过确定性归因。",
        )
        executed_values = tuple(dict.fromkeys((*self.session.executed_queries, *action_queries)))
        executed_actions = tuple(dict.fromkeys((*self.session.executed_actions, *action_keys)))
        updates = {
            "artifacts": artifacts,
            "evidence_ids": tuple(item.evidence_id for item in store.evidence),
            "executed_queries": executed_values,
            "executed_actions": executed_actions,
            "last_error": "补证阶段新增动作：" + str(len(action_keys)),
        }
        if not action_keys:
            return self._transition(
                "VERIFY_EVIDENCE",
                "补证阶段没有产生新的有效检索动作，回到最终校验并进入仓库确认",
                updates={**updates, "last_error": None},
                event_type="verification.recovery.exhausted",
                evidence_ids=server.evidence_ids,
                details={
                    "missing_predicates": list(missing_predicates),
                    "rounds_added": len(audits),
                    "planner_model_calls": self.runtime.llm_planner.model_calls,
                    "predicate_gate": "advisory",
                },
            )
        return self._transition(
            "TRACE_EVIDENCE",
            f"补证阶段新增 {len(action_keys)} 个语义检索动作，重新追踪源码证据",
            updates=updates,
            event_type="verification.recovery.completed",
            evidence_ids=tuple(item.evidence_id for item in store.evidence),
            details={
                "missing_predicates": list(missing_predicates),
                "accepted_action_keys": action_keys,
                "rounds_added": len(audits),
                "round_offset": round_offset,
            },
        )

    def _selected_mapping(self) -> RepositoryMapping:
        values = self.session.repository_mappings
        if not isinstance(values, Mapping):
            raise SourceLocatorWorkerError("session 缺少 repository_mappings")
        mappings = values.get("mappings", [])
        candidates = [_mapping_from_dict(item) for item in mappings if isinstance(item, Mapping) and item.get("status") == "resolved"]
        if not candidates:
            raise SourceLocatorWorkerError("没有可拉取的 resolved mapping")
        store = _load_evidence(self.machine)
        return max(candidates, key=lambda item: self._mapping_score(item, store, target=_target(self.session))[0])

    def _require_version_selection(
        self,
        mapping: RepositoryMapping,
        *,
        stage: str,
        reason: str,
        acquisition_status: str | None = None,
    ) -> tuple[dict[str, str], dict[str, Any]]:
        """Persist bounded remote revision choices and a resumable summary.

        A failed clone or verification is no longer represented only by a
        terminal error.  The remote query is read-only and uses the same
        allowlisted Manifest mapping; no candidate is applied automatically.
        The returned summary is deliberately small enough for ``session.json``
        while the full, user-visible list lives in its own artifact.
        """

        failure_reason = _compact(reason)
        try:
            discovery = discover_repository_versions(
                mapping,
                config=self.runtime.gitcode,
                runner=self.runtime.git_runner,
            )
            payload: dict[str, Any] = discovery.to_dict()
        except Exception as exc:  # defensive: failure recovery must not mask the original error
            discovery = None
            payload = {
                "schema_version": "openant.source-locator.repository-versions.v1",
                "status": "unavailable",
                "project_name": mapping.project_name,
                "repo_url": mapping.repo_url,
                "requested_revision": mapping.revision,
                "candidate_count": 0,
                "candidates": [],
                "commands": [],
                "reasons": [f"远程版本查询执行异常：{_compact(exc)}"],
                "warnings": [],
            }
        payload["failure"] = {
            "stage": stage,
            "reason": failure_reason,
            "acquisition_status": acquisition_status,
        }
        artifacts = _save_artifact(
            self.machine,
            "repository_version_candidates.json",
            payload,
            "Git 拉取或拉取后验证失败时生成的远程 branch/tag 候选；仅供用户选择，不会自动切换 revision。",
        )
        candidates = payload.get("candidates")
        if not isinstance(candidates, list):
            candidates = []
        candidate_revisions = tuple(
            str(item.get("revision"))
            for item in candidates[:32]
            if isinstance(item, Mapping) and isinstance(item.get("revision"), str)
        )
        status = payload.get("status") if isinstance(payload.get("status"), str) else "unavailable"
        summary: dict[str, Any] = {
            "artifact": "repository_version_candidates.json",
            "stage": stage,
            "status": status,
            "project_name": mapping.project_name,
            "repo_url": mapping.repo_url,
            "requested_revision": mapping.revision,
            "candidate_count": len(candidate_revisions),
            "candidate_revisions": list(candidate_revisions),
            "reason": failure_reason,
        }
        if discovery is not None and discovery.reasons:
            summary["discovery_reasons"] = list(discovery.reasons[:3])
        return artifacts, summary

    def _advance_clone(self) -> LocatorSession:
        if self.runtime.project_root is None:
            return self._transition("CLONE_FAILED", "未配置项目根目录，无法安全写入 source_code_base", updates={"last_error": "缺少 project_root"}, event_type="clone.missing_project_root")
        mapping = self._selected_mapping()
        manager = RepositoryManager(
            self.runtime.project_root,
            config=self.runtime.gitcode,
            runner=self.runtime.git_runner,
            on_log=lambda line: self.machine.record_event(event_type="clone.log", summary_zh=_compact(line), details={"channel": "git"}),
        )
        from .repository_manager import RepositoryConfirmation
        from .repository_policy import RepositoryPolicy

        decision = RepositoryPolicy(self.runtime.gitcode).validate_mapping(mapping)
        confirmation = RepositoryConfirmation.for_decision(decision, accepted=True, confirmation_id="worker-confirmed") if decision.allowed else None
        try:
            acquisition = manager.ensure_repository(mapping, confirmation=confirmation)
        except Exception as exc:
            artifacts, version_selection = self._require_version_selection(
                mapping,
                stage="clone",
                reason=f"Git 拉取阶段发生可解释异常：{_compact(exc)}",
            )
            return self._transition(
                "VERSION_SELECTION_REQUIRED",
                "Git 拉取异常，已生成可选择的远程版本列表",
                updates={"artifacts": artifacts, "version_selection": version_selection, "last_error": _compact(exc)},
                event_type="clone.version_selection_required",
                details={"stage": "clone", "candidate_count": version_selection["candidate_count"]},
            )
        artifacts = _save_artifact(self.machine, "clone_results.json", acquisition.to_dict(), "用户确认后执行的 Git 拉取结果、命令摘要、revision 和目录；失败时不会覆盖已有目录。")
        if not acquisition.succeeded:
            reason = "; ".join(acquisition.reasons) or acquisition.status
            version_artifacts, version_selection = self._require_version_selection(
                mapping,
                stage="clone",
                reason=reason,
                acquisition_status=acquisition.status,
            )
            artifacts = {**artifacts, **version_artifacts}
            return self._transition(
                "VERSION_SELECTION_REQUIRED",
                "Git 仓库拉取未成功，已生成可选择的远程版本列表",
                updates={"artifacts": artifacts, "version_selection": version_selection, "last_error": reason},
                event_type="clone.version_selection_required",
                details={"stage": "clone", "candidate_count": version_selection["candidate_count"], "acquisition_status": acquisition.status},
            )
        return self._transition("POST_CLONE_VERIFY", "仓库已拉取或安全复用，开始进行只读拉取后验证", updates={"artifacts": artifacts}, event_type="clone.completed")

    def _advance_post_clone_verify(self) -> LocatorSession:
        if self.runtime.project_root is None:
            return self._transition("POST_CLONE_VERIFY_FAILED", "缺少项目根目录，无法验证拉取结果", updates={"last_error": "缺少 project_root"}, event_type="post_clone_verify.missing_root")
        mapping = self._selected_mapping()
        clone = _read_json(_session_dir(self.machine) / "clone_results.json")
        acquisition = RepositoryAcquisitionResult(
            status=str(clone.get("status", "failed")),
            project_name=clone.get("project_name"),
            destination=clone.get("destination"),
            repo_url=clone.get("repo_url"),
            canonical_url=clone.get("canonical_url"),
            revision=clone.get("revision"),
            resolved_commit=clone.get("resolved_commit"),
            mapping=mapping,
        )
        target = _target(self.session)
        # A locator may have both server and client evidence from different
        # Manifest projects.  The current scanner handoff is intentionally
        # single-root, so verify only paths owned by the selected primary
        # mapping; retaining the other paths in evidence.json keeps the
        # cross-repository audit trail without making a valid primary checkout
        # fail because it cannot contain another repository's file.
        source_paths = tuple(
            dict.fromkeys(
                item.source_path
                for item in _load_evidence(self.machine).evidence
                if item.source_path.startswith("/")
                and _mapping_contains_path(item.source_path, mapping)
            )
        )
        request = PostCloneVerificationRequest(
            source_paths=source_paths[:128],
            symbols=tuple(item for item in (target.service_hint, target.macro_hint) if item),
            literals=tuple(item for item in (target.socket_path, target.basename) if item),
        )
        verifier = PostCloneVerifier(self.runtime.project_root, config=self.runtime.gitcode)
        try:
            result = verifier.verify(acquisition, mapping, request=request)
        except Exception as exc:
            return self._transition(
                "POST_CLONE_VERIFY_FAILED",
                "拉取后只读验证发生异常，禁止交接给静态扫描",
                updates={"last_error": _compact(exc)},
                event_type="post_clone_verify.exception",
            )
        artifacts = _save_artifact(self.machine, "post_clone_verification.json", result.to_dict(), "只读检查 origin、HEAD、源码文件、符号和目标字面量的结果；只有 ready 才允许交接。")
        if not result.ready:
            reason = "; ".join(result.reasons) or result.status
            version_artifacts, version_selection = self._require_version_selection(
                mapping,
                stage="post_clone_verify",
                reason=reason,
                acquisition_status=acquisition.status,
            )
            artifacts = {**artifacts, **version_artifacts}
            return self._transition(
                "VERSION_SELECTION_REQUIRED",
                "拉取后验证未通过，已生成可选择的远程版本列表",
                updates={"artifacts": artifacts, "version_selection": version_selection, "last_error": reason},
                event_type="post_clone_verify.version_selection_required",
                details={"stage": "post_clone_verify", "candidate_count": version_selection["candidate_count"]},
            )
        return self._transition("HANDOFF", "拉取后验证通过，生成静态扫描交接对象", updates={"handoff": result.handoff.to_dict() if result.handoff else None, "artifacts": artifacts}, event_type="post_clone_verify.ready")

    def _advance_handoff(self) -> LocatorSession:
        if not self.session.handoff:
            return self._transition("FAILED", "交接对象缺失，不能标记定位完成", updates={"last_error": "handoff 缺失"}, event_type="handoff.failed")
        artifacts = _save_artifact(self.machine, "source_handoff.json", self.session.handoff, "供现有静态扫描器使用的主仓库交接对象；附属客户端证据仍保留在 session。")
        return self._transition("DONE", "源码定位、仓库验证和静态扫描交接已完成", updates={"artifacts": artifacts}, event_type="handoff.completed")

    def advance(self) -> LocatorSession:
        state = self.session.state
        if state == "INTAKE":
            return self._advance_intake()
        if state == "NORMALIZE_TARGET":
            return self._advance_normalize()
        if state == "PROBE_OPENGROK":
            return self._advance_probe()
        if state == "SEARCH_INITIAL":
            return self._advance_search()
        if state == "TRACE_EVIDENCE":
            return self._advance_trace()
        if state == "ATTRIBUTION_SERVER":
            return self._advance_server()
        if state == "LOCATE_CLIENT_COMM":
            return self._advance_client()
        if state == "RESOLVE_REPOSITORIES":
            return self._advance_repositories()
        if state == "VERIFY_EVIDENCE":
            return self._advance_verify()
        if state == "RECOVER_EVIDENCE":
            return self._advance_recover()
        if state == "CLONE":
            return self._advance_clone()
        if state == "POST_CLONE_VERIFY":
            return self._advance_post_clone_verify()
        if state == "HANDOFF":
            return self._advance_handoff()
        if state in {"AWAIT_USER_CONFIRMATION", "APPLY_FEEDBACK", "VERSION_SELECTION_REQUIRED"}:
            return self.session
        return self.session

    def run_until_pause(self, *, max_steps: int = 16) -> LocatorSession:
        if isinstance(max_steps, bool) or not 1 <= max_steps <= 32:
            raise SourceLocatorWorkerError("max_steps 必须是 1 到 32 之间的整数")
        for _ in range(max_steps):
            before = self.session.state
            after = self.advance()
            if after.state in {"AWAIT_USER_CONFIRMATION", *{
                "DONE", "PARTIAL", "NEEDS_REVIEW", "OPENGROK_UNAVAILABLE", "VERSION_MISMATCH",
                "CLONE_FAILED", "POST_CLONE_VERIFY_FAILED", "VERSION_SELECTION_REQUIRED", "CANCELLED", "FAILED",
            }} or after.state == before:
                return after
        return self.session


__all__ = [
    "SourceLocatorRuntime",
    "SourceLocatorWorker",
    "SourceLocatorWorkerError",
    "runtime_from_config",
]
