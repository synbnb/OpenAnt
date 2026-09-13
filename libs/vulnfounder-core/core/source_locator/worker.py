"""有界的 source-locator worker。

这个模块把已经经过单元测试的 OpenGrok、证据、Manifest、归因和 Git
组件串成一个“每次只推进一个阶段”的 worker。它不接受 shell 字符串，
不让模型生成仓库 URL；模型若要参与，只能通过受限的检索规划器、证据
约束型角色复核器和候选仓库 PK 复核器提供下一步查询、服务端/客户端判定
或候选选择。没有
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
from .evidence_store import Evidence, EvidenceStore
from .manifest_resolver import (
    ManifestDocument,
    ManifestResolver,
    RepositoryMapping,
    load_manifest,
)
from .llm_search_planner import (
    LLM_SEARCH_DEFAULT_MAX_ACTIONS,
    LLM_SEARCH_MAX_ACTIONS,
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
from .llm_entrypoint_attributor import (
    LLMEntrypointAttributionError,
    LLMEntrypointAttributionResult,
    LLMEntrypointAttributor,
)
from .candidate_reviewer import (
    CandidateReviewError,
    LLMCandidateReviewer,
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
from .path_classifier import classify_path, is_attribution_eligible, rank_paths
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
from .target_normalizer import (
    LocatorQuery,
    TargetSpec,
    build_initial_queries,
    network_endpoint,
    normalize_target,
    target_identity_terms,
    target_relation,
)


class SourceLocatorWorkerError(ValueError):
    """Raised when a worker stage cannot be executed safely."""


_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_MAX_PATHS = 32
_MAX_HITS_PER_PATH = 8
_TRACE_CONTEXT_LINES = 64
_MAX_LLM_DUPLICATE_STREAK = 6
# A malformed/unsupported OpenGrok query should not terminate the semantic
# search after one attempt.  Let the model choose another query (with the
# failure fed back into its next context), but stop a persistent outage after
# a small consecutive-failure budget so a session remains bounded.
_MAX_LLM_EXECUTION_FAILURE_STREAK = 3
_MAX_STAGE_BYTES = 8 * 1024 * 1024
_MAX_EVENT_EVIDENCE_IDS = 256
_MAX_TRACE_EVIDENCE_PER_PATH = 128
_MAX_SEARCH_EVIDENCE = 1024
_MAX_SEARCH_ARTIFACT_PATHS_PER_EXECUTION = 32
_MAX_SEARCH_ARTIFACT_HITS_PER_PATH = 4
_MAX_SEARCH_LINE_CHARS = 2048
# Keep the checkpoint/session copy below the state-machine's 64 KiB mapping
# limit even when a generic socket basename produces many candidate roles.
# The complete evidence remains available in evidence.json and the standalone
# server_attribution.json artifact is still bounded independently.
_MAX_ATTRIBUTION_CANDIDATES = 32
_MAX_ATTRIBUTION_EVIDENCE_IDS = 256
# Repository resolution attaches project-wide evidence to each Manifest row so
# it can be ranked correctly.  That full list belongs in
# repository_resolutions.json, not in the 64 KiB session checkpoint.
_MAX_SESSION_REPOSITORY_MAPPINGS = 32
_MAX_SESSION_MAPPING_EVIDENCE_IDS = 64
_MAX_SESSION_EVIDENCE_IDS = 512
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
# A socket locator must expose the actual external-input entry functions as a
# separate, auditable artifact.  These limits keep a large generated source
# file from making the confirmation checkpoint or the web page unbounded.
_ENTRYPOINT_EVIDENCE_KINDS = frozenset({"socket_accept_read", "protocol_dispatch"})
_ENTRYPOINT_ROLES = frozenset({"server_consumer", "server_handler"})
_ENTRYPOINT_SOURCE_ANCHOR_KINDS = frozenset(
    {
        *_ENTRYPOINT_EVIDENCE_KINDS,
        "socket_server_registration",
        "socket_bind_listen",
    }
)
# Candidate roles are produced from target-scoped attribution evidence.  A
# named socket is often declared in an init ``.cfg`` while the process-side
# listener lives in a sibling source file, so an entrypoint need not repeat
# the socket name in its own ``recv``/``accept`` line.  These role facts are
# the narrow bridge between the two files; they are not a repository-wide
# permission to promote every generic receive hit.
_SERVER_CANDIDATE_ROLES = frozenset(
    {"socket_creator", "service_owner", "server_consumer", "server_handler"}
)
_MAX_ENTRYPOINT_FUNCTIONS = 32
# The semantic review receives at most the same bounded number of function
# candidates as the final artifact.  Candidate discovery remains deterministic
# and any omitted rows are reported as a truncation rather than implicitly
# considered safe or accepted.
_MAX_LLM_ENTRYPOINT_CANDIDATES = 32
_MAX_ENTRYPOINT_SOURCE_CHARS = 128 * 1024
_MAX_ENTRYPOINT_READ_BYTES = 512 * 1024
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
_NETWORK_GENERIC_QUERY_TERMS = frozenset(
    {
        "bind",
        "socket",
        "serversocket",
        "threadsocket",
        "handlemsg",
        "accept",
        "recv",
        "recvfrom",
        "read",
        "connect",
        "send",
        "sendto",
        "write",
        "sin_port",
        "sockaddr_in",
        "sock_dgram",
        "sock_stream",
        "af_inet",
        "af_inet6",
        "inet_addr",
        "inet_pton",
        "inaddr_loopback",
        "htons",
        "htonl",
    }
)
# Named sockets use the same bounded API probes as network sockets, but also
# need the OpenHarmony descriptor helper and build/config metadata.  Keeping a
# single generic-query vocabulary lets the evidence gate distinguish recall
# probes from target-bearing lines for both target types.
_SOCKET_GENERIC_QUERY_TERMS = _NETWORK_GENERIC_QUERY_TERMS | frozenset(
    {
        "getcontrolsocket",
        "getserversocket",
        "getsocket",
        "socketpair",
        "socketdevice",
        "listen",
        "build.gn",
        "bundle.json",
        "ohos_executable",
        "part_name",
        "subsystem_name",
    }
)
_COMMUNICATION_EVIDENCE_KINDS = frozenset(
    {
        "socket_server_registration",
        "socket_acquire",
        "socket_bind_listen",
        "socket_accept_read",
        "protocol_dispatch",
        "client_endpoint",
        "client_connect",
        "client_send",
        "protocol_construction",
    }
)
# Only these source facts are allowed to establish a cross-file module
# context.  A basename/literal hit is still retained in the evidence graph,
# but it must not make every neighbouring ``socket``/``bind`` call look like
# the target service.  This is particularly important for common names such
# as ``native`` and for SELinux/generated files that repeat socket labels.
_STRONG_CONTEXT_KINDS = _COMMUNICATION_EVIDENCE_KINDS | frozenset(
    {
        "service_config",
        "executable_build",
        "macro_definition",
        "constant_definition",
    }
)
_PATH_ROLE_PENALTIES = {
    # These paths remain candidates and remain visible in artifacts.  The
    # adjustment only prevents policy/generated/log records from outranking a
    # production listener when the same token appears in both places.
    "selinux": -110,
    "log": -90,
    "generated": -65,
    "build": -48,
    "unknown": -28,
    "kernel": -24,
    "third_party": -16,
}
# Directory names that describe repository layout rather than a component.
# They are intentionally used only when comparing two already collected
# context paths; they do not remove candidates or evidence.  Without this
# distinction, an anchor under ``services/etc/init`` makes every sibling
# ``recv``/``GetControlSocket`` hit under ``services`` look related.
_CONTEXT_STRUCTURAL_TOKENS = frozenset(
    {
        "base",
        "build",
        "client",
        "clients",
        "common",
        "component",
        "components",
        "daemon",
        "daemons",
        "device",
        "devices",
        "etc",
        "framework",
        "frameworks",
        "generated",
        "gen",
        "host",
        "hosts",
        "include",
        "init",
        "innerkit",
        "innerkits",
        "interface",
        "interfaces",
        "kernel",
        "linux",
        "manager",
        "managers",
        "module",
        "modules",
        "out",
        "server",
        "servers",
        "service",
        "services",
        "socket",
        "sockets",
        "src",
        "standard",
        "startup",
        "test",
        "tests",
        "testing",
        "tool",
        "tools",
    }
)
_NETWORK_SOURCE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:socket|bind|listen|accept|recv(?:from|msg|mmsg)?|send(?:to)?|connect|"
    r"sin_port|sockaddr(?:_in)?|sock_dgram|sock_stream|af_inet6?|"
    r"inet_addr|inet_pton|inaddr_loopback|htons|htonl|\w*port\w*|udp|tcp)\b"
)
_NETWORK_SOCKET_CONTEXT_RE = re.compile(
    r"(?i)\b(?:socket|bind|listen|accept|recv(?:from|msg|mmsg)?|send(?:to)?|connect|"
    r"sin_port|sockaddr(?:_in)?|sock_dgram|sock_stream|af_inet6?|"
    r"inet_addr|inet_pton|inaddr_loopback|htons|htonl)\b"
)

# ``recvmsg`` is used by several OpenHarmony services (notably appspawn) to
# receive ancillary file descriptors.  It must be treated as an inbound
# socket operation even though a plain ``recv`` search does not always return
# it from OpenGrok.  These expressions are also used by the bounded local
# scan after a target-related candidate file has been selected.
_SOCKET_NETWORK_RECEIVE_CALL_RE = re.compile(
    r"\b(?:accept|recv(?:from|msg|mmsg)?)\s*\(",
    re.IGNORECASE,
)
_SOCKET_READ_CALL_RE = re.compile(r"\b(?:readv?|readmsg)\s*\(", re.IGNORECASE)
_SOCKET_RECEIVE_CALL_RE = re.compile(
    r"\b(?:accept|recv(?:from|msg|mmsg)?|readv?|readmsg)\s*\(",
    re.IGNORECASE,
)
_SOCKET_FD_HINT_RE = re.compile(
    r"(?i)\b(?:socket|sockfd|socketfd|serverfd|listenfd|clientfd|unixfd)\w*\b"
)
_SOCKET_DISPATCH_LINE_RE = re.compile(
    r"\b(?:onreceive(?:request|message)?\w*|onrecv(?:message)?\w*|"
    r"handle(?:recv|msg|message)\w*|process(?:recv|msg|message|request)\w*|"
    r"messagehandler\w*|recvmessage\w*)\b",
    re.IGNORECASE,
)
_SOCKET_SERVER_ANCHOR_RE = re.compile(
    r"\b(?:getcontrolsocket|getserversocket|bind|listen|accept|"
    r"create\w*server|\w*servercreate|serverinit)\s*\(",
    re.IGNORECASE,
)
_SOCKET_CLIENT_CONNECT_RE = re.compile(
    r"\b(?:connect|connectserver|getclientsocket)\s*\(",
    re.IGNORECASE,
)


def _strip_source_comments(line: str) -> str:
    """Remove comments from one bounded source hit before semantic checks.

    OpenGrok returns individual lines rather than a complete translation unit.
    A line-local pass is therefore sufficient to prevent comments such as
    ``// hisysevent.h`` from becoming identity or macro evidence.  Keep
    ``://`` intact so a string literal containing a URL is not truncated while
    still removing the usual trailing C/C++ comment.
    """

    value = str(line)
    value = re.sub(r"/\*.*?\*/", "", value)
    return re.sub(r"(?<!:)//.*$", "", value)


def _macro_name_is_socket_related(name: str, target: TargetSpec) -> bool:
    """Return whether a macro/constant name is related to this socket.

    A target token in a macro name is not enough by itself: ``HISYSEVENT_MAX``
    is an event constant, while ``HISYSEVENT_SOCKET_NAME`` is an endpoint
    alias.  Require either an exact target name or a target-prefixed name with
    a socket/service/path suffix.  This keeps useful aliases while rejecting
    generic constants and comments.
    """

    if not isinstance(name, str) or not name.strip() or not isinstance(target, TargetSpec):
        return False
    compact_name = re.sub(r"[^a-z0-9]", "", name.casefold())
    if not compact_name:
        return False
    target_values = (
        target.basename,
        target.service_hint,
        target.macro_hint,
        target.process_hint,
    )
    for raw_value in target_values:
        if not raw_value:
            continue
        compact_value = re.sub(r"[^a-z0-9]", "", str(raw_value).casefold())
        if not compact_value:
            continue
        if compact_name == compact_value:
            return True
        if not compact_name.startswith(compact_value):
            continue
        suffix = compact_name[len(compact_value):]
        if suffix and re.search(r"(?:socket|sock|pipe|endpoint|service|server|path|name|fd)", suffix):
            return True
    return False


def _network_operation_matches_target(line: str, target: TargetSpec) -> bool:
    """Reject a concrete operation that belongs to the other transport."""

    if target.target_type != "network_socket":
        return True
    lower = str(line).lower()
    if target.transport == "UDP":
        return not (
            re.search(r"\bsock_stream\b", lower)
            or re.search(r"\blisten\s*\(", lower)
            or re.search(r"\baccept\s*\(", lower)
        )
    return not (
        re.search(r"\bsock_dgram\b", lower)
        or re.search(r"\brecvfrom\s*\(", lower)
        or re.search(r"\bsendto\s*\(", lower)
    )


def _named_socket_operation_matches_target(line: str, target: TargetSpec) -> bool:
    """Reject explicit non-Unix or differently named socket operations.

    A named OpenHarmony socket is commonly acquired through
    ``GetControlSocket`` and therefore has no literal ``AF_UNIX`` on the
    service line.  The same module can nevertheless contain TCP/UDP proxy,
    netlink and VPN sockets.  Those operations must not become evidence for a
    named socket merely because they share a directory context.
    """

    if target.target_type == "network_socket":
        return True
    code_line = _strip_source_comments(line).casefold()
    if re.search(
        r"\b(?:af|pf)_inet6?\b|\bsockaddr_in6?\b|\bipproto_(?:tcp|udp)\b|"
        r"\binaddr_(?:any|loopback)\b",
        code_line,
    ):
        return False
    named_socket_call = re.search(
        r"\b(?:getcontrolsocket|getserversocket|getsocket)\s*\(\s*['\"]([^'\"]+)['\"]",
        code_line,
    )
    if named_socket_call is not None:
        requested_name = named_socket_call.group(1).strip().casefold()
        target_names = {
            str(value).strip().casefold()
            for value in (target.basename, target.service_hint, target.process_hint)
            if value
        }
        if requested_name and requested_name not in target_names:
            return False
    return True


def _socket_anchor_line_matches_target(line: str, target: TargetSpec) -> bool:
    """Reject a sibling service macro when scanning a shared implementation.

    A file can initialize several init-created descriptors (for example
    appspawn and nwebspawn).  Generic ``socketName``/``PIPE_NAME`` arguments
    remain useful component evidence, while a concrete ``NWEBSPAWN_*`` macro
    must not be attributed to a ``CJAppSpawn`` target.
    """

    if target.target_type == "network_socket":
        return True
    code_line = _strip_source_comments(line)
    macro_refs = re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b", code_line)
    macro_refs = [
        ref
        for ref in macro_refs
        if re.search(r"_(?:SOCKET|PIPE|ENDPOINT|PATH|NAME|FD)(?:_|$)", ref)
    ]
    if not macro_refs:
        return True
    generic_roots = {"socket", "sock", "pipe", "name", "path", "fd"}
    target_compact = re.sub(
        r"[^a-z0-9]",
        "",
        str(target.basename or target.service_hint or "").casefold(),
    )
    specific_refs = []
    for ref in macro_refs:
        root = re.sub(
            r"(?:_(?:SOCKET|PIPE|ENDPOINT|PATH|NAME|FD))(?:_[A-Z0-9_]+)?$",
            "",
            ref.casefold(),
        )
        if root and root not in generic_roots:
            specific_refs.append(root)
    if not specific_refs:
        return True
    return any(target_compact and (root == target_compact or target_compact.endswith(root)) for root in specific_refs)


def _named_socket_path_has_conflict(
    path: str,
    executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
) -> bool:
    """Return whether a named-socket file visibly belongs to another socket.

    This is a ranking/evidence-quality signal, not a hard path exclusion.  A
    service file can legitimately handle more than one endpoint; callers that
    contain an explicit target identity remain eligible.  The signal only
    stops target-agnostic ``socket``/``recv`` lines in an IPv4, netlink or
    differently named-socket implementation from inheriting the target's
    directory context.
    """

    if target.target_type == "network_socket":
        return False
    target_names = {
        str(value).strip().casefold()
        for value in (target.basename, target.service_hint, target.process_hint)
        if value
    }
    for execution in executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        response = execution.get("response")
        results = response.get("results") if isinstance(response, Mapping) else None
        hits = results.get(path) if isinstance(results, Mapping) else None
        if not isinstance(hits, list):
            continue
        for hit in hits:
            if not isinstance(hit, Mapping) or not isinstance(hit.get("line"), str):
                continue
            code_line = _strip_source_comments(hit["line"]).casefold()
            if re.search(
                r"\b(?:af|pf)_inet6?\b|\bpf_netlink\b|\bsockaddr_in6?\b|"
                r"\bipproto_(?:tcp|udp)\b|\binaddr_(?:any|loopback)\b|\bnetlink_",
                code_line,
            ):
                return True
            named_call = re.search(
                r"\b(?:getcontrolsocket|getserversocket|getsocket|socketdevice)\s*\(\s*['\"]([^'\"]+)['\"]",
                code_line,
            )
            if named_call is not None and named_call.group(1).strip().casefold() not in target_names:
                return True
    return False


def _named_socket_conflicting_paths(
    executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
) -> frozenset[str]:
    """Collect named-socket paths with explicit competing transport/name facts."""

    if target.target_type == "network_socket":
        return frozenset()
    paths: set[str] = set()
    for execution in executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        response = execution.get("response")
        results = response.get("results") if isinstance(response, Mapping) else None
        if not isinstance(results, Mapping):
            continue
        paths.update(path for path in results if isinstance(path, str))
    return frozenset(
        path
        for path in paths
        if _named_socket_path_has_conflict(path, executions, target)
    )


def _search_hit_is_target_evidence(
    execution: Mapping[str, Any],
    hit: Any,
    target: TargetSpec,
) -> bool:
    """Decide whether one search hit is source evidence, not just a candidate.

    The deterministic network plan intentionally includes broad API queries
    (``bind``, ``recvfrom``, ``socket`` and friends) to recover implementations
    whose port is hidden behind a macro.  Those queries must not turn every
    unrelated API occurrence into a socket identity/ownership fact.  Candidate
    paths remain in ``search_plan.json``; only a source line carrying the
    endpoint/process or an unmistakable network context enters ``evidence``.
    """

    if not isinstance(execution, Mapping) or not isinstance(hit, Mapping):
        return False
    line = hit.get("line")
    if not isinstance(line, str) or not line.strip() or line.strip() in {"...", "…"}:
        # Path searches often return an ellipsis placeholder.  It identifies a
        # candidate path but contains no source fact that can support a role.
        return False
    query = execution.get("query")
    query_kind = query.get("kind") if isinstance(query, Mapping) else None
    query_value = query.get("value") if isinstance(query, Mapping) else None
    path = execution.get("path")
    path_context_dirs = execution.get("target_context_dirs")
    if not isinstance(path, str):
        path = ""
    if path and not _is_locator_evidence_path(path):
        # Dependency/object/ccache records can repeat a process name, port or
        # basename, but they are not source/config facts and cannot anchor a
        # communication context.  Keep those paths in search_plan and path
        # classification for auditability; discard them only at evidence.
        return False
    if path and not is_attribution_eligible(path, target=target):
        # Explicit test/fuzz paths can contain the same port, basename and
        # POSIX calls as the real daemon.  They remain candidates for audit,
        # but must not establish a target context or positive role evidence.
        return False
    if target.target_type == "network_socket" and not _network_operation_matches_target(line, target):
        return False
    if target.target_type != "network_socket" and not _named_socket_operation_matches_target(line, target):
        return False
    if query_kind == "path":
        # ``search_path`` responses are intentionally path-oriented and some
        # OpenGrok backends return only an ellipsis/first line for each file.
        # A path match is a candidate anchor, not source evidence, unless the
        # returned line itself carries the endpoint identity.  Treating every
        # line-1 placeholder as evidence would make a broad path query promote
        # unrelated files into the server/client graph.
        return _line_has_target_identity(line, target)
    context_match = _path_shares_target_context(path, path_context_dirs)
    path_identity = _path_contains_target_identity(path, target)
    path_conflict = bool(execution.get("target_path_conflict"))
    line_kind = _line_kind(
        line,
        target,
        query_kind=query_kind,
        query_value=query_value,
    )
    has_identity = _line_has_target_identity(line, target)
    query_specific = _query_value_targets_target(query_value, target)
    if target.target_type != "network_socket":
        query_text = str(query_value or "").strip().casefold()
        alias_query = _is_socket_alias_query(query_value, target)
        if alias_query:
            # ``DNS_SOCKET_NAME``/``APP_SPAWN_SOCKET`` is often the only token
            # present in the server implementation.  Such aliases are
            # accepted only in the same bounded module context established by
            # a concrete path/config identity (or when their definition line
            # itself contains the target value).  A follow-up query for an
            # alias that was *already inferred from this target's definition*
            # is also allowed to establish a source-backed bridge when the
            # line contains the alias and a socket/config fact.  This is the
            # common split-file pattern where init.c uses
            # ``INIT_HOLDER_SOCKET_PATH`` while the literal lives in a header;
            # it remains bounded because arbitrary model symbols are never
            # accepted by ``_is_socket_alias_query``.
            return (
                has_identity
                or (
                    (context_match or path_identity)
                    and line_kind
                    in (
                        _COMMUNICATION_EVIDENCE_KINDS
                        | {"service_config", "executable_build"}
                    )
                )
                or (
                    isinstance(query_value, str)
                    and _line_contains_identity(line, [query_value])
                    and line_kind
                    in (
                        _COMMUNICATION_EVIDENCE_KINDS
                        | {"service_config", "executable_build"}
                    )
                    and _is_locator_evidence_path(path)
                )
            )
        if query_text in _SOCKET_GENERIC_QUERY_TERMS:
            # Generic API/config/build probes are useful only after a concrete
            # path/basename/config hit established a bounded module directory.
            # An identity-bearing line is enough on its own; otherwise the
            # sibling-directory relationship must be present and the line
            # must describe a socket/server/build fact.
            if path_conflict and not has_identity:
                return False
            return (
                has_identity
                or (
                    (context_match or path_identity)
                    and line_kind
                    in (
                        _COMMUNICATION_EVIDENCE_KINDS
                        | {"service_config", "executable_build"}
                    )
                )
            )
        # Unix path/basename/macro hits are already target-specific.  Keep
        # normal source lines, but do not promote an unrelated communication
        # API just because a broad semantic query happened to find it.
        # A target-specific full-text query should normally return the line
        # containing that target.  Do not trust the query value alone: an
        # index may return a nearby/first line, and accepting it would turn a
        # common basename (``AppSpawn``/``native``) into evidence for every
        # matching client or generated file.  The target-bearing line itself
        # remains accepted through ``has_identity`` and can anchor its bounded
        # source window in ``_advance_trace``.
        return has_identity

    # Numeric ports occur in lookup tables, generated data and unrelated test
    # fixtures.  A port-bearing line is useful only when it is accompanied by
    # a network API/field or by the explicitly supplied process hint.
    query_text = str(query_value or "").strip().casefold()
    has_network_context = bool(_NETWORK_SOURCE_CONTEXT_RE.search(line))
    endpoint_query = bool(
        target.target_type == "network_socket"
        and network_endpoint(target)
        and query_text == str(network_endpoint(target)).casefold()
    )
    address_query = bool(
        target.target_type == "network_socket"
        and target.address
        and query_text == target.address.casefold()
    )
    port_query = bool(
        target.target_type == "network_socket"
        and target.port is not None
        and query_text == str(target.port).casefold()
    )
    process_query = bool(
        target.process_hint
        and isinstance(query_value, str)
        and query_value.strip().casefold() == target.process_hint.casefold()
    )
    if process_query:
        # A process name is useful for candidate-path recall, but it is not a
        # socket fact by itself: log macros, command help and unrelated
        # process-management code routinely mention ``SP_daemon``.  Promote a
        # process-query hit only when the same source line also carries a
        # network primitive/field; the bounded trace can then expand to the
        # surrounding server implementation.
        return bool(_NETWORK_SOCKET_CONTEXT_RE.search(line)) and _is_network_source_path(path)
    if address_query:
        # A loopback address is common in proxy defaults, firewall rules and
        # documentation.  It becomes socket evidence only when the same line
        # contains a concrete socket/network primitive or field and comes
        # from a source/header file.  This prevents an unrelated
        # ``LOOP_BACK_ADDR`` macro from establishing a repository context for
        # a different endpoint that happens to use 127.0.0.1.
        return bool(_NETWORK_SOCKET_CONTEXT_RE.search(line)) and _is_network_source_path(path)
    if endpoint_query:
        # A complete endpoint in a service configuration is a useful identity
        # anchor even when the config line has no POSIX API.  It still cannot
        # establish a service implementation context by itself unless
        # ``_line_kind`` classifies it as service/build metadata.
        return bool(has_identity and _is_locator_evidence_path(path))
    if query_value and str(query_value).strip().casefold() in _NETWORK_GENERIC_QUERY_TERMS:
        # Generic API/field queries are recall probes.  A target-specific line
        # is sufficient, but a source hit in the same directory as a strong
        # port/process/header hit is also a useful bounded cross-file anchor.
        # This matters when the implementation uses ``htons(sockPort)`` in a
        # .cpp while the concrete 8283/8284/8285 constants live in a sibling
        # header.  Keep the relaxation limited to real C/C++ source files so
        # .d/.o/ccache and other generated records cannot become evidence.
        # Wrapper declarations/constructors such as ``SpServerSocket`` and
        # dispatch methods such as ``HandleMsg`` may not contain a POSIX API
        # word on the hit line.  Once the target's bounded module context is
        # established, their classified server/dispatch kind is still useful
        # evidence; unrelated ``socket``/``bind`` lines continue to require
        # an actual network primitive.
        if (
            line_kind in {"socket_server_registration", "protocol_dispatch"}
            and (has_identity or context_match)
            and _is_network_source_path(path)
        ):
            return True
        return (has_identity or context_match) and has_network_context and _is_network_source_path(path)
    if query_value and str(query_value).strip().casefold() in {"build.gn", "bundle.json", "ohos_executable", "part_name", "subsystem_name"}:
        # Build metadata is not a network source file, but it can confirm the
        # executable/component owning a port once a concrete port hit has
        # established the same bounded module context.
        return (
            (has_identity or context_match)
            and line_kind in {"executable_build", "service_config"}
            and _is_locator_evidence_path(path)
        )
    if not has_identity and not query_specific:
        return False
    if port_query and str(target.port) in line and not has_network_context:
        return bool(target.process_hint and target.process_hint.casefold() in line.casefold())
    if line_kind in _COMMUNICATION_EVIDENCE_KINDS:
        return has_identity or (query_specific and has_network_context)
    return has_identity or query_specific


def _is_network_source_path(path: str) -> bool:
    """Return whether a path can carry network implementation evidence.

    Search responses may include dependency files, object metadata and other
    generated records.  They remain visible as candidates, but only source
    files should establish a socket operation or anchor a nearby source
    window.
    """

    if not isinstance(path, str) or not path.strip():
        return False
    lowered = path.rsplit("/", 1)[-1].casefold()
    return lowered.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"))


def _path_role_adjustment(path: str, target: TargetSpec) -> int:
    """Return a ranking adjustment for non-production path signals.

    ``path_classifier`` deliberately keeps generated, kernel, third-party,
    build and SELinux paths in the candidate set.  They are useful evidence
    in some repositories, so this is not a hard filter.  The adjustment is
    applied only by the socket-specific ranking functions and makes a source
    implementation win over a generated dependency or a policy label when
    both contain the same socket name.
    """

    try:
        classification = classify_path(path, target=target)
    except (TypeError, ValueError):
        return -200
    signals = set(classification.path_signals)
    adjustment = 0
    for signal, penalty in _PATH_ROLE_PENALTIES.items():
        if signal in signals:
            adjustment += penalty
    return adjustment


def _path_is_client_like(path: str) -> bool:
    """Recognize a client-oriented source path without excluding it.

    OpenHarmony keeps several client libraries next to the service itself and
    they often repeat the same socket constants.  This helper is used only by
    the ranking score: a client path remains a visible candidate and can win
    when it also contains a real listener operation.
    """

    if not isinstance(path, str) or not path.strip():
        return False
    lowered = path.casefold()
    components = [part for part in lowered.split("/") if part]
    client_component = re.compile(r"(?:^|[_-])client(?:$|[_-])")
    return any(part in {"client", "clients"} or client_component.search(part) for part in components)


def _context_path_tokens(path: str) -> frozenset[str]:
    """Return component-oriented tokens for one source directory.

    The first component after ``openharmony``/``ohos`` is the repository
    root, not a useful relationship by itself, so it is omitted.  Remaining
    components are split on common delimiters and layout words are removed.
    A compact joined token (``fault_logger`` -> ``faultlogger``) preserves
    useful relationships between a config directory named ``faultloggerd``
    and a source file directory named ``fault_logger_server``.
    """

    if not isinstance(path, str) or not path.strip():
        return frozenset()
    parts = [part.casefold() for part in path.split("/") if part]
    if not parts:
        return frozenset()
    if parts[0] in {"openharmony", "ohos"}:
        parts = parts[2:]
    elif len(parts) > 1:
        # OpenGrok normally includes the project prefix, but tests and some
        # backends return source-tree-relative paths.
        parts = parts[1:]
    tokens: set[str] = set()
    for component in parts:
        stem = component.rsplit(".", 1)[0]
        pieces = [
            piece
            for piece in re.split(r"[^a-z0-9]+", stem)
            if piece and piece not in _CONTEXT_STRUCTURAL_TOKENS and len(piece) >= 3
        ]
        if not pieces:
            continue
        tokens.update(pieces)
        compact = "".join(pieces)
        if len(compact) >= 4:
            tokens.add(compact)
    return frozenset(tokens)


def _context_tokens_overlap(left: frozenset[str], right: frozenset[str]) -> set[str]:
    """Return bounded semantic token overlaps between two path contexts."""

    overlap = set(left & right)
    if overlap:
        return set(overlap)
    # Config/source naming differs mainly by a suffix (``netsys`` vs
    # ``netsysnative``) or a trailing role word (``faultlogger`` vs
    # ``faultloggerd``).  Permit only long, exact-prefix matches to avoid
    # treating short generic fragments such as ``net`` or ``audio`` as a
    # module relationship.
    for left_token in left:
        for right_token in right:
            shorter, longer = sorted((left_token, right_token), key=len)
            if len(shorter) >= 6 and longer.startswith(shorter):
                overlap.add(shorter)
    return overlap


def _path_shares_target_context(path: str, context_dirs: Any) -> bool:
    """Check a bounded same-directory relationship supplied by this worker.

    The relationship is deliberately weaker than an ownership claim: it only
    lets a generic ``sin_port``/``socket`` hit anchor source tracing after a
    target-bearing hit established the directory.  The final server/client
    attribution still uses operation kinds, path ranking and Manifest data.
    """

    if not isinstance(path, str) or not path.strip() or not isinstance(context_dirs, (list, tuple, set, frozenset)):
        return False
    parent = path.rsplit("/", 1)[0] or "/"
    normalized = {
        value.rstrip("/") or "/"
        for value in context_dirs
        if isinstance(value, str)
        and value
        # Never treat /openharmony or another two-component root as a socket
        # context; doing so would make every generic recv/bind hit eligible.
        and len([part for part in value.split("/") if part]) >= 3
    }
    candidate_tokens = _context_path_tokens(parent)
    if parent in normalized:
        # An exact, deeply nested source directory can itself be the only
        # available component anchor (for example
        # ``services/init/standard`` around an init-created fd-holder
        # service).  Keep that direct relationship, but do not grant the same
        # exception to broad roots such as ``services`` or ``src``.
        parent_parts = [part for part in parent.split("/") if part]
        if len(parent_parts) >= 6:
            return True
    if not candidate_tokens:
        return False
    # Header/source pairs commonly live in sibling ``include``/``src``
    # directories.  Init ``.cfg`` files can be one or two levels below a
    # component's ``services`` directory, so compare a small ancestor window
    # instead of accepting a broad structural directory verbatim.
    candidate_dirs = [parent]
    current = parent
    for _depth in range(3):
        current = current.rsplit("/", 1)[0] or "/"
        candidate_dirs.append(current)
    # ``_target_context_directories`` keeps a bounded ancestor window so
    # split config/source layouts can be bridged.  An ancestor with fewer
    # semantic tokens is not itself a component anchor when a more specific
    # descendant was collected (for example ``netmanagernative`` below
    # ``netmanagernative/.../netsys``).  Ignoring that broad ancestor prevents
    # DNS/VPN siblings from being connected through a repository module root.
    specific_contexts: list[tuple[str, frozenset[str]]] = []
    for context_dir in normalized:
        context_tokens = _context_path_tokens(context_dir)
        if not context_tokens:
            continue
        context_prefix = context_dir.rstrip("/") + "/"
        has_specific_descendant = any(
            other != context_dir
            and other.startswith(context_prefix)
            and len(_context_path_tokens(other)) > len(context_tokens)
            for other in normalized
        )
        if not has_specific_descendant:
            specific_contexts.append((context_dir, context_tokens))
    for candidate_dir in candidate_dirs:
        candidate_dir_tokens = _context_path_tokens(candidate_dir)
        if not candidate_dir_tokens:
            continue
        for context_dir, context_tokens in specific_contexts:
            overlap = _context_tokens_overlap(candidate_dir_tokens, context_tokens)
            # A single semantic token is enough for a narrowly named
            # component (``param`` or ``netsys``).  When the context contains
            # multiple tokens, require two so repository-wide prefixes such
            # as ``communication_netmanager_base`` cannot connect unrelated
            # VPN/DNS manager siblings merely because they share a root.
            required = 1 if len(context_tokens) == 1 else 2
            if len(overlap) >= required:
                return True
    return False


def _network_path_priority(
    path: str,
    executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
    context_dirs: Any,
) -> int:
    """Score network candidate paths using observed target anchors.

    Generic ``socket``/``bind`` searches produce many valid source files.  A
    path-ranking score based only on directory vocabulary can therefore push
    the real server implementation below unrelated networking code.  This
    bounded score prefers paths that share a module directory with a concrete
    port/header hit and that contain server-socket source operations, while
    retaining every candidate for the audit artifact.
    """

    if target.target_type != "network_socket":
        return 0
    if not _is_network_source_path(path) or not is_attribution_eligible(path, target=target):
        return -10_000
    score = 0
    score += _path_role_adjustment(path, target)
    if _path_shares_target_context(path, context_dirs):
        score += 120
    filename = path.rsplit("/", 1)[-1].casefold()
    if "socket" in filename:
        score += 24
    if "server" in filename or "daemon" in filename:
        score += 18

    target_values = {
        str(value).casefold()
        for value in (
            target.port,
            target.address,
            network_endpoint(target),
            target.process_hint,
        )
        if value is not None
    }
    server_hits = 0
    client_hits = 0
    target_anchor_hits = 0
    path_client_like = _path_is_client_like(path)
    lowered_path = path.casefold()
    for execution in executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        response = execution.get("response")
        results = response.get("results") if isinstance(response, Mapping) else None
        raw_hits = results.get(path) if isinstance(results, Mapping) else None
        if not isinstance(raw_hits, list):
            continue
        query = execution.get("query")
        query_value = query.get("value") if isinstance(query, Mapping) else None
        query_text = str(query_value or "").strip().casefold()
        is_generic = query_text in _NETWORK_GENERIC_QUERY_TERMS
        is_target_query = query_text in target_values
        for raw_hit in raw_hits[:_MAX_SEARCH_ARTIFACT_HITS_PER_PATH]:
            if not isinstance(raw_hit, Mapping):
                continue
            line = raw_hit.get("line")
            if not isinstance(line, str):
                continue
            # Keep ranking on the same evidence boundary as the trace.  A
            # broad ``socket``/``bind`` query can return perfectly valid
            # networking code from an unrelated component; counting those
            # raw hits here would let a path outrank the actual listener even
            # though the hit is rejected by ``_search_hit_is_target_evidence``.
            # Candidate paths remain available in the search artifact, while
            # only accepted, target-related lines contribute ownership score.
            evidence_execution = {
                "path": path,
                "query": query,
                "target_context_dirs": context_dirs,
            }
            if not _search_hit_is_target_evidence(evidence_execution, raw_hit, target):
                continue
            kind = _line_kind(
                line,
                target,
                query_kind=query.get("kind") if isinstance(query, Mapping) else None,
                query_value=query_value,
            )
            if kind in {
                "socket_server_registration",
                "socket_acquire",
                "socket_bind_listen",
                "socket_accept_read",
                "protocol_dispatch",
            }:
                # ``socket()`` is direction-neutral.  A client library often
                # creates its own descriptor and then connects, so counting
                # every socket-acquire line as a server signal lets clients
                # outrank the listener.  GetControlSocket/socketpair and
                # service-side paths remain server evidence; an explicit
                # client path is counted on the client side.
                if kind == "socket_acquire" and (
                    path_client_like
                    or (
                        "/interfaces/innerkits/" in lowered_path
                        and not re.search(r"/(?:service|server|daemon|init)(?:/|$)", lowered_path)
                    )
                ) and not re.search(r"\b(?:getcontrolsocket|socketpair)\s*\(", line.casefold()):
                    client_hits += 1
                else:
                    server_hits += 1
            elif kind in {
                "client_endpoint",
                "client_connect",
                "client_send",
                "protocol_construction",
            }:
                client_hits += 1
            if is_target_query:
                if target.port is not None and str(target.port) in line:
                    score += 80
                    target_anchor_hits += 1
                    # A concrete port in a bind/receive path is substantially
                    # stronger than the same port in a client constant or
                    # documentation string.  Keep the latter as a candidate
                    # but prefer the server branch for attribution.
                    if kind in {
                        "socket_server_registration",
                        "socket_acquire",
                        "socket_bind_listen",
                        "socket_accept_read",
                        "protocol_dispatch",
                    }:
                        score += 48
                    elif kind in {
                        "client_endpoint",
                        "client_connect",
                        "client_send",
                        "protocol_construction",
                    }:
                        score += 4
                if target.process_hint and target.process_hint.casefold() in line.casefold():
                    score += 35 if _NETWORK_SOURCE_CONTEXT_RE.search(line) else 8
            elif is_generic:
                if kind in {
                    "socket_server_registration",
                    "socket_acquire",
                    "socket_bind_listen",
                    "socket_accept_read",
                    "protocol_dispatch",
                }:
                    score += 18
                elif kind in {
                    "client_endpoint",
                    "client_connect",
                    "client_send",
                    "protocol_construction",
                }:
                    score += 3
    score += min(server_hits, 4) * 44
    score += min(target_anchor_hits, 4) * 8
    # A path containing only connect/send/client protocol work is an
    # associated dependency, not the owner of the listening endpoint.
    if path_client_like and server_hits == 0:
        score -= 150
    elif path_client_like and client_hits > server_hits:
        score -= 70
    if server_hits == 0:
        score -= min(client_hits, 4) * 24
    else:
        score -= min(client_hits, 3) * 4
    return score


def _unix_path_priority(
    path: str,
    executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
    context_dirs: Any,
) -> int:
    """Rank named-socket candidates by config -> server-chain evidence.

    A basename such as ``native`` or ``AppSpawn`` is common across client,
    test and generated files.  The score therefore rewards an exact config
    or source identity, the same module directory, and server-side operations
    (``GetControlSocket``/``bind``/``listen``/``recv``).  It never removes a
    candidate; attribution_eligible remains the only hard path filter.
    """

    if target.target_type == "network_socket":
        return 0
    if not _is_locator_evidence_path(path) or not is_attribution_eligible(path, target=target):
        return -10_000
    score = 0
    score += _path_role_adjustment(path, target)
    in_context = _path_shares_target_context(path, context_dirs)
    path_identity = _path_contains_target_identity(path, target)
    if in_context:
        score += 120
    lowered_path = path.casefold()
    # A target-bearing init/config directory can contain a very large number
    # of generated artifacts (NOTICE files, install metadata and copied cfg
    # files).  Those artifacts legitimately establish ownership context, but
    # they must not crowd the bounded trace window ahead of the production
    # listener implementation that lives in the same component directory.
    # Prefer source files under a concrete target-bound component when the
    # path classifier marks them as production code.  This is deliberately a
    # ranking adjustment only: generated and build paths remain visible in
    # path_classification.json and can still be selected by later evidence.
    try:
        path_class = classify_path(path, target=target)
    except (TypeError, ValueError):
        path_class = None
    if (
        path_class is not None
        and path_class.role == "production"
        and _path_has_target_bound_component(path, context_dirs)
        and lowered_path.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"))
    ):
        # Keep this comfortably above generated ``*.cfg``/NOTICE artifacts
        # (which can otherwise receive a large context bonus simply because
        # their directory is target-bearing).  The path is still subject to
        # the normal bounded max_paths limit and all generated rows remain in
        # the audit artifact.
        score += 420
    path_client_like = _path_is_client_like(path)
    filename = path.rsplit("/", 1)[-1].casefold()
    path_conflict = _named_socket_path_has_conflict(path, executions, target)
    context_values = (
        context_dirs
        if isinstance(context_dirs, (list, tuple, set, frozenset))
        else ()
    )
    exact_deep_context = any(
        isinstance(context_dir, str)
        and context_dir.rstrip("/") == path.rsplit("/", 1)[0].rstrip("/")
        and len([part for part in context_dir.split("/") if part]) >= 6
        for context_dir in context_values
    )
    is_config = filename.endswith((".cfg", ".rc", ".conf", ".ini"))
    if is_config:
        # Init ``.cfg``/service metadata is a stronger ownership anchor than
        # a generated/stub JSON file which merely repeats the target name.
        score += 68
    elif filename.endswith(".json"):
        score += 15
    if filename in {"build.gn", "build.gni", "bundle.json"}:
        # Build metadata confirms executable ownership, but source/config
        # files should win the initial trace ordering when both are present.
        score += 15
    if any(word in filename for word in ("socket", "listen", "server", "daemon", "service", "init")):
        score += 20
    # Source implementations under ``services``/``server``/``daemon`` (and
    # init's startup code) are more likely to own the endpoint than a sibling
    # client library.  This is only a ranking hint; the operation evidence and
    # model attribution still decide the final role.
    if re.search(r"/(?:services?|server|daemon|init)(?:/|$)", lowered_path):
        score += 45
    target_terms = tuple(term.casefold() for term in target_identity_terms(target) if term)
    if _line_contains_identity(lowered_path, target_terms):
        score += 30
    if path_identity:
        # ``*_service.c``/``*_server.cpp`` is often the only place where the
        # init socket name is normalized.  It may not repeat the literal name
        # on every GetControlSocket/bind/recv line, so let that file act as a
        # bounded source anchor without making every repository-wide API hit
        # eligible.
        score += 65
    identity_hits = 0
    server_hits = 0
    config_hits = 0
    build_hits = 0
    client_hits = 0
    control_acquire_hits = 0
    for execution in executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        response = execution.get("response")
        results = response.get("results") if isinstance(response, Mapping) else None
        raw_hits = results.get(path) if isinstance(results, Mapping) else None
        if not isinstance(raw_hits, list):
            continue
        query = execution.get("query")
        query_value = query.get("value") if isinstance(query, Mapping) else None
        query_text = str(query_value or "").strip().casefold()
        is_generic = query_text in _SOCKET_GENERIC_QUERY_TERMS
        rows: list[tuple[str, bool, bool, bool, str]] = []
        for raw_hit in raw_hits[:_MAX_SEARCH_ARTIFACT_HITS_PER_PATH]:
            if not isinstance(raw_hit, Mapping):
                continue
            line = raw_hit.get("line")
            if not isinstance(line, str):
                continue
            kind = _line_kind(line, target, query_value=query_value)
            has_identity = _line_has_target_identity(line, target)
            alias_query = _is_socket_alias_query(query_value, target)
            # A target-specific query is not itself proof that this returned
            # line contains the target: OpenGrok can return a path/summary
            # line or a longer identifier containing a common basename.  Use
            # the actual source identity as the anchor; a narrowly validated
            # socket alias is the only exception and still needs module
            # context before it can promote generic operations.
            # Do not count context-only operations from a file that visibly
            # creates an IPv4/netlink or differently named socket.  The file
            # can still contribute an explicit target line, and remains in
            # the candidate artifact for model review.
            if is_generic and path_conflict and not has_identity and not alias_query:
                continue
            if is_generic and not has_identity and not alias_query and not exact_deep_context:
                continue
            rows.append((kind, has_identity, has_identity or alias_query, is_generic, line))
        # A generic ``socket``/``bind`` hit is useful only in the bounded
        # module context established by a target-bearing hit.  This prevents
        # unrelated netlink, iptables and utility calls elsewhere in the tree
        # from outranking the actual listener while still allowing the common
        # init-created-socket pattern where the implementation file does not
        # repeat the socket name.
        for kind, has_identity, anchor, is_generic, line in rows:
            if (
                kind == "socket_acquire"
                and re.search(r"\b(?:getcontrolsocket|getserversocket)\s*\(", line.casefold()) is not None
                and (has_identity or anchor or (is_generic and (in_context or path_identity)))
            ):
                control_acquire_hits += 1
            if has_identity or anchor:
                identity_hits += 1
                if kind in {"service_config", "socket_server_registration"}:
                    config_hits += 1
                if kind in {
                    "socket_acquire",
                    "socket_server_registration",
                    "socket_bind_listen",
                    "socket_accept_read",
                    "protocol_dispatch",
                }:
                    # A bare ``socket()`` in an inner-kit/client source file is
                    # normally the client descriptor.  Keep explicit
                    # OpenHarmony server hand-offs (GetControlSocket,
                    # GetServerSocket, socketpair) as server evidence, and
                    # leave bind/listen/accept/dispatch untouched because
                    # those operations establish the listening direction.
                    if (
                        kind == "socket_acquire"
                        and (
                            path_client_like
                            or (
                                "/interfaces/innerkits/" in lowered_path
                                and not re.search(r"/(?:services?|server|daemon|init)(?:/|$)", lowered_path)
                            )
                        )
                        and not re.search(
                            r"\b(?:getcontrolsocket|getserversocket|socketpair)\s*\(",
                            line.casefold(),
                        )
                    ):
                        client_hits += 1
                    else:
                        server_hits += 1
                if kind in {"client_connect", "client_send", "client_endpoint", "protocol_construction"}:
                    client_hits += 1
            elif is_generic and (in_context or path_identity):
                if kind in {
                    "socket_acquire",
                    "socket_server_registration",
                    "socket_bind_listen",
                    "socket_accept_read",
                    "protocol_dispatch",
                    "executable_build",
                }:
                    if kind == "executable_build":
                        build_hits += 1
                    else:
                        server_hits += 1
    # ``GetControlSocket`` is the canonical OpenHarmony hand-off from init's
    # named socket configuration to a service listener.  Give that operation
    # a separate bounded bonus: otherwise a sibling implementation which
    # happens to contain many generic ``socket``/``bind`` calls (for example a
    # DNS proxy helper) can tie or outrank the actual Unix-socket listener.
    # The bonus is counted only for already relevant identity/context rows, so
    # a repository-wide helper definition cannot become ownership evidence.
    # Cap repeated basename hits.  A client/header with dozens of comments
    # must not outrank one config + listener chain merely by volume.
    score += min(identity_hits, 4) * 12
    score += min(server_hits, 4) * 52
    score += min(config_hits, 3) * 38
    score += min(build_hits, 3) * 18
    score += min(client_hits, 3) * 3
    score += min(control_acquire_hits, 3) * 85
    if "client" in filename and server_hits == 0:
        score -= 150
    elif "client" in lowered_path and server_hits == 0:
        score -= 90
    if path_client_like and server_hits == 0:
        score -= 100
    if is_config and config_hits:
        score += 35
    return score


def _target_context_directories(
    executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
) -> tuple[str, ...]:
    """Collect source directories established by target-specific search hits.

    Network implementations often split their identity across files: a
    sibling header contains the concrete port while the server .cpp contains
    ``socket``/``bind`` and uses a variable.  Recording only the exact hit
    would lose that implementation.  We retain only parent directories of
    non-generic, target-bearing hits and keep the result bounded/deduplicated.
    """

    # Collect scored anchors first instead of taking the first 64 OpenGrok
    # paths.  Full-text basename results are ordered by index/path and can put
    # hundreds of YAML/BUILD/client files before the real listener; a
    # two-pass selection keeps the strongest config/server anchors regardless
    # of response order.
    anchors: dict[str, int] = {}
    for execution in executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        query = execution.get("query")
        query_value = query.get("value") if isinstance(query, Mapping) else None
        if isinstance(query_value, str) and query_value.strip().casefold() in _SOCKET_GENERIC_QUERY_TERMS:
            continue
        response = execution.get("response")
        results = response.get("results") if isinstance(response, Mapping) else None
        if not isinstance(results, Mapping):
            continue
        for path, raw_hits in results.items():
            if not isinstance(path, str) or not _is_locator_evidence_path(path) or not isinstance(raw_hits, list):
                continue
            try:
                if not is_attribution_eligible(path, target=target):
                    continue
            except Exception:
                continue
            best_score = 0
            for hit in raw_hits:
                if not isinstance(hit, Mapping) or not _search_hit_is_target_evidence(
                    {"query": query, "path": path}, hit, target
                ):
                    continue
                line = hit.get("line")
                if not isinstance(line, str):
                    continue
                kind = _line_kind(
                    line,
                    target,
                    query_kind=query.get("kind") if isinstance(query, Mapping) else None,
                    query_value=query_value,
                )
                path_name = path.rsplit("/", 1)[-1].casefold()
                is_build_metadata = path_name.endswith(("build.gn", "build.gni", "bundle.json", "args.gn"))
                # Do not let an arbitrary basename/literal (especially a
                # SELinux label or a log string) establish a repository-wide
                # context.  Build source-list lines are the one intentional
                # exception: they may contain only ``"foo/server.cpp"`` but
                # still prove that the target implementation belongs to this
                # component.
                if kind not in _STRONG_CONTEXT_KINDS:
                    code_line = _strip_source_comments(line)
                    # A BUILD.gn/bundle.json hit is a useful ownership hint
                    # only when it names a real source file.  Dependency labels
                    # such as ``"hisysevent:libhisysevent"`` occur throughout
                    # the tree and must not make an entire repository a socket
                    # context.  Executable/component declarations are already
                    # classified as ``executable_build`` by ``_line_kind``.
                    build_source_link = bool(
                        is_build_metadata
                        and _line_has_target_identity(line, target)
                        and re.search(
                            r"[\"'][^\"'\n]+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)\b",
                            code_line,
                        )
                    )
                    if not (
                        build_source_link
                    ):
                        continue
                    kind = "executable_build"
                score = 20
                if _line_has_target_identity(line, target):
                    score += 35
                if kind in {"service_config", "executable_build"}:
                    score += 35
                if kind in _COMMUNICATION_EVIDENCE_KINDS:
                    score += 60
                if path.rsplit("/", 1)[-1].casefold().endswith((".cfg", ".json", ".gn", ".gni", ".rc")):
                    score += 15
                best_score = max(best_score, score)
            if best_score:
                anchors[path] = max(anchors.get(path, 0), best_score)
    directories: list[str] = []
    seen: set[str] = set()
    for path, _score in sorted(anchors.items(), key=lambda item: (-item[1], item[0]))[:48]:
        parent = path.rsplit("/", 1)[0] or "/"
        # Retain the file directory plus a bounded ancestor window.  A config
        # under ``services/etc/init`` and an implementation under
        # ``services/<daemon>/src`` meet at the component services directory.
        context_candidates = [parent]
        current = parent
        for _depth in range(4):
            current = current.rsplit("/", 1)[0] or "/"
            if len([part for part in current.split("/") if part]) < 3:
                break
            context_candidates.append(current)
        for context_dir in context_candidates:
            if context_dir in seen:
                continue
            seen.add(context_dir)
            directories.append(context_dir)
            if len(directories) >= 128:
                return tuple(directories)
    return tuple(directories)


def _is_macro_definition_path(path: str) -> bool:
    """Return whether a path can contain a source/config macro definition."""

    if not isinstance(path, str) or not path.strip():
        return False
    lowered = path.rsplit("/", 1)[-1].casefold()
    return _is_locator_evidence_path(path)


def _is_locator_evidence_path(path: str) -> bool:
    """Return whether a path can carry source, config or build evidence.

    The path classifier intentionally keeps kernel/third_party/generated/out
    and build paths visible.  This helper only removes non-source records
    (dependency/object/cache files) and leaves test/fuzz exclusion to
    ``is_attribution_eligible``.
    """

    if not isinstance(path, str) or not path.strip():
        return False
    lowered = path.rsplit("/", 1)[-1].casefold()
    return lowered.endswith(
        (
            ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
            ".gn", ".gni", ".cfg", ".json", ".rc", ".conf", ".ini",
            ".xml", ".yaml", ".yml", ".toml", ".te",
        )
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
    # Optional semantic adjudicator for the concrete function candidates
    # extracted from socket receive/dispatch evidence.  It is wired only by
    # the explicit --llm-search path; deterministic callers retain the legacy
    # evidence filters.
    llm_entrypoint_attributor: LLMEntrypointAttributor | None = None
    # Optional final PK among multiple Manifest-resolved repositories.  This
    # is deliberately separate from role attribution: it is only invoked
    # when two or more candidates expose competing socket evidence.
    llm_candidate_reviewer: LLMCandidateReviewer | None = None
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
        if self.llm_entrypoint_attributor is not None and not isinstance(self.llm_entrypoint_attributor, LLMEntrypointAttributor):
            raise SourceLocatorWorkerError("runtime.llm_entrypoint_attributor 必须是 LLMEntrypointAttributor 或 null")
        if self.llm_candidate_reviewer is not None and not isinstance(self.llm_candidate_reviewer, LLMCandidateReviewer):
            raise SourceLocatorWorkerError("runtime.llm_candidate_reviewer 必须是 LLMCandidateReviewer 或 null")
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
    llm_entrypoint_attributor: LLMEntrypointAttributor | None = None,
    llm_candidate_reviewer: LLMCandidateReviewer | None = None,
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
            llm_entrypoint_attributor=llm_entrypoint_attributor,
            llm_candidate_reviewer=llm_candidate_reviewer,
        )
    except SourceLocatorWorkerError:
        raise
    except Exception as exc:
        raise SourceLocatorWorkerError(f"无法构建 source-locator runtime：{_compact(exc)}") from exc


def _compact(value: Any, limit: int = 512) -> str:
    return " ".join(str(value).split())[:limit]


def _function_name_from_tree_node(node: Any, source: bytes) -> str:
    """Return a display name for a tree-sitter function definition.

    Tree-sitter deliberately does not perform C++ name binding.  The source
    range is nevertheless authoritative for this artifact, so a bounded
    declarator spelling is preferable to guessing a symbol from an evidence
    line.  The function is only used for presentation and grouping; the
    source range remains the stable identity.
    """

    declarator = None
    try:
        declarator = node.child_by_field_name("declarator")
    except (AttributeError, TypeError):
        declarator = None
    # ``function_definition.declarator`` is usually a complete
    # ``function_declarator`` node.  Its own ``declarator`` child is the
    # actual identifier/qualified identifier.  Running the name regex over
    # the complete parameter list picks up callback types such as ``void
    # (*callback)(int)`` and used to return ``void`` instead of
    # ``UnixSocketServer::UnixSocketAccept``.  Descend through declarator
    # fields first and only use the regex as a compatibility fallback.
    candidate = declarator if declarator is not None else node
    seen_nodes: set[int] = set()
    while candidate is not None:
        marker = id(candidate)
        if marker in seen_nodes:
            break
        seen_nodes.add(marker)
        try:
            nested = candidate.child_by_field_name("declarator")
        except (AttributeError, TypeError):
            nested = None
        if nested is None:
            break
        candidate = nested
    try:
        text = source[candidate.start_byte:candidate.end_byte].decode("utf-8", errors="replace")
    except (AttributeError, TypeError, IndexError):
        text = ""
    text = re.sub(r"\s+", "", text)
    if text and "(" not in text and ")" not in text:
        return text[:256]
    # A few grammar versions represent operator/destructor declarators
    # differently; retain the old bounded extraction as a fallback.
    matches = re.findall(
        r"(?:(?:[A-Za-z_~][A-Za-z0-9_~]*)\s*::\s*)*"
        r"(?:[A-Za-z_~][A-Za-z0-9_~]*|operator\s*[A-Za-z0-9_+\-*/%<>=!&|~^]+)\s*(?=\()",
        text,
    )
    if matches:
        return re.sub(r"\s+", "", matches[-1])[:256]
    return "入口函数"


def _lexical_function_at_line(content: str, line_no: int) -> dict[str, Any] | None:
    """Best-effort fallback when an optional tree-sitter grammar is unavailable.

    This fallback is intentionally conservative: it only considers a
    declaration-like line followed by a brace and balances braces.  It never
    turns a call expression into a function definition.  The artifact marks
    the result as ``parser=lexical_fallback`` so reviewers can distinguish it
    from a syntax-tree range.
    """

    if line_no < 1:
        return None
    pattern = re.compile(
        r"(?m)^[^\n;{}]*\b(?P<name>(?:(?:[A-Za-z_~][A-Za-z0-9_~]*)\s*::\s*)*"
        r"(?:[A-Za-z_~][A-Za-z0-9_~]*|operator\s*[^\s(]+))\s*\([^;{}]*\)"
        r"[^;{}]*\{"
    )
    lines = content.splitlines(keepends=True)
    selected: tuple[int, int, str] | None = None
    for match in pattern.finditer(content):
        start = content.count("\n", 0, match.start()) + 1
        brace = content.find("{", match.start(), match.end())
        if brace < 0:
            continue
        depth = 0
        end_offset = None
        for index in range(brace, len(content)):
            char = content[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end_offset = index + 1
                    break
        if end_offset is None:
            continue
        end = content.count("\n", 0, end_offset) + 1
        if start <= line_no <= end and (selected is None or start >= selected[0]):
            selected = (start, end, match.group("name"))
    if selected is None:
        return None
    start, end, raw_name = selected
    source_text = "".join(lines[start - 1:end])
    # A header declaration such as ``class SpServerSocket { ... }`` can
    # satisfy the bounded declaration regex because the class body contains
    # methods with ``recv``/``accept`` names.  It is a type definition, not a
    # callable entry function, and must not be presented as one.
    if _looks_like_type_definition(source_text):
        return None
    return {
        "function": re.sub(r"\s+", "", raw_name)[:256] or "入口函数",
        "line_start": start,
        "line_end": end,
        "source": source_text,
        "parser": "lexical_fallback",
        "complete": True,
    }


def _extract_enclosing_function(document: SourceDocument, line_no: int) -> dict[str, Any] | None:
    """Extract the complete enclosing C/C++ function for an evidence line.

    The locator evidence stores an operation line (for example ``recv``),
    while the reviewer needs the complete top-level receiver.  We parse the
    OpenGrok document and climb from the anchor node to ``function_definition``
    rather than inferring a function boundary from a fixed line window.
    """

    if not isinstance(document, SourceDocument) or not isinstance(line_no, int) or line_no < 1:
        return None
    content = document.content
    if not isinstance(content, str) or not content:
        return None
    source = content.encode("utf-8", errors="replace")
    lines = content.splitlines(keepends=True)
    if line_no > max(1, len(lines)):
        return None
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_c as tsc
        import tree_sitter_cpp as tscpp

        suffix = Path(document.path).suffix.lower()
        language = Language(tscpp.language() if suffix in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"} else tsc.language())
        parser = Parser(language)
        tree = parser.parse(source)
        row = line_no - 1
        line_length = len(lines[row].rstrip("\r\n").encode("utf-8", errors="replace"))
        node = tree.root_node.descendant_for_point_range(
            (row, 0),
            (row, max(1, line_length)),
        )
        while node is not None and getattr(node, "type", "") != "function_definition":
            node = getattr(node, "parent", None)
        if node is None:
            return _lexical_function_at_line(content, line_no)
        start_line = int(node.start_point[0]) + 1
        end_line = int(node.end_point[0]) + 1
        source_text = "".join(lines[start_line - 1:end_line])
        truncated = len(source_text) > _MAX_ENTRYPOINT_SOURCE_CHARS
        if truncated:
            source_text = source_text[:_MAX_ENTRYPOINT_SOURCE_CHARS]
        if _looks_like_type_definition(source_text):
            return None
        return {
            "function": _function_name_from_tree_node(node, source),
            "line_start": start_line,
            "line_end": end_line,
            "source": source_text,
            "parser": "tree_sitter",
            "complete": not truncated and not bool(document.truncated),
            "truncated": truncated or bool(document.truncated),
        }
    except Exception:
        # Source retrieval must remain useful even when a particular file has
        # a grammar construct unsupported by the installed parser.  The
        # fallback is marked explicitly and the caller retains an error note.
        return _lexical_function_at_line(content, line_no)


def _looks_like_type_definition(source: str) -> bool:
    """Return whether a supposedly enclosing range is a class/type body.

    Tree-sitter C/C++ grammar versions have historically represented a class
    declaration containing method prototypes as a function-like node for
    some anchor points.  The locator only wants definitions with executable
    bodies; rejecting a range whose first declaration is ``class``/``struct``
    keeps header prototypes from becoming fake socket receivers.
    """

    text = _strip_source_comments(str(source or ""))
    text = text.lstrip()
    # Keep this deliberately shallow.  A real function may declare a local
    # class, but its source starts with a return type/name rather than one of
    # these type-definition keywords.
    return bool(re.match(r"(?is)^(?:template\s*<[^;{}]*>\s*)?(?:class|struct|union|enum)\b", text))


def _server_candidate_path_facts(
    server: ServerAttributionResult,
    store: EvidenceStore,
) -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
    """Index target-scoped server roles and evidence kinds by source path.

    Init configuration and the process-side listener are commonly split over
    different files.  The old entrypoint filter only accepted a receive line
    when that *same file* repeated the socket identity, which silently dropped
    valid ``accept``/``read`` functions in services such as faultloggerd and
    hiprofiler.  Attribution has already performed the target/repository
    scoping; re-use its bounded candidate/evidence links here instead of
    issuing a broad search or matching a socket basename in arbitrary code.

    The first mapping contains paths carrying an explicit server role.  The
    second contains paths carrying target-scoped server evidence (including
    entries whose role list was compacted by an older checkpoint).  Both are
    deliberately limited to server roles and the evidence IDs known to the
    current attribution result; client-only rows cannot establish this bridge.
    """

    if not isinstance(server, ServerAttributionResult) or not isinstance(store, EvidenceStore):
        return {}, {}
    by_id = {item.evidence_id: item for item in store.evidence if isinstance(item, Evidence)}
    path_roles: dict[str, set[str]] = {}
    path_kinds: dict[str, set[str]] = {}

    def add_role(path: Any, role: Any) -> None:
        if not isinstance(path, str) or not path or role not in _SERVER_CANDIDATE_ROLES:
            return
        path_roles.setdefault(path, set()).add(str(role))

    def add_evidence(evidence_id: Any) -> None:
        if not isinstance(evidence_id, str):
            return
        item = by_id.get(evidence_id)
        if item is None:
            return
        # ``server.evidence_ids`` is already role-attribution scoped, but only
        # source-side operations can establish a listener path.  Config and
        # build rows remain useful for identity and are intentionally omitted
        # from this per-source entry bridge.
        if item.kind in _ENTRYPOINT_SOURCE_ANCHOR_KINDS:
            path_kinds.setdefault(item.source_path, set()).add(item.kind)

    for candidate in server.candidates:
        if candidate.role not in _SERVER_CANDIDATE_ROLES:
            continue
        for location in candidate.source_locations:
            add_role(location.source_path, candidate.role)
        for evidence_id in candidate.evidence_ids:
            evidence = by_id.get(evidence_id)
            if evidence is not None:
                add_role(evidence.source_path, candidate.role)
            add_evidence(evidence_id)
    for evidence_id in server.evidence_ids:
        add_evidence(evidence_id)

    return (
        {path: frozenset(roles) for path, roles in path_roles.items()},
        {path: frozenset(kinds) for path, kinds in path_kinds.items()},
    )


def _entrypoint_scope(function_name: str, source: str, entry_kinds: Iterable[str]) -> str:
    """Classify an accepted entry function for presentation and audit.

    A direct transport receiver is the highest-level byte ingress.  A
    protocol dispatcher may be invoked by a framework callback, while a
    helper that only appears in a dispatch search is kept as a lower-level
    protocol helper.  This metadata does not remove any accepted evidence;
    it prevents the UI and downstream reports from treating all receive-like
    functions as equivalent top-level listeners.
    """

    text = str(source or "")
    kinds = set(entry_kinds or ())
    if _SOCKET_NETWORK_RECEIVE_CALL_RE.search(text) or (
        _SOCKET_READ_CALL_RE.search(text) and _SOCKET_SERVER_ANCHOR_RE.search(text)
    ):
        return "transport_receive"
    if "protocol_dispatch" in kinds:
        return "protocol_dispatch"
    compact_name = re.sub(r"[^A-Za-z0-9_]", "", str(function_name or ""))
    if re.search(r"(?i)(?:receive|recv|handle|process|dispatch|message|request)", compact_name):
        return "protocol_helper"
    return "other"


def _build_socket_entrypoint_sources(
    target: TargetSpec,
    store: EvidenceStore,
    server: ServerAttributionResult,
    client: OpenGrokClient | None,
    *,
    max_source_bytes: int,
    llm_entrypoint_attributor: LLMEntrypointAttributor | None = None,
) -> dict[str, Any]:
    """Build the standalone external-input entry-function evidence artifact.

    Only server consumer/handler candidates backed by ``recv``/protocol
    dispatch evidence are selected.  Socket creators, clients and downstream
    business functions stay in the normal evidence graph and are deliberately
    not presented as the top-level input entry list.
    """

    payload: dict[str, Any] = {
        "schema_version": "openant.source-locator.socket-entrypoint-sources.v1",
        "status": "unavailable",
        "target": target.to_dict(),
        "entrypoint_count": 0,
        "entries": [],
        "errors": [],
        "candidate_count": 0,
        "reviewed_candidate_count": 0,
        "unreviewed_candidate_count": 0,
        "decision_source": "rule",
        "llm_review": None,
        "selection": {
            "evidence_kinds": sorted(_ENTRYPOINT_SOURCE_ANCHOR_KINDS),
            "roles": sorted(_ENTRYPOINT_ROLES),
            "description": "只展示接收外部输入或协议分派的服务端入口函数；不展开具体业务处理函数。",
            "entry_scope_order": ["transport_receive", "protocol_dispatch", "protocol_helper", "other"],
            "server_candidate_paths": [],
            "server_evidence_paths": [],
            "needs_source_entry_evidence": False,
            "excluded_client_only_paths": [],
            "excluded_setup_functions": [],
            "excluded_target_mismatch_paths": [],
            "excluded_transport_functions": [],
            "excluded_non_definition_anchors": [],
        },
    }
    if client is None:
        payload["errors"].append("OpenGrok 客户端不可用，无法读取入口函数完整源码。")
        return payload

    server_path_roles, server_evidence_path_kinds = _server_candidate_path_facts(server, store)
    server_candidate_paths = set(server_path_roles)
    server_evidence_paths = set(server_evidence_path_kinds)
    payload["selection"]["server_candidate_paths"] = sorted(server_candidate_paths)[:_MAX_LLM_ENTRYPOINT_CANDIDATES]
    payload["selection"]["server_evidence_paths"] = sorted(server_evidence_paths)[:_MAX_LLM_ENTRYPOINT_CANDIDATES]

    role_ids = {
        evidence_id
        for candidate in server.candidates
        if candidate.role in _ENTRYPOINT_ROLES
        for evidence_id in candidate.evidence_ids
    }
    client_ids = {
        evidence_id
        for candidate in server.candidates
        if candidate.role in {"client_transport", "client_protocol", "client_sender"}
        for evidence_id in candidate.evidence_ids
    }
    candidate_ids = role_ids or set(server.evidence_ids)
    anchors = [
        item
        for item in store.evidence
        if item.evidence_id in candidate_ids
        and item.evidence_id not in client_ids
        and item.kind in _ENTRYPOINT_SOURCE_ANCHOR_KINDS
    ]
    if not anchors:
        # Older attribution results may not have retained role candidate IDs;
        # the server evidence list is still a safe, auditable fallback.
        anchors = [
            item
            for item in store.evidence
            if item.evidence_id in set(server.evidence_ids)
            and item.evidence_id not in client_ids
            and item.kind in _ENTRYPOINT_SOURCE_ANCHOR_KINDS
        ]
    # A semantic role review may retain only the generic receiver row while
    # dropping the co-located registration/acquire row from its role
    # candidates.  That must not prevent the target's own source file from
    # being scanned for the real protocol callback (for example
    # ``param_service.c:ProcessMessage``).  Add only setup anchors already
    # present in the target-scoped server evidence; the same target-binding
    # predicates below still gate which derived receive/dispatch lines can be
    # promoted.  This is deliberately not a repository-wide ``recv`` search.
    anchor_ids = {item.evidence_id for item in anchors}
    server_evidence_id_set = set(server.evidence_ids)
    for item in store.evidence:
        if (
            item.evidence_id in server_evidence_id_set
            and item.evidence_id not in anchor_ids
            and item.kind in {
                "socket_acquire",
                "socket_bind_listen",
                "socket_server_registration",
            }
            and (
                _line_has_target_identity(item.excerpt, target)
                or _path_contains_target_identity(item.source_path, target)
                or _path_has_target_component_affinity(item.source_path, target)
                or re.search(
                    r"\b(?:getcontrolsocket|getserversocket|getsocket)\s*\(\s*"
                    r"(?:socketname|socket_name|socketname_|name|socket|"
                    r"[a-z_][a-z0-9_]*_socket_name)\b",
                    _strip_source_comments(item.excerpt).casefold(),
                )
            )
        ):
            anchors.append(item)
            anchor_ids.add(item.evidence_id)
    if not anchors:
        # ``empty`` looked like a confirmed absence.  A target with only an
        # init/config identity is instead an explicit coverage gap which may
        # be resolved by a later bounded source probe; do not fabricate an
        # entry function or silently call it safe.
        payload["status"] = "unavailable"
        payload["selection"]["needs_source_entry_evidence"] = True
        payload["errors"].append(
            "当前服务端归因没有可核验的接收/协议分派证据，需补充服务实现源码或确认该目标不在当前仓库。"
        )
        return payload

    source_cache: dict[str, SourceDocument] = {}
    grouped: dict[tuple[str, int, int, str], dict[str, Any]] = {}

    semantic_entrypoint_review = llm_entrypoint_attributor is not None

    def add_entry_anchor(
        anchor: Evidence,
        document: SourceDocument,
        *,
        allow_non_entrypoint: bool = False,
    ) -> None:
        """Add one receive/dispatch evidence row to the grouped entry list."""

        extracted = _extract_enclosing_function(document, anchor.line_start)
        if extracted is None:
            # Header prototypes and class bodies are valid search evidence,
            # but they do not contain an executable function definition.  Do
            # not downgrade an otherwise complete target merely because a
            # broad method-name hit landed in a declaration-only header.
            if Path(anchor.source_path).suffix.lower() in {
                ".h",
                ".hh",
                ".hpp",
                ".hxx",
            }:
                excluded = payload["selection"]["excluded_non_definition_anchors"]
                label = f"{anchor.source_path}:{anchor.line_start}"
                if label not in excluded:
                    excluded.append(label)
            else:
                payload["errors"].append(
                    f"{anchor.source_path}:{anchor.line_start}: 未能定位包含证据行的完整函数。"
                )
            return
        if not _network_function_matches_target(
            extracted["function"], extracted["source"], target
        ):
            # A shared network implementation can expose both UDP and TCP
            # methods in one directory.  The search evidence is retained in
            # the graph, but a method that is provably for the other
            # transport must not be shown as the requested endpoint's
            # external entry.  Keep the exact function/range for audit rather
            # than silently dropping it.
            excluded = payload["selection"]["excluded_transport_functions"]
            label = (
                f"{anchor.source_path}:{extracted['line_start']}-{extracted['line_end']}"
                f":{extracted['function']}"
            )
            if label not in excluded:
                excluded.append(label)
            return
        # Registration/setup functions can contain a callback assignment such
        # as ``info.recvMessage = ProcessMessage``.  The assignment is useful
        # evidence in the graph, but the enclosing initializer is not itself
        # the function that receives external bytes.  Keep it auditable while
        # excluding it from the standalone entrypoint source list.
        if not allow_non_entrypoint and not _function_source_is_socket_entrypoint(
            extracted["function"], extracted["source"]
        ):
            excluded = payload["selection"]["excluded_setup_functions"]
            label = (
                f"{anchor.source_path}:{extracted['line_start']}-{extracted['line_end']}"
                f":{extracted['function']}"
            )
            if label not in excluded:
                excluded.append(label)
            return
        key = (
            anchor.source_path,
            int(extracted["line_start"]),
            int(extracted["line_end"]),
            str(extracted["function"]),
        )
        item = grouped.setdefault(
            key,
            {
                "source_path": anchor.source_path,
                "line_start": extracted["line_start"],
                "line_end": extracted["line_end"],
                "function": extracted["function"],
                "entry_kinds": set(),
                "anchor_lines": set(),
                "evidence_ids": set(),
                "source": extracted["source"],
                "parser": extracted.get("parser", "unknown"),
                "complete": bool(extracted.get("complete", False)),
                "truncated": bool(extracted.get("truncated", False)),
                "entry_scope": _entrypoint_scope(
                    extracted["function"], extracted["source"], (anchor.kind,)
                ),
            },
        )
        item["entry_kinds"].add(anchor.kind)
        item["anchor_lines"].add(anchor.line_start)
        item["evidence_ids"].add(anchor.evidence_id)
        # If the same function was anchored by multiple lines, keep the
        # longest source text and the more conservative completeness status.
        if len(extracted["source"]) > len(item["source"]):
            item["source"] = extracted["source"]
        item["complete"] = bool(item["complete"] and extracted.get("complete", False))
        item["truncated"] = bool(item["truncated"] or extracted.get("truncated", False))
        item["entry_scope"] = _entrypoint_scope(
            str(item["function"]), str(item["source"]), item["entry_kinds"]
        )

    derived_anchor_cache: dict[tuple[str, int, str], Evidence] = {}
    for anchor in sorted(anchors, key=lambda item: (item.source_path, item.line_start, item.evidence_id)):
        path = anchor.source_path
        # A source file may host several listeners (for example the VPN
        # manager contains both ``tunfd`` and ``multivpnfd``).  Merely having
        # *some* setup evidence in the same file is not enough to bind a
        # generic recv/accept line to the requested socket.  The co-located
        # setup row must itself carry the target identity; otherwise the
        # generic row remains audit evidence but is not promoted to the
        # standalone entrypoint artifact.
        target_specific_setup = any(
            item.source_path == path
            and item.kind
            in {
                "socket_acquire",
                "socket_bind_listen",
                "socket_server_registration",
            }
            and (
                _line_has_target_identity(item.excerpt, target)
                or _path_contains_target_identity(path, target)
                or _path_has_target_component_affinity(path, target)
            )
            for item in store.evidence
        )
        # Some services multiplex several init-created socket names through a
        # single generic setup function, e.g. appspawn's
        # ``CreateAppSpawnServer(..., socketName)`` and
        # ``GetControlSocket(socketName)``.  The target identity is then
        # carried by a sibling macro/config row rather than repeated in the
        # implementation file.  Treat that as target-bound only when the
        # selected file itself has a parameterised socket acquisition; a
        # literal sibling listener such as ``GetControlSocket("multivpnfd")``
        # must remain excluded for a ``tunfd`` query.
        generic_target_setup = any(
            item.source_path == path
            and item.kind
            in {
                "socket_acquire",
                "socket_bind_listen",
                "socket_server_registration",
            }
            and re.search(
                r"\b(?:getcontrolsocket|getserversocket|getsocket)\s*\(\s*"
                r"(?:socketname|socket_name|socketname_|name|socket|"
                r"[a-z_][a-z0-9_]*_socket_name)\b",
                _strip_source_comments(item.excerpt).casefold(),
            )
            for item in store.evidence
        )
        # The socket identity may be present only in an init/config file.
        # When attribution has independently linked this source file to a
        # server-consumer/handler candidate (or to target-scoped entry
        # evidence), that link is sufficient to bridge the split layout.  It
        # is intentionally narrower than a shared directory or a basename
        # match and is checked again against the local transport profile
        # below, where client-only response readers are excluded.
        # A role attributed by the model is not, by itself, a target binding:
        # broad ``recv`` searches routinely give the same server_consumer role
        # to DNS, VPN and fwmark implementations in one repository.  The
        # cross-file bridge therefore requires a target-named component (or a
        # target identity on the line/path); repository/module ancestry alone
        # is insufficient.  A small generic descriptor exception keeps init's
        # shared ``HandleRecvMessage(... recvFd ...)`` receiver visible when a
        # named socket is created by init and the concrete service consumes the
        # descriptor in a sibling file.
        path_target_affinity = _path_has_target_component_affinity(path, target)
        path_target_identity = _path_contains_target_identity(path, target)
        generic_descriptor_receiver = bool(
            target.target_type != "network_socket"
            and re.search(r"\b(?:recvfd|socketfd|serverfd)\b", _strip_source_comments(anchor.excerpt), re.IGNORECASE)
            and re.search(r"(?:init_context|socket_context|fd_holder)", path, re.IGNORECASE)
        )
        cross_file_server_path = (
            (path_target_affinity or path_target_identity or generic_descriptor_receiver)
            and (
                (
                    path in server_candidate_paths
                    and bool(server_path_roles.get(path, frozenset()) & _ENTRYPOINT_ROLES)
                )
                or (
                    path in server_evidence_paths
                    and bool(server_evidence_path_kinds.get(path, frozenset()) & _ENTRYPOINT_EVIDENCE_KINDS)
                )
            )
        )
        if (
            target.target_type != "network_socket"
            and anchor.kind in _ENTRYPOINT_EVIDENCE_KINDS
            and not (target_specific_setup or generic_target_setup)
            and not _line_has_target_identity(anchor.excerpt, target)
            and not _path_contains_target_identity(path, target)
            and not cross_file_server_path
        ):
            # A generic recv/dispatch hit in a sibling directory can share
            # the same repository context without belonging to this named
            # socket (for example ``clatd.cpp`` next to the ``tunfd`` VPN
            # listener).  Require a co-located target-specific setup/anchor
            # before presenting such a function as the socket's external
            # entrypoint.  The full evidence graph still retains the row for
            # auditability; this filter only protects the standalone entry
            # artifact from unrelated sibling receivers.
            excluded = payload["selection"]["excluded_target_mismatch_paths"]
            if path not in excluded:
                excluded.append(path)
            continue
        if path not in source_cache:
            try:
                source_cache[path] = client.read_source(path, max_bytes=max_source_bytes)
                # The normal trace budget is intentionally small, but a
                # standalone entrypoint must contain the complete enclosing
                # function.  Retry only target-selected source files with a
                # bounded larger read when OpenGrok reports truncation; this
                # avoids inflating every generic candidate read.
                if source_cache[path].truncated:
                    expanded_limit = max(max_source_bytes, _MAX_ENTRYPOINT_READ_BYTES)
                    try:
                        expanded = client.read_source(path, max_bytes=expanded_limit)
                    except Exception:
                        expanded = None
                    if expanded is not None and not expanded.truncated:
                        source_cache[path] = expanded
            except Exception as exc:
                payload["errors"].append(f"{path}: 读取源码失败：{_compact(exc)}")
                continue
        document = source_cache[path]
        profile = _source_transport_profile(document.content)
        if profile["client_connect"] > 0 and profile["accept"] == 0:
            # A response-reading helper can be classified as
            # ``server_consumer`` by a generic recv hit.  Keep its evidence
            # in the audit graph, but do not present it as this socket's
            # external-input entry function.
            excluded = payload["selection"]["excluded_client_only_paths"]
            if path not in excluded:
                excluded.append(path)
            continue

        # A selected registration/bind/config row identifies the source file,
        # but its enclosing function may only initialize a reusable device.
        # Inspect receive/dispatch calls in that same bounded file so the
        # artifact contains the actual receiver (for example
        # ``SocketDevice::ReceiveMsg``), even when the recv line does not
        # repeat the socket name.
        candidates: list[Evidence] = [anchor]
        if anchor.kind not in _ENTRYPOINT_EVIDENCE_KINDS:
            for local_line, local_kind in _target_local_entrypoint_lines(
                path,
                document,
                target,
                _target_bound_context_directories(store, target),
                allow_bound_file=True,
            ):
                cache_key = (path, local_line, local_kind)
                derived = derived_anchor_cache.get(cache_key)
                if derived is None:
                    try:
                        derived = store.add_source_excerpt(
                            document,
                            line_start=local_line,
                            kind=local_kind,
                            symbol=_evidence_symbol_for_line(
                                document.content.splitlines()[local_line - 1], target
                            ),
                            source_endpoint="opengrok.read_source.socket_entrypoint_scan",
                            relation_from=target_relation(target),
                            relation_to=f"{path}:{local_line}",
                            tool_name="opengrok.read_source.socket_entrypoint_scan",
                        )
                    except Exception as exc:
                        payload["errors"].append(
                            f"{path}:{local_line}: 入口证据记录失败：{_compact(exc)}"
                        )
                        continue
                    derived_anchor_cache[cache_key] = derived
                candidates.append(derived)
        for candidate in candidates:
            if candidate.kind in _ENTRYPOINT_EVIDENCE_KINDS:
                add_entry_anchor(
                    candidate,
                    document,
                    allow_non_entrypoint=semantic_entrypoint_review,
                )

    scope_rank = {
        "transport_receive": 0,
        "protocol_dispatch": 1,
        "protocol_helper": 2,
        "other": 3,
    }
    ordered_grouped = sorted(
        grouped.items(),
        key=lambda pair: (
            scope_rank.get(str(pair[1].get("entry_scope", "other")), 3),
            pair[0],
        ),
    )
    payload["candidate_count"] = len(ordered_grouped)
    selected_grouped = ordered_grouped[:_MAX_ENTRYPOINT_FUNCTIONS]
    decisions_by_id: dict[str, Any] = {}

    def candidate_id_for(item: Mapping[str, Any]) -> str:
        identity = (
            f"{item['source_path']}:{item['line_start']}:{item['line_end']}"
            f":{item['function']}"
        )
        return "EP-C-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]

    if llm_entrypoint_attributor is not None and ordered_grouped:
        # The model sees only bounded function candidates that were already
        # read from OpenGrok.  It is not allowed to discover new paths or
        # promote an unreviewed candidate.  Direct receive evidence is sorted
        # first by the deterministic grouping above; candidates beyond the
        # cap remain explicitly unreviewed.
        review_grouped = ordered_grouped[:_MAX_LLM_ENTRYPOINT_CANDIDATES]
        rows = []
        for _key, item in review_grouped:
            rows.append(
                {
                    "candidate_id": candidate_id_for(item),
                    "function": item["function"],
                    "source_path": item["source_path"],
                    "line_start": item["line_start"],
                    "line_end": item["line_end"],
                    "entry_kinds": sorted(item["entry_kinds"]),
                    "entry_scope": item.get("entry_scope", "other"),
                    "anchor_lines": sorted(item["anchor_lines"]),
                    "evidence_ids": sorted(item["evidence_ids"]),
                    "source": str(item["source"])[:_MAX_ENTRYPOINT_SOURCE_CHARS],
                }
            )
        payload["reviewed_candidate_count"] = len(rows)
        payload["unreviewed_candidate_count"] = max(0, len(ordered_grouped) - len(rows))
        payload["decision_source"] = "llm"
        try:
            result: LLMEntrypointAttributionResult = llm_entrypoint_attributor.attribute(
                target=target,
                candidates=rows,
            )
            payload["llm_review"] = result.to_dict()
            decisions_by_id = {decision.candidate_id: decision for decision in result.decisions}
            selected_grouped = [
                pair
                for pair in review_grouped
                if decisions_by_id.get(candidate_id_for(pair[1])) is not None
                and decisions_by_id[candidate_id_for(pair[1])].eligible
            ]
        except Exception as exc:
            # LLM attribution is optional.  A provider outage, malformed
            # response, or prompt-size failure must not make a previously
            # usable deterministic locator fail.  Re-apply the old local
            # entrypoint predicate and make the fallback visible to reviewers.
            payload["decision_source"] = "rule_fallback"
            payload["llm_review"] = {
                "status": "error",
                "error": _compact(exc),
                "model_calls": getattr(llm_entrypoint_attributor, "model_calls", 0),
            }
            payload["errors"].append(f"入口函数语义复核失败，已回退确定性筛选：{_compact(exc)}")
            selected_grouped = [
                pair
                for pair in ordered_grouped
                if _function_source_is_socket_entrypoint(
                    str(pair[1]["function"]), str(pair[1]["source"])
                )
            ][: _MAX_ENTRYPOINT_FUNCTIONS]
    elif llm_entrypoint_attributor is None:
        payload["reviewed_candidate_count"] = 0

    entries: list[dict[str, Any]] = []
    for key, item in selected_grouped[:_MAX_ENTRYPOINT_FUNCTIONS]:
        identity = f"{item['source_path']}:{item['line_start']}:{item['line_end']}"
        source_text = str(item["source"])
        entry = {
            "entrypoint_id": "EP-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
            "candidate_id": candidate_id_for(item),
            "function": item["function"],
            "source_path": item["source_path"],
            "line_start": item["line_start"],
            "line_end": item["line_end"],
            "entry_kinds": sorted(item["entry_kinds"]),
            "entry_scope": item.get("entry_scope", "other"),
            "anchor_lines": sorted(item["anchor_lines"]),
            "evidence_ids": sorted(item["evidence_ids"]),
            "source": source_text,
            "complete": bool(item["complete"]),
            "truncated": bool(item["truncated"]),
            "parser": item["parser"],
            "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        }
        decision = decisions_by_id.get(entry["candidate_id"])
        if decision is not None:
            # Keep only the validated, compact decision; never persist the
            # provider's raw response or hidden reasoning trace.
            entry["llm_decision"] = decision.to_dict()
        entries.append(entry)
    payload["entries"] = entries
    payload["entrypoint_count"] = len(entries)
    if entries and not payload["errors"] and all(item.get("complete") is True for item in entries):
        payload["status"] = "complete"
    elif entries:
        payload["status"] = "partial"
    else:
        payload["status"] = "unavailable"
        if not payload["selection"]["needs_source_entry_evidence"]:
            payload["selection"]["needs_source_entry_evidence"] = True
            payload["errors"].append(
                "已发现通信候选，但没有通过目标身份关联的服务端入口函数；需补充目标绑定证据或确认候选属于其他服务。"
            )
    if len(grouped) > _MAX_ENTRYPOINT_FUNCTIONS:
        payload["errors"].append(f"入口函数超过 {_MAX_ENTRYPOINT_FUNCTIONS} 个，已按源码位置截断展示。")
        payload["status"] = "partial"
    if llm_entrypoint_attributor is not None and len(ordered_grouped) > _MAX_LLM_ENTRYPOINT_CANDIDATES:
        payload["errors"].append(
            f"入口候选超过 {_MAX_LLM_ENTRYPOINT_CANDIDATES} 个，剩余候选未交给模型复核。"
        )
        payload["status"] = "partial"
    return payload


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
            if type_separator and file_type in {"c", "cxx", "all"}:
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


def _evidence_scoped_to_mapping(
    evidence: Iterable[Evidence],
    mapping: RepositoryMapping,
) -> tuple[Evidence, ...]:
    """Keep final attribution candidates inside the selected repository.

    Target-scoped searches intentionally retain competing repositories until
    the mapping/PK stage.  Once a mapping is selected, feeding the complete
    target evidence back to ``ServiceAttributor`` can make an unrelated
    high-volume candidate (for example a generic ``native`` helper) become
    ``best_candidate`` even though the repository itself is correct.  Include
    explicitly linked mapping rows and all source rows under the selected
    Manifest root; preserve order and deduplicate by evidence ID.
    """

    if not isinstance(mapping, RepositoryMapping):
        return tuple(evidence)
    mapping_ids = set(mapping.evidence_ids)
    selected: list[Evidence] = []
    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, Evidence) or item.evidence_id in seen:
            continue
        if item.evidence_id not in mapping_ids and not _mapping_contains_path(item.source_path, mapping):
            continue
        seen.add(item.evidence_id)
        selected.append(item)
    return tuple(selected)


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
    # Comments are useful for human context but must not become identity or
    # ownership evidence.  In particular, generated headers often contain
    # notes such as ``// see hisysevent.h`` next to an unrelated constant.
    code_line = _strip_source_comments(line)
    lower = code_line.lower()
    identity_terms = [term for term in (*target_identity_terms(target), query_value) if term]
    identity = _line_contains_identity(code_line, identity_terms)
    # A full-text/path query may find a declaration without carrying the
    # ``definition`` query kind.  Recognize source-level macro/constant
    # declarations directly so they can establish a bounded module context
    # just like an explicit definition search.
    macro_match = _MACRO_DEFINITION_RE.match(code_line)
    if macro_match is not None:
        macro_name = macro_match.group(1)
        macro_rhs = (macro_match.group(2) or "").strip()
        target_terms = [term for term in target_identity_terms(target) if term]
        rhs_has_target = _line_contains_identity(macro_rhs, target_terms)
        if (
            target.target_type == "network_socket"
            and target.address
            and _line_contains_identity(macro_rhs, [target.address])
            and target.port is not None
            and str(target.port) not in macro_rhs
            and not _NETWORK_SOCKET_CONTEXT_RE.search(code_line)
        ):
            # An address-only macro such as ``LOOP_BACK_ADDR`` is common
            # infrastructure data, not evidence that this file owns the
            # requested port.  Keep it as a weak literal candidate; the
            # address query gate and port/source anchors will locate the real
            # listener without poisoning the module context.
            rhs_has_target = False
        # A deterministic alias query is already tied to a stronger target
        # definition by ``_infer_related_macros``.  Allow its declaration to
        # participate in the bounded trace even when the RHS is another macro
        # and does not repeat the socket string.
        alias_definition = (
            isinstance(query_value, str)
            and query_value.casefold() == macro_name.casefold()
            and _is_socket_alias_query(query_value, target)
        )
        if rhs_has_target or _macro_name_is_socket_related(macro_name, target) or alias_definition:
            return "macro_definition"
    constant_match = _CONSTANT_DEFINITION_RE.search(code_line)
    if constant_match is not None and identity:
        constant_name = constant_match.group(1)
        constant_rhs = code_line[constant_match.end():].strip()
        target_terms = [term for term in target_identity_terms(target) if term]
        rhs_has_target = _line_contains_identity(constant_rhs, target_terms)
        if (
            target.target_type == "network_socket"
            and target.address
            and _line_contains_identity(constant_rhs, [target.address])
            and target.port is not None
            and str(target.port) not in constant_rhs
            and not _NETWORK_SOCKET_CONTEXT_RE.search(code_line)
        ):
            rhs_has_target = False
        alias_definition = (
            isinstance(query_value, str)
            and query_value.casefold() == constant_name.casefold()
            and _is_socket_alias_query(query_value, target)
        )
        if rhs_has_target or _macro_name_is_socket_related(constant_name, target) or alias_definition:
            return "constant_definition"
    # Network ports are frequently held in a lower-case member/constant (for
    # example ``const int udpPort = 8283``), which is intentionally outside
    # the all-caps constant pattern above.  Treat an assignment of the exact
    # target port as a bounded constant fact so it can establish the module
    # context for a sibling ``SpServerSocket``/``bind`` implementation.  A
    # bare numeric occurrence is not promoted.
    if (
        target.target_type == "network_socket"
        and target.port is not None
        and str(target.port) in code_line
        and re.search(r"\b(?:[A-Za-z_][A-Za-z0-9_]*port[A-Za-z0-9_]*|sin_port)\b\s*(?:=|:)", code_line, re.IGNORECASE)
    ):
        return "constant_definition"
    # OpenHarmony commonly receives an init-created descriptor through
    # GetControlSocket rather than calling bind() in the service itself.  The
    # operation is only considered relevant when the queried symbol/target is
    # present in the line (or the line is already in the bounded context
    # window), so a generic helper definition does not become a service hit.
    if re.search(r"\b(?:getcontrolsocket|getsocket|socketpair)\s*\(", lower):
        return "socket_acquire"
    if re.search(r"\bsocket\s*\(", lower):
        return "socket_acquire"
    # ``std::bind`` is a callable adapter, not a socket bind.  Require the
    # POSIX name not to be preceded by an identifier/namespace/member token so
    # generic full-text searches do not turn unrelated C++ code into listener
    # evidence.
    if re.search(r"(?<![A-Za-z0-9_:.])(?:bind|listen)\s*\(", lower):
        return "socket_bind_listen"
    if _SOCKET_RECEIVE_CALL_RE.search(lower):
        return "socket_accept_read"
    if _is_server_registration_line(lower):
        return "socket_server_registration"
    # Follow-up searches for an inferred socket alias often land on a source
    # assignment that bridges the init/config name to a sockaddr.  An alias
    # use alone is not a listener proof: client code also fills
    # ``addr.sun_path`` before ``connect``.  Promote it to server registration
    # only when the same line carries an actual registration/acquire operation
    # (or the generic registration-shape helper matched above).  Otherwise
    # retain a weaker service/config fact so it can establish bounded context
    # without claiming server ownership.
    if (
        _is_socket_alias_query(query_value, target)
        and isinstance(query_value, str)
        and _line_contains_identity(code_line, [query_value])
    ):
        if re.search(
            r"\b(?:getcontrolsocket|socketpair|socket|bind|listen|accept|recv|recvfrom)\s*\(",
            lower,
        ) or _is_server_registration_line(lower):
            return "socket_server_registration"
        if re.search(r"\b(?:sun_path|sockaddr(?:_in)?)\b", lower):
            # A sockaddr/path assignment is useful evidence that the alias is
            # consumed by a socket implementation, but without a registration
            # operation on the same line it is direction-neutral (and very
            # often client-side).  Keep it as a communication candidate so the
            # bounded source window can still recover a nearby bind/listen.
            return "client_endpoint"
        return "service_config"
    # Besides POSIX send/write calls, OpenHarmony wrappers such as
    # PollSendData and SendVpnInterfaceFdToClient carry the same direction.
    # Do not classify every domain method ending in ``Write`` (for example
    # ``HiSysEventWrite``) as socket traffic: require a nearby descriptor/
    # endpoint/message term for wrapper names.  The explicit POSIX calls remain
    # unambiguous.
    explicit_send = re.search(r"\b(?:connect|send|sendto|write|writev)\s*\(", lower)
    wrapper_send = re.search(r"\b\w*(?:send|write)\w*\s*\(", lower)
    wrapper_context = re.search(
        r"\b(?:fd|sock(?:et)?|endpoint|connection|channel|pipe|client|server|listener|message|payload|buffer)\w*\b",
        lower,
    )
    if explicit_send or (wrapper_send and wrapper_context):
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
        or _SOCKET_DISPATCH_LINE_RE.search(lower)
    ):
        return "protocol_dispatch"
    # Init/build metadata is a first-class ownership clue.  A socket name is
    # often declared in a ``.cfg`` file while the executable is selected in a
    # sibling BUILD.gn; retain that relation instead of treating the lines as
    # ordinary text hits.
    if re.search(
        r"\b(?:ohos_executable|ohos_shared_library|part_name|subsystem_name|sources)\b\s*(?:=|:|\(|\[)",
        lower,
    ) or re.search(r"\b(?:bundle|component|module)\b\s*[:=]", lower):
        return "executable_build"
    # A service/socket assignment is a useful, source-backed ownership
    # relation (for example ``info.server = PIPE_NAME`` or an init
    # ``service_name = ...`` line).  It is deliberately narrower than a raw
    # identity hit, so a random comment containing the basename cannot satisfy
    # the server attribution predicate.
    if identity and re.search(
        # Keep the key at an identifier boundary.  Without this boundary,
        # ``HiSysEvent::EventType::BEHAVIOR`` was matched as ``type:`` and
        # promoted ordinary event-telemetry code to ``service_config``.  A
        # small explicit suffix form still covers source fields such as
        # ``sun_path`` and ``socket_name`` without treating ``EventType`` as
        # a configuration key.
        r"(?:\b(?:service|server|socket|endpoint)(?:[._-](?:name|path|id))?\s*[:=]|"
        r"(?<![A-Za-z0-9_])[\"']?(?:name|path|family|type|protocol|permissions?|uid|gid)[\"']?\s*[:=]|"
        r"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*_(?:name|path|family|protocol|permissions?|uid|gid)\s*[:=])",
        lower,
    ):
        return "service_config"
    if identity and query_kind == "definition":
        return "macro_definition" if target.macro_hint else "symbol_reference"
    if identity:
        return "literal_match"
    return "symbol_reference" if query_kind in {"definition", "symbol"} else "literal_match"


def _query_value_targets_target(
    query_value: str | None,
    target: TargetSpec,
    *,
    allow_non_generic: bool = False,
) -> bool:
    """Return whether a query value carries target identity, not only API noise.

    Generic searches for ``bind``/``socket`` are useful for recall but their
    hits cannot establish ownership on their own.  A port, address, endpoint,
    process hint, Unix path or service name is target-specific and may justify
    retaining nearby communication calls during bounded source tracing.
    """

    if not isinstance(query_value, str) or not query_value.strip():
        return False
    value = query_value.strip()
    if value.casefold() in _NETWORK_GENERIC_QUERY_TERMS:
        return False
    if target.target_type == "network_socket":
        target_values = {
            str(item).casefold()
            for item in (
                target.port,
                target.address,
                network_endpoint(target),
                target.process_hint,
                target.service_hint,
            )
            if item is not None
        }
        if value.casefold() in target_values:
            return True
        # A model-selected wrapper/symbol (for example
        # ``CreateSocketListener``) can be a useful second-hop query after
        # the target evidence has already been cited.  It is allowed only for
        # semantic LLM actions, never for the deterministic broad API plan.
        return allow_non_generic and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.:()\-]{2,127}", value
        ) is not None
    if value.casefold() in {item.casefold() for item in target_identity_terms(target)}:
        return True
    return allow_non_generic and re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.:()\-]{2,127}", value
    ) is not None


def _line_has_target_identity(line: str, target: TargetSpec) -> bool:
    # A comment can mention a socket name without connecting the line to the
    # implementation.  Keep identity checks consistent with ``_line_kind``
    # and inspect only source/config text.
    code_line = _strip_source_comments(line)
    return _line_contains_identity(code_line, [term for term in target_identity_terms(target) if term])


def _line_contains_identity(line: str, terms: Iterable[str | int | None]) -> bool:
    """Match target tokens without treating a longer symbol as the socket.

    ``AppSpawn`` appears inside symbols such as ``AppSpawnHookExecute`` and
    ``hisysevent`` appears in ``hisysevent_util``.  Substring matching made
    those unrelated files look like socket ownership.  Identifier/path/port
    boundaries preserve exact macro, config and endpoint matches while still
    accepting punctuation around names such as ``faultloggerd.crash.server``.
    """

    for raw in terms:
        if raw is None:
            continue
        term = str(raw).strip().casefold()
        if not term:
            continue
        if term.startswith("/"):
            pattern = rf"(?<![A-Za-z0-9._+@=-]){re.escape(term)}(?![A-Za-z0-9._+@=-])"
            if re.search(pattern, line.casefold()) is not None:
                return True
            continue

        # Do not case-fold an entire C/C++ identifier.  For a lower-case
        # socket name such as ``paramservice``, that would make the unrelated
        # lowerCamel variable ``paramService`` look like an exact socket
        # identity.  First accept the spelling as written (and the all-caps
        # macro spelling), then allow a title-case symbol only when it is a
        # complete identifier.  A prefixed/suffixed identifier such as
        # ``NotifyParamService`` remains a miss.
        exact_variants = {str(raw).strip(), str(raw).strip().upper()}
        for variant in exact_variants:
            pattern = rf"(?<![A-Za-z0-9_]){re.escape(variant)}(?![A-Za-z0-9_])"
            if re.search(pattern, line) is not None:
                return True
        if term.isalpha() and term.islower():
            identifier_pattern = r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]*(?![A-Za-z0-9_])"
            for match in re.finditer(identifier_pattern, line):
                token = match.group(0)
                if token.casefold() != term or not token[0].isupper():
                    continue
                # Preserve PascalCase symbols (``ParamService``) while
                # rejecting lowerCamel data fields (``paramService``).
                if any(char.isupper() for char in token[1:]):
                    return True
    return False


def _line_contains_strong_target_identity(
    line: str,
    terms: Iterable[str | int | None],
) -> bool:
    """Match an exact endpoint/configuration identity for ownership ranking.

    ``_line_contains_identity`` intentionally accepts PascalCase spellings so
    generic source exploration can relate names such as ``ParamService`` to a
    lower-case endpoint.  That permissive rule is unsafe for repository
    attribution: a telemetry API such as ``HiSysEvent::EventType`` can occur
    in hundreds of client repositories without owning the ``hisysevent``
    socket.  Ranking therefore uses only the exact spelling (plus an explicit
    all-caps macro spelling) and keeps the broader matcher for search and
    evidence discovery.
    """

    text = str(line or "")
    for raw in terms:
        if raw is None:
            continue
        value = str(raw).strip()
        if not value:
            continue
        if value.startswith("/"):
            pattern = rf"(?<![A-Za-z0-9._+@=-]){re.escape(value)}(?![A-Za-z0-9._+@=-])"
            if re.search(pattern, text) is not None:
                return True
            continue
        variants = [value]
        if value.isalpha():
            variants.append(value.upper())
        pattern = rf"(?<![A-Za-z0-9_])(?:{'|'.join(re.escape(item) for item in variants)})(?![A-Za-z0-9_])"
        if re.search(pattern, text) is not None:
            return True
    return False


def _path_contains_target_identity(path: str, target: TargetSpec) -> bool:
    """Match a target against a source filename/component without substring noise.

    Service implementations frequently use a normalized filename instead of
    repeating the init socket name (``init_control_fd_service.c`` for
    ``init_control_fd`` or ``param_service.c`` for ``paramservice``).  A plain
    substring check is too permissive for names such as
    ``AppSpawnHookExecute``.  Compare delimiter-separated pieces and allow a
    small, explicit service suffix (``service``, ``server``, ``daemon``,
    ``socket``, ``listen`` or ``impl``) after an exact compact target.
    """

    if not isinstance(path, str) or not path.strip() or not isinstance(target, TargetSpec):
        return False
    values = (
        target.basename,
        target.service_hint,
        target.macro_hint,
        target.process_hint,
    )
    components = [part for part in path.split("/") if part]
    suffixes = {"service", "server", "daemon", "socket", "listen", "impl", "listener"}
    for raw_value in values:
        if not raw_value:
            continue
        value = str(raw_value).strip().casefold()
        compact_value = re.sub(r"[^a-z0-9]", "", value)
        if not compact_value:
            continue
        for component in components:
            stem = component.rsplit(".", 1)[0] if "." in component else component
            pieces = [piece.casefold() for piece in re.split(r"[^A-Za-z0-9]+", stem) if piece]
            compact_component = "".join(pieces)
            if any(piece == value for piece in pieces) and (
                len(pieces) == 1 or any(piece in suffixes for piece in pieces if piece != value)
            ):
                return True
            if compact_component == compact_value:
                return True
            if compact_component.startswith(compact_value):
                remainder = compact_component[len(compact_value):]
                if remainder in suffixes:
                    return True
    return False


_GENERIC_TARGET_COMPONENTS = frozenset(
    {
        "socket",
        "unix",
        "pipe",
        "endpoint",
        "server",
        "service",
        "daemon",
        "listener",
        "control",
        "crash",
        "sdkdump",
        "fast",
        "root",
    }
)


def _target_component_tokens(target: TargetSpec) -> frozenset[str]:
    """Return meaningful component roots for a target-scoped path bridge.

    A named socket is frequently represented by a short suffix in a source
    path (``faultloggerd.server`` -> ``faultloggerd`` or
    ``hiprofiler_unix_socket`` -> ``profiler``).  The regular identity
    matcher intentionally stays strict, so this helper is used only by the
    entrypoint bridge and never by repository attribution.  Generic transport
    words are removed; the remaining roots are bounded and compared only as
    exact tokens or long prefix/suffix relationships.
    """

    if not isinstance(target, TargetSpec):
        return frozenset()
    values = (
        target.basename,
        target.service_hint,
        target.macro_hint,
        target.process_hint,
    )
    roots: set[str] = set()
    suffixes = ("service", "server", "daemon", "listener", "socket", "fd")
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            continue
        value = raw.strip().casefold()
        pieces = [
            piece
            for piece in re.split(r"[^a-z0-9]+", value)
            if piece and piece not in _GENERIC_TARGET_COMPONENTS
        ]
        compact = "".join(pieces)
        # Strip a common role suffix from a compact spelling so
        # ``paramservice`` can match the ``param`` component directory.
        compact_roots = [compact]
        for suffix in suffixes:
            if compact.endswith(suffix) and len(compact) - len(suffix) >= 4:
                compact_roots.append(compact[: -len(suffix)])
        for piece in pieces:
            if len(piece) >= 4:
                roots.add(piece)
        for item in compact_roots:
            if len(item) >= 4:
                roots.add(item)
    return frozenset(roots)


def _path_has_target_component_affinity(path: str, target: TargetSpec) -> bool:
    """Whether a source path belongs to the target-named component.

    This is deliberately narrower than sharing a repository or an ancestor
    such as ``communication/netmanager_base``.  It prevents a generic VPN
    receiver from being presented for ``dnsproxyd`` while still bridging
    split config/implementation layouts such as faultloggerd and hiprofiler.
    """

    if not isinstance(path, str) or not path.strip() or not isinstance(target, TargetSpec):
        return False
    roots = _target_component_tokens(target)
    if not roots:
        return False
    parent = path.rsplit("/", 1)[0] or "/"
    tokens = set(_context_path_tokens(parent))
    # The target identity is often encoded in the implementation filename
    # rather than its parent directory (``dns_resolv_listen.cpp`` and
    # ``fault_logger_server.cpp`` are common examples).  Include filename
    # pieces in this narrow affinity check; the general path matcher remains
    # unchanged and therefore does not become more permissive globally.
    filename = path.rsplit("/", 1)[-1]
    stem = filename.rsplit(".", 1)[0]
    pieces = [
        piece
        for piece in re.split(r"[^a-z0-9]+", stem.casefold())
        if piece and piece not in _GENERIC_TARGET_COMPONENTS
    ]
    # Keep a three-letter filename root only for the one-way prefix check
    # below (the full target root must start with it).  This covers
    # ``dns_resolv_listen.cpp`` for ``dnsproxyd`` without allowing a generic
    # ``vpn`` token to match ``multivpnfd``.
    tokens.update(piece for piece in pieces if len(piece) >= 3)
    compact_filename = "".join(pieces)
    if len(compact_filename) >= 4:
        tokens.add(compact_filename)
    if not tokens:
        return False
    for root in roots:
        for token in tokens:
            if token == root:
                return True
            shorter, longer = sorted((root, token), key=len)
            # Only long relationships may bridge a split source path.  A
            # three-letter prefix (e.g. ``dns``) is accepted only when it is
            # a complete path token and the full target root starts with it;
            # generic fragments such as ``net``/``app`` never qualify.
            if len(shorter) >= 5 and (longer.startswith(shorter) or longer.endswith(shorter)):
                return True
            if len(token) >= 3 and len(root) >= 6 and root.startswith(token):
                return True
    return False


def _evidence_symbol_for_line(
    line: str,
    target: TargetSpec,
    *,
    query_value: str | None = None,
) -> str | None:
    """Return a symbol only when the source line actually supports it.

    The old worker copied ``target.service_hint`` into every evidence row.
    That made a generic hit such as ``SocketDevice::Open`` look as if it were
    a ``paramservice`` symbol and caused unrelated rows to be merged into the
    same attribution candidate.  A target name is now retained only when the
    line contains the target identity; an inferred socket alias is retained
    when the line contains that alias.  Generic context rows deliberately
    have no synthetic symbol and are linked by their source location instead.
    """

    if not isinstance(line, str) or not isinstance(target, TargetSpec):
        return None
    code_line = _strip_source_comments(line).lower()
    target_terms = tuple(term for term in target_identity_terms(target) if term)
    if _line_contains_identity(code_line, target_terms):
        return target.service_hint or target.process_hint or target.basename
    if (
        isinstance(query_value, str)
        and _is_socket_alias_query(query_value, target)
        and _line_contains_identity(code_line, (query_value,))
    ):
        return query_value.strip()
    return None


def _target_bound_context_directories(
    store: EvidenceStore,
    target: TargetSpec,
) -> tuple[str, ...]:
    """Build context directories only from target-anchored source evidence.

    Search plans contain broad API hits and policy/generated references.  They
    must not establish a repository-wide context by themselves.  This helper
    derives a bounded directory window from lines that contain the endpoint
    identity or from a source path whose component clearly names the target.
    """

    if not isinstance(store, EvidenceStore) or not isinstance(target, TargetSpec):
        return ()
    anchors: list[str] = []
    seen_paths: set[str] = set()
    for item in store.evidence:
        if not isinstance(item, Evidence):
            continue
        try:
            path_role = classify_path(item.source_path, target=target).role
        except (TypeError, ValueError):
            path_role = "unknown"
        # SELinux policy/audit snippets can repeat the exact socket path, but
        # they do not create or consume the socket.  They must remain visible
        # in the complete evidence graph without establishing source context.
        if path_role in {"selinux", "log", "test", "fuzz"}:
            continue
        if not (
            _line_has_target_identity(item.excerpt, target)
            or _path_contains_target_identity(item.source_path, target)
        ):
            continue
        if item.source_path in seen_paths:
            continue
        seen_paths.add(item.source_path)
        anchors.append(item.source_path)
        if len(anchors) >= 64:
            break
    directories: list[str] = []
    seen_dirs: set[str] = set()
    for path in anchors:
        parent = path.rsplit("/", 1)[0] or "/"
        current = parent
        for depth in range(5):
            if len([part for part in current.split("/") if part]) < 3:
                break
            if current not in seen_dirs:
                seen_dirs.add(current)
                directories.append(current)
            current = current.rsplit("/", 1)[0] or "/"
            if depth >= 4:
                break
        if len(directories) >= 128:
            break
    return tuple(directories[:128])


def _target_evidence_is_bound(
    path: str,
    line: str,
    target: TargetSpec,
    context_dirs: Iterable[str] = (),
) -> bool:
    """Whether a source row is tied to this target, not just its API shape."""

    try:
        path_role = classify_path(path, target=target).role
    except (TypeError, ValueError):
        path_role = "unknown"
    if path_role in {"selinux", "log", "test", "fuzz"}:
        return False
    if _line_has_target_identity(line, target):
        return True
    if _path_contains_target_identity(path, target):
        return True
    # ``_path_shares_target_context`` intentionally ignores broad ancestors
    # when a deeper header/config directory exists.  Attribution still needs
    # to accept a sibling implementation below the explicitly anchored
    # component (for example appspawn/standard/appspawn_service.c), so use the
    # stricter component-ancestor check as a final, target-scoped fallback.
    return _path_shares_target_context(path, context_dirs) or _path_has_target_bound_component(
        path, context_dirs
    )


def _source_transport_profile(content: str) -> dict[str, int]:
    """Count bounded transport signals in one already selected source file.

    This is deliberately a *local* profile, never a repository-wide search.
    It prevents a client helper that happens to call ``recv`` from becoming
    an entrypoint while still allowing init-created descriptor services such
    as appspawn, whose implementation uses ``GetControlSocket`` + ``recvmsg``
    rather than a literal ``bind``.
    """

    text = str(content or "")
    return {
        "receive": len(_SOCKET_NETWORK_RECEIVE_CALL_RE.findall(text))
        + len(_SOCKET_READ_CALL_RE.findall(text)),
        "dispatch": len(_SOCKET_DISPATCH_LINE_RE.findall(text)),
        "server_anchor": len(_SOCKET_SERVER_ANCHOR_RE.findall(text)),
        # ``bind``/``listen`` also occur in reusable client-side helpers (for
        # example faultloggerd's shared StartListen routine).  Keep a direct
        # accept count and descriptor-acquisition count so an entire source
        # file containing connect + listen helpers is not mistaken for the
        # requested service's inbound receiver.
        "accept": len(re.findall(r"\baccept(?:4)?\s*\(", text, re.IGNORECASE)),
        "control_socket": len(
            re.findall(r"\b(?:getcontrolsocket|getserversocket)\s*\(", text, re.IGNORECASE)
        ),
        "client_connect": len(_SOCKET_CLIENT_CONNECT_RE.findall(text)),
    }


def _path_has_target_bound_component(path: str, context_dirs: Iterable[str]) -> bool:
    """Match a path to an explicitly anchored component directory.

    ``_path_shares_target_context`` is intentionally tolerant for the broad
    search/attribution phase.  The local entrypoint scan needs a stricter
    relationship: prefer a concrete anchored directory that is an ancestor of
    the candidate, and never use a repository-wide ``base``/``services``
    ancestor as the sole reason to scan a file.
    """

    if not isinstance(path, str) or not isinstance(context_dirs, (list, tuple, set, frozenset)):
        return False
    parent = path.rsplit("/", 1)[0].rstrip("/") or "/"
    candidates = []
    for value in context_dirs:
        if not isinstance(value, str) or not value.strip():
            continue
        context = value.rstrip("/") or "/"
        if parent == context or parent.startswith(context + "/"):
            # At least a component-level directory is required.  This keeps
            # /openharmony/base/startup from connecting unrelated daemons,
            # while accepting /openharmony/base/startup/appspawn and
            # /openharmony/base/startup/init/services/param.
            if len([part for part in context.split("/") if part]) >= 4:
                candidates.append(context)
    return bool(candidates)


def _target_local_entrypoint_lines(
    path: str,
    document: SourceDocument,
    target: TargetSpec,
    context_dirs: Iterable[str],
    *,
    allow_bound_file: bool = False,
) -> tuple[tuple[int, str], ...]:
    """Find target-bound receive/dispatch lines inside one ranked file.

    The caller has already selected ``path`` from target-scoped OpenGrok
    results.  We scan only that bounded source document, not the whole index.
    ``allow_bound_file`` is used after a target-bound registration/owner row
    has selected the file: receive/dispatch lines in that same file need not
    repeat the socket name on every line (for example ``SocketDevice``'s
    ``ReceiveMsg`` implementation).
    A file whose only transport direction is ``connect``/``ConnectServer`` is
    treated as a client dependency, even if it reads the server response.
    """

    if not isinstance(document, SourceDocument) or not document.content:
        return ()
    try:
        if not is_attribution_eligible(path, target=target):
            return ()
    except (TypeError, ValueError):
        return ()
    if not (
        _path_contains_target_identity(path, target)
        or _path_has_target_bound_component(path, context_dirs)
    ):
        return ()
    profile = _source_transport_profile(document.content)
    if profile["receive"] == 0 and profile["dispatch"] == 0:
        return ()
    # A source file that connects to a named socket and only reads the reply
    # is not the socket's server entry.  Require a server anchor in that case.
    if profile["client_connect"] > 0 and profile["accept"] == 0:
        return ()
    lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(document.content.splitlines(), 1):
        if not allow_bound_file:
            if not _named_socket_operation_matches_target(line, target):
                continue
            if not _network_operation_matches_target(line, target):
                continue
        if _SOCKET_RECEIVE_CALL_RE.search(line):
            # ``read`` is also used for internal pipes and files.  Treat it
            # as a socket entry only when the same function has a server
            # descriptor anchor/dispatch shape, or the call explicitly names
            # a socket-like fd.  ``recv*``/``accept`` remain direct inbound
            # socket evidence.
            if _SOCKET_READ_CALL_RE.search(line) and not _SOCKET_NETWORK_RECEIVE_CALL_RE.search(line):
                enclosing = _extract_enclosing_function(document, line_number)
                if enclosing is None or not (
                    _SOCKET_SERVER_ANCHOR_RE.search(enclosing["source"])
                    or _SOCKET_DISPATCH_LINE_RE.search(enclosing["source"])
                    or _SOCKET_FD_HINT_RE.search(line)
                ):
                    continue
            lines.append((line_number, "socket_accept_read"))
        elif (
            _SOCKET_DISPATCH_LINE_RE.search(line)
            and "=" not in line
            and not line.rstrip().endswith(";")
        ):
            lines.append((line_number, "protocol_dispatch"))
    # A source file can contain many switch cases and wrapper references.  A
    # bounded, stable set of lines is enough because the subsequent function
    # extractor groups all anchors belonging to the same complete function.
    return tuple(lines[:_MAX_TRACE_EVIDENCE_PER_PATH])


def _function_source_is_socket_entrypoint(function_name: str, source: str) -> bool:
    """Reject setup/registration functions from the standalone entry list."""

    text = str(source or "")
    if _SOCKET_NETWORK_RECEIVE_CALL_RE.search(text):
        return True
    if _SOCKET_READ_CALL_RE.search(text) and (
        _SOCKET_SERVER_ANCHOR_RE.search(text) or _SOCKET_FD_HINT_RE.search(text)
    ):
        return True
    # Some socket frameworks hide the actual ``recv`` loop in a reusable
    # epoll/receiver object and expose a callback factory instead.  For
    # example, netmanager's ``ProcCommand`` returns a ``ReceiverRunner``
    # lambda; the callback receives a fixed-length message and dispatches on
    # its command value, while the underlying ``EpollServer`` performs the
    # read.  Treat this as a protocol entry only when the source contains the
    # framework's receiver types *and* a real switch/case dispatch.  A generic
    # business switch remains excluded.
    if (
        re.search(r"\b(?:ReceiverRunner|FixedLengthReceiverState|EpollServer|AddReceiver)\b", text)
        and re.search(r"\bswitch\s*\(", text)
        and re.search(r"\bcase\b", text)
    ):
        return True
    # A dispatch function may receive an already decoded message from a
    # framework callback rather than call recv itself.  Do not treat every
    # ``switch`` in a business helper as a socket entry (``SetMark`` and
    # command parsers are common false positives); require an explicitly
    # receive/dispatch-shaped function name.  The source-level switch/case
    # evidence remains in the audit graph and can still identify the handler
    # once its enclosing function has a suitable name.
    compact_name = re.sub(r"[^A-Za-z0-9_]", "", str(function_name or ""))
    return bool(
        re.search(
            r"(?i)^(?:onreceive|onrecv|onremoterequest|handle(?:recv|msg|message|request)|"
            r"process(?:recv|msg|message|request)|recvmessage|dispatch)",
            compact_name,
        )
    )


def _network_function_matches_target(
    function_name: str,
    source: str,
    target: TargetSpec,
) -> bool:
    """Keep a network entry function only when its transport is compatible.

    A single daemon commonly implements both transports beside each other.
    Generic endpoint/port searches can therefore produce ``Recvfrom`` while
    the query is TCP (or ``TypeTcp``/``Accept`` while it is UDP).  This check
    is intentionally conservative and function-scoped: generic dispatcher
    functions such as ``Process`` remain eligible, while methods whose name
    or body unambiguously selects the opposite transport are excluded.
    """

    if not isinstance(target, TargetSpec) or target.target_type != "network_socket":
        return True
    name = re.sub(r"[^A-Za-z0-9]", "", str(function_name or "")).casefold()
    text = _strip_source_comments(str(source or "")).casefold()
    if target.transport == "UDP":
        # TCP-specific method names are stronger than a nearby generic recv
        # hit.  ``Process`` intentionally does not match and remains the
        # shared protocol dispatcher for both UDP ports.
        if re.search(r"(?:typetcp|tcp|accept|recv)$", name):
            return False
        if re.search(r"\b(?:accept|listen)\s*\(", text) and not re.search(
            r"\b(?:recvfrom|sendto|sock_dgram)\s*\(", text
        ):
            return False
        return True
    if target.transport == "TCP":
        # UDP-specific handlers must not be advertised for the TCP endpoint.
        if re.search(r"(?:recvfrom|handlemsg|handleudp|udpstart|udp)$", name):
            return False
        if (
            re.search(r"\b(?:recvfrom|sendto|sock_dgram)\s*\(", text)
            and not re.search(r"\b(?:accept|recv)\s*\(", text)
            and not re.search(r"(?:process|dispatch|run|loop|thread)$", name)
        ):
            return False
        return True
    return True


def _target_bound_evidence(
    store: EvidenceStore,
    target: TargetSpec,
) -> tuple[Evidence, ...]:
    """Return attribution input limited to source rows tied to the target.

    ``evidence.json`` remains append-only and keeps noisy hits for audit.  The
    role attributors, however, must not let a generic ``SocketDevice`` or
    ``recv`` row from another component satisfy the target's server predicates.
    """

    context_dirs = _target_bound_context_directories(store, target)
    return tuple(
        item
        for item in store.evidence
        if _target_evidence_is_bound(
            item.source_path,
            item.excerpt,
            target,
            context_dirs,
        )
    )


def _is_socket_alias_query(query_value: str | None, target: TargetSpec) -> bool:
    """Whether a deterministic macro follow-up names a socket alias.

    This is intentionally narrower than accepting arbitrary model-selected
    symbols: only all-caps macro names containing a socket/service/pipe word
    qualify, and the caller still needs a target context or identity line.
    """

    if target.target_type == "network_socket" or not isinstance(query_value, str):
        return False
    value = query_value.strip()
    if not _MACRO_NAME_RE.fullmatch(value):
        return False
    return _SOCKET_WORD_RE.search(value) is not None


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
    # Several OpenHarmony components wrap the POSIX calls in a compact
    # ``*SockInit``/``*SocketCreate`` helper.  For example init's
    # ``FdHolderSockInit`` creates and binds ``fd_holder`` while the service
    # source itself only exposes the returned descriptor.  Treat the helper
    # as a registration fact so the source trace can connect the target macro
    # to the actual bind path.  The name must contain both a socket token and
    # an initialization/creation verb; ordinary ``GetSocketFd`` accessors do
    # not match.
    socket_named_init = re.search(
        r"\b(?:[a-z0-9_]*(?:sock|socket)[a-z0-9_]*"
        r"(?:create|init|start|open|register|setup|listen|bind)[a-z0-9_]*|"
        r"(?:create|init|start|open|register|setup|make)[a-z0-9_]*"
        r"(?:sock|socket)[a-z0-9_]*)\s*\(",
        normalized,
    )
    # Device-oriented servers (for example HiView's
    # ``AddDev(std::make_shared<SocketDevice>(name, ...))``) may not expose a
    # POSIX bind in the same class.  The device is opened through
    # ``GetControlSocket`` later, so this registration line is the missing
    # config-to-consumer edge.  Restrict the pattern to an explicit
    # ``SocketDevice``/socket device registration; a generic ``AddDev`` must
    # not classify unrelated devices as listeners.
    socket_device_registration = re.search(
        r"\b(?:adddev|adddevice|register(?:dev|device|socket)|addsocket)\s*\([^)]*"
        r"\b(?:socketdevice|unixsocketdevice|socket_device)\b",
        normalized,
    )
    # ``CmdServiceInit`` is an OpenHarmony control-FD wrapper: its name does
    # not contain ``socket``, but its signature/call carries a socket path
    # and the implementation immediately constructs a stream server.  Keep
    # this generic (service/server + init/create/start/register) and require
    # a socket-like argument/field, avoiding a global classification of every
    # unrelated service initializer.
    service_socket_init = re.search(
        r"\b[a-z0-9_]*(?:service|server|listener)[a-z0-9_]*"
        r"(?:init|create|start|open|register|setup|listen|bind)[a-z0-9_]*\s*\([^)]*"
        r"(?:sock|socket|endpoint|pipe|path|server)[a-z0-9_]*",
        normalized,
    )
    # Project-specific wrappers are common in SmartPerf and other
    # OpenHarmony components (for example ``SpServerSocket::Init`` or
    # ``SpThreadSocket::HandleMsg``).  They are useful registration/consumer
    # clues even when no POSIX ``bind`` appears in the same source file.
    socket_wrapper_call = re.search(
        r"\b(?P<class>[a-z0-9_]*(?:server[_]?socket|socket[_]?server|thread[_]?socket|socket[_]?thread)"
        r"[a-z0-9_]*)(?:::(?P<method>[a-z0-9_]+))?\s*\(",
        normalized,
    )
    if socket_wrapper_call is not None:
        method = socket_wrapper_call.group("method")
        class_name = socket_wrapper_call.group("class")
        registration_methods = {
            "create",
            "init",
            "start",
            "open",
            "register",
            "setup",
            "listen",
            "bind",
        }
        # A constructor is written ``SpServerSocket::SpServerSocket``; a
        # message handler such as ``SpThreadSocket::HandleMsg`` is not a
        # registration fact and must be classified by its receive/dispatch
        # operation (if present) instead.
        wrapper_registration = method is None or method in registration_methods or method == class_name
    else:
        wrapper_registration = False
    return bool(
        field_assignment
        or factory_call
        or socket_named_init
        or socket_device_registration
        or service_socket_init
        or wrapper_registration
    )


def _client_kind(line: str, target: TargetSpec) -> str | None:
    lower = line.lower()
    if not _line_contains_identity(line, target_identity_terms(target)):
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
        for term in target_identity_terms(target)
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
                code_line = _strip_source_comments(line)
                try:
                    line_no = int(hit.get("line_number", hit.get("lineNumber", 0)))
                except (TypeError, ValueError):
                    line_no = 0
                match = _MACRO_DEFINITION_RE.match(code_line)
                if match is not None:
                    name = match.group(1)
                    rhs = (match.group(2) or "").strip()
                else:
                    # Some OpenHarmony headers use a static/constexpr
                    # sockaddr or string constant instead of ``#define``;
                    # e.g. ``FWMARK_SERVER_PATH = {...}``.  Capture only a
                    # clearly macro-shaped constant immediately before an
                    # assignment/initializer.
                    constant = _CONSTANT_DEFINITION_RE.search(code_line)
                    if constant is None:
                        continue
                    name = constant.group(1)
                    rhs = code_line[constant.end():].strip()
                if not _MACRO_NAME_RE.fullmatch(name):
                    continue
                rows.append((line_no, name, rhs, code_line.lower()))

    # First pass: direct identity-bearing definitions are strongest.
    strong_rows: list[tuple[str, int, str, str]] = []
    for path, rows in by_path.items():
        for line_no, name, rhs, line in rows:
            # The target may appear in the value (a literal path/string) or in
            # an endpoint-shaped alias name such as
            # ``HISYSEVENT_SOCKET_NAME``.  Generic constants such as
            # ``ERR_SUCCESS`` must not become aliases merely because their
            # trailing comment mentioned the target file.
            direct_value = (
                _line_contains_identity(line, identity_terms)
                or _line_contains_identity(rhs, identity_terms)
            )
            name_related = _macro_name_is_socket_related(name, target)
            if direct_value and (name_related or _line_contains_identity(rhs, identity_terms)):
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
    # Do not add every socket-looking macro from a file that happened to
    # contain the target.  Headers commonly define unrelated ``KEY_SOCKET_FD``
    # or ``FUNCTION_BIND_SOCKET`` constants; querying all of them consumed the
    # bounded follow-up budget and promoted client/UI code.  A macro is now
    # eligible only when it is identity-bearing or immediately adjacent to an
    # identity-bearing definition (the two passes above).
    excluded = {
        value.upper()
        for value in (target.basename, target.service_hint, target.macro_hint, target.process_hint)
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


def _component_source_queries(
    result_executions: Iterable[Mapping[str, Any]],
    target: TargetSpec,
    *,
    max_queries: int,
    start_index: int,
) -> tuple[LocatorQuery, ...]:
    """Build bounded source-file probes from a target-owned service config.

    Init-created sockets commonly name the endpoint in ``*.cfg`` while the
    service implementation uses a normalized component file such as
    ``appspawn_service.c``.  A basename/path search can return generated
    outputs before that source file, so derive a few role-suffixed filenames
    from the *same target-bearing config directory*.  This remains target
    scoped and does not issue repository-wide ``recv``/``bind`` searches.
    """

    if max_queries <= 0:
        return ()
    stems: list[str] = []
    seen_stems: set[str] = set()
    config_suffixes = (".cfg", ".rc", ".conf", ".ini")
    generic_parent_names = {
        "init", "etc", "system", "phone", "packages", "out", "obj", "gen",
        "security_config", "sepolicy",
    }
    target_compact = re.sub(r"[^a-z0-9]", "", (target.basename or "").casefold())
    # Common OpenHarmony service variants use a short product prefix while
    # sharing one implementation component.  ``CJAppSpawn`` and the native /
    # hybrid spawn aliases are handled by ``appspawn_service.c``; NWebSpawn is
    # the webspawn variant.  Do not derive the literal suffix ``spawn`` for
    # NativeSpawn/HybridSpawn: with a small query budget that consumes the
    # only source-probe slot and misses the actual appspawn implementation.
    variant_stems = {
        "cj": "appspawn",
        "native": "appspawn",
        "hybrid": "appspawn",
        "nweb": "webspawn",
    }
    for prefix, component in variant_stems.items():
        if target_compact.startswith(prefix) and len(target_compact) - len(prefix) >= 5:
            stems.append(component)
            seen_stems.add(component)
            break
    for execution in result_executions:
        if not isinstance(execution, Mapping) or execution.get("status") != "ok":
            continue
        response = execution.get("response")
        results = response.get("results") if isinstance(response, Mapping) else None
        if not isinstance(results, Mapping):
            continue
        for path, raw_hits in results.items():
            if not isinstance(path, str) or not isinstance(raw_hits, list):
                continue
            lowered_path = path.casefold()
            if not lowered_path.endswith(config_suffixes):
                continue
            if not (
                _path_contains_target_identity(path, target)
                or any(
                isinstance(hit, Mapping)
                and isinstance(hit.get("line"), str)
                and _line_has_target_identity(hit["line"], target)
                for hit in raw_hits
                )
            ):
                continue
            parent = path.rsplit("/", 1)[0].rstrip("/")
            parent_leaf = parent.rsplit("/", 1)[-1]
            filename = path.rsplit("/", 1)[-1]
            filename_stem = filename.rsplit(".", 1)[0]
            raw_stems: list[str] = []
            # Prefer a meaningful component directory.  Generated output
            # paths end in ``.../system/etc/init``; those directory names are
            # not service implementations and must not consume the one-slot
            # follow-up budget.
            if parent_leaf.casefold() not in generic_parent_names:
                raw_stems.append(parent_leaf)
            parent_compact = re.sub(r"[^a-z0-9]", "", parent_leaf.casefold())
            filename_compact = re.sub(r"[^a-z0-9]", "", filename_stem.casefold())
            # The init name may carry a variant prefix (CJAppSpawn,
            # NativeSpawn, HybridSpawn) while the source component is
            # appspawn.  Derive only known product variants; do not guess
            # arbitrary repository directories.
            if filename_compact == target_compact and target_compact:
                for prefix, component in variant_stems.items():
                    if target_compact.startswith(prefix) and len(target_compact) - len(prefix) >= 5:
                        raw_stems.insert(0, component)
                        break
            if (
                parent_compact
                and target_compact
                and len(parent_compact) >= 5
                and target_compact.endswith(parent_compact)
            ):
                raw_stems.insert(0, parent_leaf)
            raw_stems.extend((target.basename, target.service_hint or ""))
            for raw_stem in raw_stems:
                stem = re.sub(r"[^A-Za-z0-9_]+", "_", str(raw_stem or "")).strip("_")
                if len(stem) < 4 or stem.casefold() in seen_stems:
                    continue
                seen_stems.add(stem.casefold())
                stems.append(stem)
                if len(stems) >= 4:
                    break
            if len(stems) >= 4:
                break
        if len(stems) >= 4:
            break

    queries: list[LocatorQuery] = []
    index = start_index
    for stem in stems:
        for suffix in ("_service.c", "_service.cpp", "_server.c", "_server.cpp"):
            if len(queries) >= max_queries:
                return tuple(queries)
            queries.append(
                LocatorQuery(
                    query_id=f"Q-SOURCE-{index:04d}",
                    kind="path",
                    value=f"{stem}{suffix}",
                    file_type="all",
                    reason="由目标 socket 所属 init 配置目录推断服务端源码文件名",
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
        # The deterministic attributor orders by score.  For noisy services
        # that can place dozens of creator/owner rows before the actual
        # server-consumer rows, causing the latter to disappear from the
        # session/UI copy even though they remain in ``roles``.  Reserve one
        # slot for each observed role first, then fill the remaining budget
        # in original order.  This changes only the bounded presentation
        # projection; the append-only evidence graph and full role decisions
        # remain the source of truth.
        raw_items = [raw for raw in raw_candidates if isinstance(raw, Mapping)]
        role_priority = (
            "server_consumer",
            "server_handler",
            "service_owner",
            "socket_creator",
            "client_transport",
            "client_protocol",
            "client_sender",
        )
        selected_indices: list[int] = []
        selected_set: set[int] = set()
        for role in role_priority:
            for index, raw in enumerate(raw_items):
                if index in selected_set or raw.get("role") != role:
                    continue
                selected_indices.append(index)
                selected_set.add(index)
                break
        for index in range(len(raw_items)):
            if len(selected_indices) >= _MAX_ATTRIBUTION_CANDIDATES:
                break
            if index not in selected_set:
                selected_indices.append(index)
                selected_set.add(index)
        for index in selected_indices:
            raw = raw_items[index]
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
    # ``best_candidate`` is a derived convenience field for the UI.  Apply
    # the same bounds as the ordinary candidate list so a high-volume
    # service/config group cannot make the session payload unbounded.
    best = payload.get("best_candidate")
    if isinstance(best, Mapping):
        best_payload = dict(best)
        if isinstance(best_payload.get("source_locations"), list):
            best_payload["source_locations"] = [
                dict(item)
                for item in best_payload["source_locations"][:8]
                if isinstance(item, Mapping)
            ]
        if isinstance(best_payload.get("evidence_ids"), list):
            best_payload["evidence_ids"] = best_payload["evidence_ids"][:16]
        if isinstance(best_payload.get("reasons"), list):
            best_payload["reasons"] = best_payload["reasons"][:8]
        payload["best_candidate"] = best_payload
    roles = payload.get("roles")
    if isinstance(roles, Mapping):
        compact_roles: dict[str, list[dict[str, Any]]] = {}
        for role, entries in roles.items():
            if not isinstance(entries, list):
                compact_roles[str(role)] = []
                continue
            compact_roles[str(role)] = [
                dict(item)
                for item in entries[:_MAX_CONFIRMATION_ROLES]
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
    excluded_evidence_ids = payload.get("excluded_evidence_ids")
    if isinstance(excluded_evidence_ids, list):
        payload["excluded_evidence_ids"] = excluded_evidence_ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS]
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


def _scope_llm_role_result_to_mapping(
    result: LLMRoleAttributionResult | None,
    mapping: RepositoryMapping,
) -> LLMRoleAttributionResult | None:
    """Keep semantic role claims only when their evidence belongs to ``mapping``.

    Role attribution runs before competing Manifest candidates are adjudicated,
    so a valid model answer may cite the implementation copy from a different
    repository.  Merging that answer after candidate PK would make the final
    ``best_candidate`` point back to the losing repository.  Keep the original
    role artifact for audit, but scope the decision used by the final
    attribution/confirmation payload to the selected mapping.
    """

    if result is None:
        return None
    allowed = set(mapping.evidence_ids)

    def scope(decision: LLMRoleDecision) -> LLMRoleDecision:
        original_ids = tuple(decision.evidence_ids)
        if not original_ids or set(original_ids).issubset(allowed):
            return decision
        selected_ids = tuple(item for item in original_ids if item in allowed)
        if not selected_ids:
            return LLMRoleDecision(
                role=decision.role,
                status="unresolved",
                confidence="low",
                subject="",
                evidence_ids=(),
                reason="原始语义证据属于其他候选仓库，候选 PK 后未合并到所选仓库归因。",
            )
        status = "possible" if decision.status == "confirmed" else decision.status
        confidence = "low" if decision.confidence == "high" else decision.confidence
        return LLMRoleDecision(
            role=decision.role,
            status=status,
            confidence=confidence,
            subject=decision.subject,
            evidence_ids=selected_ids,
            reason=(
                decision.reason
                + "；原始决策包含其他候选仓库证据，最终仅保留所选仓库证据。"
            ),
        )

    return LLMRoleAttributionResult(
        server=scope(result.server),
        client=scope(result.client),
        model_calls=result.model_calls,
        prompt_version=result.prompt_version,
        schema_version=result.schema_version,
    )


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
        for term in target_identity_terms(target)
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

# A validated semantic server decision is an ownership signal, not merely
# another occurrence of the socket basename.  Keep the bonus large enough to
# outrank a repository that only contains many HiSysEvent/API telemetry uses,
# while preferring an actual registration/bind evidence row when the model
# cites more than one repository (for example the service and its client
# library both mention the same endpoint).
_SEMANTIC_SERVER_ROLE_BONUS: Mapping[str, int] = {
    "socket_bind_listen": 700,
    "socket_server_registration": 650,
    "socket_accept_read": 500,
    "protocol_dispatch": 450,
    "socket_acquire": 350,
    "service_config": 250,
    "executable_build": 150,
    "client_endpoint": 50,
    "client_connect": 25,
    "client_send": 10,
    "literal_match": 0,
    "symbol_reference": 0,
}


def _mapping_identity_path_is_eligible(path: str) -> bool:
    """Return whether a path may establish repository ownership.

    Policy and log artifacts often repeat a socket path as an AVC/access
    record.  They remain useful evidence for permissions and exposure, but a
    target string in such a file is not proof that the file's repository owns
    the listener.  Keep the exclusion local to ownership scoring so those
    records are still available to the UI and later semantic review.
    """

    try:
        classification = classify_path(path)
    except (TypeError, ValueError):
        return False
    return classification.role not in {"selinux", "log"}


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
            counts["llm_server_owner_anchor"] = counts.get("llm_server_owner_anchor", 0) + 1
            score += 900 + _SEMANTIC_SERVER_ROLE_BONUS.get(item.kind, 0)
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
    semantic_anchor_count = counts.get("llm_server_owner_anchor", 0)
    target_anchor_count = 0
    # A target-bound receive/dispatch or registration fact is stronger
    # ownership evidence than an isolated bind/listen/client occurrence.  The
    # latter is common in generic networking helpers and client libraries,
    # while the former points at the source file that actually owns or
    # consumes the endpoint.  Keep this as a path-scoped bonus (rather than a
    # global role weight) so unrelated repositories cannot win merely by
    # containing many transport calls.
    target_server_source_count = 0
    if target is not None:
        # Keep the original spelling here.  ``_line_contains_identity`` has
        # its own boundary-aware matching and deliberately preserves
        # lowerCamel/PascalCase distinctions (for example ``hilogControl``).
        # Case-folding the terms before passing them in removes the exact
        # configuration/macro anchor and can make all repositories tie.
        target_terms = tuple(term for term in target_identity_terms(target) if term)
        # A plain ``literal_match`` or ``symbol_reference`` is deliberately
        # not an ownership anchor: short/common names such as ``native`` occur
        # in unrelated variables and APIs throughout the tree.  Restrict
        # strong identity evidence to rows whose role can actually bind an
        # endpoint to a component.
        strong_identity_kinds = {
            "service_config",
            "executable_build",
            "macro_definition",
            "constant_definition",
            "socket_server_registration",
            "socket_bind_listen",
            "socket_acquire",
            "client_endpoint",
        }
        strong_identity_present = any(
            item.evidence_id in ids
            and item.kind in strong_identity_kinds
            # SELinux AVC/policy rows can mention the target path and even
            # contain a ``path=``/``name=`` assignment, but they describe an
            # access-control relationship, not the repository that creates
            # or consumes the socket.  They must not lift a policy repository
            # into an ownership anchor for targets such as ``dnsproxyd``.
            and _mapping_identity_path_is_eligible(item.source_path)
            and _line_contains_strong_target_identity(item.excerpt, target_terms)
            for item in store.evidence
        )
        for item in store.evidence:
            if item.evidence_id not in ids:
                continue
            try:
                classification = classify_path(item.source_path)
                if not classification.attribution_eligible:
                    continue
            except Exception:
                continue
            # Keep SELinux/log evidence visible in the audit graph, but do
            # not let it satisfy the target-identity ownership anchor.  The
            # same path may legitimately carry a target label while the
            # implementation lives in another repository.
            if classification.role in {"selinux", "log"}:
                continue
            exact_identity = (
                item.kind in strong_identity_kinds
                and _line_contains_strong_target_identity(item.excerpt, target_terms)
            )
            if exact_identity:
                target_anchor_count += 1
            if item.kind in {
                "socket_accept_read",
                "protocol_dispatch",
                "socket_server_registration",
            } and _target_evidence_is_bound(
                item.source_path,
                item.excerpt,
                target,
            ) and _mapping_contains_path(item.source_path, mapping) and (
                _path_contains_target_identity(item.source_path, target)
                or strong_identity_present
            ):
                target_server_source_count += 1
        counts["target_identity_anchor"] = target_anchor_count
        if target_server_source_count:
            counts["target_server_source_anchor"] = target_server_source_count
            # One target-bound consumer/dispatch/registration source is enough
            # to identify the implementation repository in the common
            # split-source case.  Multiple sites are retained in the count but
            # capped to keep the ranking stable for large services.
            score += min(target_server_source_count, 4) * 700
    # A confirmed, evidence-linked semantic server decision is itself an
    # ownership anchor.  Do not apply the generic-only cap to that mapping:
    # registration rows such as ``SocketDevice("hisysevent", ...)`` may not
    # carry a separate macro/configuration evidence kind, but the model has
    # already tied the exact source row to the target.
    # Only an exact target identity, a target-bound server source, or an
    # evidence-linked semantic owner can lift the generic-only cap.  Generic
    # ``service_config`` rows (for example HiSysEvent API calls) are useful
    # audit evidence but are not ownership proof by themselves.
    has_target_ownership_anchor = bool(
        target_anchor_count or target_server_source_count or semantic_anchor_count
    )
    if semantic_anchor_count == 0 and not has_target_ownership_anchor:
        score = min(score, 180)
    else:
        # An exact target-bearing init/service configuration is already a
        # concrete ownership fact, even when the implementation receives the
        # descriptor through a generic framework (for example ``sa_main``)
        # and no component-local ``GetControlSocket``/recv line is indexed.
        # Give that fact enough weight to outrank unrelated generic socket
        # helpers, while keeping the absence of a consumer visible as an
        # unresolved server predicate rather than fabricating one.
        if target_anchor_count:
            score += min(600, target_anchor_count * 500)
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


_MAX_CANDIDATE_REVIEW_CANDIDATES = 3
_MAX_CANDIDATE_METADATA_FILES = 12
_MAX_CANDIDATE_SOURCE_FACTS = 12
_MAX_CANDIDATE_SOURCE_FACTS_PER_FILE = 3
_MAX_CANDIDATE_BUILD_FACTS = 3
_MAX_CANDIDATE_CONFIG_FACTS = 3


def _candidate_metadata_paths(mapping: RepositoryMapping) -> tuple[str, ...]:
    """Return a bounded, symmetric OpenGrok-only candidate evidence set.

    Duplicate/split OpenHarmony repositories frequently expose the same
    socket implementation under different roots.  Reading only the first
    repository's implementation gives the LLM an artificial semantic
    advantage, so competing candidates receive the same implementation,
    peer-handler, build and bundle probes.  This is path derivation only; it
    never reads the local checkout.
    """

    paths: list[str] = []
    source_path = mapping.source_path.strip()
    source_basename = source_path.rsplit("/", 1)[-1] if source_path else ""
    source_stem = source_basename.rsplit(".", 1)[0] if "." in source_basename else source_basename

    def add(path: str) -> None:
        normalized = "/" + "/".join(part for part in path.split("/") if part and part != ".")
        if normalized and normalized not in paths:
            paths.append(normalized)

    if source_path:
        directory = source_path.rsplit("/", 1)[0]
        source_bases: list[str] = []
        if "/include/" in source_path:
            source_bases.append(source_path.split("/include/", 1)[0])
        elif "/src/" in source_path:
            source_bases.append(source_path.split("/src/", 1)[0])
        if not source_bases and directory:
            source_bases.append(directory)
        # Read the implementation and the adjacent protocol handler for the
        # common SP_daemon-style split.  Missing paths are normal and ignored
        # by _candidate_metadata_facts.
        peer_stems = [source_stem] if source_stem else []
        if source_stem == "sp_server_socket":
            peer_stems.append("sp_thread_socket")
        elif source_stem == "sp_thread_socket":
            peer_stems.append("sp_server_socket")
        for base in dict.fromkeys(source_bases):
            for stem in peer_stems:
                add(f"{base}/{stem}.cpp")
                # Some candidates keep headers under ``include/`` while the
                # implementation is under the sibling ``src/`` directory.
                # Probe both layouts so the candidate PK sees the same
                # bind/recv/dispatch implementation for every repository.
                add(f"{base}/src/{stem}.cpp")
            add(f"{base}/{source_basename}")
            add(f"{base}/BUILD.gn")
            parent = base.rsplit("/", 1)[0]
            if parent:
                add(f"{parent}/BUILD.gn")
    if mapping.source_root:
        root = "/openharmony/" + mapping.source_root.strip("/")
        add(f"{root}/BUILD.gn")
        add(f"{root}/bundle.json")
    return tuple(paths[:_MAX_CANDIDATE_METADATA_FILES])


def _candidate_metadata_facts(
    *,
    mapping: RepositoryMapping,
    target: TargetSpec,
    client: Any,
    store: EvidenceStore,
    max_source_bytes: int,
) -> tuple[tuple[str, ...], tuple[dict[str, Any], ...], tuple[str, ...]]:
    """Read bounded build/config facts from OpenGrok for one candidate.

    The method never falls back to ``project_root``.  Missing metadata is a
    normal condition and simply yields no supplemental facts.
    """

    read_source = getattr(client, "read_source", None)
    if not callable(read_source):
        return (), (), ()
    tokens = tuple(
        dict.fromkeys(
            item.casefold()
            for item in (
                target.process_hint,
                target.service_hint,
                target.basename,
            )
            if isinstance(item, str) and item.strip()
        )
    )
    source_basename = mapping.source_path.rsplit("/", 1)[-1].casefold() if mapping.source_path else ""
    source_stem = source_basename.rsplit(".", 1)[0] if "." in source_basename else source_basename
    # Keep category budgets separate.  The previous implementation stopped
    # after the first implementation file produced 12 lines, so BUILD.gn,
    # bundle.json and the peer protocol handler never reached the PK prompt.
    # These bounded buckets guarantee that ownership and implementation facts
    # are both visible without allowing a large source file to dominate.
    source_candidates: list[tuple[int, int, SourceDocument, str, str]] = []
    build_candidates: list[tuple[int, int, SourceDocument, str, str]] = []
    config_candidates: list[tuple[int, int, SourceDocument, str, str]] = []
    files_read: list[str] = []
    for path in _candidate_metadata_paths(mapping):
        try:
            document = read_source(path, max_bytes=max_source_bytes)
        except Exception:
            continue
        if not isinstance(document, SourceDocument):
            continue
        files_read.append(document.path)
        suffix = document.path.rsplit(".", 1)[-1].casefold() if "." in document.path else ""
        for line_number, line in enumerate(document.content.splitlines(), 1):
            lowered = line.casefold()
            target_match = bool(tokens and any(token in lowered for token in tokens))
            build_target_match = suffix in {"gn", "gni"} and (
                target_match
                or (source_basename and source_basename in lowered)
                or (source_stem and source_stem in lowered)
                or "ohos_executable" in lowered
                and ("executable" in lowered or "target" in lowered)
            )
            config_match = suffix in {"json", "cfg", "rc", "conf", "xml"} and target_match
            # Source implementation facts are collected symmetrically for
            # competing candidates.  This captures bind/recv/dispatch lines
            # even when the implementation does not repeat the process name
            # or port literal on every line.
            source_operation_match = suffix in {"c", "cc", "cpp", "cxx", "h", "hpp"} and (
                re.search(r"\b(?:bind|listen|accept|recvfrom|recv)\s*\(", lowered) is not None
                or "spserversocket::" in lowered
                or "spthreadsocket::" in lowered
                or "handlem" in lowered
                or "udpport" in lowered
                or "udpexport" in lowered
                or "tcpport" in lowered
            )
            if suffix in {"gn", "gni"}:
                if not build_target_match:
                    continue
                kind = "executable_build"
                # Direct process/executable declarations outrank source-name
                # references, which in turn outrank generic target blocks.
                priority = 5 if target_match else 4 if (target.process_hint and target.process_hint.casefold() in lowered) else 2
                build_candidates.append((priority, line_number, document, kind, line))
                continue
            elif suffix in {"json", "cfg", "rc", "conf", "xml"}:
                if not config_match:
                    continue
                kind = "service_config"
                config_candidates.append((5 if target_match else 2, line_number, document, kind, line))
                continue
            if suffix not in {"c", "cc", "cpp", "cxx", "h", "hpp"} or not source_operation_match:
                continue
            if re.search(r"\b(?:bind|listen)\s*\(", lowered):
                kind = "socket_bind_listen"
            elif re.search(r"\b(?:accept|recvfrom|recv)\s*\(", lowered):
                kind = "socket_accept_read"
            elif "handlem" in lowered or "spthreadsocket::" in lowered:
                kind = "protocol_dispatch"
            elif "udpport" in lowered or "udpexport" in lowered or "tcpport" in lowered:
                kind = "constant_definition"
            else:
                kind = "symbol_reference"
            # Bind/recv/dispatch/port facts are more useful than constructor
            # and logging lines.  Sorting within each file keeps the bounded
            # sample stable while ensuring the security-relevant operations
            # survive truncation.
            priority = {
                "socket_bind_listen": 5,
                "socket_accept_read": 5,
                "protocol_dispatch": 4,
                "constant_definition": 4,
                "symbol_reference": 1,
            }[kind]
            source_candidates.append((priority, line_number, document, kind, line))

    def select_candidates(
        candidates: list[tuple[int, int, SourceDocument, str, str]],
        limit: int,
        *,
        per_file: int | None = None,
    ) -> list[tuple[int, int, SourceDocument, str, str]]:
        selected: list[tuple[int, int, SourceDocument, str, str]] = []
        counts: dict[str, int] = {}
        # Preserve path discovery order for ties, but prefer concrete
        # operation/ownership lines over constructors and generic references.
        for item in sorted(candidates, key=lambda value: (-value[0], value[1], value[2].path)):
            if len(selected) >= limit:
                break
            path_key = item[2].path
            if per_file is not None and counts.get(path_key, 0) >= per_file:
                continue
            selected.append(item)
            counts[path_key] = counts.get(path_key, 0) + 1
        return selected

    selected = []
    # Build/config facts are placed before source facts in the model prompt so
    # process ownership is visible before the nearly identical socket code.
    selected.extend(select_candidates(build_candidates, _MAX_CANDIDATE_BUILD_FACTS))
    selected.extend(select_candidates(config_candidates, _MAX_CANDIDATE_CONFIG_FACTS))
    selected.extend(
        select_candidates(
            source_candidates,
            _MAX_CANDIDATE_SOURCE_FACTS - _MAX_CANDIDATE_BUILD_FACTS - _MAX_CANDIDATE_CONFIG_FACTS,
            per_file=_MAX_CANDIDATE_SOURCE_FACTS_PER_FILE,
        )
    )

    # If a candidate has no build/config metadata, fill the unused slots with
    # additional source facts while retaining the per-file cap for the first
    # pass.  This keeps ordinary single-file services useful without allowing
    # them to crowd out metadata when it exists.
    if len(selected) < _MAX_CANDIDATE_SOURCE_FACTS:
        chosen_keys = {(item[2].path, item[1], item[3]) for item in selected}
        for item in select_candidates(source_candidates, _MAX_CANDIDATE_SOURCE_FACTS):
            key = (item[2].path, item[1], item[3])
            if key in chosen_keys:
                continue
            selected.append(item)
            chosen_keys.add(key)
            if len(selected) >= _MAX_CANDIDATE_SOURCE_FACTS:
                break

    evidence_ids: list[str] = []
    facts: list[dict[str, Any]] = []
    for _, line_number, document, kind, _line in selected:
        try:
            evidence = store.add_source_excerpt(
                document,
                line_start=line_number,
                kind=kind,
                tool_name="opengrok.read_source.candidate_metadata",
                source_endpoint="opengrok.read_source",
                relation_from=target.raw_input,
                relation_to=f"{mapping.project_name}:{mapping.source_root or mapping.source_path}",
            )
        except Exception:
            continue
        if evidence.evidence_id in evidence_ids:
            continue
        evidence_ids.append(evidence.evidence_id)
        facts.append(
            {
                "evidence_id": evidence.evidence_id,
                "kind": evidence.kind,
                "source_path": evidence.source_path,
                "line_start": evidence.line_start,
                "line_end": evidence.line_end,
                "excerpt": evidence.excerpt[:_MAX_CONFIRMATION_TEXT],
            }
        )
    return tuple(evidence_ids), tuple(facts), tuple(files_read)


def _compact_repository_mappings_payload(
    mappings: Iterable[RepositoryMapping | Mapping[str, Any]],
) -> dict[str, Any]:
    """Bound repository mappings stored in the session checkpoint.

    ``repository_resolutions.json`` keeps the complete, auditable mapping
    rows.  The session only needs the highest-ranked rows and enough evidence
    IDs to reselect a repository in the next stage.  Without this split, a
    broad LLM search can attach thousands of evidence IDs to dozens of
    project rows and exceed ``LocatorSession``'s 64 KiB mapping field limit.
    """

    rows: list[dict[str, Any]] = []
    for item in mappings:
        if isinstance(item, RepositoryMapping):
            row = item.to_dict()
        elif isinstance(item, Mapping):
            row = dict(item)
        else:
            continue
        evidence_ids = row.get("evidence_ids")
        if isinstance(evidence_ids, list):
            row["evidence_ids"] = evidence_ids[:_MAX_SESSION_MAPPING_EVIDENCE_IDS]
        warnings = row.get("warnings")
        if isinstance(warnings, list):
            row["warnings"] = warnings[:_MAX_CONFIRMATION_REASONS]
        rows.append(row)

    total = len(rows)
    rows = rows[:_MAX_SESSION_REPOSITORY_MAPPINGS]
    payload: dict[str, Any] = {"mappings": rows}
    if total > len(rows):
        payload["truncated"] = True
        payload["total_mappings"] = total
        payload["truncated_mapping_count"] = total - len(rows)
    return payload


def _session_evidence_checkpoint_updates(
    evidence_ids: Iterable[str],
    metrics: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a bounded evidence-id patch for the resumable session.

    ``evidence.json`` is the complete evidence store.  The checkpoint only
    needs a navigational sample.  Keeping this normalization here also lets a
    session created by an older worker repair its oversized evidence list when
    it next crosses the repository-resolution boundary.
    """

    normalized = tuple(dict.fromkeys(str(item) for item in evidence_ids if item))
    checkpoint_metrics = dict(metrics or {})
    checkpoint_metrics["evidence_total"] = len(normalized)
    checkpoint_metrics["evidence_ids_truncated"] = len(normalized) > _MAX_SESSION_EVIDENCE_IDS
    return {
        "evidence_ids": normalized[:_MAX_SESSION_EVIDENCE_IDS],
        "metrics": checkpoint_metrics,
    }


def _confirmation_role_payload(
    result: Any,
    *,
    store: EvidenceStore | None = None,
    limit: int,
) -> list[dict[str, Any]]:
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
    by_id = {item.evidence_id: item for item in store.evidence} if store else {}
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
        source_evidence: list[dict[str, Any]] = []
        if isinstance(evidence_ids, list) and by_id:
            for evidence_id in evidence_ids:
                if not isinstance(evidence_id, str):
                    continue
                item = by_id.get(evidence_id)
                if item is None:
                    continue
                source_evidence.append(
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
                if len(source_evidence) >= _MAX_CONFIRMATION_LOCATIONS:
                    break
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
                # Keep the source line beside the role instead of forcing the
                # confirmation UI to guess which of the global evidence rows
                # supports this candidate.  This is bounded to the same small
                # number of locations shown above.
                "source_evidence": source_evidence,
            }
        )
    return compact


def _confirmation_candidate_evidence_ids(result: Any) -> tuple[str, ...]:
    """Return evidence cited by bounded attribution candidates in stable order."""

    try:
        raw = result.to_dict()
    except (AttributeError, TypeError, ValueError):
        return ()
    candidates = raw.get("candidates", [])
    if not isinstance(candidates, list):
        return ()
    ids: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        evidence_ids = candidate.get("evidence_ids", [])
        if not isinstance(evidence_ids, list):
            continue
        for evidence_id in evidence_ids:
            if isinstance(evidence_id, str) and evidence_id not in ids:
                ids.append(evidence_id)
    return tuple(ids[:_MAX_ATTRIBUTION_EVIDENCE_IDS])


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
    # Candidate role evidence is placed first so the bounded global evidence
    # list contains the actual server/client source lines shown in the role
    # cards.  The aggregate result IDs are retained for compatibility and for
    # repository/target evidence that is useful in the confirmation view.
    referenced_ids = tuple(
        dict.fromkeys(
            (
                *_confirmation_candidate_evidence_ids(server),
                *_confirmation_candidate_evidence_ids(client),
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
            "transport": target.transport,
            "address": target.address,
            "port": target.port,
            "process_hint": target.process_hint,
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
            "chain_status": server.status,
            "confirmed": server.confirmed,
            "score": server.score,
            "best_candidate": server_payload.get("best_candidate"),
            "repository_confidence": server_payload.get("repository_confidence", "UNKNOWN"),
            "selection_confidence_score": server_payload.get("selection_confidence_score", 0),
            "selection_reasons": list(server_payload.get("selection_reasons", ())),
            "predicates": dict(server.predicates),
            "missing_predicates": list(missing_server_predicates),
            # The structural predicates remain an auditable signal.  They are
            # advisory at this point: an explicit user decision is still
            # required before any repository operation is attempted.
            "predicate_gate": "advisory" if missing_server_predicates else "satisfied",
            "roles": _confirmation_role_payload(
                server,
                store=store,
                limit=_MAX_CONFIRMATION_ROLES,
            ),
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
            "roles": _confirmation_role_payload(
                client,
                store=store,
                limit=_MAX_CONFIRMATION_ROLES,
            ),
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

        target = _target(self.session)
        bound_ids = {item.evidence_id for item in _target_bound_evidence(store, target)}
        semantic = _load_llm_role_result(
            self.machine,
            allowed_evidence_ids=(item.evidence_id for item in store.evidence),
        )
        if semantic is None or semantic.server.status not in {"confirmed", "possible"}:
            return ()
        # A stale role artifact may cite a generic row that was later rejected
        # by the target-identity gate.  Do not let it add ranking weight back
        # to an unrelated repository.
        if any(item not in bound_ids for item in semantic.server.evidence_ids):
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
        target = _target(self.session)
        attribution_evidence = _target_bound_evidence(store, target)
        attributor = self.runtime.llm_role_attributor
        if attributor is None:
            return _load_llm_role_result(
                self.machine,
                allowed_evidence_ids=(item.evidence_id for item in attribution_evidence),
            ), dict(self.session.artifacts)
        # The server stage is the owner of this one-call artifact.  When the
        # client stage runs immediately afterwards (or a session is resumed),
        # reuse it instead of spending a second model call.
        if role_artifact_path.exists():
            cached = _load_llm_role_result(
                self.machine,
                allowed_evidence_ids=(item.evidence_id for item in attribution_evidence),
            )
            if cached is not None:
                return cached, dict(self.session.artifacts)
            # A previous run may have cited rows that the stricter target gate
            # now rejects.  Fall through and regenerate the bounded decision
            # when a role model is available instead of reusing stale claims.
        eligible, excluded = partition_attribution_evidence(attribution_evidence)
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

    def _run_candidate_review(
        self,
        resolved: Iterable[RepositoryMapping],
        store: EvidenceStore,
        target: TargetSpec,
    ) -> tuple[RepositoryMapping, dict[str, Any], dict[str, str]]:
        """Optionally let the model PK competing repository mappings.

        The deterministic score remains the fallback and is never replaced by
        model prose.  Supplemental build/config evidence is read only through
        the configured OpenGrok client and is persisted in ``evidence.json``.
        """

        def enrich_selected_mapping(
            mapping: RepositoryMapping,
            review: Mapping[str, Any],
        ) -> RepositoryMapping:
            """Attach candidate-PK metadata evidence to the selected mapping.

            Candidate metadata is read after Manifest resolution.  Keeping its
            evidence IDs on the selected mapping lets the final attribution
            stage recognize BUILD.gn/bundle.json ownership facts and prevents
            the confirmation summary from mixing a selected repository with
            pre-PK evidence from a competing copy.
            """

            rows = review.get("candidates", []) if isinstance(review, Mapping) else []
            if not isinstance(rows, list):
                return mapping
            row = next(
                (
                    item
                    for item in rows
                    if isinstance(item, Mapping)
                    and item.get("project_name") == mapping.project_name
                ),
                None,
            )
            if not isinstance(row, Mapping):
                return mapping
            supplemental_ids: list[str] = []
            facts = row.get("source_facts", [])
            if isinstance(facts, list):
                for fact in facts:
                    if not isinstance(fact, Mapping):
                        continue
                    evidence_id = fact.get("evidence_id")
                    if isinstance(evidence_id, str) and evidence_id.startswith("E-"):
                        supplemental_ids.append(evidence_id)
            if not supplemental_ids:
                return mapping
            return replace(
                mapping,
                evidence_ids=tuple(
                    dict.fromkeys((*mapping.evidence_ids, *supplemental_ids))
                ),
            )

        ordered = sorted(
            tuple(resolved),
            key=lambda item: (
                -self._mapping_score(item, store, target=target)[0],
                -(1 if item.status == "resolved" else 0),
                item.project_name or "",
            ),
        )
        fallback = ordered[0]
        review_path = _session_dir(self.machine) / "repository_candidate_review.json"
        if review_path.exists() and review_path.is_file() and not review_path.is_symlink():
            try:
                cached = _read_json(review_path)
                cached_candidates = cached.get("candidates", []) if isinstance(cached, Mapping) else []
                cached_names = tuple(
                    item.get("project_name")
                    for item in cached_candidates
                    if isinstance(item, Mapping) and isinstance(item.get("project_name"), str)
                )
                current_names = tuple(item.project_name for item in ordered[:_MAX_CANDIDATE_REVIEW_CANDIDATES])
                cached_selected = cached.get("selected_repository") if isinstance(cached, Mapping) else None
                if (
                    isinstance(cached, Mapping)
                    and cached.get("status") in {"complete", "ERROR_FALLBACK", "SKIPPED"}
                    and cached_names == current_names
                    and isinstance(cached_selected, str)
                ):
                    selected = next(
                        (item for item in ordered if item.project_name == cached_selected),
                        fallback,
                    )
                    return (
                        enrich_selected_mapping(selected, cached),
                        dict(cached),
                        dict(self.session.artifacts),
                    )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
        competitive: list[RepositoryMapping] = []
        for item in ordered:
            kinds = {
                evidence.kind
                for evidence in store.evidence
                if evidence.evidence_id in set(item.evidence_ids)
            }
            if "socket_accept_read" in kinds:
                competitive.append(item)
        trigger = len(competitive) >= 2 or (bool(target.process_hint) and len(ordered) >= 2)
        base_payload: dict[str, Any] = {
            "schema_version": "openant.source-locator.candidate-review.v1",
            "status": "SKIPPED",
            "triggered": trigger,
            "candidate_count": len(ordered),
            "competing_candidate_count": len(competitive),
            "fallback_repository": fallback.project_name,
            "candidates": [],
            "decision": None,
        }
        if self.runtime.llm_candidate_reviewer is None or not trigger:
            base_payload["reason"] = (
                "未检测到两个以上具有竞争性 socket 接收证据的候选，"
                "或未启用候选仓库 LLM 复核。"
            )
            artifacts = _save_artifact(
                self.machine,
                "repository_candidate_review.json",
                base_payload,
                "候选仓库 PK 未触发；保留确定性最高分候选。",
            )
            return fallback, base_payload, artifacts

        rows: list[dict[str, Any]] = []
        for item in ordered[:_MAX_CANDIDATE_REVIEW_CANDIDATES]:
            supplemental_ids, source_facts, files_read = _candidate_metadata_facts(
                mapping=item,
                target=target,
                client=self.runtime.client,
                store=store,
                max_source_bytes=self.runtime.max_source_bytes,
            )
            mapping_score, counts = self._mapping_score(item, store, target=target)
            # Keep newly read build/config IDs first so the bounded candidate
            # row cannot truncate away the very facts the model is expected to
            # use when a mapping already carries 64 historical IDs.
            evidence_ids = tuple(dict.fromkeys((*supplemental_ids, *item.evidence_ids)))
            rows.append(
                {
                    "project_name": item.project_name,
                    "source_root": item.source_root,
                    "source_path": item.source_path,
                    "repo_url": item.repo_url,
                    "ranking_score": mapping_score,
                    "role_evidence_counts": counts,
                    "evidence_ids": list(evidence_ids[:_MAX_SESSION_MAPPING_EVIDENCE_IDS]),
                    "source_facts": list(source_facts),
                    "metadata_files_read": list(files_read),
                }
            )
        if any(row.get("source_facts") for row in rows):
            _json_write(_session_dir(self.machine) / "evidence.json", store.to_dict())
        base_payload["candidates"] = rows
        base_payload["metadata_evidence_count"] = sum(
            len(row.get("source_facts", ())) for row in rows
        )
        try:
            result = self.runtime.llm_candidate_reviewer.review(
                target=target.to_dict(),
                candidates=rows,
            )
            selected = next(
                (item for item in ordered if item.project_name == result.primary_repository),
                None,
            )
            if selected is None:
                raise CandidateReviewError("模型选择的仓库不在 resolved mapping 中")
            base_payload.update(
                {
                    "status": "complete",
                    "selected_repository": selected.project_name,
                    "selected_by": "llm_candidate_review",
                    "decision": result.to_dict(),
                    "fallback_used": False,
                }
            )
            artifacts = _save_artifact(
                self.machine,
                "repository_candidate_review.json",
                base_payload,
                "多个候选仓库的最终 LLM PK；只接受候选集合内的项目和源码证据，失败时回退最高分。",
            )
            return enrich_selected_mapping(selected, base_payload), base_payload, artifacts
        except Exception as exc:
            base_payload.update(
                {
                    "status": "ERROR_FALLBACK",
                    "selected_repository": fallback.project_name,
                    "selected_by": "deterministic_score",
                    "fallback_used": True,
                    "error": _compact(exc),
                }
            )
            artifacts = _save_artifact(
                self.machine,
                "repository_candidate_review.json",
                base_payload,
                "候选 LLM PK 失败的结构化错误摘要；已安全回退确定性最高分候选。",
            )
            return enrich_selected_mapping(fallback, base_payload), base_payload, artifacts

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
            result = client.probe(probe_path=target.socket_path if target.target_type == "unix_socket" else None)
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
                target_context_dirs = _target_bound_context_directories(store, target)
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
                            if (
                                not _network_operation_matches_target(hit.line, target)
                                or not _target_evidence_is_bound(
                                    path,
                                    hit.line,
                                    target,
                                    target_context_dirs,
                                )
                            ):
                                continue
                            store.add_search_hit(
                                path,
                                hit,
                                kind=kind,
                                symbol=_evidence_symbol_for_line(
                                    hit.line,
                                    target,
                                    query_value=action.query,
                                ),
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
        identity_terms = tuple(term.lower() for term in target_identity_terms(target) if term)
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
        target_context_dirs = _target_bound_context_directories(store, target)
        for line_no in selected_lines:
            try:
                if not _network_operation_matches_target(lines[line_no - 1], target):
                    continue
                line_kind = self._llm_evidence_kind(action.expected_relation, lines[line_no - 1], target)
                if (
                    not _target_evidence_is_bound(
                        document.path,
                        lines[line_no - 1],
                        target,
                        target_context_dirs,
                    )
                ):
                    continue
                evidence = store.add_source_excerpt(
                    document,
                    line_start=line_no,
                    kind=line_kind,
                    symbol=_evidence_symbol_for_line(
                        lines[line_no - 1],
                        target,
                        query_value=requested_path,
                    ),
                    query_id=query_id,
                    source_endpoint="opengrok.read_source.llm",
                    relation_from=target_relation(target),
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
        max_actions = _budget_int(
            budget,
            "max_llm_actions",
            default=(
                planner.budget.max_actions
                if planner is not None
                else LLM_SEARCH_DEFAULT_MAX_ACTIONS
            ),
            maximum=LLM_SEARCH_MAX_ACTIONS,
            minimum=0,
        )
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
        execution_failure_streak = 0
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
                if duplicate_streak >= _MAX_LLM_DUPLICATE_STREAK:
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
                    if duplicate_streak >= _MAX_LLM_DUPLICATE_STREAK:
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
                if duplicate_streak >= _MAX_LLM_DUPLICATE_STREAK:
                    self.machine.record_event(
                        event_type="llm.search.retry_exhausted",
                        summary_zh="连续重复检索达到上限，结束本轮语义检索",
                        details={"duplicate_streak": duplicate_streak, "phase": phase},
                    )
                    break
                continue

            duplicate_streak = 0
            local_actions.append(llm_action_key)
            action_keys.append(llm_action_key)
            plan = audit.get("plan")
            if isinstance(plan, Mapping):
                action_payload = plan.get("action")
                query = action_payload.get("query") if isinstance(action_payload, Mapping) else None
                if isinstance(query, str):
                    action_queries.append(query)
            if isinstance(execution, Mapping) and execution.get("status") not in {"ok", "skipped_duplicate"}:
                # OpenGrok 400s, transient connection failures and missing
                # raw documents are tool failures, not proof that the target
                # has no source.  Keep the accepted action in history (so it
                # is not replayed), expose the failure to the next model
                # turn, and let it choose a different query or file.  A
                # consecutive cap prevents an unavailable endpoint from
                # consuming the entire semantic budget.
                execution_failure_streak += 1
                error_type = execution.get("error_type") or "OpenGrok 查询失败"
                error_message = execution.get("error_message") or execution.get("status") or "未知工具错误"
                planner_feedback = (
                    f"上一动作 {llm_action_key} 执行失败（{error_type}: {_compact(error_message)}）；"
                    "不要重复该动作，改用不同的查询类型、目标符号或已知候选文件继续补证。"
                )
                if execution_failure_streak >= _MAX_LLM_EXECUTION_FAILURE_STREAK:
                    self.machine.record_event(
                        event_type="llm.search.execution_retry_exhausted",
                        summary_zh="连续 OpenGrok 工具失败达到上限，结束本轮语义检索",
                        details={
                            "failure_streak": execution_failure_streak,
                            "phase": phase,
                            "last_error": _compact(error_message),
                        },
                    )
                    break
                continue
            execution_failure_streak = 0
            planner_feedback = ""
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
        remaining_query_budget = max(0, session_query_limit - consumed_queries)
        # Keep one slot for the source-defined alias follow-up (for example
        # ``PARAM_SERVICE`` discovered beside a path macro).  Without this
        # reservation a small but valid ``max_queries`` value can consume the
        # entire budget during the broad first pass and silently skip the
        # more selective listener query.  If no alias is found the reserved
        # slot simply remains unused; the session is still bounded.
        initial_budget = remaining_query_budget
        if remaining_query_budget > 1:
            initial_budget -= 1
        initial_queries = build_initial_queries(
            target,
            max_queries=min(32, max(1, initial_budget)),
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
        # A target-bearing init config is a stronger hint than a generic
        # ``recv``/``bind`` query.  First probe a few normalized service
        # source filenames (for example appspawn_service.c); use any
        # remaining follow-up budget for source-defined macro aliases.
        # Keep room for the aliases discovered beside a target-bearing
        # definition.  A service config often defines both a path and a
        # short name (for example ``DNS_SOCKET_PATH`` and
        # ``DNS_SOCKET_NAME``), while the listener only uses the short alias.
        # Letting normalized filename probes consume the entire follow-up
        # budget silently loses the actual implementation.  Reserve one
        # C/C++ query per alias (up to two aliases) and spend the remainder on
        # component filename probes.
        alias_budget = min(4, len(related_macros) * 2)
        source_budget = max(0, macro_budget - alias_budget)
        source_queries = _component_source_queries(
            initial_payload,
            target,
            max_queries=min(8, source_budget),
            start_index=len(result.executions) + 1,
        )
        remaining_follow_up_budget = max(0, macro_budget - len(source_queries))
        macro_queries = _macro_queries(
            related_macros,
            max_queries=remaining_follow_up_budget,
            start_index=len(result.executions) + 1 + len(source_queries),
        )
        follow_up_queries = tuple(
            query
            for query in (*source_queries, *macro_queries)
            if query.value not in executed_values
            and _query_key(query.kind, query.value, query.file_type) not in executed_actions
            and all(query.value != initial.value or query.file_type != initial.file_type for initial in queries)
        )
        all_executions = list(result.executions)
        if follow_up_queries:
            macro_planner = SearchPlanner(
                client,
                max_results=_budget_int(budget, "max_results", default=50, maximum=1000),
                max_hits_per_file=_budget_int(budget, "max_hits_per_file", default=3, maximum=1000),
                max_queries=min(32, len(follow_up_queries)),
            )
            try:
                macro_result = macro_planner.execute(follow_up_queries, target=target)
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
        target_context_dirs = _target_context_directories(search_result.to_dict().get("executions", ()), target)
        target_conflicting_paths = _named_socket_conflicting_paths(
            search_result.to_dict().get("executions", ()), target
        )
        for execution in search_result.executions:
            if execution.status != "ok" or execution.response is None:
                continue
            for path, hits in execution.response.results.items():
                for hit in hits:
                    if len(store.evidence) >= _MAX_SEARCH_EVIDENCE:
                        break
                    execution_payload = {
                        "query": execution.query.to_dict(),
                        "path": path,
                        "target_context_dirs": target_context_dirs,
                        "target_path_conflict": path in target_conflicting_paths,
                    }
                    if not _search_hit_is_target_evidence(execution_payload, hit.to_dict(), target):
                        # Keep the path in search_plan.json for later ranking,
                        # but do not let an unrelated numeric/API hit satisfy
                        # socket_identity or server predicates.
                        continue
                    try:
                        # Preserve the semantic kind discovered from the
                        # actual source line.  In particular, a config
                        # ``"name": "dnsproxyd"`` or a
                        # ``GetControlSocket("dnsproxyd")`` hit should not
                        # be flattened into ``literal_match`` merely because
                        # it came from a full-text query.
                        semantic_kind = _line_kind(
                            hit.line,
                            target,
                            query_kind=execution.query.kind,
                            query_value=execution.query.value,
                        )
                        if semantic_kind not in _LLM_EVIDENCE_KINDS:
                            semantic_kind = (
                                "macro_definition"
                                if execution.query.kind == "definition" and target.macro_hint
                                else (
                                    "symbol_reference"
                                    if execution.query.kind in {"definition", "symbol"}
                                    else "literal_match"
                                )
                            )
                        store.add_search_hit(
                            path,
                            hit,
                            kind=semantic_kind,
                            symbol=_evidence_symbol_for_line(
                                hit.line,
                                target,
                                query_value=execution.query.value,
                            ),
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
        if follow_up_queries and macro_error is not None:
            search_payload.setdefault("follow_up", {})["status"] = "error"
            search_payload["follow_up"]["error_message"] = macro_error
        elif follow_up_queries:
            search_payload.setdefault("follow_up", {})["status"] = "ok"
            search_payload["follow_up"]["source_queries"] = [
                query.value for query in source_queries
            ]
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
        target_context_dirs = _target_context_directories(search_payload.get("executions", ()), target)
        target_bound_context_dirs = _target_bound_context_directories(store, target)
        target_conflicting_paths = _named_socket_conflicting_paths(
            search_payload.get("executions", ()), target
        )
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
        ranked_candidates = list(rank_paths(paths, target=target))
        if target.target_type == "network_socket":
            ranked_candidates.sort(
                key=lambda item: (
                    -_network_path_priority(
                        item.path,
                        search_payload.get("executions", ()),
                        target,
                        target_context_dirs,
                    ),
                    -item.score,
                    item.path,
                )
            )
        elif target.target_type in {"unix_socket", "service_name", "macro"}:
            ranked_candidates.sort(
                key=lambda item: (
                    -_unix_path_priority(
                        item.path,
                        search_payload.get("executions", ()),
                        target,
                        target_context_dirs,
                    ),
                    -item.score,
                    item.path,
                )
            )
        ranked = tuple(ranked_candidates[: self.runtime.max_paths])
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
            if document.truncated and (
                _path_contains_target_identity(path, target)
                or _path_has_target_bound_component(path, target_bound_context_dirs)
            ):
                try:
                    expanded = client.read_source(
                        path,
                        max_bytes=max(self.runtime.max_source_bytes, _MAX_ENTRYPOINT_READ_BYTES),
                    )
                except (OpenGrokError, ValueError):
                    expanded = None
                if expanded is not None and not expanded.truncated:
                    document = expanded
            trace_keys: set[tuple[int, str]] = set()
            # OpenGrok's generic ``recv`` query is intentionally bounded and
            # may not return method variants such as ``recvmsg``.  Once this
            # path has already been selected by target-scoped ranking, scan
            # only the retrieved source document for inbound/dispatch lines.
            # This recovers init-created descriptor services (for example
            # appspawn) without issuing a repository-wide ``recvmsg`` query.
            local_entrypoint_lines = list(_target_local_entrypoint_lines(
                path,
                document,
                target,
                # Use only source-derived target-bound contexts here.  The
                # broader search-plan context also contains policy/generated
                # siblings and would make an unrelated ``hiview`` recv look
                # like the named socket's listener.
                target_bound_context_dirs,
            ))
            # The same bounded source file can reveal the init-created fd
            # acquisition that precedes ``recvmsg``.  Add it to the evidence
            # graph for server attribution, but keep it out of the standalone
            # entry list (which only contains receive/dispatch functions).
            seen_local_lines = set(local_entrypoint_lines)
            for local_line, line in enumerate(document.content.splitlines(), 1):
                if not _SOCKET_SERVER_ANCHOR_RE.search(line):
                    continue
                if not _socket_anchor_line_matches_target(line, target):
                    continue
                if not _network_operation_matches_target(line, target):
                    continue
                if not _named_socket_operation_matches_target(line, target):
                    continue
                anchor_kind = _line_kind(line, target)
                if anchor_kind not in {
                    "socket_acquire",
                    "socket_bind_listen",
                    "socket_server_registration",
                }:
                    anchor_kind = "socket_acquire"
                candidate = (local_line, anchor_kind)
                if candidate not in seen_local_lines:
                    local_entrypoint_lines.append(candidate)
                    seen_local_lines.add(candidate)
                if len(local_entrypoint_lines) >= _MAX_TRACE_EVIDENCE_PER_PATH:
                    break
            for local_line, local_kind in local_entrypoint_lines:
                trace_keys.add((local_line, local_kind))
                try:
                    evidence = store.add_source_excerpt(
                        document,
                        line_start=local_line,
                        kind=local_kind,
                        symbol=_evidence_symbol_for_line(
                            document.content.splitlines()[local_line - 1],
                            target,
                        ),
                        source_endpoint="opengrok.read_source.local_entrypoint_scan",
                        relation_from=target_relation(target),
                        relation_to=f"{path}:{local_line}",
                        tool_name="opengrok.read_source.local_entrypoint_scan",
                    )
                    relation = target_relation(target)
                    if relation:
                        try:
                            store.add_edge(
                                src=relation,
                                relation="candidate_source",
                                dst=f"{path}:{local_line}",
                                evidence_ids=(evidence.evidence_id,),
                                confidence="moderate",
                            )
                        except ValueError:
                            pass
                except (IndexError, ValueError):
                    continue
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
                query_kind = query.get("kind") if isinstance(query, Mapping) else None
                query_value = query.get("value") if isinstance(query, Mapping) else None
                # A broad API hit is only a candidate.  Do not let a generic
                # ``recvfrom``/``bind`` declaration, or an incidental port in
                # a lookup table, anchor the whole nearby window.  For a
                # process path query OpenGrok may return an ellipsis instead
                # of source text; the path itself is the explicit anchor in
                # that one bounded case.
                hit_payload = hit if isinstance(hit, Mapping) else {}
                hit_is_evidence = _search_hit_is_target_evidence(
                    {
                        "query": query,
                        "path": path,
                        "target_context_dirs": target_context_dirs,
                        "target_path_conflict": path in target_conflicting_paths,
                    },
                    hit_payload,
                    target,
                )
                path_anchor = (
                    isinstance(query_kind, str)
                    and query_kind == "path"
                    and target.process_hint is not None
                    and target.process_hint.casefold() in path.casefold()
                )
                if not hit_is_evidence and not path_anchor:
                    continue
                # Keep the decision made for the actual search hit constant
                # while walking its bounded source window.  The previous
                # implementation recomputed it for every neighbouring line,
                # which meant a valid ``sin_port = htons(8283)`` hit could not
                # retain the adjacent socket()/bind()/recvfrom() calls.
                query_anchor_ok = hit_is_evidence or path_anchor
                start = max(1, line - _TRACE_CONTEXT_LINES)
                end = min(len(lines), line + _TRACE_CONTEXT_LINES)
                for line_no in range(start, end + 1):
                    excerpt = lines[line_no - 1]
                    if not _network_operation_matches_target(excerpt, target):
                        continue
                    if not _named_socket_operation_matches_target(excerpt, target):
                        continue
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
                        term.lower() for term in (*target_identity_terms(target), query_value) if term
                    )
                    has_target_identity = _line_has_target_identity(excerpt, target)
                    # The search-hit filter above establishes the target
                    # anchor.  It applies to every line in this bounded
                    # context, so a target-specific port/path hit can recover
                    # the adjacent server operations while generic queries
                    # remain recall-only.
                    # Keep the exact hit, identity-bearing context, and
                    # concrete communication operations.  A 129-line window
                    # is useful for OpenHarmony's init-created descriptor and
                    # switch-based handlers, but retaining every line would
                    # turn comments and unrelated helpers into evidence.
                    # Generic API queries (``bind``, ``socket``, ``recvfrom``,
                    # and similar) are recall-only.  Their hits cannot become
                    # positive server/client evidence unless the line or its
                    # target-specific query also carries this target's
                    # identity.  A port/process/path query may promote a
                    # nearby operation because the window is anchored by a
                    # target-bearing hit.
                    if (
                        kind in _COMMUNICATION_EVIDENCE_KINDS
                        and not _target_evidence_is_bound(
                            path,
                            excerpt,
                            target,
                            target_bound_context_dirs,
                        )
                    ):
                        continue
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
                            symbol=_evidence_symbol_for_line(
                                excerpt,
                                target,
                                query_value=query_value,
                            ),
                            query_id=query.get("query_id"),
                            source_endpoint="opengrok.read_source",
                            relation_from=target_relation(target),
                            relation_to=f"{path}:{line_no}",
                        )
                        # Attach the target relation for attribution and client
                        # completion without making a claim about business callers.
                        relation = target_relation(target)
                        if relation:
                            try:
                                store.add_edge(
                                    src=relation,
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
        all_evidence_ids = tuple(item.evidence_id for item in store.evidence)
        checkpoint_metrics = dict(self.session.metrics)
        checkpoint_metrics["evidence_total"] = len(all_evidence_ids)
        checkpoint_metrics["evidence_ids_truncated"] = len(all_evidence_ids) > _MAX_SESSION_EVIDENCE_IDS
        return self._transition(
            "ATTRIBUTION_SERVER",
            f"已读取 {len(ranked)} 个候选文件并生成证据图，开始区分服务端角色",
            updates={
                "artifacts": artifacts,
                # evidence.json is the complete source of truth; the session
                # checkpoint keeps only a navigational sample so thousands of
                # noisy search hits cannot overflow the 256 KiB checkpoint.
                "evidence_ids": all_evidence_ids[:_MAX_SESSION_EVIDENCE_IDS],
                "metrics": checkpoint_metrics,
            },
            event_type="evidence.traced",
            evidence_ids=all_evidence_ids,
        )

    def _advance_server(self) -> LocatorSession:
        store = _load_evidence(self.machine)
        target = _target(self.session)
        attribution_evidence = _target_bound_evidence(store, target)
        result = ServiceAttributor().attribute(attribution_evidence)
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
        target = _target(self.session)
        attribution_evidence = _target_bound_evidence(store, target)
        result = ClientLocator().locate(attribution_evidence)
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
                updates={
                    **_session_evidence_checkpoint_updates(
                        self.session.evidence_ids,
                        self.session.metrics,
                    ),
                    "last_error": "未配置可验证的 Manifest",
                },
                event_type="repository.mapping.missing_manifest",
            )
        store = _load_evidence(self.machine)
        checkpoint_updates = _session_evidence_checkpoint_updates(
            (item.evidence_id for item in store.evidence),
            self.session.metrics,
        )
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
                # Keep model-confirmed server anchors at the front of the
                # bounded session copy.  The complete repository artifact
                # remains unchanged, while VERIFY_EVIDENCE must not lose the
                # semantic IDs when a noisy project has more than the session
                # evidence-id limit.
                semantic_project_ids = tuple(
                    evidence_id
                    for evidence_id in semantic_server_evidence_ids
                    if evidence_id in project_evidence_ids
                )
                mapping = replace(
                    mapping,
                    evidence_ids=tuple(
                        dict.fromkeys(
                            (*semantic_project_ids, *mapping.evidence_ids, *project_evidence_ids)
                        )
                    ),
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
            return self._transition(
                "NEEDS_REVIEW",
                "Manifest 没有匹配任何证据路径，等待人工选择版本或补充 Manifest",
                updates={
                    **checkpoint_updates,
                    "artifacts": artifacts,
                    "last_error": "没有 Manifest 路径匹配",
                },
                event_type="repository.mapping.empty",
            )
        if any(item.status == "version_mismatch" for item in mappings):
            return self._transition(
                "VERSION_MISMATCH",
                "Manifest revision 与目标版本不一致，禁止自动拉取",
                updates={
                    **checkpoint_updates,
                    "repository_mappings": _compact_repository_mappings_payload(mappings),
                    "artifacts": artifacts,
                    "last_error": "Manifest revision 与目标 revision 不一致",
                },
                event_type="repository.mapping.version_mismatch",
            )
        resolved = [item for item in mappings if item.is_resolved]
        if not resolved:
            return self._transition(
                "NEEDS_REVIEW",
                "候选路径存在但没有可验证的 GitCode 映射，等待人工复核",
                updates={
                    **checkpoint_updates,
                    "repository_mappings": _compact_repository_mappings_payload(mappings),
                    "artifacts": artifacts,
                    "last_error": "没有 resolved repository mapping",
                },
                event_type="repository.mapping.needs_review",
            )
        return self._transition(
            "VERIFY_EVIDENCE",
            f"已得到 {len(resolved)} 个可验证仓库映射，执行服务端强制谓词复核",
            updates={
                **checkpoint_updates,
                "repository_mappings": _compact_repository_mappings_payload(mappings),
                "artifacts": artifacts,
            },
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
        mapping, candidate_review, candidate_review_artifacts = self._run_candidate_review(
            resolved,
            store,
            target,
        )
        # Candidate PK may have read additional BUILD.gn/bundle/source facts
        # into the in-memory evidence store.  Rebuild the attribution input so
        # the selected repository's metadata participates in the final result;
        # the tuple captured before PK would otherwise omit those facts.
        attribution_evidence = _evidence_scoped_to_mapping(
            _target_bound_evidence(store, target),
            mapping,
        )
        server = ServiceAttributor(mapping=mapping).attribute(attribution_evidence, mapping=mapping)
        client = ClientLocator(mapping=mapping).locate(attribution_evidence, mapping=mapping)
        semantic = _load_llm_role_result(
            self.machine,
            allowed_evidence_ids=(item.evidence_id for item in attribution_evidence),
        )
        if semantic is not None:
            # The role review predates repository PK and may have cited a
            # duplicate/split implementation.  Do not let that stale semantic
            # candidate overwrite the selected repository's best evidence.
            semantic = _scope_llm_role_result_to_mapping(semantic, mapping)
            server = _merge_server_semantic(server, semantic.server, store)
            client = _merge_client_semantic(client, semantic.client, store)
        missing_predicates = tuple(
            name for name in _REQUIRED_SERVER_PREDICATES
            if not bool(server.predicates.get(name, False))
        )
        server_payload = _compact_attribution_payload(server.to_dict())
        client_payload = _compact_attribution_payload(client.to_dict())
        # The initial ATTRIBUTION_SERVER artifact is intentionally produced
        # before repository PK.  Overwrite it here with the final, selected-
        # mapping-scoped view so users do not see smartperf_host evidence after
        # developtools_profiler has been chosen.
        artifacts = dict(self.session.artifacts)
        _json_write(_session_dir(self.machine) / "server_attribution.json", server_payload)
        _json_write(_session_dir(self.machine) / "client_attribution.json", client_payload)
        artifacts.update(
            {
                "server_attribution.json": "最终候选仓库范围内的服务端角色、结构性谓词、语义判定和源码证据。",
                "client_attribution.json": "最终候选仓库范围内的客户端通信边界和源码证据。",
            }
        )
        # Keep the socket's real external-input receivers separate from the
        # broad evidence graph.  This artifact is intentionally generated
        # from the final mapping-scoped attribution, so a client-side recv or
        # a downstream business method cannot be presented as the top-level
        # server entry by accident.
        entrypoint_sources = _build_socket_entrypoint_sources(
            target,
            store,
            server,
            self.runtime.client,
            max_source_bytes=self.runtime.max_source_bytes,
            llm_entrypoint_attributor=self.runtime.llm_entrypoint_attributor,
        )
        entrypoint_artifacts = _save_artifact(
            self.machine,
            "socket_entrypoint_sources.json",
            entrypoint_sources,
            "Socket 外部输入入口函数的完整源码片段；仅列接收/协议分派入口，不展开具体业务处理函数。",
        )
        artifacts.update(entrypoint_artifacts)
        # Keep the semantic adjudication independently inspectable.  The
        # main entrypoint artifact still contains the compact decision fields
        # needed by the UI, while this sidecar records the complete bounded
        # candidate decision set.  It never contains the provider response.
        if self.runtime.llm_entrypoint_attributor is not None and isinstance(
            entrypoint_sources.get("llm_review"), Mapping
        ):
            llm_entrypoint_artifacts = _save_artifact(
                self.machine,
                "llm_entrypoint_attribution.json",
                {
                    "schema_version": "openant.source-locator.llm-entrypoint-artifact.v1",
                    "target": target.to_dict(),
                    "decision_source": entrypoint_sources.get("decision_source"),
                    "candidate_count": entrypoint_sources.get("candidate_count", 0),
                    "reviewed_candidate_count": entrypoint_sources.get("reviewed_candidate_count", 0),
                    "unreviewed_candidate_count": entrypoint_sources.get("unreviewed_candidate_count", 0),
                    "review": entrypoint_sources.get("llm_review"),
                },
                "Socket 入口函数候选的大模型语义复核结果；仅保存经过校验的决策。",
            )
            artifacts.update(llm_entrypoint_artifacts)
        payload = {
            "server": server_payload,
            "client": client_payload,
            "mapping": mapping.to_dict(),
            "missing_server_predicates": list(missing_predicates),
            "predicate_gate": "advisory" if missing_predicates else "satisfied",
            "semantic_review": semantic.to_dict() if semantic else None,
            "candidate_review": candidate_review,
        }
        verification_artifacts = _save_artifact(
            self.machine,
            "verification.json",
            payload,
            "进入人工确认前的结构性谓词、服务端/客户端状态和主仓库候选。",
        )
        artifacts.update(verification_artifacts)
        artifacts.update(candidate_review_artifacts)
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
        confirmation_summary["candidate_review"] = candidate_review
        summary_artifacts = _save_artifact(
            self.machine,
            "confirmation_summary.json",
            confirmation_summary,
            "确认前摘要：将拉取的 GitCode 仓库、版本、落盘位置、服务端判定和关键源码证据。",
        )
        summary_artifacts.update(artifacts)
        artifacts = summary_artifacts
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
                default=(
                    self.runtime.llm_planner.budget.max_actions
                    if self.runtime.llm_planner is not None
                    else LLM_SEARCH_DEFAULT_MAX_ACTIONS
                ),
                maximum=LLM_SEARCH_MAX_ACTIONS,
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
        attribution_evidence = _evidence_scoped_to_mapping(
            _target_bound_evidence(store, target),
            mapping,
        )
        server = ServiceAttributor(mapping=mapping).attribute(attribution_evidence, mapping=mapping)
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
        all_evidence_ids = tuple(item.evidence_id for item in store.evidence)
        checkpoint_metrics = dict(self.session.metrics)
        checkpoint_metrics["evidence_total"] = len(all_evidence_ids)
        checkpoint_metrics["evidence_ids_truncated"] = len(all_evidence_ids) > _MAX_SESSION_EVIDENCE_IDS
        updates = {
            "artifacts": artifacts,
            "evidence_ids": all_evidence_ids[:_MAX_SESSION_EVIDENCE_IDS],
            "metrics": checkpoint_metrics,
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
        review_path = _session_dir(self.machine) / "repository_candidate_review.json"
        if review_path.exists() and review_path.is_file() and not review_path.is_symlink():
            try:
                review = _read_json(review_path)
                selected_name = review.get("selected_repository") if isinstance(review, Mapping) else None
                if isinstance(selected_name, str):
                    selected = next(
                        (item for item in candidates if item.project_name == selected_name),
                        None,
                    )
                    if selected is not None:
                        return selected
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                # The deterministic score below remains the safe fallback if
                # the optional audit artifact is missing or malformed.
                pass
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
            symbols=tuple(
                item
                for item in (target.service_hint, target.process_hint, target.macro_hint)
                if item
            ),
            literals=tuple(
                item
                for item in (
                    target.socket_path,
                    target.basename,
                    target.address,
                    str(target.port) if target.port is not None else None,
                    target_relation(target),
                )
                if item
            ),
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
