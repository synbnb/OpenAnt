"""Deterministic GitCode and revision policy for source-locator mappings.

The Manifest resolver tells us *which* repository a source path appears to
belong to.  This module decides whether that mapping is safe to hand to a
future repository manager.  It deliberately performs no network or Git
operation: URL shape, host/organization allowlists, provenance and revision
alignment are checked before a clone stage is even eligible to run.

All values that could have originated in OpenGrok or an LLM are treated as
untrusted.  A caller receives a structured rejection rather than a guessed
URL or silently substituted branch.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import urlsplit

from .config import GitCodeConfig
from .manifest_resolver import RepositoryMapping


_SCHEMA_VERSION = "openant.source-locator.repository-policy.v1"
_MAX_URL_LENGTH = 2048
_MAX_REVISION_LENGTH = 128
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+~-]{0,127}$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$")
_ALLOWED_REVISION_SOURCES = frozenset({"manifest", "config", "user_confirmed"})
_POLICY_STATUSES = frozenset({"allowed", "rejected", "version_mismatch", "missing"})


class RepositoryPolicyError(ValueError):
    """Raised when a policy API receives an invalid typed argument."""


def _message(value: Any, *, limit: int = 512) -> str:
    """Collapse untrusted text before placing it in an audit result."""

    return " ".join(str(value).split())[:limit]


def _policy_config(config: GitCodeConfig | None) -> GitCodeConfig:
    if config is None:
        return GitCodeConfig()
    if not isinstance(config, GitCodeConfig):
        raise RepositoryPolicyError("config 必须是 GitCodeConfig")
    return config


def _host_allowlist(config: GitCodeConfig) -> frozenset[str]:
    hosts: set[str] = set()
    for host in config.allowed_hosts:
        if not isinstance(host, str):
            raise RepositoryPolicyError("GitCode host 白名单只能包含字符串")
        normalized = host.strip().lower()
        if not normalized or "://" in normalized or "/" in normalized:
            raise RepositoryPolicyError("GitCode host 白名单包含无效主机名")
        # Explicit ports are intentionally not accepted.  The source locator
        # only trusts the configured HTTPS host, not an alternate endpoint.
        if ":" in normalized or any(char.isspace() for char in normalized):
            raise RepositoryPolicyError("GitCode host 白名单不得包含端口或空白")
        hosts.add(normalized)
    if not hosts:
        raise RepositoryPolicyError("GitCode host 白名单不能为空")
    return frozenset(hosts)


def _organization_allowlist(config: GitCodeConfig) -> frozenset[str]:
    organizations: set[str] = set()
    for organization in config.allowed_orgs:
        if not isinstance(organization, str):
            raise RepositoryPolicyError("GitCode 组织白名单只能包含字符串")
        normalized = organization.strip()
        if (
            not normalized
            or "/" in normalized
            or "\\" in normalized
            or any(char.isspace() for char in normalized)
        ):
            raise RepositoryPolicyError("GitCode 组织白名单包含无效名称")
        organizations.add(normalized)
    if not organizations:
        raise RepositoryPolicyError("GitCode 组织白名单不能为空")
    return frozenset(organizations)


def _normalise_expected_repository(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.endswith(".git"):
        value = value[:-4]
    return value if _PATH_SEGMENT_RE.fullmatch(value) else None


def _safe_revision(value: Any) -> tuple[str | None, str | None]:
    """Return ``(normalized, reason)`` without raising for untrusted input."""

    if value is None:
        return None, "revision 缺失"
    if not isinstance(value, str):
        return None, "revision 必须是字符串"
    value = value.strip()
    if not value or value == "unknown":
        return None, "revision 缺失或仍为 unknown"
    if len(value) > _MAX_REVISION_LENGTH or not _REVISION_RE.fullmatch(value):
        return None, "revision 含有不安全字符或超出长度上限"
    if (
        ".." in value
        or "//" in value
        or value.endswith(".")
        or value.endswith(".lock")
    ):
        return None, "revision 含有不允许的 Git ref 片段"
    return value, None


def _canonical_url(host: str, organization: str, repository: str | None, suffix: str = "") -> str:
    path = f"https://{host}/{organization}"
    if repository is not None:
        path += f"/{repository}{suffix}"
    return path


@dataclass(frozen=True)
class GitCodeURLValidation:
    """Auditable validation result for a GitCode repository or remote root."""

    allowed: bool
    status: str
    url: str | None = None
    canonical_url: str | None = None
    host: str | None = None
    organization: str | None = None
    repository: str | None = None
    expected_repository: str | None = None
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    observed_url: str | None = None
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in {"allowed", "rejected"}:
            raise RepositoryPolicyError("GitCode URL 状态无效")
        if not isinstance(self.allowed, bool):
            raise RepositoryPolicyError("GitCode URL allowed 必须是布尔值")
        if self.allowed != (self.status == "allowed"):
            raise RepositoryPolicyError("GitCode URL allowed 与 status 不一致")
        object.__setattr__(self, "reasons", tuple(_message(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_message(item) for item in self.warnings))

    @property
    def is_allowed(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "allowed": self.allowed,
            "status": self.status,
            "url": self.url,
            "canonical_url": self.canonical_url,
            "host": self.host,
            "organization": self.organization,
            "repository": self.repository,
            "expected_repository": self.expected_repository,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "observed_url": self.observed_url,
        }


def _validate_url_parts(
    url: Any,
    config: GitCodeConfig,
    *,
    expected_repository: str | None,
    expected_organization: str | None,
    require_repository: bool,
    observed_url: str | None,
) -> GitCodeURLValidation:
    reasons: list[str] = []
    warnings: list[str] = []
    raw_url = url.strip() if isinstance(url, str) else None
    host: str | None = None
    organization: str | None = None
    repository: str | None = None
    suffix = ""
    parsed = None

    if raw_url is None or not raw_url:
        reasons.append("仓库 URL 缺失")
    elif len(raw_url) > _MAX_URL_LENGTH:
        reasons.append(f"仓库 URL 超过 {_MAX_URL_LENGTH} 个字符")
    elif any(ord(char) < 0x20 or ord(char) == 0x7F or char.isspace() for char in raw_url):
        reasons.append("仓库 URL 含有空白或控制字符")
    else:
        try:
            parsed = urlsplit(raw_url)
        except ValueError as exc:
            reasons.append(f"仓库 URL 无法解析：{_message(exc)}")

    if parsed is not None:
        if parsed.scheme.lower() != "https":
            reasons.append("仓库 URL 必须使用 HTTPS")
        if not parsed.netloc:
            reasons.append("仓库 URL 缺少主机名")
        if parsed.username is not None or parsed.password is not None:
            reasons.append("仓库 URL 不得包含用户名或密码")
        if parsed.query or parsed.fragment:
            reasons.append("仓库 URL 不得包含 query 或 fragment")
        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None
            reasons.append("仓库 URL 的端口无效")
        if parsed_port is not None:
            reasons.append("仓库 URL 不允许显式端口")
        try:
            host = parsed.hostname.lower() if parsed.hostname else None
        except AttributeError:
            host = None
        if host is None:
            reasons.append("仓库 URL 缺少有效主机名")
        elif host not in _host_allowlist(config):
            reasons.append(f"主机 {host} 不在 GitCode allowlist 中")
        if host and ":" in host:
            reasons.append("仓库 URL 不允许 IPv6 主机名")

        path = parsed.path
        if not path.startswith("/"):
            reasons.append("仓库 URL 路径必须以 / 开头")
        if "%" in path:
            reasons.append("仓库 URL 路径不允许百分号编码")
        if "\\" in path or "\x00" in path:
            reasons.append("仓库 URL 路径含有禁止字符")
        if path.endswith("//"):
            reasons.append("仓库 URL 路径含有重复结尾斜杠")
        path_without_trailing = path[:-1] if path.endswith("/") else path
        raw_parts = path_without_trailing.split("/") if path_without_trailing else []
        parts = raw_parts[1:] if raw_parts and raw_parts[0] == "" else raw_parts
        if not parts or any(not part for part in parts):
            reasons.append("仓库 URL 路径必须是非空段")
        expected_parts = 2 if require_repository else 1
        if len(parts) != expected_parts:
            kind = "组织/仓库两段" if require_repository else "组织一段"
            reasons.append(f"仓库 URL 路径必须恰好包含{kind}")
        if parts:
            organization = parts[0]
            if not _PATH_SEGMENT_RE.fullmatch(organization):
                reasons.append("仓库 URL 组织名不是安全的单段名称")
            elif organization not in _organization_allowlist(config):
                reasons.append(f"组织 {organization} 不在 GitCode allowlist 中")
            if expected_organization is not None and organization != expected_organization:
                reasons.append("仓库 URL 的组织与 remote.fetch 不一致")
        if require_repository and len(parts) >= 2:
            raw_repository = parts[1]
            if raw_repository.endswith(".git"):
                suffix = ".git"
                raw_repository = raw_repository[:-4]
            repository = raw_repository
            if not _PATH_SEGMENT_RE.fullmatch(repository):
                reasons.append("仓库 URL 仓库名不是安全的单段名称")

    expected = _normalise_expected_repository(expected_repository)
    if expected_repository is not None and expected is None:
        reasons.append("Manifest project.name 不是安全的仓库名")
    if expected is not None and repository is not None and repository != expected:
        reasons.append(f"URL 仓库名 {repository} 与 Manifest 项目 {expected} 不一致")

    canonical = None
    if host is not None and organization is not None and (repository is not None or not require_repository):
        canonical = _canonical_url(host, organization, repository, suffix)

    if observed_url is not None:
        observed = _validate_url_parts(
            observed_url,
            config,
            expected_repository=expected_repository,
            expected_organization=expected_organization,
            require_repository=require_repository,
            observed_url=None,
        )
        if not observed.allowed:
            reasons.append("检测到的重定向目标不满足同一 GitCode allowlist")
        elif canonical is None or observed.canonical_url != canonical:
            reasons.append("不允许未授权的 URL 重定向")

    allowed = not reasons
    return GitCodeURLValidation(
        allowed=allowed,
        status="allowed" if allowed else "rejected",
        url=raw_url,
        canonical_url=canonical if allowed else canonical,
        host=host,
        organization=organization,
        repository=repository,
        expected_repository=expected,
        reasons=tuple(dict.fromkeys(reasons)),
        warnings=tuple(dict.fromkeys(warnings)),
        observed_url=observed_url,
    )


def validate_gitcode_url(
    url: Any,
    config: GitCodeConfig | None = None,
    *,
    expected_repository: str | None = None,
    observed_url: str | None = None,
) -> GitCodeURLValidation:
    """Validate a repository URL against the configured GitCode allowlist."""

    policy_config = _policy_config(config)
    return _validate_url_parts(
        url,
        policy_config,
        expected_repository=expected_repository,
        expected_organization=None,
        require_repository=True,
        observed_url=observed_url,
    )


def validate_gitcode_remote(
    url: Any,
    config: GitCodeConfig | None = None,
    *,
    expected_organization: str | None = None,
) -> GitCodeURLValidation:
    """Validate a Manifest ``remote.fetch`` organization root."""

    policy_config = _policy_config(config)
    return _validate_url_parts(
        url,
        policy_config,
        expected_repository=None,
        expected_organization=expected_organization,
        require_repository=False,
        observed_url=None,
    )


@dataclass(frozen=True)
class RevisionValidation:
    """Auditable revision and target-revision comparison."""

    allowed: bool
    status: str
    revision: str | None = None
    requested_revision: str | None = None
    source: str | None = None
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in {"allowed", "rejected", "version_mismatch", "missing"}:
            raise RepositoryPolicyError("revision 状态无效")
        if not isinstance(self.allowed, bool):
            raise RepositoryPolicyError("revision allowed 必须是布尔值")
        if self.allowed != (self.status == "allowed"):
            raise RepositoryPolicyError("revision allowed 与 status 不一致")
        object.__setattr__(self, "reasons", tuple(_message(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_message(item) for item in self.warnings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "allowed": self.allowed,
            "status": self.status,
            "revision": self.revision,
            "requested_revision": self.requested_revision,
            "source": self.source,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


def validate_revision(
    revision: Any,
    requested_revision: Any = None,
    *,
    source: str = "manifest",
) -> RevisionValidation:
    """Validate a trusted-source revision and optional requested revision.

    ``source`` is part of the security contract.  Values marked ``llm`` or
    ``bundle_fallback`` are rejected even when their text looks like a valid
    Git ref; a model may suggest a candidate but cannot authorize a clone.
    """

    reasons: list[str] = []
    warnings: list[str] = []
    normalized_source = source.strip() if isinstance(source, str) else None
    normalized_revision, revision_error = _safe_revision(revision)
    normalized_requested, requested_error = _safe_revision(requested_revision)
    revision_missing = revision is None or (
        isinstance(revision, str) and revision.strip() in {"", "unknown"}
    )

    if normalized_source not in _ALLOWED_REVISION_SOURCES:
        reasons.append("revision 来源不是 Manifest、配置或用户确认")
    if revision_error is not None:
        reasons.append(revision_error)
    if requested_revision is not None and requested_error is not None:
        reasons.append(f"目标 revision 无效：{requested_error}")

    source_allowed = normalized_source in _ALLOWED_REVISION_SOURCES
    if normalized_revision is None and revision_missing and source_allowed:
        status = "missing"
    elif normalized_requested is not None and normalized_revision != normalized_requested:
        status = "version_mismatch"
        reasons.append(
            f"Manifest revision {normalized_revision} 与目标 revision {normalized_requested} 不一致"
        )
    elif reasons:
        status = "rejected"
    else:
        status = "allowed"
        if requested_revision is None:
            warnings.append("未提供额外目标 revision，使用 Manifest/配置中的确定版本")

    # An invalid requested value or untrusted source must never be converted
    # into a version-mismatch that looks like a recoverable alignment issue.
    if requested_error is not None and requested_revision is not None:
        status = "rejected"
    if normalized_source not in _ALLOWED_REVISION_SOURCES:
        status = "rejected"
    allowed = status == "allowed"
    return RevisionValidation(
        allowed=allowed,
        status=status,
        revision=normalized_revision,
        requested_revision=normalized_requested,
        source=normalized_source,
        reasons=tuple(dict.fromkeys(reasons)),
        warnings=tuple(dict.fromkeys(warnings)),
    )


@dataclass(frozen=True)
class RepositoryPolicyDecision:
    """Final pre-clone decision for one Manifest mapping."""

    allowed: bool
    status: str
    mapping_status: str | None = None
    project_name: str | None = None
    repo_url: str | None = None
    canonical_url: str | None = None
    remote_fetch: str | None = None
    revision: str | None = None
    requested_revision: str | None = None
    host: str | None = None
    organization: str | None = None
    repository: str | None = None
    url_validation: GitCodeURLValidation | None = None
    remote_validation: GitCodeURLValidation | None = None
    revision_validation: RevisionValidation | None = None
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in _POLICY_STATUSES:
            raise RepositoryPolicyError("仓库策略状态无效")
        if not isinstance(self.allowed, bool):
            raise RepositoryPolicyError("仓库策略 allowed 必须是布尔值")
        if self.allowed != (self.status == "allowed"):
            raise RepositoryPolicyError("仓库策略 allowed 与 status 不一致")
        object.__setattr__(self, "reasons", tuple(_message(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_message(item) for item in self.warnings))

    @property
    def can_clone(self) -> bool:
        """Alias used by a future RepositoryManager as the hard gate."""

        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "allowed": self.allowed,
            "can_clone": self.can_clone,
            "status": self.status,
            "mapping_status": self.mapping_status,
            "project_name": self.project_name,
            "repo_url": self.repo_url,
            "canonical_url": self.canonical_url,
            "remote_fetch": self.remote_fetch,
            "revision": self.revision,
            "requested_revision": self.requested_revision,
            "host": self.host,
            "organization": self.organization,
            "repository": self.repository,
            "url_validation": self.url_validation.to_dict() if self.url_validation else None,
            "remote_validation": self.remote_validation.to_dict() if self.remote_validation else None,
            "revision_validation": self.revision_validation.to_dict()
            if self.revision_validation
            else None,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


def validate_repository_mapping(
    mapping: RepositoryMapping,
    config: GitCodeConfig | None = None,
    *,
    requested_revision: str | None = None,
    observed_url: str | None = None,
) -> RepositoryPolicyDecision:
    """Apply URL, provenance, mapping and revision checks to one resolution."""

    if not isinstance(mapping, RepositoryMapping):
        raise RepositoryPolicyError("mapping 必须是 RepositoryMapping")
    policy_config = _policy_config(config)
    effective_requested = (
        requested_revision if requested_revision is not None else mapping.requested_revision
    )
    reasons: list[str] = []
    warnings: list[str] = list(mapping.warnings)

    if mapping.status != "resolved":
        reasons.append(f"Manifest 映射状态为 {mapping.status}，不能进入 clone")
    if mapping.project_name is None:
        reasons.append("Manifest 项目名缺失")
    if mapping.resolution_method not in _ALLOWED_REVISION_SOURCES:
        reasons.append("仓库映射来源不是可信的 Manifest/配置/用户确认结果")

    url_result = validate_gitcode_url(
        mapping.repo_url,
        policy_config,
        expected_repository=mapping.project_name,
        observed_url=observed_url,
    )
    remote_result = validate_gitcode_remote(
        mapping.remote_fetch,
        policy_config,
        expected_organization=url_result.organization,
    )
    revision_result = validate_revision(
        mapping.revision,
        effective_requested,
        source=mapping.resolution_method,
    )
    reasons.extend(url_result.reasons)
    reasons.extend(remote_result.reasons)
    reasons.extend(revision_result.reasons)
    warnings.extend(url_result.warnings)
    warnings.extend(remote_result.warnings)
    warnings.extend(revision_result.warnings)

    if (
        url_result.organization is not None
        and remote_result.organization is not None
        and url_result.organization != remote_result.organization
    ):
        reasons.append("仓库 URL 与 Manifest remote.fetch 的组织不一致")
    if (
        url_result.host is not None
        and remote_result.host is not None
        and url_result.host != remote_result.host
    ):
        reasons.append("仓库 URL 与 Manifest remote.fetch 的主机不一致")
    if not mapping.verified:
        warnings.append("当前尚未执行拉取后验证；允许只代表可以进入 clone 门禁")

    reasons = list(dict.fromkeys(reasons))
    warnings = list(dict.fromkeys(warnings))
    if mapping.status == "version_mismatch" or revision_result.status == "version_mismatch":
        status = "version_mismatch"
    elif revision_result.status == "missing" or mapping.repo_url is None or mapping.revision is None:
        status = "missing"
    elif reasons:
        status = "rejected"
    else:
        status = "allowed"
    allowed = status == "allowed" and url_result.allowed and remote_result.allowed and revision_result.allowed
    if not allowed and status == "allowed":
        status = "rejected"
    return RepositoryPolicyDecision(
        allowed=allowed,
        status=status,
        mapping_status=mapping.status,
        project_name=mapping.project_name,
        repo_url=mapping.repo_url,
        canonical_url=url_result.canonical_url,
        remote_fetch=mapping.remote_fetch,
        revision=mapping.revision,
        requested_revision=effective_requested,
        host=url_result.host,
        organization=url_result.organization,
        repository=url_result.repository,
        url_validation=url_result,
        remote_validation=remote_result,
        revision_validation=revision_result,
        reasons=tuple(reasons),
        warnings=tuple(warnings),
    )


class RepositoryPolicy:
    """Reusable policy object for orchestrators and future clone workers."""

    def __init__(self, config: GitCodeConfig | None = None) -> None:
        self.config = _policy_config(config)

    def validate_url(self, url: Any, **kwargs: Any) -> GitCodeURLValidation:
        return validate_gitcode_url(url, self.config, **kwargs)

    def validate_remote(self, url: Any, **kwargs: Any) -> GitCodeURLValidation:
        return validate_gitcode_remote(url, self.config, **kwargs)

    def validate_revision(self, revision: Any, requested_revision: Any = None, **kwargs: Any) -> RevisionValidation:
        return validate_revision(revision, requested_revision, **kwargs)

    def validate_mapping(self, mapping: RepositoryMapping, **kwargs: Any) -> RepositoryPolicyDecision:
        return validate_repository_mapping(mapping, self.config, **kwargs)


# Compatibility spelling for callers that use the plan's generic wording.
validate_repository_url = validate_gitcode_url


__all__ = [
    "GitCodeURLValidation",
    "RepositoryPolicy",
    "RepositoryPolicyDecision",
    "RepositoryPolicyError",
    "RevisionValidation",
    "validate_gitcode_remote",
    "validate_gitcode_url",
    "validate_repository_mapping",
    "validate_repository_url",
    "validate_revision",
]
