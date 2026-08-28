"""Typed configuration for the OpenHarmony source locator.

The source locator is intentionally opt-in.  A normal OpenAnt configuration
without a ``source_locator`` section keeps the existing scan-only behaviour.
When the section is present, this module validates the values that later
workers will use to contact OpenGrok and to map/clone repositories.  It does
not perform network or Git operations by itself.

Credentials are never accepted as JSON values.  ``bearer_env`` stores only
the name of an environment variable and resolves its value at the moment an
``OpenGrokClient`` is constructed.  Probe results contain endpoint metadata,
not request headers, and may be persisted as ``last_probe`` for UI display.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from .opengrok_client import (
    OpenGrokClient,
    OpenGrokPathError,
    ProbeResult,
    normalize_base_url,
)


class SourceLocatorConfigError(ValueError):
    """Raised when the optional source-locator configuration is invalid."""


_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}$")
_AUTH_MODES = frozenset({"none", "bearer_env"})
_MANIFEST_SOURCES = frozenset({"local", "git", "local_or_git"})
_SOURCE_LOCATOR_KEYS = frozenset({
    "enabled",
    "target_revision",
    "opengrok",
    "manifest",
    "gitcode",
})
_OPENGROK_KEYS = frozenset({
    "base_url",
    "project",
    "api_prefix",
    "timeout_seconds",
    "max_retries",
    "max_source_bytes",
    "max_results",
    "max_hits_per_file",
    "verify_tls",
    "auth",
    "last_probe",
})
_AUTH_KEYS = frozenset({"mode", "token_env"})
_MANIFEST_KEYS = frozenset({
    "source",
    "path",
    "repository_url",
    "revision",
    "manifest_file",
})
_GITCODE_KEYS = frozenset({"allowed_hosts", "allowed_orgs", "destination_root"})


def _mapping(value: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceLocatorConfigError(f"{name} 必须是 JSON 对象")
    return value


def _reject_unknown(data: Mapping[str, Any], allowed: frozenset[str], *, name: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise SourceLocatorConfigError(f"{name} 包含未知字段：{', '.join(unknown)}")


def _required_string(data: Mapping[str, Any], key: str, *, name: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SourceLocatorConfigError(f"{name}.{key} 必须是非空字符串")
    if any(char in value for char in "\r\n\x00"):
        raise SourceLocatorConfigError(f"{name}.{key} 包含禁止的控制字符")
    return value.strip()


def _optional_string(data: Mapping[str, Any], key: str, *, name: str) -> str | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise SourceLocatorConfigError(f"{name}.{key} 必须是非空字符串或 null")
    if any(char in value for char in "\r\n\x00"):
        raise SourceLocatorConfigError(f"{name}.{key} 包含禁止的控制字符")
    return value.strip()


def _positive_number(value: Any, *, name: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SourceLocatorConfigError(f"{name} 必须是数字")
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number > maximum:
        raise SourceLocatorConfigError(f"{name} 必须大于 0 且不超过 {maximum:g}")
    return number


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SourceLocatorConfigError(f"{name} 必须是 {minimum} 到 {maximum} 之间的整数")
    return value


def _validate_revision(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SourceLocatorConfigError(f"{name} 必须是非空字符串")
    if not _REVISION_RE.fullmatch(value):
        raise SourceLocatorConfigError(
            f"{name} 不是安全的 Git revision；只允许字母、数字、/、.、_、@、+、-"
        )
    # Git ref syntax forbids these ambiguous/traversal forms.  Keeping the
    # check here prevents a later worker from passing attacker-controlled ref
    # text to a Git command or constructing an unsafe archive path.
    if ".." in value or "//" in value or value.endswith(".") or value.endswith(".lock"):
        raise SourceLocatorConfigError(f"{name} 包含不允许的 Git ref 片段")
    return value


def _validate_https_url(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceLocatorConfigError(f"{name} 必须是非空 HTTPS URL")
    value = value.strip()
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SourceLocatorConfigError(f"{name} 必须是带主机名的 HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise SourceLocatorConfigError(f"{name} 不得包含用户名或密码")
    if parsed.query or parsed.fragment:
        raise SourceLocatorConfigError(f"{name} 不得包含 query 或 fragment")
    return value.rstrip("/")


def _relative_path(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceLocatorConfigError(f"{name} 必须是安全的相对路径")
    value = value.strip()
    if value.startswith(("/", "\\")) or "\x00" in value or "\\" in value:
        raise SourceLocatorConfigError(f"{name} 必须是安全的相对路径")
    parts = [part for part in value.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        raise SourceLocatorConfigError(f"{name} 不得包含空路径或路径穿越片段")
    return "/".join(parts)


def _string_list(value: Any, *, name: str, normalize_lower: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise SourceLocatorConfigError(f"{name} 必须是非空字符串数组")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SourceLocatorConfigError(f"{name} 只能包含非空字符串")
        item = item.strip()
        if any(char in item for char in "\r\n\x00"):
            raise SourceLocatorConfigError(f"{name} 包含禁止的控制字符")
        output.append(item.lower() if normalize_lower else item)
    if len(set(output)) != len(output):
        raise SourceLocatorConfigError(f"{name} 不得包含重复项")
    return tuple(output)


@dataclass(frozen=True)
class SourceLocatorAuth:
    """How the OpenGrok client obtains an optional Bearer token."""

    mode: str = "none"
    token_env: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, str):
            raise SourceLocatorConfigError("source_locator.opengrok.auth.mode 必须是字符串")
        if self.mode not in _AUTH_MODES:
            raise SourceLocatorConfigError(
                f"source_locator.opengrok.auth.mode 必须是：{', '.join(sorted(_AUTH_MODES))}"
            )
        if self.mode == "bearer_env":
            if (
                self.token_env is None
                or not isinstance(self.token_env, str)
                or not _ENV_NAME_RE.fullmatch(self.token_env)
            ):
                raise SourceLocatorConfigError(
                    "source_locator.opengrok.auth.token_env 必须是大写环境变量名"
                )
        elif self.token_env is not None:
            raise SourceLocatorConfigError(
                "auth.mode=none 时不得配置 auth.token_env"
            )

    @classmethod
    def from_mapping(cls, raw: Any) -> "SourceLocatorAuth":
        data = _mapping(raw, name="source_locator.opengrok.auth")
        _reject_unknown(data, _AUTH_KEYS, name="source_locator.opengrok.auth")
        mode = data.get("mode", "none")
        if not isinstance(mode, str):
            raise SourceLocatorConfigError("source_locator.opengrok.auth.mode 必须是字符串")
        token_env = _optional_string(data, "token_env", name="source_locator.opengrok.auth")
        return cls(mode=mode.strip(), token_env=token_env)

    def resolve_token(self, environ: Mapping[str, str] | None = None) -> str | None:
        if self.mode != "bearer_env" or self.token_env is None:
            return None
        values = os.environ if environ is None else environ
        token = values.get(self.token_env)
        return token.strip() if isinstance(token, str) and token.strip() else None

    def to_dict(self) -> dict[str, str]:
        result = {"mode": self.mode}
        if self.token_env is not None:
            result["token_env"] = self.token_env
        return result


@dataclass(frozen=True)
class OpenGrokConfig:
    """Validated connection and request limits for one OpenGrok instance."""

    base_url: str
    project: str = "openharmony"
    api_prefix: str = "/api/v1"
    timeout_seconds: float = 15.0
    max_retries: int = 1
    max_source_bytes: int = 32 * 1024
    max_results: int = 50
    max_hits_per_file: int = 3
    verify_tls: bool = True
    auth: SourceLocatorAuth = SourceLocatorAuth()
    last_probe: ProbeResult | None = None

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.base_url, str):
                raise SourceLocatorConfigError("source_locator.opengrok.base_url 必须是字符串")
            normalized_url = _validate_https_url(
                self.base_url, name="source_locator.opengrok.base_url"
            )
            normalized_url = normalize_base_url(normalized_url)
            if normalized_url != self.base_url:
                object.__setattr__(self, "base_url", normalized_url)
            # Constructing a throwaway client is unnecessary; these helpers
            # are pure and the client will revalidate when it is built.
            if not isinstance(self.project, str) or not self.project.strip():
                raise SourceLocatorConfigError("source_locator.opengrok.project 必须是非空字符串")
            if any(char in self.project for char in "\r\n\x00"):
                raise SourceLocatorConfigError("source_locator.opengrok.project 包含禁止的控制字符")
            normalized_api = self.api_prefix
            if not isinstance(normalized_api, str) or not normalized_api.strip():
                raise SourceLocatorConfigError("source_locator.opengrok.api_prefix 必须是非空路径")
            parsed_api = urlsplit(normalized_api)
            if (
                parsed_api.scheme
                or parsed_api.netloc
                or parsed_api.query
                or parsed_api.fragment
                or "\x00" in normalized_api
                or "\\" in normalized_api
            ):
                raise SourceLocatorConfigError("source_locator.opengrok.api_prefix 必须是安全的相对路径")
            api_parts = [part for part in normalized_api.split("/") if part]
            if not api_parts or any(part in {".", ".."} for part in api_parts):
                raise SourceLocatorConfigError("source_locator.opengrok.api_prefix 必须是安全的相对路径")
            normalized_api = "/" + "/".join(api_parts)
            if normalized_api != self.api_prefix:
                object.__setattr__(self, "api_prefix", normalized_api)
            _positive_number(self.timeout_seconds, name="source_locator.opengrok.timeout_seconds", maximum=300)
            _bounded_int(self.max_retries, name="source_locator.opengrok.max_retries", minimum=0, maximum=3)
            _bounded_int(
                self.max_source_bytes,
                name="source_locator.opengrok.max_source_bytes",
                minimum=1,
                maximum=16 * 1024 * 1024,
            )
            _bounded_int(self.max_results, name="source_locator.opengrok.max_results", minimum=1, maximum=1000)
            _bounded_int(
                self.max_hits_per_file,
                name="source_locator.opengrok.max_hits_per_file",
                minimum=1,
                maximum=1000,
            )
            if not isinstance(self.verify_tls, bool):
                raise SourceLocatorConfigError("source_locator.opengrok.verify_tls 必须是布尔值")
            if not isinstance(self.auth, SourceLocatorAuth):
                raise SourceLocatorConfigError("source_locator.opengrok.auth 类型无效")
            if self.last_probe is not None:
                if not isinstance(self.last_probe, ProbeResult):
                    raise SourceLocatorConfigError("source_locator.opengrok.last_probe 类型无效")
                if self.last_probe.base_url != self.base_url:
                    raise SourceLocatorConfigError("last_probe.base_url 与 OpenGrok base_url 不一致")
        except OpenGrokPathError as exc:
            raise SourceLocatorConfigError(str(exc)) from exc

    @classmethod
    def from_mapping(cls, raw: Any) -> "OpenGrokConfig":
        data = _mapping(raw, name="source_locator.opengrok")
        _reject_unknown(data, _OPENGROK_KEYS, name="source_locator.opengrok")
        base_url = _required_string(data, "base_url", name="source_locator.opengrok")
        project = data.get("project", "openharmony")
        if not isinstance(project, str) or not project.strip():
            raise SourceLocatorConfigError("source_locator.opengrok.project 必须是非空字符串")
        api_prefix = data.get("api_prefix", "/api/v1")
        if not isinstance(api_prefix, str) or not api_prefix.strip():
            raise SourceLocatorConfigError("source_locator.opengrok.api_prefix 必须是非空字符串")
        timeout = data.get("timeout_seconds", 15.0)
        timeout_seconds = _positive_number(
            timeout, name="source_locator.opengrok.timeout_seconds", maximum=300
        )
        max_retries = _bounded_int(
            data.get("max_retries", 1),
            name="source_locator.opengrok.max_retries",
            minimum=0,
            maximum=3,
        )
        max_source_bytes = _bounded_int(
            data.get("max_source_bytes", 32 * 1024),
            name="source_locator.opengrok.max_source_bytes",
            minimum=1,
            maximum=16 * 1024 * 1024,
        )
        max_results = _bounded_int(
            data.get("max_results", 50),
            name="source_locator.opengrok.max_results",
            minimum=1,
            maximum=1000,
        )
        max_hits_per_file = _bounded_int(
            data.get("max_hits_per_file", 3),
            name="source_locator.opengrok.max_hits_per_file",
            minimum=1,
            maximum=1000,
        )
        verify_tls = data.get("verify_tls", True)
        if not isinstance(verify_tls, bool):
            raise SourceLocatorConfigError("source_locator.opengrok.verify_tls 必须是布尔值")
        auth = SourceLocatorAuth.from_mapping(data.get("auth", {"mode": "none"}))
        last_probe = _parse_probe(data.get("last_probe")) if data.get("last_probe") is not None else None
        try:
            return cls(
                base_url=base_url.rstrip("/"),
                project=project.strip(),
                api_prefix=api_prefix.strip(),
                timeout_seconds=timeout_seconds,
                max_retries=max_retries,
                max_source_bytes=max_source_bytes,
                max_results=max_results,
                max_hits_per_file=max_hits_per_file,
                verify_tls=verify_tls,
                auth=auth,
                last_probe=last_probe,
            )
        except (SourceLocatorConfigError, OpenGrokPathError):
            raise
        except (TypeError, ValueError) as exc:
            raise SourceLocatorConfigError(str(exc)) from exc

    def build_client(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        transport: Any = None,
        client: Any = None,
    ) -> OpenGrokClient:
        """Construct the read-only client without logging or serializing tokens."""

        return OpenGrokClient(
            self.base_url,
            project=self.project,
            api_prefix=self.api_prefix,
            token=self.auth.resolve_token(environ),
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            max_source_bytes=self.max_source_bytes,
            verify=self.verify_tls,
            transport=transport,
            client=client,
        )

    def with_probe(self, result: ProbeResult) -> "OpenGrokConfig":
        """Attach a probe result after verifying it belongs to this endpoint."""

        if not isinstance(result, ProbeResult):
            raise SourceLocatorConfigError("probe result 类型无效")
        if result.base_url != self.base_url or result.api_prefix != self.api_prefix:
            raise SourceLocatorConfigError("probe result 与当前 OpenGrok 配置不匹配")
        return replace(self, last_probe=result)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "base_url": self.base_url,
            "project": self.project,
            "api_prefix": self.api_prefix,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_source_bytes": self.max_source_bytes,
            "max_results": self.max_results,
            "max_hits_per_file": self.max_hits_per_file,
            "verify_tls": self.verify_tls,
            "auth": self.auth.to_dict(),
        }
        if self.last_probe is not None:
            result["last_probe"] = self.last_probe.to_dict()
        return result


@dataclass(frozen=True)
class ManifestConfig:
    """Manifest source declaration; fetching is intentionally out of scope."""

    source: str
    path: str | None = None
    repository_url: str | None = None
    revision: str | None = None
    manifest_file: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, str):
            raise SourceLocatorConfigError("source_locator.manifest.source 必须是字符串")
        if self.source not in _MANIFEST_SOURCES:
            raise SourceLocatorConfigError(
                f"source_locator.manifest.source 必须是：{', '.join(sorted(_MANIFEST_SOURCES))}"
            )
        if self.path is not None:
            _relative_path(self.path, name="source_locator.manifest.path")
        if self.manifest_file is not None:
            _relative_path(self.manifest_file, name="source_locator.manifest.manifest_file")
        if self.repository_url is not None:
            _validate_https_url(self.repository_url, name="source_locator.manifest.repository_url")
        if self.revision is not None:
            _validate_revision(self.revision, name="source_locator.manifest.revision")
        if self.source == "local" and self.path is None:
            raise SourceLocatorConfigError("source_locator.manifest.source=local 时必须提供 path")
        if self.source == "git" and (self.repository_url is None or self.revision is None):
            raise SourceLocatorConfigError(
                "source_locator.manifest.source=git 时必须提供 repository_url 和 revision"
            )
        if self.source == "local_or_git" and self.path is None and self.repository_url is None:
            raise SourceLocatorConfigError(
                "source_locator.manifest.source=local_or_git 时至少提供 path 或 repository_url"
            )

    @classmethod
    def from_mapping(cls, raw: Any) -> "ManifestConfig":
        data = _mapping(raw, name="source_locator.manifest")
        _reject_unknown(data, _MANIFEST_KEYS, name="source_locator.manifest")
        source = _required_string(data, "source", name="source_locator.manifest")
        path = _optional_string(data, "path", name="source_locator.manifest")
        repository_url = _optional_string(data, "repository_url", name="source_locator.manifest")
        revision = _optional_string(data, "revision", name="source_locator.manifest")
        manifest_file = _optional_string(data, "manifest_file", name="source_locator.manifest")
        return cls(source, path, repository_url, revision, manifest_file)

    def to_dict(self) -> dict[str, str]:
        result: dict[str, str] = {"source": self.source}
        for key, value in (
            ("path", self.path),
            ("repository_url", self.repository_url),
            ("revision", self.revision),
            ("manifest_file", self.manifest_file),
        ):
            if value is not None:
                result[key] = value
        return result


@dataclass(frozen=True)
class GitCodeConfig:
    """Allowlist and destination for a future repository manager."""

    allowed_hosts: tuple[str, ...] = ("gitcode.com",)
    allowed_orgs: tuple[str, ...] = ("openharmony",)
    destination_root: str = "source_code_base"

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_hosts, (tuple, list)) or not isinstance(
            self.allowed_orgs, (tuple, list)
        ):
            raise SourceLocatorConfigError("source_locator.gitcode 白名单必须是字符串数组")
        if not self.allowed_hosts or any(
            not isinstance(host, str) or not host.strip() or "://" in host or "/" in host
            for host in self.allowed_hosts
        ):
            raise SourceLocatorConfigError("source_locator.gitcode.allowed_hosts 必须是主机名数组")
        if not self.allowed_orgs or any(
            not isinstance(org, str) or not org.strip() or "/" in org or "\\" in org
            for org in self.allowed_orgs
        ):
            raise SourceLocatorConfigError("source_locator.gitcode.allowed_orgs 必须是组织名数组")
        _relative_path(self.destination_root, name="source_locator.gitcode.destination_root")

    @classmethod
    def from_mapping(cls, raw: Any) -> "GitCodeConfig":
        data = _mapping(raw, name="source_locator.gitcode")
        _reject_unknown(data, _GITCODE_KEYS, name="source_locator.gitcode")
        hosts = _string_list(
            data.get("allowed_hosts", ["gitcode.com"]),
            name="source_locator.gitcode.allowed_hosts",
            normalize_lower=True,
        )
        orgs = _string_list(
            data.get("allowed_orgs", ["openharmony"]),
            name="source_locator.gitcode.allowed_orgs",
        )
        destination = data.get("destination_root", "source_code_base")
        if not isinstance(destination, str) or not destination.strip():
            raise SourceLocatorConfigError("source_locator.gitcode.destination_root 必须是非空字符串")
        return cls(hosts, orgs, destination.strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_orgs": list(self.allowed_orgs),
            "destination_root": self.destination_root,
        }


@dataclass(frozen=True)
class SourceLocatorConfig:
    """Opt-in source-locator settings embedded in the main config file."""

    enabled: bool = True
    target_revision: str | None = None
    opengrok: OpenGrokConfig | None = None
    manifest: ManifestConfig | None = None
    gitcode: GitCodeConfig | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise SourceLocatorConfigError("source_locator.enabled 必须是布尔值")
        if self.target_revision is not None:
            if not isinstance(self.target_revision, str):
                raise SourceLocatorConfigError("source_locator.target_revision 必须是字符串或 null")
            _validate_revision(self.target_revision, name="source_locator.target_revision")
        if self.enabled and self.opengrok is None:
            raise SourceLocatorConfigError(
                "source_locator.enabled=true 时必须配置 source_locator.opengrok"
            )
        if self.opengrok is not None and not isinstance(self.opengrok, OpenGrokConfig):
            raise SourceLocatorConfigError("source_locator.opengrok 类型无效")
        if self.manifest is not None and not isinstance(self.manifest, ManifestConfig):
            raise SourceLocatorConfigError("source_locator.manifest 类型无效")
        if self.gitcode is not None and not isinstance(self.gitcode, GitCodeConfig):
            raise SourceLocatorConfigError("source_locator.gitcode 类型无效")

    @classmethod
    def from_mapping(cls, raw: Any) -> "SourceLocatorConfig":
        data = _mapping(raw, name="source_locator")
        _reject_unknown(data, _SOURCE_LOCATOR_KEYS, name="source_locator")
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise SourceLocatorConfigError("source_locator.enabled 必须是布尔值")
        target_revision = _optional_string(data, "target_revision", name="source_locator")
        if target_revision is not None:
            _validate_revision(target_revision, name="source_locator.target_revision")
        opengrok = (
            OpenGrokConfig.from_mapping(data["opengrok"])
            if data.get("opengrok") is not None
            else None
        )
        manifest = (
            ManifestConfig.from_mapping(data["manifest"])
            if data.get("manifest") is not None
            else None
        )
        gitcode = (
            GitCodeConfig.from_mapping(data["gitcode"])
            if data.get("gitcode") is not None
            else None
        )
        return cls(enabled, target_revision, opengrok, manifest, gitcode)

    def require_opengrok(self) -> OpenGrokConfig:
        if not self.enabled:
            raise SourceLocatorConfigError("source_locator 当前已禁用")
        if self.opengrok is None:
            raise SourceLocatorConfigError("未配置 source_locator.opengrok")
        return self.opengrok

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"enabled": self.enabled}
        if self.target_revision is not None:
            result["target_revision"] = self.target_revision
        if self.opengrok is not None:
            result["opengrok"] = self.opengrok.to_dict()
        if self.manifest is not None:
            result["manifest"] = self.manifest.to_dict()
        if self.gitcode is not None:
            result["gitcode"] = self.gitcode.to_dict()
        return result


def _parse_probe(raw: Any) -> ProbeResult:
    """Validate a serialized, credential-free :class:`ProbeResult`."""

    data = _mapping(raw, name="source_locator.opengrok.last_probe")
    allowed = {"base_url", "api_prefix", "reachable", "version", "index_time", "capabilities", "warnings"}
    _reject_unknown(data, frozenset(allowed), name="source_locator.opengrok.last_probe")
    base_url = _required_string(data, "base_url", name="source_locator.opengrok.last_probe")
    api_prefix = _required_string(data, "api_prefix", name="source_locator.opengrok.last_probe")
    reachable = data.get("reachable")
    if not isinstance(reachable, bool):
        raise SourceLocatorConfigError("last_probe.reachable 必须是布尔值")
    version = _optional_string(data, "version", name="source_locator.opengrok.last_probe")
    index_time = _optional_string(data, "index_time", name="source_locator.opengrok.last_probe")
    warnings_raw = data.get("warnings", [])
    if not isinstance(warnings_raw, list) or any(not isinstance(item, str) for item in warnings_raw):
        raise SourceLocatorConfigError("last_probe.warnings 必须是字符串数组")
    capabilities_raw = _mapping(
        data.get("capabilities", {}), name="source_locator.opengrok.last_probe.capabilities"
    )
    from .opengrok_client import EndpointCapability

    capabilities: dict[str, EndpointCapability] = {}
    for name, raw_capability in capabilities_raw.items():
        if not isinstance(name, str) or not name:
            raise SourceLocatorConfigError("last_probe.capabilities 的名称必须是非空字符串")
        capability = _mapping(raw_capability, name=f"last_probe.capabilities.{name}")
        _reject_unknown(
            capability,
            frozenset({"name", "available", "status_code", "requires_auth", "detail"}),
            name=f"last_probe.capabilities.{name}",
        )
        cap_name = capability.get("name", name)
        available = capability.get("available")
        requires_auth = capability.get("requires_auth", False)
        status_code = capability.get("status_code")
        detail = capability.get("detail")
        if not isinstance(cap_name, str) or not cap_name:
            raise SourceLocatorConfigError(f"last_probe.capabilities.{name}.name 无效")
        if not isinstance(available, bool) or not isinstance(requires_auth, bool):
            raise SourceLocatorConfigError(f"last_probe.capabilities.{name} 的布尔字段无效")
        if status_code is not None and (
            isinstance(status_code, bool) or not isinstance(status_code, int) or not 100 <= status_code <= 599
        ):
            raise SourceLocatorConfigError(f"last_probe.capabilities.{name}.status_code 无效")
        if detail is not None and not isinstance(detail, str):
            raise SourceLocatorConfigError(f"last_probe.capabilities.{name}.detail 必须是字符串或 null")
        capabilities[name] = EndpointCapability(
            name=cap_name,
            available=available,
            status_code=status_code,
            requires_auth=requires_auth,
            detail=detail,
        )
    try:
        return ProbeResult(
            base_url=base_url,
            api_prefix=api_prefix,
            reachable=reachable,
            version=version,
            index_time=index_time,
            capabilities=capabilities,
            warnings=tuple(warnings_raw),
        )
    except (TypeError, ValueError) as exc:
        raise SourceLocatorConfigError(f"last_probe 无效：{exc}") from exc


def parse_source_locator_config(raw: Mapping[str, Any]) -> SourceLocatorConfig | None:
    """Parse the optional section from a full ``config.json`` object."""

    root = _mapping(raw, name="config.json")
    if "source_locator" not in root or root["source_locator"] is None:
        return None
    return SourceLocatorConfig.from_mapping(root["source_locator"])


def load_source_locator_config(path: str | os.PathLike[str], *, required: bool = False) -> SourceLocatorConfig | None:
    """Load only the source-locator section from an explicit config path.

    ``required=False`` preserves the old scan-only behaviour when the section
    or file is absent.  ``required=True`` is for a locator command that should
    explain a missing configuration instead of guessing a public endpoint.
    """

    target = Path(path).expanduser()
    if not target.exists():
        if required:
            raise SourceLocatorConfigError(f"配置文件不存在：{target}")
        return None
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SourceLocatorConfigError(f"无法读取配置文件 {target}：{exc}") from exc
    except json.JSONDecodeError as exc:
        raise SourceLocatorConfigError(f"配置文件 {target} 不是有效 JSON：{exc}") from exc
    config = parse_source_locator_config(raw)
    if required and config is None:
        raise SourceLocatorConfigError(
            f"配置文件 {target} 未设置 source_locator，不能猜测 OpenGrok 地址"
        )
    return config
