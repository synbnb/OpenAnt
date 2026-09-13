"""Deterministic OpenHarmony Manifest-to-repository resolution.

OpenGrok returns source paths, while the repository that owns a path is
declared by an OpenHarmony ``manifest``.  This module parses that declaration
without network access and resolves a path by longest project-prefix match.
It intentionally does not clone repositories or let a model invent a remote
or revision; unresolved, ambiguous and version-mismatched results remain
explicit in the returned mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Mapping
from urllib.parse import quote, urlsplit, urlunsplit


_SCHEMA_VERSION = "openant.source-locator.repository-mapping.v1"
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_PATH_LENGTH = 2048
_MAX_NAME_LENGTH = 128
_MAX_WARNING_LENGTH = 512
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+~-]{0,127}$")
_REMOTE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ManifestResolverError(ValueError):
    """Base error for malformed or unsafe Manifest data."""


class ManifestParseError(ManifestResolverError):
    """Raised when XML cannot be parsed as a supported Manifest."""


class ManifestAmbiguityError(ManifestResolverError):
    """Raised when equally specific projects compete for one source path."""

    def __init__(self, source_path: str, candidates: tuple["ManifestProject", ...]) -> None:
        self.source_path = source_path
        self.candidates = candidates
        names = ", ".join(item.name for item in candidates)
        super().__init__(f"Manifest 路径匹配存在同长度冲突：{source_path} -> {names}")


def _bounded_text(value: Any, *, name: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ManifestResolverError(f"{name} 必须是字符串")
    value = value.strip()
    if not value and not allow_empty:
        raise ManifestResolverError(f"{name} 不能为空")
    if len(value) > limit:
        raise ManifestResolverError(f"{name} 超过 {limit} 个字符")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ManifestResolverError(f"{name} 包含控制字符")
    return value


def _normalize_manifest_path(value: Any, *, name: str, allow_empty: bool = False) -> str:
    raw = _bounded_text(value, name=name, limit=_MAX_PATH_LENGTH, allow_empty=allow_empty)
    if not raw:
        return ""
    if "\\" in raw or "\x00" in raw or "?" in raw or "#" in raw or "://" in raw:
        raise ManifestResolverError(f"{name} 不是安全的仓库相对路径")
    parts = [part for part in raw.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        raise ManifestResolverError(f"{name} 不得包含路径穿越片段")
    return "/".join(parts)


def _normalize_source_path(value: Any) -> str:
    relative = _normalize_manifest_path(value, name="source_path")
    return "/" + relative


def _normalize_name(value: Any, *, name: str) -> str:
    result = _bounded_text(value, name=name, limit=_MAX_NAME_LENGTH)
    if (
        result in {".", ".."}
        or "/" in result
        or "\\" in result
        or "?" in result
        or "#" in result
        or any(char.isspace() for char in result)
    ):
        raise ManifestResolverError(f"{name} 不是安全的单段标识符")
    return result


def _normalize_remote_name(value: Any, *, name: str) -> str:
    result = _bounded_text(value, name=name, limit=_MAX_NAME_LENGTH)
    if not _REMOTE_NAME_RE.fullmatch(result):
        raise ManifestResolverError(f"{name} 不是安全的 remote 名称")
    return result


def _normalize_revision(value: Any, *, name: str) -> str:
    result = _bounded_text(value, name=name, limit=128)
    if not _REVISION_RE.fullmatch(result) or ".." in result or "//" in result:
        raise ManifestResolverError(f"{name} 不是安全的 Git revision")
    if result.endswith(".") or result.endswith(".lock"):
        raise ManifestResolverError(f"{name} 不是安全的 Git revision")
    return result


def _optional_attr(attrs: Mapping[str, str], key: str, *, name: str) -> str | None:
    if key not in attrs or attrs[key] is None:
        return None
    value = attrs[key].strip()
    if not value:
        raise ManifestParseError(f"{name}.{key} 不能为空")
    return value


def _local_tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _manifest_path_label(value: str) -> str:
    # The path is metadata for display and hashing, not a file access target.
    return _bounded_text(value or "<inline>", name="manifest_path", limit=1024)


def _manifest_bytes(content: str | bytes) -> bytes:
    if isinstance(content, str):
        raw = content.encode("utf-8")
    elif isinstance(content, bytes):
        raw = content
    else:
        raise ManifestParseError("Manifest 内容必须是字符串或字节串")
    if not raw:
        raise ManifestParseError("Manifest 内容不能为空")
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ManifestParseError(f"Manifest 超过 {_MAX_MANIFEST_BYTES} 字节上限")
    # ElementTree does not need DTDs for OpenHarmony manifests.  Rejecting
    # them avoids entity expansion and keeps the parser fail-closed for input
    # that did not come from the expected manifest format.
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ManifestParseError("Manifest 不允许 DOCTYPE/ENTITY 声明")
    return raw


def manifest_cache_key(content: str | bytes, revision: str | None = None) -> str:
    """Return the cache key required by the plan: revision + content hash."""

    raw = _manifest_bytes(content)
    normalized_revision = "unknown" if revision is None else _normalize_revision(revision, name="revision")
    return f"{normalized_revision}:{hashlib.sha256(raw).hexdigest()}"


def _normalize_fetch(value: Any, *, name: str) -> str:
    raw = _bounded_text(value, name=name, limit=2048)
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise ManifestResolverError(f"{name} 不是有效 URL：{exc}") from exc
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ManifestResolverError(f"{name} 必须是带主机名的 HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ManifestResolverError(f"{name} 不得包含用户名或密码")
    if parsed.query or parsed.fragment:
        raise ManifestResolverError(f"{name} 不得包含 query 或 fragment")
    path = parsed.path or ""
    path_parts = [part for part in path.split("/") if part]
    if any(part in {".", ".."} for part in path_parts):
        raise ManifestResolverError(f"{name} 包含路径穿越片段")
    return urlunsplit((parsed.scheme, parsed.netloc, "/" + "/".join(path_parts), "", "")).rstrip("/")


def build_repository_url(remote_fetch: str, project_name: str) -> str:
    """Join a Manifest remote fetch URL and project name without guessing refs."""

    base = _normalize_fetch(remote_fetch, name="remote.fetch")
    name = _normalize_name(project_name, name="project.name")
    encoded_name = quote(name, safe="._-~+@")
    parsed = urlsplit(base)
    path = (parsed.path.rstrip("/") + "/" + encoded_name).replace("//", "/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


@dataclass(frozen=True)
class ManifestRemote:
    """One named remote declaration from a Manifest."""

    name: str
    fetch: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_remote_name(self.name, name="remote.name"))
        object.__setattr__(self, "fetch", _normalize_fetch(self.fetch, name="remote.fetch"))

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "fetch": self.fetch}


@dataclass(frozen=True)
class ManifestProject:
    """A normalized ``<project>`` entry.

    ``remote`` and ``revision`` are optional because OpenHarmony manifests can
    inherit them from a ``<default>`` element.  The resolver applies that
    inheritance only after choosing the longest matching project.
    """

    name: str
    path: str
    remote: str | None = None
    revision: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _normalize_name(self.name, name="project.name"))
        object.__setattr__(self, "path", _normalize_manifest_path(self.path, name="project.path"))
        if self.remote is not None:
            object.__setattr__(self, "remote", _normalize_remote_name(self.remote, name="project.remote"))
        if self.revision is not None:
            object.__setattr__(self, "revision", _normalize_revision(self.revision, name="project.revision"))

    @property
    def source_root(self) -> str:
        return self.path

    @property
    def project_name(self) -> str:
        return self.name

    def to_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "path": self.path,
            "remote": self.remote,
            "revision": self.revision,
        }


@dataclass(frozen=True)
class ManifestDocument:
    """Parsed Manifest plus provenance needed for cache and UI display."""

    manifest_path: str
    content_sha256: str
    projects: tuple[ManifestProject, ...]
    remotes: tuple[ManifestRemote, ...]
    default_remote: str | None = None
    default_revision: str | None = None
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifest_path", _manifest_path_label(self.manifest_path))
        if not isinstance(self.content_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.content_sha256.lower()
        ):
            raise ManifestResolverError("Manifest content_sha256 无效")
        object.__setattr__(self, "content_sha256", self.content_sha256.lower())
        projects = tuple(self.projects)
        remotes = tuple(self.remotes)
        if any(not isinstance(project, ManifestProject) for project in projects):
            raise ManifestResolverError("ManifestDocument.projects 只能包含 ManifestProject")
        if any(not isinstance(remote, ManifestRemote) for remote in remotes):
            raise ManifestResolverError("ManifestDocument.remotes 只能包含 ManifestRemote")
        object.__setattr__(self, "projects", projects)
        object.__setattr__(self, "remotes", remotes)
        if self.default_remote is not None:
            object.__setattr__(
                self,
                "default_remote",
                _normalize_remote_name(self.default_remote, name="default.remote"),
            )
        if self.default_revision is not None:
            object.__setattr__(
                self,
                "default_revision",
                _normalize_revision(self.default_revision, name="default.revision"),
            )
        normalized_warnings = tuple(
            _bounded_text(item, name="manifest warning", limit=_MAX_WARNING_LENGTH)
            for item in self.warnings
        )
        object.__setattr__(self, "warnings", normalized_warnings)

    @property
    def cache_key(self) -> str:
        revision = self.default_revision or "unknown"
        return f"{revision}:{self.content_sha256}"

    def remote_by_name(self, name: str | None) -> ManifestRemote | None:
        if name is None:
            return None
        return next((remote for remote in self.remotes if remote.name == name), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "openant.source-locator.manifest.v1",
            "manifest_path": self.manifest_path,
            "content_sha256": self.content_sha256,
            "cache_key": self.cache_key,
            "default_remote": self.default_remote,
            "default_revision": self.default_revision,
            "projects": [project.to_dict() for project in self.projects],
            "remotes": [remote.to_dict() for remote in self.remotes],
            "warnings": list(self.warnings),
        }


def parse_manifest(content: str | bytes, *, manifest_path: str = "<inline>") -> ManifestDocument:
    """Parse a bounded Manifest and normalize project/remote declarations."""

    raw = _manifest_bytes(content)
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError) as exc:
        raise ManifestParseError(f"Manifest XML 无法解析：{exc}") from exc
    if _local_tag(root) != "manifest":
        raise ManifestParseError("Manifest 根节点必须是 manifest")

    remotes: list[ManifestRemote] = []
    remote_by_name: dict[str, ManifestRemote] = {}
    projects: list[ManifestProject] = []
    warnings: list[str] = []
    default_remote: str | None = None
    default_revision: str | None = None

    for element in root.iter():
        tag = _local_tag(element)
        attrs = element.attrib
        if tag == "remote":
            name = _optional_attr(attrs, "name", name="remote")
            fetch = _optional_attr(attrs, "fetch", name="remote")
            if name is None or fetch is None:
                raise ManifestParseError("remote 节点必须包含 name 和 fetch")
            remote = ManifestRemote(name, fetch)
            previous = remote_by_name.get(remote.name)
            if previous is not None and previous != remote:
                raise ManifestParseError(f"remote {remote.name} 被重复定义且内容冲突")
            if previous is None:
                remote_by_name[remote.name] = remote
                remotes.append(remote)
        elif tag == "default":
            remote_value = _optional_attr(attrs, "remote", name="default")
            revision_value = _optional_attr(attrs, "revision", name="default")
            if remote_value is not None:
                remote_value = _normalize_remote_name(remote_value, name="default.remote")
            if revision_value is not None:
                revision_value = _normalize_revision(revision_value, name="default.revision")
            if default_remote is not None and remote_value != default_remote:
                raise ManifestParseError("Manifest 包含冲突的 default.remote")
            if default_revision is not None and revision_value != default_revision:
                raise ManifestParseError("Manifest 包含冲突的 default.revision")
            default_remote = remote_value or default_remote
            default_revision = revision_value or default_revision
        elif tag == "project":
            name = _optional_attr(attrs, "name", name="project")
            path = _optional_attr(attrs, "path", name="project")
            if name is None or path is None:
                raise ManifestParseError("project 节点必须包含 name 和 path")
            projects.append(
                ManifestProject(
                    name=name,
                    path=path,
                    remote=_optional_attr(attrs, "remote", name="project"),
                    revision=_optional_attr(attrs, "revision", name="project"),
                )
            )
        elif tag == "include":
            include_name = attrs.get("name", "")
            if include_name:
                warnings.append(
                    f"Manifest include 未展开：{_bounded_text(include_name, name='include.name', limit=512)}"
                )

    if not projects:
        warnings.append("Manifest 未声明 project 节点")
    return ManifestDocument(
        manifest_path=_manifest_path_label(manifest_path),
        content_sha256=hashlib.sha256(raw).hexdigest(),
        projects=tuple(projects),
        remotes=tuple(remotes),
        default_remote=default_remote,
        default_revision=default_revision,
        warnings=tuple(warnings),
    )


def load_manifest(path: str | os.PathLike[str], *, max_bytes: int = _MAX_MANIFEST_BYTES) -> ManifestDocument:
    """Read one explicit local Manifest; no remote fetch is performed."""

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= _MAX_MANIFEST_BYTES:
        raise ManifestResolverError(f"max_bytes 必须是 1 到 {_MAX_MANIFEST_BYTES} 之间的整数")
    target = Path(path).expanduser()
    try:
        if target.stat().st_size > max_bytes:
            raise ManifestParseError(f"Manifest 超过 {max_bytes} 字节上限")
        content = target.read_bytes()
    except ManifestResolverError:
        raise
    except OSError as exc:
        raise ManifestResolverError(f"无法读取 Manifest {target}：{exc}") from exc
    if len(content) > max_bytes:
        raise ManifestParseError(f"Manifest 超过 {max_bytes} 字节上限")
    return parse_manifest(content, manifest_path=str(target))


def _matching_projects(source_path: str, projects: Iterable[ManifestProject]) -> tuple[ManifestProject, ...]:
    normalized = _normalize_manifest_path(source_path, name="source_path")
    project_list = tuple(projects)
    if any(not isinstance(project, ManifestProject) for project in project_list):
        raise ManifestResolverError("projects 只能包含 ManifestProject")

    def matches(candidate_path: str) -> tuple[ManifestProject, ...]:
        return tuple(
            project
            for project in project_list
            if candidate_path == project.path or candidate_path.startswith(project.path + "/")
        )

    direct = matches(normalized)
    if direct:
        return direct
    # OpenGrok project paths commonly look like /openharmony/base/... while
    # Manifest paths start at base/.  Only remove the first component when the
    # direct form has no match, so manifests that intentionally include a
    # top-level project directory still work.
    pieces = normalized.split("/")
    if len(pieces) > 1 and pieces[0].lower() in {"openharmony", "ohos"}:
        return matches("/".join(pieces[1:]))
    return ()


def resolve_project(source_path: str, projects: Iterable[ManifestProject]) -> ManifestProject | None:
    """Return the unique longest-prefix project, or ``None`` if unmatched."""

    candidates = _matching_projects(source_path, projects)
    if not candidates:
        return None
    longest_length = max(len(project.path) for project in candidates)
    longest = tuple(project for project in candidates if len(project.path) == longest_length)
    unique = tuple(dict.fromkeys(longest))
    if len(unique) > 1:
        raise ManifestAmbiguityError(_normalize_source_path(source_path), unique)
    return unique[0]


@dataclass(frozen=True)
class RepositoryMapping:
    """A mapping result suitable for UI, evidence graph and later Git stages."""

    # Keep the first fields compatible with the RepositoryResolution shape in
    # the design document; richer audit fields follow as optional values.
    project_name: str | None = None
    source_root: str | None = None
    remote_name: str | None = None
    remote_fetch: str | None = None
    repo_url: str | None = None
    revision: str | None = None
    resolution_method: str = "manifest"
    evidence_ids: tuple[str, ...] = ()
    source_path: str = ""
    manifest_path: str = ""
    matched_prefix: str | None = None
    match_method: str = "manifest_longest_prefix"
    verified: bool = False
    warnings: tuple[str, ...] = ()
    status: str = "resolved"
    content_sha256: str | None = None
    requested_revision: str | None = None

    def __post_init__(self) -> None:
        if self.project_name is not None:
            object.__setattr__(self, "project_name", _normalize_name(self.project_name, name="project_name"))
        if self.source_root is not None:
            object.__setattr__(self, "source_root", _normalize_manifest_path(self.source_root, name="source_root"))
        if self.remote_name is not None:
            object.__setattr__(self, "remote_name", _normalize_remote_name(self.remote_name, name="remote_name"))
        if self.remote_fetch is not None:
            object.__setattr__(self, "remote_fetch", _normalize_fetch(self.remote_fetch, name="remote_fetch"))
        if self.repo_url is not None:
            object.__setattr__(self, "repo_url", _normalize_fetch(self.repo_url, name="repo_url"))
        if self.revision is not None:
            object.__setattr__(self, "revision", _normalize_revision(self.revision, name="revision"))
        if self.requested_revision is not None:
            object.__setattr__(self, "requested_revision", _normalize_revision(self.requested_revision, name="requested_revision"))
        if self.source_path:
            object.__setattr__(self, "source_path", _normalize_source_path(self.source_path))
        if self.manifest_path:
            object.__setattr__(self, "manifest_path", _manifest_path_label(self.manifest_path))
        if self.matched_prefix is not None:
            object.__setattr__(self, "matched_prefix", _normalize_manifest_path(self.matched_prefix, name="matched_prefix"))
        object.__setattr__(self, "resolution_method", _bounded_text(self.resolution_method, name="resolution_method", limit=64))
        object.__setattr__(self, "match_method", _bounded_text(self.match_method, name="match_method", limit=64))
        if self.status not in {"resolved", "needs_review", "ambiguous", "unresolved", "version_mismatch"}:
            raise ManifestResolverError(f"未知 RepositoryMapping.status: {self.status}")
        if not isinstance(self.verified, bool):
            raise ManifestResolverError("RepositoryMapping.verified 必须是布尔值")
        if isinstance(self.evidence_ids, (str, bytes)):
            raise ManifestResolverError("evidence_ids 必须是字符串序列")
        ids = tuple(self.evidence_ids)
        if any(not isinstance(item, str) or not item.strip() for item in ids):
            raise ManifestResolverError("evidence_ids 只能包含非空字符串")
        object.__setattr__(self, "evidence_ids", tuple(dict.fromkeys(item.strip() for item in ids)))
        if isinstance(self.warnings, (str, bytes)):
            raise ManifestResolverError("warnings 必须是字符串序列")
        object.__setattr__(
            self,
            "warnings",
            tuple(
                _bounded_text(item, name="mapping warning", limit=_MAX_WARNING_LENGTH)
                for item in self.warnings
            ),
        )
        if self.content_sha256 is not None:
            if not isinstance(self.content_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", self.content_sha256.lower()
            ):
                raise ManifestResolverError("RepositoryMapping.content_sha256 无效")
            object.__setattr__(self, "content_sha256", self.content_sha256.lower())

    @property
    def name(self) -> str | None:
        return self.project_name

    @property
    def git_url(self) -> str | None:
        return self.repo_url

    @property
    def is_resolved(self) -> bool:
        return self.status == "resolved" and self.repo_url is not None and self.revision is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "source_path": self.source_path,
            "manifest_path": self.manifest_path,
            "matched_prefix": self.matched_prefix,
            "project_name": self.project_name,
            "source_root": self.source_root,
            "remote_name": self.remote_name,
            "remote_fetch": self.remote_fetch,
            "repo_url": self.repo_url,
            "git_url": self.repo_url,
            "revision": self.revision,
            "requested_revision": self.requested_revision,
            "resolution_method": self.resolution_method,
            "match_method": self.match_method,
            "verified": self.verified,
            "status": self.status,
            "content_sha256": self.content_sha256,
            "evidence_ids": list(self.evidence_ids),
            "warnings": list(self.warnings),
        }


# Both names are used in the design notes; they intentionally share one data
# contract until the later repository-manager slice adds clone-specific state.
RepositoryResolution = RepositoryMapping


class ManifestResolver:
    """Resolve source paths against one already parsed Manifest."""

    def __init__(
        self,
        manifest: ManifestDocument | str | bytes,
        *,
        manifest_path: str = "<inline>",
        target_revision: str | None = None,
    ) -> None:
        if isinstance(manifest, ManifestDocument):
            self.document = manifest
        else:
            self.document = parse_manifest(manifest, manifest_path=manifest_path)
        self.target_revision = (
            None
            if target_revision is None
            else _normalize_revision(target_revision, name="target_revision")
        )

    @property
    def cache_key(self) -> str:
        return self.document.cache_key

    def resolve_project(self, source_path: str) -> ManifestProject | None:
        return resolve_project(source_path, self.document.projects)

    def resolve(
        self,
        source_path: str,
        *,
        requested_revision: str | None = None,
        evidence_ids: Iterable[str] = (),
    ) -> RepositoryMapping:
        normalized_source = _normalize_source_path(source_path)
        if isinstance(evidence_ids, (str, bytes)):
            raise ManifestResolverError("evidence_ids 必须是字符串序列")
        evidence_tuple = tuple(evidence_ids)
        requested = requested_revision if requested_revision is not None else self.target_revision
        if requested is not None:
            requested = _normalize_revision(requested, name="requested_revision")
        warnings = list(self.document.warnings)
        try:
            project = self.resolve_project(normalized_source)
        except ManifestAmbiguityError as exc:
            warnings.append(str(exc))
            return RepositoryMapping(
                source_path=normalized_source,
                manifest_path=self.document.manifest_path,
                resolution_method="manifest",
                evidence_ids=evidence_tuple,
                warnings=tuple(warnings),
                status="ambiguous",
                content_sha256=self.document.content_sha256,
                requested_revision=requested,
            )
        if project is None:
            warnings.append(f"Manifest 没有匹配路径：{normalized_source}")
            return RepositoryMapping(
                source_path=normalized_source,
                manifest_path=self.document.manifest_path,
                resolution_method="unresolved",
                evidence_ids=evidence_tuple,
                warnings=tuple(warnings),
                status="unresolved",
                content_sha256=self.document.content_sha256,
                requested_revision=requested,
            )

        remote_name = project.remote or self.document.default_remote
        revision = project.revision or self.document.default_revision
        remote = self.document.remote_by_name(remote_name)
        status = "resolved"
        repo_url: str | None = None
        if remote_name is None:
            warnings.append(f"项目 {project.name} 没有 remote，且 default.remote 未提供")
            status = "needs_review"
        elif remote is None:
            warnings.append(f"Manifest 未声明 remote：{remote_name}")
            status = "needs_review"
        else:
            try:
                repo_url = build_repository_url(remote.fetch, project.name)
            except ManifestResolverError as exc:
                warnings.append(f"remote URL 无法构造：{exc}")
                status = "needs_review"
            if urlsplit(remote.fetch).scheme != "https":
                warnings.append("remote.fetch 不是 HTTPS，需经过后续 GitCode 安全校验")
                status = "needs_review"
        if revision is None:
            warnings.append(f"项目 {project.name} 没有 revision，不能猜测 master")
            status = "needs_review"
        if requested is not None:
            if revision is not None and revision != requested:
                warnings.append(
                    f"Manifest revision {revision} 与请求 revision {requested} 不一致"
                )
                status = "version_mismatch"
            elif revision is None:
                warnings.append("请求 revision 存在，但 Manifest 没有可比较的 revision")
                status = "needs_review"

        return RepositoryMapping(
            project_name=project.name,
            source_root=project.path,
            remote_name=remote_name,
            remote_fetch=remote.fetch if remote is not None else None,
            repo_url=repo_url,
            revision=revision,
            resolution_method="manifest",
            evidence_ids=evidence_tuple,
            source_path=normalized_source,
            manifest_path=self.document.manifest_path,
            matched_prefix=project.path,
            match_method="manifest_longest_prefix",
            verified=False,
            warnings=tuple(warnings),
            status=status,
            content_sha256=self.document.content_sha256,
            requested_revision=requested,
        )

    def resolve_many(
        self,
        source_paths: Iterable[str],
        *,
        requested_revision: str | None = None,
    ) -> tuple[RepositoryMapping, ...]:
        if isinstance(source_paths, (str, bytes)):
            raise ManifestResolverError("source_paths 必须是路径序列")
        try:
            paths = tuple(source_paths)
        except TypeError as exc:
            raise ManifestResolverError("source_paths 必须是可迭代对象") from exc
        return tuple(self.resolve(path, requested_revision=requested_revision) for path in paths)
