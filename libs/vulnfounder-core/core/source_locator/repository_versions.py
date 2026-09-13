"""Safe discovery of remote Git revisions after a failed acquisition.

The source locator must not silently change a user-confirmed revision.  This
module therefore performs only a bounded, read-only ``git ls-remote`` query and
returns validated branch/tag candidates for a later, explicit user choice.
It never clones, checks out, or turns model-provided text into a Git command.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable

from .config import GitCodeConfig
from .manifest_resolver import RepositoryMapping
from .repository_manager import (
    CommandRecord,
    CommandResult,
    RepositoryManagerError,
    _default_runner,
    _git_transport_url,
    _safe_revision,
)
from .repository_policy import RepositoryPolicy


_SCHEMA_VERSION = "openant.source-locator.repository-versions.v1"
_MAX_REASON = 512
_MAX_REF_LINE = 1024
_MAX_CANDIDATES = 64
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,128}$")
_RESULT_STATUSES = frozenset({"ok", "unavailable", "rejected"})
_CANDIDATE_KINDS = frozenset({"branch", "tag"})
_OH_VERSION_RE = re.compile(r"(?i)openharmony[-_]?v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _clean(value: Any, *, limit: int = _MAX_REASON) -> str:
    return " ".join(str(value).split())[:limit]


@dataclass(frozen=True)
class RepositoryVersionCandidate:
    """One remote branch or tag that can be shown to a user."""

    revision: str
    ref: str
    kind: str
    commit: str | None = None
    recommended: bool = False

    def __post_init__(self) -> None:
        safe_revision = _safe_revision(self.revision)
        if safe_revision is None:
            raise RepositoryManagerError("远程候选 revision 不是安全值")
        if self.kind not in _CANDIDATE_KINDS:
            raise RepositoryManagerError("远程候选类型无效")
        expected_prefix = "refs/heads/" if self.kind == "branch" else "refs/tags/"
        if self.ref != expected_prefix + safe_revision:
            raise RepositoryManagerError("远程候选 ref 与 revision 不一致")
        if self.commit is not None:
            if not isinstance(self.commit, str) or not _COMMIT_RE.fullmatch(self.commit.strip()):
                raise RepositoryManagerError("远程候选 commit 不是安全值")
            object.__setattr__(self, "commit", self.commit.strip().lower())
        if not isinstance(self.recommended, bool):
            raise RepositoryManagerError("远程候选 recommended 必须是布尔值")
        object.__setattr__(self, "revision", safe_revision)

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "ref": self.ref,
            "kind": self.kind,
            "commit": self.commit,
            "recommended": self.recommended,
        }


@dataclass(frozen=True)
class RepositoryVersionDiscoveryResult:
    """Bounded result of one remote version listing."""

    status: str
    project_name: str | None = None
    repo_url: str | None = None
    canonical_url: str | None = None
    requested_revision: str | None = None
    candidates: tuple[RepositoryVersionCandidate, ...] = ()
    commands: tuple[CommandRecord, ...] = ()
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_VERSION:
            raise RepositoryManagerError("远程版本查询 schema_version 不受支持")
        if self.status not in _RESULT_STATUSES:
            raise RepositoryManagerError("远程版本查询结果状态无效")
        if self.requested_revision is not None and _safe_revision(self.requested_revision) is None:
            raise RepositoryManagerError("requested_revision 不是安全值")
        if len(self.candidates) > _MAX_CANDIDATES:
            raise RepositoryManagerError("远程候选版本超过数量上限")
        if any(not isinstance(item, RepositoryVersionCandidate) for item in self.candidates):
            raise RepositoryManagerError("远程候选必须是 RepositoryVersionCandidate")
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "commands", tuple(self.commands))
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_clean(item) for item in self.warnings))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "project_name": self.project_name,
            "repo_url": self.repo_url,
            "canonical_url": self.canonical_url,
            "requested_revision": self.requested_revision,
            "candidate_count": len(self.candidates),
            "candidates": [item.to_dict() for item in self.candidates],
            "commands": [item.to_dict() for item in self.commands],
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


Runner = Callable[..., CommandResult]


def _candidate_rank(candidate: RepositoryVersionCandidate, requested: str | None) -> tuple[int, int, int, int, int, int, str]:
    """Prefer the requested revision, then newer stable OpenHarmony refs."""

    if requested and candidate.revision == requested:
        requested_rank = 0
    else:
        requested_rank = 1
    lowered = candidate.revision.lower()
    version_match = _OH_VERSION_RE.search(candidate.revision)
    if version_match:
        major = int(version_match.group(1))
        minor = int(version_match.group(2) or 0)
        patch = int(version_match.group(3) or 0)
        version_known = 0
    else:
        major = minor = patch = 0
        version_known = 1
    if "lts" in lowered:
        stability_rank = 0
    elif "release" in lowered:
        stability_rank = 1
    elif lowered in {"main", "master", "default"}:
        stability_rank = 2
    else:
        stability_rank = 3
    kind_rank = 0 if candidate.kind == "branch" else 1
    # Numeric OpenHarmony release versions are sorted newest-first.  Feature
    # or timestamp-only refs remain available but are placed after numbered
    # releases rather than accidentally outranking an LTS branch.
    return requested_rank, version_known, -major, -minor, -patch, stability_rank, kind_rank, candidate.revision


def _parse_refs(
    stdout: str,
    *,
    requested_revision: str | None,
    max_candidates: int,
) -> tuple[tuple[RepositoryVersionCandidate, ...], tuple[str, ...]]:
    candidates: list[RepositoryVersionCandidate] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if len(line) > _MAX_REF_LINE:
            warnings.append("远程版本列表包含超长记录，已跳过")
            continue
        commit, separator, ref = line.partition("\t")
        if not separator or not _COMMIT_RE.fullmatch(commit.strip()):
            warnings.append("远程版本列表包含无法解析的记录，已跳过")
            continue
        if ref.startswith("refs/heads/"):
            kind = "branch"
            prefix = "refs/heads/"
        elif ref.startswith("refs/tags/"):
            kind = "tag"
            prefix = "refs/tags/"
        else:
            # ``--heads --tags --refs`` should already exclude symbolic and
            # peeled refs; keeping this check makes the parser fail closed if
            # a Git implementation emits an unexpected ref kind.
            continue
        revision = ref[len(prefix) :]
        if revision.endswith("^{}"):  # peeled tag, never a selectable ref
            continue
        safe_revision = _safe_revision(revision)
        if safe_revision is None:
            warnings.append("远程版本列表包含不安全的 revision，已跳过")
            continue
        key = (kind, safe_revision)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            RepositoryVersionCandidate(
                revision=safe_revision,
                ref=prefix + safe_revision,
                kind=kind,
                commit=commit.strip().lower(),
                recommended=bool(requested_revision and safe_revision == requested_revision),
            )
        )
    candidates.sort(key=lambda item: _candidate_rank(item, requested_revision))
    if len(candidates) > max_candidates:
        warnings.append(f"远程候选版本超过 {max_candidates} 项，已按稳定性截取")
        candidates = candidates[:max_candidates]
    return tuple(candidates), tuple(dict.fromkeys(warnings))


def discover_repository_versions(
    mapping: RepositoryMapping,
    *,
    config: GitCodeConfig | None = None,
    runner: Runner | None = None,
    timeout_seconds: float = 60.0,
    max_candidates: int = 32,
) -> RepositoryVersionDiscoveryResult:
    """List safe remote branch/tag candidates without changing local state."""

    if not isinstance(mapping, RepositoryMapping):
        raise RepositoryManagerError("mapping 必须是 RepositoryMapping")
    if config is None:
        config = GitCodeConfig()
    if not isinstance(config, GitCodeConfig):
        raise RepositoryManagerError("config 必须是 GitCodeConfig")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise RepositoryManagerError("timeout_seconds 必须是数字")
    if not 1 <= float(timeout_seconds) <= 300:
        raise RepositoryManagerError("timeout_seconds 必须在 1 到 300 秒之间")
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= _MAX_CANDIDATES:
        raise RepositoryManagerError(f"max_candidates 必须是 1 到 {_MAX_CANDIDATES} 之间的整数")

    policy = RepositoryPolicy(config)
    decision = policy.validate_mapping(mapping)
    if not decision.allowed:
        return RepositoryVersionDiscoveryResult(
            status="rejected",
            project_name=mapping.project_name,
            repo_url=mapping.repo_url,
            requested_revision=mapping.revision,
            reasons=decision.reasons or ("仓库策略拒绝远程版本查询",),
            warnings=decision.warnings,
        )
    requested = _safe_revision(mapping.revision)
    if requested is None or decision.canonical_url is None:
        return RepositoryVersionDiscoveryResult(
            status="rejected",
            project_name=mapping.project_name,
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url,
            requested_revision=mapping.revision,
            reasons=("Manifest mapping 缺少安全 revision 或 canonical URL",),
            warnings=decision.warnings,
        )

    command = (
        "git",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "http.followRedirects=false",
        "ls-remote",
        "--heads",
        "--tags",
        "--refs",
        "--",
        _git_transport_url(decision),
    )
    selected_runner = runner or _default_runner
    records: list[CommandRecord] = []
    try:
        result = selected_runner(command, cwd=None, timeout_seconds=float(timeout_seconds))
        if not isinstance(result, CommandResult):
            raise RepositoryManagerError("runner 必须返回 CommandResult")
    except RepositoryManagerError:
        raise
    except Exception as exc:  # pragma: no cover - defensive adapter boundary
        records.append(CommandRecord(command, None, "exception", stderr=_clean(exc)))
        return RepositoryVersionDiscoveryResult(
            status="unavailable",
            project_name=mapping.project_name,
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url,
            requested_revision=requested,
            commands=tuple(records),
            reasons=(f"远程版本查询执行异常：{_clean(exc)}",),
            warnings=decision.warnings,
        )

    command_status = "ok" if result.returncode == 0 else "error"
    if result.returncode == 124:
        command_status = "timeout"
    records.append(CommandRecord(command, result.returncode, command_status, result.stdout, result.stderr))
    if result.returncode != 0:
        detail = _clean(result.stderr or result.stdout or "无错误输出")
        return RepositoryVersionDiscoveryResult(
            status="unavailable",
            project_name=mapping.project_name,
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url,
            requested_revision=requested,
            commands=tuple(records),
            reasons=(f"远程版本查询失败：{detail}",),
            warnings=decision.warnings,
        )

    candidates, parse_warnings = _parse_refs(
        result.stdout,
        requested_revision=requested,
        max_candidates=max_candidates,
    )
    warnings = tuple(dict.fromkeys((*decision.warnings, *parse_warnings)))
    if not candidates:
        return RepositoryVersionDiscoveryResult(
            status="unavailable",
            project_name=mapping.project_name,
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url,
            requested_revision=requested,
            commands=tuple(records),
            reasons=("远程仓库没有返回可选择的 branch/tag",),
            warnings=warnings,
        )
    return RepositoryVersionDiscoveryResult(
        status="ok",
        project_name=mapping.project_name,
        repo_url=mapping.repo_url,
        canonical_url=decision.canonical_url,
        requested_revision=requested,
        candidates=candidates,
        commands=tuple(records),
        warnings=warnings,
    )


__all__ = [
    "RepositoryVersionCandidate",
    "RepositoryVersionDiscoveryResult",
    "discover_repository_versions",
]
