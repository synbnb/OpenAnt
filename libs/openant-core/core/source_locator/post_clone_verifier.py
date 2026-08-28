"""Read-only verification and analysis handoff for acquired repositories.

``RepositoryManager`` proves that a confirmed Git operation completed.  It does
not prove that the checkout contains the source file and symbols that led to a
locator decision.  This module performs that second proof without modifying
the checkout.  A failed check is explicit and no ``ready_for_analysis`` handoff
is produced.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Iterable, Sequence

from .config import GitCodeConfig
from .manifest_resolver import RepositoryMapping
from .repository_manager import (
    CommandRecord,
    CommandResult,
    RepositoryAcquisitionResult,
)
from .repository_policy import RepositoryPolicy, validate_gitcode_url


_SCHEMA_VERSION = "openant.source-locator.post-clone-verification.v1"
_MAX_PATH_LENGTH = 2048
_MAX_QUERY_LENGTH = 256
_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_LINES_PER_CHECK = 64
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,128}$")
_CHECK_KINDS = frozenset(
    {"directory", "origin", "head", "source_file", "symbol", "literal", "revision_ref"}
)
_CHECK_STATUSES = frozenset({"verified", "missing", "error"})
_RESULT_STATUSES = frozenset({"ready_for_analysis", "post_clone_verify_failed", "rejected"})


class PostCloneVerifierError(ValueError):
    """Raised when verifier configuration or typed input is invalid."""


def _clean(value: Any, *, limit: int = 512) -> str:
    return " ".join(str(value).split())[:limit]


def _bounded_text(value: Any, *, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise PostCloneVerifierError(f"{name} 必须是字符串")
    value = value.strip()
    if not value or len(value) > limit:
        raise PostCloneVerifierError(f"{name} 为空或超过长度上限")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PostCloneVerifierError(f"{name} 包含控制字符")
    return value


def _normalise_path(value: Any, *, name: str) -> str:
    raw = _bounded_text(value, name=name, limit=_MAX_PATH_LENGTH)
    if "\\" in raw or "?" in raw or "#" in raw or "\x00" in raw or "://" in raw:
        raise PostCloneVerifierError(f"{name} 不是安全源码相对路径")
    parts = [part for part in raw.lstrip("/").split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        raise PostCloneVerifierError(f"{name} 包含路径穿越片段")
    return "/".join(parts)


def _strip_opengrok_prefix(path: str) -> str:
    parts = path.split("/")
    if parts and parts[0].lower() in {"openharmony", "ohos"}:
        return "/".join(parts[1:])
    return path


def _relative_from_mapping(value: Any, mapping: RepositoryMapping, *, name: str) -> str:
    candidate = _strip_opengrok_prefix(_normalise_path(value, name=name))
    if not mapping.source_root:
        raise PostCloneVerifierError("Manifest source_root 缺失，不能计算仓库内路径")
    source_root = mapping.source_root.strip("/")
    if candidate == source_root:
        raise PostCloneVerifierError(f"{name} 指向目录而不是源码文件")
    prefix = source_root + "/"
    if not candidate.startswith(prefix):
        raise PostCloneVerifierError(f"{name} 不属于 Manifest project source_root")
    relative = candidate[len(prefix) :]
    return _normalise_path(relative, name=f"{name}.relative")


def _relative_search_path(
    value: Any,
    mapping: RepositoryMapping,
    *,
    name: str,
) -> str:
    """Normalize an auxiliary OpenGrok path to a repository-relative path.

    Search evidence may be emitted either as a repository path (for example
    ``include/foo.h``) or as the complete OpenGrok/manifest path (for example
    ``/openharmony/base/startup/init/include/foo.h``).  Treating the latter as
    repository-relative would silently look below a duplicated ``base``
    directory, so strip the resolved manifest ``source_root`` when present.
    """

    candidate = _strip_opengrok_prefix(_normalise_path(value, name=name))
    source_root = mapping.source_root.strip("/")
    if not source_root:
        raise PostCloneVerifierError("Manifest source_root 缺失，不能计算搜索路径")
    prefix = source_root + "/"
    if candidate == source_root:
        raise PostCloneVerifierError(f"{name} 指向目录而不是源码文件")
    if candidate.startswith(prefix):
        candidate = candidate[len(prefix) :]
    return _normalise_path(candidate, name=name)


def _has_symlink_component(path: Path, *, stop: Path) -> bool:
    try:
        relative = path.relative_to(stop)
    except ValueError:
        return True
    current = stop
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _within(child: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((str(child), str(parent))) == str(parent)
    except ValueError:
        return False


def _safe_commit(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not _COMMIT_RE.fullmatch(value):
        return None
    return value.lower()


@dataclass(frozen=True)
class PostCloneVerificationRequest:
    """Expected files and literal text that must survive the acquisition."""

    source_paths: tuple[str, ...] = ()
    search_paths: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    literals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("source_paths", "search_paths", "symbols", "literals"):
            value = getattr(self, field_name)
            if isinstance(value, (str, bytes)):
                raise PostCloneVerifierError(f"{field_name} 必须是序列")
            try:
                items = tuple(value)
            except TypeError as exc:
                raise PostCloneVerifierError(f"{field_name} 必须是可迭代序列") from exc
            if len(items) > 128:
                raise PostCloneVerifierError(f"{field_name} 数量超过 128")
            normalized: list[str] = []
            for index, item in enumerate(items):
                if field_name in {"source_paths", "search_paths"}:
                    normalized.append(
                        _normalise_path(item, name=f"{field_name}[{index}]")
                    )
                else:
                    normalized.append(
                        _bounded_text(
                            item,
                            name=f"{field_name}[{index}]",
                            limit=_MAX_QUERY_LENGTH,
                        )
                    )
            object.__setattr__(self, field_name, tuple(dict.fromkeys(normalized)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_paths": list(self.source_paths),
            "search_paths": list(self.search_paths),
            "symbols": list(self.symbols),
            "literals": list(self.literals),
        }


@dataclass(frozen=True)
class VerificationCheck:
    """One bounded, user-visible post-clone check."""

    kind: str
    target: str
    status: str
    detail: str
    lines: tuple[int, ...] = ()
    sha256: str | None = None
    bytes_read: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in _CHECK_KINDS:
            raise PostCloneVerifierError("验证项 kind 无效")
        if self.status not in _CHECK_STATUSES:
            raise PostCloneVerifierError("验证项 status 无效")
        object.__setattr__(self, "target", _clean(self.target, limit=_MAX_PATH_LENGTH))
        object.__setattr__(self, "detail", _clean(self.detail))
        object.__setattr__(self, "lines", tuple(self.lines[:_MAX_LINES_PER_CHECK]))
        if self.sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", self.sha256.lower()):
            raise PostCloneVerifierError("验证项 sha256 无效")
        if self.bytes_read is not None and (
            isinstance(self.bytes_read, bool) or not isinstance(self.bytes_read, int) or self.bytes_read < 0
        ):
            raise PostCloneVerifierError("验证项 bytes_read 无效")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "status": self.status,
            "detail": self.detail,
            "lines": list(self.lines),
            "sha256": self.sha256,
            "bytes_read": self.bytes_read,
        }


@dataclass(frozen=True)
class SourceHandoff:
    """The only repository object that is eligible for scanner handoff."""

    project_name: str
    repository_path: str
    repo_url: str
    revision: str
    resolved_commit: str
    source_paths: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()
    status: str = "ready_for_analysis"
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status != "ready_for_analysis":
            raise PostCloneVerifierError("SourceHandoff 只能是 ready_for_analysis")
        for value, name in (
            (self.project_name, "project_name"),
            (self.repo_url, "repo_url"),
            (self.revision, "revision"),
        ):
            _bounded_text(value, name=name, limit=_MAX_PATH_LENGTH)
        if _safe_commit(self.resolved_commit) is None:
            raise PostCloneVerifierError("SourceHandoff resolved_commit 无效")
        if not self.source_paths:
            raise PostCloneVerifierError("SourceHandoff 必须包含已验证源码文件")
        object.__setattr__(self, "resolved_commit", self.resolved_commit.strip().lower())
        object.__setattr__(self, "source_paths", tuple(self.source_paths))
        object.__setattr__(self, "evidence_ids", tuple(dict.fromkeys(self.evidence_ids)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "project_name": self.project_name,
            "repository_path": self.repository_path,
            "repo_url": self.repo_url,
            "revision": self.revision,
            "resolved_commit": self.resolved_commit,
            "source_paths": list(self.source_paths),
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class PostCloneVerificationResult:
    """Complete verification result; ``handoff`` is null unless ready."""

    status: str
    project_name: str | None = None
    repository_path: str | None = None
    repo_url: str | None = None
    revision: str | None = None
    resolved_commit: str | None = None
    request: PostCloneVerificationRequest | None = None
    checks: tuple[VerificationCheck, ...] = ()
    commands: tuple[CommandRecord, ...] = ()
    handoff: SourceHandoff | None = None
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in _RESULT_STATUSES:
            raise PostCloneVerifierError("拉取后验证结果状态无效")
        if self.handoff is not None:
            if self.status != "ready_for_analysis" or self.handoff.status != "ready_for_analysis":
                raise PostCloneVerifierError("非 ready 状态不能包含 SourceHandoff")
        if self.status == "ready_for_analysis" and self.handoff is None:
            raise PostCloneVerifierError("ready 状态必须包含 SourceHandoff")
        if self.status != "ready_for_analysis" and self.handoff is not None:
            raise PostCloneVerifierError("失败状态不得生成 SourceHandoff")
        object.__setattr__(self, "checks", tuple(self.checks))
        object.__setattr__(self, "commands", tuple(self.commands))
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_clean(item) for item in self.warnings))

    @property
    def ready(self) -> bool:
        return self.status == "ready_for_analysis"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "ready": self.ready,
            "project_name": self.project_name,
            "repository_path": self.repository_path,
            "repo_url": self.repo_url,
            "revision": self.revision,
            "resolved_commit": self.resolved_commit,
            "request": self.request.to_dict() if self.request else None,
            "checks": [check.to_dict() for check in self.checks],
            "commands": [command.to_dict() for command in self.commands],
            "handoff": self.handoff.to_dict() if self.handoff else None,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


Runner = Callable[..., CommandResult]
LogCallback = Callable[[str], None]


def _default_runner(argv: Sequence[str], *, cwd: Path | None, timeout_seconds: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            shell=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandResult(124, stdout=stdout, stderr=stderr or "命令超时")
    except OSError as exc:
        raise PostCloneVerifierError(f"无法执行只读 Git 命令：{exc}") from exc
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class PostCloneVerifier:
    """Verify one acquisition and build a scanner handoff only on success."""

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        *,
        config: GitCodeConfig | None = None,
        runner: Runner | None = None,
        command_timeout_seconds: float = 60.0,
        max_source_bytes: int = _MAX_SOURCE_BYTES,
        on_log: LogCallback | None = None,
    ) -> None:
        if config is None:
            config = GitCodeConfig()
        if not isinstance(config, GitCodeConfig):
            raise PostCloneVerifierError("config 必须是 GitCodeConfig")
        if isinstance(command_timeout_seconds, bool) or not isinstance(
            command_timeout_seconds, (int, float)
        ) or not 1 <= float(command_timeout_seconds) <= 3600:
            raise PostCloneVerifierError("command_timeout_seconds 必须在 1 到 3600 秒之间")
        if isinstance(max_source_bytes, bool) or not isinstance(max_source_bytes, int) or not 1 <= max_source_bytes <= _MAX_SOURCE_BYTES:
            raise PostCloneVerifierError(f"max_source_bytes 必须在 1 到 {_MAX_SOURCE_BYTES} 之间")
        if runner is not None and not callable(runner):
            raise PostCloneVerifierError("runner 必须是可调用对象")
        if on_log is not None and not callable(on_log):
            raise PostCloneVerifierError("on_log 必须是可调用对象")
        self.project_root = Path(project_root)
        self.config = config
        self.policy = RepositoryPolicy(config)
        self.runner = runner or _default_runner
        self.command_timeout_seconds = float(command_timeout_seconds)
        self.max_source_bytes = max_source_bytes
        self.on_log = on_log

    def _record_command(
        self,
        argv: Sequence[str],
        *,
        records: list[CommandRecord],
    ) -> CommandResult | None:
        command = tuple(str(item) for item in argv)
        try:
            result = self.runner(command, cwd=None, timeout_seconds=self.command_timeout_seconds)
            if not isinstance(result, CommandResult):
                raise PostCloneVerifierError("runner 必须返回 CommandResult")
        except PostCloneVerifierError:
            raise
        except Exception as exc:  # pragma: no cover - defensive adapter boundary
            records.append(CommandRecord(command, None, "exception", stderr=_clean(exc)))
            raise PostCloneVerifierError(f"只读 Git 命令执行异常：{_clean(exc)}") from exc
        status = "ok" if result.returncode == 0 else "error"
        if result.returncode == 124:
            status = "timeout"
        records.append(CommandRecord(command, result.returncode, status, result.stdout, result.stderr))
        if self.on_log is not None:
            for line in (result.stdout + "\n" + result.stderr).splitlines():
                line = _clean(line)
                if line:
                    self.on_log(f"[post-clone] {line}")
        return result

    def _base_result(
        self,
        acquisition: RepositoryAcquisitionResult,
        *,
        status: str,
        request: PostCloneVerificationRequest | None,
        checks: Iterable[VerificationCheck] = (),
        commands: Iterable[CommandRecord] = (),
        reasons: Iterable[str] = (),
        warnings: Iterable[str] = (),
        handoff: SourceHandoff | None = None,
        mapping: RepositoryMapping | None = None,
        destination: str | None = None,
        commit: str | None = None,
    ) -> PostCloneVerificationResult:
        active_mapping = mapping or acquisition.mapping
        return PostCloneVerificationResult(
            status=status,
            project_name=active_mapping.project_name if active_mapping else acquisition.project_name,
            repository_path=destination or acquisition.destination,
            repo_url=active_mapping.repo_url if active_mapping else acquisition.repo_url,
            revision=active_mapping.revision if active_mapping else acquisition.revision,
            resolved_commit=commit or acquisition.resolved_commit,
            request=request,
            checks=tuple(checks),
            commands=tuple(commands),
            handoff=handoff,
            reasons=tuple(dict.fromkeys(_clean(item) for item in reasons)),
            warnings=tuple(dict.fromkeys(_clean(item) for item in warnings)),
        )

    def _resolve_repository_path(
        self,
        acquisition: RepositoryAcquisitionResult,
        mapping: RepositoryMapping,
    ) -> tuple[Path | None, tuple[str, ...]]:
        reasons: list[str] = []
        try:
            raw_project_root = self.project_root.expanduser().absolute()
            project_root = raw_project_root.resolve(strict=True)
            raw_root = project_root / self.config.destination_root
            if _has_symlink_component(raw_root, stop=project_root):
                reasons.append("source_code_base 路径包含符号链接")
            destination_root = raw_root.resolve(strict=False)
            if not destination_root.is_dir():
                reasons.append("source_code_base 不存在或不是目录")
            project_name = mapping.project_name
            if not project_name:
                reasons.append("Manifest project_name 缺失")
                return None, tuple(reasons)
            expected = (destination_root / project_name).resolve(strict=False)
            actual_raw = Path(acquisition.destination or "")
            if not actual_raw.is_absolute():
                reasons.append("拉取结果 destination 必须是绝对路径")
                return None, tuple(reasons)
            actual = actual_raw.resolve(strict=False)
            if actual != expected:
                reasons.append("拉取结果 destination 与项目级目标目录不一致")
            if not _within(actual, destination_root) or not _within(actual, project_root):
                reasons.append("仓库真实路径超出 source_code_base 或项目根目录")
            # Compare the un-resolved acquisition path with the un-resolved
            # project root so a harmless macOS alias such as /var -> /private/var
            # is not mistaken for a symlink in the repository itself.  The
            # resolved path is still checked independently for containment.
            if _has_symlink_component(actual_raw, stop=raw_project_root):
                reasons.append("仓库真实路径包含符号链接")
            if not actual.is_dir():
                reasons.append("仓库目标不存在或不是目录")
            return (None if reasons else actual), tuple(reasons)
        except OSError as exc:
            return None, (f"无法确认仓库目录边界：{_clean(exc)}",)

    def _read_file(
        self,
        repository: Path,
        relative: str,
    ) -> tuple[VerificationCheck, str | None]:
        raw_path = repository / relative
        # Inspect the lexical path before resolving it.  Otherwise a symlink
        # which points *inside* the checkout would disappear during resolve()
        # and be treated as an ordinary source file.
        if not _within(raw_path, repository) or _has_symlink_component(raw_path, stop=repository):
            return (
                VerificationCheck("source_file", relative, "error", "文件路径越出仓库或包含符号链接"),
                None,
            )
        path = raw_path.resolve(strict=False)
        if not _within(path, repository):
            return (
                VerificationCheck("source_file", relative, "error", "文件路径越出仓库或包含符号链接"),
                None,
            )
        try:
            if not path.exists():
                return VerificationCheck("source_file", relative, "missing", "源码文件不存在"), None
            if path.is_symlink() or not path.is_file():
                return VerificationCheck("source_file", relative, "error", "目标不是普通源码文件"), None
            size = path.stat().st_size
            if size > self.max_source_bytes:
                return (
                    VerificationCheck(
                        "source_file",
                        relative,
                        "error",
                        f"源码文件超过 {self.max_source_bytes} 字节读取上限",
                        bytes_read=size,
                    ),
                    None,
                )
            raw = path.read_bytes()
        except OSError as exc:
            return VerificationCheck("source_file", relative, "error", f"读取源码失败：{_clean(exc)}"), None
        digest = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8", errors="replace")
        return (
            VerificationCheck(
                "source_file",
                relative,
                "verified",
                "源码文件存在且为普通文件",
                sha256=digest,
                bytes_read=len(raw),
            ),
            text,
        )

    @staticmethod
    def _text_lines(texts: dict[str, str], needle: str) -> tuple[int, ...]:
        lines: list[int] = []
        for text in texts.values():
            for index, line in enumerate(text.splitlines(), 1):
                if needle in line:
                    lines.append(index)
                    if len(lines) >= _MAX_LINES_PER_CHECK:
                        return tuple(lines)
        return tuple(lines)

    def verify(
        self,
        acquisition: RepositoryAcquisitionResult,
        mapping: RepositoryMapping | None = None,
        *,
        request: PostCloneVerificationRequest | None = None,
    ) -> PostCloneVerificationResult:
        """Verify an acquisition; never mutate the checkout."""

        if not isinstance(acquisition, RepositoryAcquisitionResult):
            raise PostCloneVerifierError("acquisition 必须是 RepositoryAcquisitionResult")
        active_mapping = mapping or acquisition.mapping
        if active_mapping is None or not isinstance(active_mapping, RepositoryMapping):
            raise PostCloneVerifierError("必须提供 RepositoryMapping")
        if acquisition.mapping is not None and acquisition.mapping != active_mapping:
            return self._base_result(
                acquisition,
                status="rejected",
                request=request,
                mapping=active_mapping,
                reasons=("拉取结果内置 mapping 与验证 mapping 不一致",),
                warnings=acquisition.warnings,
            )
        if request is None:
            request = PostCloneVerificationRequest()
        if not isinstance(request, PostCloneVerificationRequest):
            raise PostCloneVerifierError("request 必须是 PostCloneVerificationRequest")

        if not acquisition.succeeded:
            return self._base_result(
                acquisition,
                status="rejected",
                request=request,
                mapping=active_mapping,
                reasons=(f"拉取结果状态为 {acquisition.status}，不能验证",),
                warnings=acquisition.warnings,
            )
        decision = self.policy.validate_mapping(active_mapping)
        if not decision.allowed:
            return self._base_result(
                acquisition,
                status="rejected",
                request=request,
                mapping=active_mapping,
                reasons=decision.reasons or ("仓库策略在验证阶段未通过",),
                warnings=tuple(acquisition.warnings) + tuple(decision.warnings),
            )
        if (
            acquisition.project_name != decision.project_name
            or acquisition.revision != decision.revision
            or acquisition.canonical_url != decision.canonical_url
        ):
            return self._base_result(
                acquisition,
                status="rejected",
                request=request,
                mapping=active_mapping,
                reasons=("拉取结果与 Manifest 策略结果不一致",),
                warnings=acquisition.warnings,
            )

        repository, boundary_reasons = self._resolve_repository_path(acquisition, active_mapping)
        if repository is None:
            return self._base_result(
                acquisition,
                status="rejected",
                request=request,
                mapping=active_mapping,
                reasons=boundary_reasons,
                warnings=acquisition.warnings,
            )

        records: list[CommandRecord] = []
        checks: list[VerificationCheck] = [
            VerificationCheck("directory", str(repository), "verified", "仓库路径位于项目级 source_code_base 内")
        ]
        origin_result = self._record_command(
            ("git", "-C", str(repository), "remote", "get-url", "origin"),
            records=records,
        )
        if origin_result is None or origin_result.returncode != 0:
            checks.append(VerificationCheck("origin", "origin", "error", "无法读取 origin"))
        else:
            origin = origin_result.stdout.strip()
            origin_check = validate_gitcode_url(
                origin,
                self.config,
                expected_repository=decision.project_name,
            )
            if (
                origin_check.allowed
                and origin_check.host == decision.host
                and origin_check.organization == decision.organization
                and origin_check.repository == decision.repository
            ):
                checks.append(VerificationCheck("origin", origin, "verified", "origin 与策略仓库一致"))
            else:
                checks.append(VerificationCheck("origin", origin, "error", "origin 与策略仓库不一致"))

        head_result = self._record_command(
            ("git", "-C", str(repository), "rev-parse", "HEAD"),
            records=records,
        )
        head = _safe_commit(head_result.stdout if head_result and head_result.returncode == 0 else None)
        expected_commit = _safe_commit(acquisition.resolved_commit)
        if expected_commit is None:
            revision_result = self._record_command(
                (
                    "git",
                    "-C",
                    str(repository),
                    "rev-parse",
                    "--verify",
                    f"{active_mapping.revision}^{{commit}}",
                ),
                records=records,
            )
            expected_commit = _safe_commit(
                revision_result.stdout if revision_result and revision_result.returncode == 0 else None
            )
            checks.append(
                VerificationCheck(
                    "revision_ref",
                    active_mapping.revision or "<missing>",
                    "verified" if expected_commit else "error",
                    "revision ref 可解析" if expected_commit else "revision ref 无法解析",
                )
            )
        if head is None:
            checks.append(VerificationCheck("head", "HEAD", "error", "无法读取或解析 HEAD"))
        elif expected_commit is None or head != expected_commit:
            checks.append(VerificationCheck("head", "HEAD", "error", "HEAD 与目标 commit 不一致"))
        else:
            checks.append(VerificationCheck("head", head, "verified", "HEAD 与拉取时确认的 commit 一致"))

        source_inputs = request.source_paths or ((active_mapping.source_path,) if active_mapping.source_path else ())
        if not source_inputs:
            checks.append(
                VerificationCheck(
                    "source_file",
                    "<mapping.source_path>",
                    "error",
                    "没有可验证的 Manifest 源码文件路径",
                )
            )
        source_relatives: list[str] = []
        for index, source_path in enumerate(source_inputs):
            try:
                relative = _relative_from_mapping(source_path, active_mapping, name=f"source_paths[{index}]")
            except PostCloneVerifierError as exc:
                checks.append(
                    VerificationCheck("source_file", str(source_path), "error", str(exc))
                )
                continue
            if relative not in source_relatives:
                source_relatives.append(relative)

        search_relatives = list(source_relatives)
        for index, search_path in enumerate(request.search_paths):
            try:
                relative = _relative_search_path(
                    search_path,
                    active_mapping,
                    name=f"search_paths[{index}]",
                )
            except PostCloneVerifierError as exc:
                checks.append(VerificationCheck("source_file", str(search_path), "error", str(exc)))
                continue
            if relative not in search_relatives:
                search_relatives.append(relative)

        texts: dict[str, str] = {}
        verified_sources: list[str] = []
        for relative in search_relatives:
            check, text = self._read_file(repository, relative)
            checks.append(check)
            if check.status == "verified" and text is not None:
                texts[relative] = text
                if relative in source_relatives:
                    verified_sources.append(relative)

        for symbol in request.symbols:
            lines = self._text_lines(texts, symbol)
            checks.append(
                VerificationCheck(
                    "symbol",
                    symbol,
                    "verified" if lines else "missing",
                    "在已验证源码中找到符号" if lines else "在已验证源码中未找到符号",
                    lines=lines,
                )
            )
        for literal in request.literals:
            lines = self._text_lines(texts, literal)
            checks.append(
                VerificationCheck(
                    "literal",
                    literal,
                    "verified" if lines else "missing",
                    "在已验证源码中找到字面量" if lines else "在已验证源码中未找到字面量",
                    lines=lines,
                )
            )

        failures = tuple(check for check in checks if check.status != "verified")
        warnings = tuple(acquisition.warnings)
        if failures:
            reasons = tuple(
                f"{check.kind}:{check.target}：{check.detail}" for check in failures
            )
            return self._base_result(
                acquisition,
                status="post_clone_verify_failed",
                request=request,
                checks=checks,
                commands=records,
                reasons=reasons,
                warnings=warnings,
                mapping=active_mapping,
                destination=str(repository),
                commit=head or expected_commit,
            )

        handoff = SourceHandoff(
            project_name=active_mapping.project_name or decision.project_name or "",
            repository_path=str(repository),
            repo_url=decision.canonical_url or active_mapping.repo_url or "",
            revision=active_mapping.revision or decision.revision or "",
            resolved_commit=head or expected_commit or "",
            source_paths=tuple(verified_sources),
            evidence_ids=active_mapping.evidence_ids,
        )
        return self._base_result(
            acquisition,
            status="ready_for_analysis",
            request=request,
            checks=checks,
            commands=records,
            warnings=warnings,
            handoff=handoff,
            mapping=active_mapping,
            destination=str(repository),
            commit=head or expected_commit,
        )


__all__ = [
    "PostCloneVerificationRequest",
    "PostCloneVerifier",
    "PostCloneVerifierError",
    "PostCloneVerificationResult",
    "SourceHandoff",
    "VerificationCheck",
]
