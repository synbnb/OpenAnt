"""Safe, confirmation-gated repository acquisition for the source locator.

The source locator must never turn a model-proposed URL into an implicit
``git clone``.  ``RepositoryManager`` therefore accepts a
``RepositoryMapping`` only after:

* ``RepositoryPolicy`` has accepted the Manifest mapping;
* a caller has supplied an explicit, scope-bound ``RepositoryConfirmation``;
* the destination has been proven to remain below the project-local
  ``source_code_base`` directory.

``RepositoryManager`` itself performs only the acquisition step: it performs a
shallow, non-recursive fetch into a new directory, safely reuses an identical
existing checkout, records the resolved commit and returns the validated
Manifest mapping.  ``PostCloneVerifier`` consumes that result for the
read-only source/evidence checks and produces the ``SourceHandoff`` used by a
scanner.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Sequence

from .config import GitCodeConfig
from .manifest_resolver import RepositoryMapping
from .repository_policy import (
    RepositoryPolicy,
    RepositoryPolicyDecision,
    validate_gitcode_url,
)


_SCHEMA_VERSION = "openant.source-locator.repository-manager.v1"
_MAX_OUTPUT = 4096
_PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@+~-]{0,127}$")
_RESULT_STATUSES = frozenset(
    {"cloned", "reused", "conflict", "rejected", "failed", "cancelled"}
)


class RepositoryManagerError(ValueError):
    """Raised when the manager receives invalid typed configuration."""


def _clean(value: Any, *, limit: int = _MAX_OUTPUT) -> str:
    return " ".join(str(value).split())[:limit]


def _safe_project_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _PROJECT_NAME_RE.fullmatch(value) else None


def _safe_revision(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if (
        not _REVISION_RE.fullmatch(value)
        or value == "unknown"
        or ".." in value
        or "//" in value
        or value.endswith(".")
        or value.endswith(".lock")
    ):
        return None
    return value


def _git_transport_url(decision: "RepositoryPolicyDecision") -> str:
    """Return the Git transport endpoint without weakening redirect policy.

    GitCode's web URL without a suffix redirects its smart-HTTP endpoint to a
    trailing-slash form.  The repository manager deliberately disables Git's
    automatic redirect following, so use GitCode's native ``.git`` endpoint
    directly.  The policy/confirmation URL remains the suffix-free canonical
    repository identity; this helper only changes the wire endpoint.
    """

    url = decision.canonical_url or ""
    if decision.host == "gitcode.com" and not url.endswith(".git"):
        return f"{url}.git"
    return url


def _within(child: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath((str(child), str(parent))) == str(parent)
    except ValueError:
        return False


def _has_symlink_component(path: Path, *, stop: Path) -> bool:
    """Return whether an existing component between ``stop`` and ``path`` is a symlink."""

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


def _safe_relative_destination(project_root: Path, config: GitCodeConfig) -> tuple[Path, Path]:
    """Resolve and validate the project root and configured destination."""

    try:
        root = project_root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise RepositoryManagerError(f"项目根目录不可用：{exc}") from exc
    if not root.is_dir():
        raise RepositoryManagerError("项目根目录必须是目录")
    # GitCodeConfig already validates this as a relative path.  Rechecking the
    # resolved path protects callers that construct objects directly and also
    # catches a pre-existing symlink such as source_code_base -> /tmp.
    raw_destination = root / config.destination_root
    if _has_symlink_component(raw_destination, stop=root):
        raise RepositoryManagerError("仓库目标目录路径不得包含符号链接")
    destination = raw_destination.resolve(strict=False)
    if not _within(destination, root) or destination == root:
        raise RepositoryManagerError("仓库目标目录必须位于项目根目录内")
    return root, destination


def _safe_destination(root: Path, destination_root: Path, project_name: str) -> Path:
    raw_destination = destination_root / project_name
    if _has_symlink_component(raw_destination, stop=root):
        raise RepositoryManagerError("仓库目录路径不得包含符号链接")
    destination = raw_destination.resolve(strict=False)
    if not _within(destination, destination_root) or destination == destination_root:
        raise RepositoryManagerError("仓库目录必须位于 source_code_base 内")
    # The parent is re-resolved after creation by the caller; this check is
    # deliberately before any mkdir so a malicious project name cannot escape.
    if not _within(destination_root, root):
        raise RepositoryManagerError("source_code_base 不在项目根目录内")
    return destination


@dataclass(frozen=True)
class RepositoryConfirmation:
    """Explicit user approval scoped to one exact project, URL and revision."""

    project_name: str
    canonical_url: str
    revision: str
    accepted: bool = False
    confirmation_id: str | None = None

    def __post_init__(self) -> None:
        if _safe_project_name(self.project_name) is None:
            raise RepositoryManagerError("确认中的项目名不是安全名称")
        if not isinstance(self.canonical_url, str) or not self.canonical_url.strip():
            raise RepositoryManagerError("确认中的仓库 URL 不能为空")
        if _safe_revision(self.revision) is None:
            raise RepositoryManagerError("确认中的 revision 不是安全版本")
        if not isinstance(self.accepted, bool):
            raise RepositoryManagerError("confirmation.accepted 必须是布尔值")
        if self.confirmation_id is not None:
            if not isinstance(self.confirmation_id, str) or not self.confirmation_id.strip():
                raise RepositoryManagerError("confirmation_id 必须是非空字符串或 null")
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in self.confirmation_id):
                raise RepositoryManagerError("confirmation_id 包含控制字符")

    @classmethod
    def for_decision(
        cls,
        decision: RepositoryPolicyDecision,
        *,
        accepted: bool = False,
        confirmation_id: str | None = None,
    ) -> "RepositoryConfirmation":
        if not isinstance(decision, RepositoryPolicyDecision) or not decision.allowed:
            raise RepositoryManagerError("只有允许的策略结果才能生成确认对象")
        if decision.project_name is None or decision.canonical_url is None or decision.revision is None:
            raise RepositoryManagerError("策略结果缺少确认所需字段")
        return cls(
            project_name=decision.project_name,
            canonical_url=decision.canonical_url,
            revision=decision.revision,
            accepted=accepted,
            confirmation_id=confirmation_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "project_name": self.project_name,
            "canonical_url": self.canonical_url,
            "revision": self.revision,
            "accepted": self.accepted,
            "confirmation_id": self.confirmation_id,
        }


@dataclass(frozen=True)
class CommandResult:
    """Small adapter contract used by the default and test command runners."""

    returncode: int
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.returncode, bool) or not isinstance(self.returncode, int):
            raise RepositoryManagerError("命令返回码必须是整数")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise RepositoryManagerError("命令 stdout/stderr 必须是字符串")


@dataclass(frozen=True)
class CommandRecord:
    """Auditable command summary; output is bounded before persistence."""

    argv: tuple[str, ...]
    returncode: int | None
    status: str
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self) -> None:
        if self.status not in {"ok", "error", "timeout", "exception"}:
            raise RepositoryManagerError("命令记录状态无效")
        object.__setattr__(self, "argv", tuple(str(item) for item in self.argv))
        object.__setattr__(self, "stdout", _clean(self.stdout))
        object.__setattr__(self, "stderr", _clean(self.stderr))

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "status": self.status,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


@dataclass(frozen=True)
class RepositoryAcquisitionResult:
    """Result of one confirmation-gated repository acquisition attempt."""

    status: str
    project_name: str | None = None
    destination: str | None = None
    repo_url: str | None = None
    canonical_url: str | None = None
    revision: str | None = None
    decision: RepositoryPolicyDecision | None = None
    confirmation: RepositoryConfirmation | None = None
    commands: tuple[CommandRecord, ...] = ()
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION
    # Appended after the original fields to keep positional construction of
    # the public result object backward compatible.
    resolved_commit: str | None = None
    mapping: RepositoryMapping | None = None

    def __post_init__(self) -> None:
        if self.status not in _RESULT_STATUSES:
            raise RepositoryManagerError("仓库拉取结果状态无效")
        if self.resolved_commit is not None:
            if not isinstance(self.resolved_commit, str) or not re.fullmatch(
                r"[0-9a-fA-F]{7,128}", self.resolved_commit.strip()
            ):
                raise RepositoryManagerError("resolved_commit 不是安全的 Git commit")
            object.__setattr__(self, "resolved_commit", self.resolved_commit.strip().lower())
        if self.mapping is not None and not isinstance(self.mapping, RepositoryMapping):
            raise RepositoryManagerError("mapping 必须是 RepositoryMapping 或 null")
        object.__setattr__(self, "commands", tuple(self.commands))
        object.__setattr__(self, "reasons", tuple(_clean(item) for item in self.reasons))
        object.__setattr__(self, "warnings", tuple(_clean(item) for item in self.warnings))

    @property
    def succeeded(self) -> bool:
        return self.status in {"cloned", "reused"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "succeeded": self.succeeded,
            "project_name": self.project_name,
            "destination": self.destination,
            "repo_url": self.repo_url,
            "canonical_url": self.canonical_url,
            "revision": self.revision,
            "resolved_commit": self.resolved_commit,
            "mapping": self.mapping.to_dict() if self.mapping else None,
            "decision": self.decision.to_dict() if self.decision else None,
            "confirmation": self.confirmation.to_dict() if self.confirmation else None,
            "commands": [command.to_dict() for command in self.commands],
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
        }


Runner = Callable[..., CommandResult]
LogCallback = Callable[[str], None]


def _default_runner(argv: Sequence[str], *, cwd: Path | None, timeout_seconds: float) -> CommandResult:
    """Run one fixed executable command without shell interpolation."""

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
        raise RepositoryManagerError(f"无法执行 Git 命令：{exc}") from exc
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class RepositoryManager:
    """Acquire one allowlisted repository below a project-local root."""

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        *,
        config: GitCodeConfig | None = None,
        runner: Runner | None = None,
        command_timeout_seconds: float = 900.0,
        on_log: LogCallback | None = None,
    ) -> None:
        if config is None:
            config = GitCodeConfig()
        if not isinstance(config, GitCodeConfig):
            raise RepositoryManagerError("config 必须是 GitCodeConfig")
        if isinstance(command_timeout_seconds, bool) or not isinstance(
            command_timeout_seconds, (int, float)
        ):
            raise RepositoryManagerError("command_timeout_seconds 必须是数字")
        if not 1 <= float(command_timeout_seconds) <= 3600:
            raise RepositoryManagerError("command_timeout_seconds 必须在 1 到 3600 秒之间")
        if runner is not None and not callable(runner):
            raise RepositoryManagerError("runner 必须是可调用对象")
        if on_log is not None and not callable(on_log):
            raise RepositoryManagerError("on_log 必须是可调用对象")
        self.config = config
        self.project_root = Path(project_root)
        self.policy = RepositoryPolicy(config)
        self.runner = runner or _default_runner
        self.command_timeout_seconds = float(command_timeout_seconds)
        self.on_log = on_log

    def _record_command(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None,
        records: list[CommandRecord],
    ) -> CommandResult | None:
        command = tuple(str(item) for item in argv)
        try:
            result = self.runner(command, cwd=cwd, timeout_seconds=self.command_timeout_seconds)
            if not isinstance(result, CommandResult):
                raise RepositoryManagerError("runner 必须返回 CommandResult")
        except RepositoryManagerError:
            raise
        except Exception as exc:  # pragma: no cover - defensive adapter boundary
            records.append(CommandRecord(command, None, "exception", stderr=_clean(exc)))
            raise RepositoryManagerError(f"Git 命令执行异常：{_clean(exc)}") from exc
        status = "ok" if result.returncode == 0 else "error"
        if result.returncode == 124:
            status = "timeout"
        records.append(
            CommandRecord(
                command,
                result.returncode,
                status,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        )
        if self.on_log is not None:
            for line in (result.stdout + "\n" + result.stderr).splitlines():
                line = _clean(line)
                if line:
                    self.on_log(f"[repository] {line}")
        return result

    def _reject(
        self,
        *,
        status: str,
        mapping: RepositoryMapping,
        decision: RepositoryPolicyDecision | None,
        confirmation: RepositoryConfirmation | None,
        reasons: Sequence[str],
        warnings: Sequence[str] = (),
    ) -> RepositoryAcquisitionResult:
        return RepositoryAcquisitionResult(
            status=status,
            project_name=mapping.project_name,
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url if decision else None,
            revision=mapping.revision,
            mapping=mapping,
            decision=decision,
            confirmation=confirmation,
            reasons=tuple(dict.fromkeys(_clean(item) for item in reasons)),
            warnings=tuple(dict.fromkeys(_clean(item) for item in warnings)),
        )

    def _confirmation_matches(
        self,
        confirmation: RepositoryConfirmation | None,
        decision: RepositoryPolicyDecision,
    ) -> tuple[bool, tuple[str, ...]]:
        if confirmation is None:
            return False, ("缺少明确的用户确认，禁止执行 Git 拉取",)
        if not confirmation.accepted:
            return False, ("用户确认未接受，禁止执行 Git 拉取",)
        reasons: list[str] = []
        if confirmation.project_name != decision.project_name:
            reasons.append("用户确认的项目名与策略结果不一致")
        if confirmation.canonical_url != decision.canonical_url:
            reasons.append("用户确认的仓库 URL 与策略结果不一致")
        if confirmation.revision != decision.revision:
            reasons.append("用户确认的 revision 与策略结果不一致")
        return not reasons, tuple(reasons)

    def _inspect_existing(
        self,
        destination: Path,
        *,
        decision: RepositoryPolicyDecision,
        records: list[CommandRecord],
    ) -> tuple[str, tuple[str, ...], str | None]:
        """Classify an existing directory without modifying it."""

        inside = self._record_command(
            ("git", "-C", str(destination), "rev-parse", "--is-inside-work-tree"),
            cwd=None,
            records=records,
        )
        if inside is None or inside.returncode != 0 or inside.stdout.strip().lower() != "true":
            return "conflict", ("目标目录已存在但不是 Git 工作树，不覆盖",), None
        remote = self._record_command(
            ("git", "-C", str(destination), "remote", "get-url", "origin"),
            cwd=None,
            records=records,
        )
        if remote is None or remote.returncode != 0:
            return "conflict", ("已有 Git 目录缺少 origin，不能确认来源，不覆盖",), None
        origin = remote.stdout.strip()
        origin_check = validate_gitcode_url(
            origin,
            self.config,
            expected_repository=decision.project_name,
        )
        if (
            not origin_check.allowed
            or origin_check.host != decision.host
            or origin_check.organization != decision.organization
            or origin_check.repository != decision.repository
        ):
            return "conflict", ("已有仓库 origin 与确认的 GitCode 地址不一致，不覆盖",), None
        target = _safe_revision(decision.revision)
        if target is None:
            return "conflict", ("目标 revision 不安全，不能复用已有目录",), None
        expected = self._record_command(
            (
                "git",
                "-C",
                str(destination),
                "rev-parse",
                "--verify",
                f"{target}^{{commit}}",
            ),
            cwd=None,
            records=records,
        )
        head = self._record_command(
            ("git", "-C", str(destination), "rev-parse", "HEAD"),
            cwd=None,
            records=records,
        )
        if (
            expected is None
            or expected.returncode != 0
            or head is None
            or head.returncode != 0
            or expected.stdout.strip() != head.stdout.strip()
        ):
            return "conflict", ("已有仓库 HEAD 与确认的 revision 不一致，不覆盖",), None
        return "reused", (), head.stdout.strip().lower()

    def _clone_new(
        self,
        destination: Path,
        *,
        decision: RepositoryPolicyDecision,
        records: list[CommandRecord],
    ) -> tuple[str, tuple[str, ...], str | None]:
        destination_root = destination.parent
        project_root = self.project_root.expanduser().resolve(strict=True)
        raw_destination_root = project_root / self.config.destination_root
        if _has_symlink_component(raw_destination_root, stop=project_root):
            return "rejected", ("source_code_base 不能是符号链接",), None
        try:
            raw_destination_root.mkdir(parents=True, exist_ok=True)
            resolved_root = destination_root.resolve(strict=True)
        except OSError as exc:
            return "failed", (f"无法创建或确认 source_code_base：{_clean(exc)}",), None
        if (
            not _within(resolved_root, project_root)
            or _has_symlink_component(raw_destination_root, stop=project_root)
        ):
            return "rejected", ("source_code_base 解析后超出项目根目录",), None
        if destination.exists():
            return "conflict", ("目标目录在拉取前已出现，不覆盖",), None

        staging: Path | None = None
        try:
            staging = Path(
                tempfile.mkdtemp(prefix=f".{decision.project_name}.openant-", dir=str(resolved_root))
            )
            # git clone accepts an empty destination, but removing our
            # reservation makes the contract explicit and lets git create the
            # worktree itself.
            staging.rmdir()
        except OSError as exc:
            if staging is not None and (staging.exists() or staging.is_symlink()):
                try:
                    if staging.is_symlink() or not staging.is_dir():
                        staging.unlink()
                    else:
                        shutil.rmtree(staging)
                except OSError:
                    pass
            return "failed", (f"无法创建 Git staging 目录：{_clean(exc)}",), None
        try:
            transport_url = _git_transport_url(decision)
            base = (
                self.runner_git_prefix
                + ("clone", "--depth", "1", "--no-tags", "--no-checkout", "--", transport_url, str(staging))
            )
            clone = self._record_command(base, cwd=None, records=records)
            if clone is None or clone.returncode != 0:
                return "failed", ("git clone 初始化失败",), None
            fetch = self._record_command(
                self.runner_git_prefix
                + ("-C", str(staging), "fetch", "--depth", "1", "origin", decision.revision or ""),
                cwd=None,
                records=records,
            )
            if fetch is None or fetch.returncode != 0:
                return "failed", ("目标 revision 拉取失败",), None
            fetched = self._record_command(
                self.runner_git_prefix + ("-C", str(staging), "rev-parse", "FETCH_HEAD"),
                cwd=None,
                records=records,
            )
            checkout = self._record_command(
                self.runner_git_prefix + ("-C", str(staging), "checkout", "--detach", "FETCH_HEAD"),
                cwd=None,
                records=records,
            )
            head = self._record_command(
                self.runner_git_prefix + ("-C", str(staging), "rev-parse", "HEAD"),
                cwd=None,
                records=records,
            )
            if (
                fetched is None
                or fetched.returncode != 0
                or checkout is None
                or checkout.returncode != 0
                or head is None
                or head.returncode != 0
                or fetched.stdout.strip() != head.stdout.strip()
            ):
                return "failed", ("拉取后无法确认目标 revision",), None
            if destination.exists():
                return "conflict", ("拉取完成后目标目录出现，不覆盖",), None
            try:
                os.rename(staging, destination)
            except FileExistsError:
                return "conflict", ("目标目录发生并发冲突，不覆盖",), None
            except OSError as exc:
                return "failed", (f"无法提交仓库目录：{_clean(exc)}",), None
            return "cloned", (), head.stdout.strip().lower()
        finally:
            if staging.exists() or staging.is_symlink():
                try:
                    if staging.is_symlink() or not staging.is_dir():
                        staging.unlink()
                    else:
                        shutil.rmtree(staging)
                except OSError:
                    # Cleanup failure is included in logs by the caller only
                    # when the command itself failed; never broaden deletion.
                    pass

    @property
    def runner_git_prefix(self) -> tuple[str, ...]:
        """Fixed Git hardening options shared by every command."""

        return (
            "git",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "http.followRedirects=false",
        )

    def ensure_repository(
        self,
        mapping: RepositoryMapping,
        *,
        confirmation: RepositoryConfirmation | None = None,
        observed_url: str | None = None,
    ) -> RepositoryAcquisitionResult:
        """Clone or safely reuse one mapping after explicit user confirmation."""

        if not isinstance(mapping, RepositoryMapping):
            raise RepositoryManagerError("mapping 必须是 RepositoryMapping")
        decision = self.policy.validate_mapping(mapping, observed_url=observed_url)
        if not decision.allowed:
            return self._reject(
                status="rejected",
                mapping=mapping,
                decision=decision,
                confirmation=confirmation,
                reasons=decision.reasons or ("仓库策略拒绝该映射",),
                warnings=decision.warnings,
            )
        matched, confirmation_reasons = self._confirmation_matches(confirmation, decision)
        if not matched:
            return self._reject(
                status="rejected",
                mapping=mapping,
                decision=decision,
                confirmation=confirmation,
                reasons=confirmation_reasons,
                warnings=decision.warnings,
            )
        project_name = _safe_project_name(decision.project_name)
        if project_name is None or decision.canonical_url is None or _safe_revision(decision.revision) is None:
            return self._reject(
                status="rejected",
                mapping=mapping,
                decision=decision,
                confirmation=confirmation,
                reasons=("策略结果包含不安全的项目名、URL 或 revision",),
                warnings=decision.warnings,
            )
        try:
            root, destination_root = _safe_relative_destination(self.project_root, self.config)
            destination = _safe_destination(root, destination_root, project_name)
        except RepositoryManagerError as exc:
            return self._reject(
                status="rejected",
                mapping=mapping,
                decision=decision,
                confirmation=confirmation,
                reasons=(str(exc),),
                warnings=decision.warnings,
            )

        records: list[CommandRecord] = []
        if destination.exists():
            if destination.is_symlink():
                return self._reject(
                    status="conflict",
                    mapping=mapping,
                    decision=decision,
                    confirmation=confirmation,
                    reasons=("目标仓库目录是符号链接，不覆盖",),
                    warnings=decision.warnings,
                )
            try:
                existing_status, existing_reasons, existing_commit = self._inspect_existing(
                    destination,
                    decision=decision,
                    records=records,
                )
            except RepositoryManagerError as exc:
                return RepositoryAcquisitionResult(
                    status="failed",
                    project_name=project_name,
                    destination=str(destination),
                    repo_url=mapping.repo_url,
                    canonical_url=decision.canonical_url,
                    revision=decision.revision,
                    mapping=mapping,
                    decision=decision,
                    confirmation=confirmation,
                    commands=tuple(records),
                    reasons=(str(exc),),
                    warnings=decision.warnings,
                )
            if existing_status == "reused":
                return RepositoryAcquisitionResult(
                    status="reused",
                    project_name=project_name,
                    destination=str(destination),
                    repo_url=mapping.repo_url,
                    canonical_url=decision.canonical_url,
                    revision=decision.revision,
                    resolved_commit=existing_commit,
                    mapping=mapping,
                    decision=decision,
                    confirmation=confirmation,
                    commands=tuple(records),
                    warnings=decision.warnings,
                )
            return RepositoryAcquisitionResult(
                status="conflict",
                project_name=project_name,
                destination=str(destination),
                repo_url=mapping.repo_url,
                canonical_url=decision.canonical_url,
                revision=decision.revision,
                resolved_commit=existing_commit,
                mapping=mapping,
                decision=decision,
                confirmation=confirmation,
                commands=tuple(records),
                reasons=existing_reasons,
                warnings=decision.warnings,
            )

        resolved_commit: str | None = None
        try:
            status, reasons, resolved_commit = self._clone_new(
                destination,
                decision=decision,
                records=records,
            )
        except RepositoryManagerError as exc:
            status, reasons = "failed", (str(exc),)
        return RepositoryAcquisitionResult(
            status=status,
            project_name=project_name,
            destination=str(destination),
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url,
            revision=decision.revision,
            resolved_commit=resolved_commit,
            mapping=mapping,
            decision=decision,
            confirmation=confirmation,
            commands=tuple(records),
            reasons=reasons,
            warnings=decision.warnings,
        )


__all__ = [
    "CommandRecord",
    "CommandResult",
    "RepositoryAcquisitionResult",
    "RepositoryConfirmation",
    "RepositoryManager",
    "RepositoryManagerError",
]
