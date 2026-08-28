"""SL-04A tests for confirmation-gated repository acquisition."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    CommandResult,
    ManifestResolver,
    RepositoryConfirmation,
    RepositoryManager,
    RepositoryManagerError,
    parse_manifest,
    validate_repository_mapping,
)


FIXTURE = Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml"


def _mapping(*, path: str = "base/startup/init/param_service.c", **kwargs):
    document = parse_manifest(FIXTURE.read_text(encoding="utf-8"))
    return ManifestResolver(document).resolve(path, **kwargs)


class ScriptedGit:
    """A deterministic command adapter; it never starts a real process."""

    def __init__(self, *, mode: str = "clone", create_race: Path | None = None):
        self.mode = mode
        self.calls: list[tuple[str, ...]] = []
        self.create_race = create_race

    def __call__(self, argv, *, cwd, timeout_seconds):
        command = tuple(argv)
        self.calls.append(command)
        if self.mode == "fail" and "clone" in command:
            return CommandResult(1, stderr="remote failed")
        if "clone" in command:
            staging = Path(command[-1])
            staging.mkdir(parents=True)
            (staging / "README.md").write_text("fixture", encoding="utf-8")
            (staging / ".git").mkdir()
            if self.create_race is not None:
                self.create_race.mkdir(parents=True, exist_ok=True)
            return CommandResult(0, stderr="Cloning into…")
        if "fetch" in command:
            return CommandResult(0, stderr="from gitcode")
        if "checkout" in command:
            return CommandResult(0, stderr="HEAD detached")
        if "FETCH_HEAD" in command:
            return CommandResult(0, stdout="abc123\n")
        if command[-1] == "HEAD":
            return CommandResult(0, stdout="abc123\n")
        if "--is-inside-work-tree" in command:
            if self.mode == "nongit":
                return CommandResult(128, stderr="not a git repository")
            return CommandResult(0, stdout="true\n")
        if "get-url" in command:
            if self.mode == "wrong-origin":
                return CommandResult(0, stdout="https://gitcode.com/openharmony/other\n")
            return CommandResult(0, stdout="https://gitcode.com/openharmony/startup_init.git\n")
        if "--verify" in command:
            if self.mode == "wrong-revision":
                return CommandResult(0, stdout="different\n")
            return CommandResult(0, stdout="abc123\n")
        return CommandResult(0)


def _confirmed_mapping():
    mapping = _mapping()
    decision = validate_repository_mapping(mapping)
    assert decision.allowed is True
    confirmation = RepositoryConfirmation.for_decision(
        decision,
        accepted=True,
        confirmation_id="test-confirmation-1",
    )
    return mapping, decision, confirmation


def test_no_confirmation_is_a_hard_gate_and_runs_no_git_command(tmp_path):
    mapping, _, _ = _confirmed_mapping()
    runner = ScriptedGit()
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(mapping)

    assert result.status == "rejected"
    assert result.succeeded is False
    assert any("用户确认" in reason for reason in result.reasons)
    assert runner.calls == []
    assert not (tmp_path / "source_code_base").exists()


def test_unaccepted_or_scope_mismatched_confirmation_is_rejected(tmp_path):
    mapping, decision, _ = _confirmed_mapping()
    runner = ScriptedGit()
    not_accepted = RepositoryConfirmation.for_decision(decision, accepted=False)
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=not_accepted,
    )
    assert result.status == "rejected"
    assert runner.calls == []

    mismatched = RepositoryConfirmation(
        project_name="startup_init",
        canonical_url=decision.canonical_url or "",
        revision="OpenHarmony-5.0-LTS",
        accepted=True,
    )
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=mismatched,
    )
    assert result.status == "rejected"
    assert any("revision" in reason for reason in result.reasons)
    assert runner.calls == []


def test_policy_is_rechecked_at_the_clone_boundary(tmp_path):
    mapping = _mapping(path="base/startup/appspawn/main.cpp")
    runner = ScriptedGit()
    decision = validate_repository_mapping(mapping)

    assert decision.allowed is False
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=None,
    )
    assert result.status == "rejected"
    assert runner.calls == []


def test_new_repository_is_fetched_with_fixed_git_options_and_no_shell(tmp_path):
    mapping, decision, confirmation = _confirmed_mapping()
    runner = ScriptedGit()
    logs: list[str] = []
    result = RepositoryManager(tmp_path, runner=runner, on_log=logs.append).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    destination = tmp_path / "source_code_base" / "startup_init"
    assert result.status == "cloned"
    assert result.succeeded is True
    assert result.destination == str(destination)
    assert destination.is_dir()
    assert (destination / "README.md").read_text(encoding="utf-8") == "fixture"
    assert any("[repository]" in line for line in logs)
    assert len(result.commands) == 5
    for call in runner.calls:
        assert call[0] == "git"
        assert "protocol.ext.allow=never" in call
        assert "protocol.file.allow=never" in call
        assert "http.followRedirects=false" in call
    clone_call = next(call for call in runner.calls if "clone" in call)
    assert "--" in clone_call
    assert clone_call[clone_call.index("--") + 1] == decision.canonical_url


def test_clone_failure_cleans_only_its_staging_directory(tmp_path):
    mapping, _, confirmation = _confirmed_mapping()
    runner = ScriptedGit(mode="fail")
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    assert result.status == "failed"
    assert result.succeeded is False
    assert not (tmp_path / "source_code_base" / "startup_init").exists()
    source_root = tmp_path / "source_code_base"
    assert list(source_root.glob(".startup_init.openant-*")) == []


def test_existing_matching_checkout_is_reused_without_clone(tmp_path):
    mapping, _, confirmation = _confirmed_mapping()
    destination = tmp_path / "source_code_base" / "startup_init"
    destination.mkdir(parents=True)
    runner = ScriptedGit()
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    assert result.status == "reused"
    assert result.succeeded is True
    assert not any("clone" in call for call in runner.calls)


@pytest.mark.parametrize("mode", ["nongit", "wrong-origin", "wrong-revision"])
def test_existing_conflicting_checkout_is_never_overwritten(tmp_path, mode: str):
    mapping, _, confirmation = _confirmed_mapping()
    destination = tmp_path / "source_code_base" / "startup_init"
    destination.mkdir(parents=True)
    marker = destination / "user-file.txt"
    marker.write_text("preserve", encoding="utf-8")
    runner = ScriptedGit(mode=mode)
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    assert result.status == "conflict"
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert not any("clone" in call for call in runner.calls)


def test_symlinked_destination_root_is_rejected_before_git(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "source_code_base").symlink_to(outside, target_is_directory=True)
    mapping, _, confirmation = _confirmed_mapping()
    runner = ScriptedGit()
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    assert result.status == "rejected"
    assert any("符号链接" in reason for reason in result.reasons)
    assert runner.calls == []
    assert list(outside.iterdir()) == []


def test_symlinked_repository_directory_is_rejected_without_touching_target(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    destination_root = tmp_path / "source_code_base"
    destination_root.mkdir()
    (destination_root / "startup_init").symlink_to(outside, target_is_directory=True)
    mapping, _, confirmation = _confirmed_mapping()
    runner = ScriptedGit()
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    assert result.status == "rejected"
    assert any("符号链接" in reason for reason in result.reasons)
    assert runner.calls == []
    assert list(outside.iterdir()) == []


def test_destination_race_is_reported_as_conflict_and_not_overwritten(tmp_path):
    destination = tmp_path / "source_code_base" / "startup_init"
    mapping, _, confirmation = _confirmed_mapping()
    runner = ScriptedGit(create_race=destination)
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(
        mapping,
        confirmation=confirmation,
    )

    assert result.status == "conflict"
    assert not (destination / "README.md").exists()


def test_policy_rejection_and_version_mismatch_never_run_git(tmp_path):
    mapping = _mapping(requested_revision="OpenHarmony-5.0-LTS")
    runner = ScriptedGit()
    result = RepositoryManager(tmp_path, runner=runner).ensure_repository(mapping)

    assert result.status == "rejected"
    assert runner.calls == []


def test_acquisition_result_serialization_is_bounded_and_auditable(tmp_path):
    mapping, _, confirmation = _confirmed_mapping()
    result = RepositoryManager(tmp_path, runner=ScriptedGit()).ensure_repository(
        mapping,
        confirmation=confirmation,
    )
    payload = result.to_dict()

    assert payload["schema_version"] == "openant.source-locator.repository-manager.v1"
    assert payload["succeeded"] is True
    assert payload["confirmation"]["accepted"] is True
    assert all(len(command["stderr"]) <= 4096 for command in payload["commands"])
    assert "shell" not in json.dumps(payload, ensure_ascii=False).lower()


def test_invalid_manager_configuration_raises_typed_error(tmp_path):
    with pytest.raises(RepositoryManagerError):
        RepositoryManager(tmp_path, command_timeout_seconds=0)
    with pytest.raises(RepositoryManagerError):
        RepositoryManager(tmp_path, runner="not-callable")  # type: ignore[arg-type]
