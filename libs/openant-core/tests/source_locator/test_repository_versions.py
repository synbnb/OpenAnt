"""Tests for bounded, read-only remote revision discovery."""

from __future__ import annotations

import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    CommandResult,
    RepositoryVersionCandidate,
    discover_repository_versions,
    parse_manifest,
    ManifestResolver,
)


FIXTURE = Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml"


def _mapping():
    document = parse_manifest(FIXTURE.read_text(encoding="utf-8"))
    return ManifestResolver(document).resolve("base/startup/init/param_service.c")


def test_discovery_lists_stable_refs_and_rejects_unsafe_refs():
    calls: list[tuple[str, ...]] = []

    def runner(argv, *, cwd, timeout_seconds):
        del cwd, timeout_seconds
        calls.append(tuple(argv))
        return CommandResult(
            0,
            stdout=(
                "a" * 40 + "\trefs/heads/master\n"
                + "b" * 40 + "\trefs/heads/OpenHarmony-6.1-LTS\n"
                + "c" * 40 + "\trefs/tags/OpenHarmony-6.0-Release\n"
                + "d" * 40 + "\trefs/tags/OpenHarmony-6.0-Release^{}\n"
                + "e" * 40 + "\trefs/heads/../escape\n"
                + "not-a-commit\trefs/heads/bad\n"
            ),
        )

    result = discover_repository_versions(_mapping(), runner=runner)

    assert result.status == "ok"
    assert [item.revision for item in result.candidates] == [
        "OpenHarmony-6.1-LTS",
        "OpenHarmony-6.0-Release",
        "master",
    ]
    assert result.candidates[0].recommended is True
    assert result.candidates[0].kind == "branch"
    assert result.candidates[1].kind == "tag"
    assert any("不安全" in warning for warning in result.warnings)
    assert calls and calls[0][0] == "git"
    assert "ls-remote" in calls[0]
    assert "--" in calls[0]
    assert calls[0][-1].endswith("startup_init.git")


def test_discovery_returns_unavailable_without_guessing_a_revision():
    def runner(argv, *, cwd, timeout_seconds):
        del argv, cwd, timeout_seconds
        return CommandResult(128, stderr="HTTP 301 redirect")

    result = discover_repository_versions(_mapping(), runner=runner)

    assert result.status == "unavailable"
    assert result.candidates == ()
    assert result.requested_revision == "OpenHarmony-6.1-LTS"
    assert "301" in result.reasons[0]


def test_candidate_validation_rejects_peeled_or_mismatched_refs():
    try:
        RepositoryVersionCandidate(
            revision="OpenHarmony-6.1-LTS",
            ref="refs/tags/OpenHarmony-6.1-LTS",
            kind="branch",
            commit="a" * 40,
        )
    except ValueError as exc:
        assert "ref" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("mismatched candidate ref was accepted")
