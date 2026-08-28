"""SL-03A tests for deterministic OpenHarmony Manifest mapping."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    ManifestAmbiguityError,
    ManifestParseError,
    ManifestProject,
    ManifestResolver,
    ManifestResolverError,
    RepositoryMapping,
    build_repository_url,
    load_manifest,
    manifest_cache_key,
    parse_manifest,
    resolve_project,
)


FIXTURE = Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml"


def test_fixture_manifest_is_parsed_with_defaults_and_cache_provenance():
    document = load_manifest(FIXTURE)

    assert document.default_remote == "gitcode"
    assert document.default_revision == "OpenHarmony-6.1-LTS"
    assert len(document.projects) == 4
    assert document.remote_by_name("gitcode") is not None
    assert document.cache_key == f"OpenHarmony-6.1-LTS:{document.content_sha256}"
    assert document.content_sha256 == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()


def test_longest_prefix_selects_specific_project():
    projects = [
        ManifestProject(
            name="broad",
            path="foundation/communication",
            remote="gitcode",
            revision="R",
        ),
        ManifestProject(
            name="communication_netmanager_base",
            path="foundation/communication/netmanager_base",
            remote="gitcode",
            revision="R",
        ),
    ]
    result = resolve_project(
        "foundation/communication/netmanager_base/services/a.cpp",
        projects,
    )
    assert result is not None
    assert result.name == "communication_netmanager_base"


def test_open_grok_project_prefix_is_supported_without_changing_mapping_root():
    document = load_manifest(FIXTURE)
    result = ManifestResolver(document).resolve(
        "/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=["E-param-path"],
    )

    assert result.status == "resolved"
    assert result.project_name == "startup_init"
    assert result.source_root == "base/startup/init"
    assert result.matched_prefix == "base/startup/init"
    assert result.repo_url == "https://gitcode.com/openharmony/startup_init"
    assert result.revision == "OpenHarmony-6.1-LTS"
    assert result.evidence_ids == ("E-param-path",)


def test_remote_url_construction_is_deterministic_and_does_not_add_a_revision():
    assert (
        build_repository_url("https://gitcode.com/openharmony/", "startup_init")
        == "https://gitcode.com/openharmony/startup_init"
    )
    assert build_repository_url("https://gitcode.com/openharmony", "repo.git").endswith("/repo.git")


def test_project_specific_remote_and_revision_override_manifest_defaults():
    document = load_manifest(FIXTURE)
    result = ManifestResolver(document).resolve("base/startup/appspawn/main.cpp")

    assert result.project_name == "startup_appspawn"
    assert result.remote_name == "mirror"
    assert result.remote_fetch == "https://mirror.example.invalid/openharmony"
    assert result.repo_url == "https://mirror.example.invalid/openharmony/startup_appspawn"
    assert result.revision == "OpenHarmony-6.1-LTS"
    assert result.status == "resolved"


def test_requested_revision_mismatch_is_explicit_and_never_silently_rewritten():
    document = load_manifest(FIXTURE)
    result = ManifestResolver(document).resolve(
        "base/startup/init/param_service.c",
        requested_revision="OpenHarmony-5.0-LTS",
    )

    assert result.status == "version_mismatch"
    assert result.revision == "OpenHarmony-6.1-LTS"
    assert result.requested_revision == "OpenHarmony-5.0-LTS"
    assert any("不一致" in warning for warning in result.warnings)


def test_unmatched_path_is_needs_review_and_has_no_guessed_repository():
    result = ManifestResolver(load_manifest(FIXTURE)).resolve("base/unknown/service/a.cpp")

    assert result.status == "unresolved"
    assert result.project_name is None
    assert result.repo_url is None
    assert result.revision is None
    assert any("没有匹配路径" in warning for warning in result.warnings)


def test_unrelated_top_level_prefix_is_not_stripped_as_if_it_were_opengrok_project_name():
    projects = [ManifestProject(name="startup_init", path="base/startup/init", remote="r", revision="R")]

    assert resolve_project("vendor/base/startup/init/a.c", projects) is None


def test_same_length_prefix_conflict_fails_closed():
    projects = [
        ManifestProject(name="one", path="base/conflict", remote="r", revision="R"),
        ManifestProject(name="two", path="base/conflict", remote="r", revision="R"),
    ]
    with pytest.raises(ManifestAmbiguityError, match="同长度冲突"):
        resolve_project("base/conflict/file.c", projects)

    document = parse_manifest(
        """
        <manifest>
          <remote name="r" fetch="https://gitcode.com/openharmony" />
          <project name="one" path="base/conflict" remote="r" revision="R" />
          <project name="two" path="base/conflict" remote="r" revision="R" />
        </manifest>
        """,
        manifest_path="conflict.xml",
    )
    result = ManifestResolver(document).resolve("base/conflict/file.c")
    assert result.status == "ambiguous"
    assert result.repo_url is None


def test_missing_remote_or_revision_is_not_treated_as_a_complete_mapping():
    document = parse_manifest(
        """
        <manifest>
          <project name="missing_metadata" path="base/missing" />
        </manifest>
        """
    )
    result = ManifestResolver(document).resolve("base/missing/a.c")

    assert result.status == "needs_review"
    assert result.repo_url is None
    assert result.revision is None
    assert len(result.warnings) == 2


@pytest.mark.parametrize(
    "content",
    [
        "<!DOCTYPE manifest [<!ENTITY x 'x'>]><manifest />",
        "<not-manifest />",
        "<manifest><project name='x' /></manifest>",
        "<manifest><remote name='r' fetch='https://user:pass@example.invalid/x' /></manifest>",
    ],
)
def test_malformed_or_unsafe_manifest_input_fails_closed(content: str):
    with pytest.raises(ManifestResolverError):
        parse_manifest(content)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@gitcode.com/openharmony",
        "https://gitcode.com/openharmony?x=1",
        "https://gitcode.com/../openharmony",
        "file:///tmp/openharmony",
    ],
)
def test_repository_url_builder_rejects_unsafe_remote(url: str):
    with pytest.raises(ManifestResolverError):
        build_repository_url(url, "startup_init")


def test_revision_and_path_validation_reject_traversal():
    with pytest.raises(ManifestResolverError):
        ManifestProject(name="x", path="base/../x", remote="r", revision="main..bad")
    with pytest.raises(ManifestResolverError):
        manifest_cache_key("<manifest />", "main..bad")


def test_manifest_cache_key_changes_when_revision_or_content_changes():
    content = "<manifest />"
    first = manifest_cache_key(content, "R1")
    second = manifest_cache_key(content, "R2")
    third = manifest_cache_key(content + "\n", "R1")

    assert first != second
    assert first != third


def test_repository_mapping_serialization_keeps_unresolved_fields_explicit():
    mapping = RepositoryMapping(
        source_path="base/a.c",
        manifest_path="ohos.xml",
        status="unresolved",
        warnings=("没有匹配",),
        content_sha256="a" * 64,
    )
    payload = mapping.to_dict()

    assert payload["schema_version"] == "openant.source-locator.repository-mapping.v1"
    assert payload["source_path"] == "/base/a.c"
    assert payload["project_name"] is None
    assert payload["repo_url"] is None
    assert payload["warnings"] == ["没有匹配"]
