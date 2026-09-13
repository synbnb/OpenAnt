"""SL-03B tests for GitCode URL and revision policy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    GitCodeConfig,
    ManifestResolver,
    RepositoryMapping,
    RepositoryPolicy,
    RepositoryPolicyError,
    parse_manifest,
    validate_gitcode_remote,
    validate_gitcode_url,
    validate_repository_mapping,
    validate_revision,
)


FIXTURE = Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml"


def _mapping(*, path: str = "base/startup/init/param_service.c", **kwargs) -> RepositoryMapping:
    document = parse_manifest(FIXTURE.read_text(encoding="utf-8"))
    return ManifestResolver(document).resolve(path, **kwargs)


def test_manifest_mapping_from_allowlisted_gitcode_is_allowed_but_not_post_clone_verified():
    decision = validate_repository_mapping(_mapping())

    assert decision.allowed is True
    assert decision.can_clone is True
    assert decision.status == "allowed"
    assert decision.canonical_url == "https://gitcode.com/openharmony/startup_init"
    assert decision.organization == "openharmony"
    assert decision.repository == "startup_init"
    assert decision.revision == "OpenHarmony-6.1-LTS"
    assert decision.url_validation is not None and decision.url_validation.allowed is True
    assert decision.remote_validation is not None and decision.remote_validation.allowed is True
    assert decision.revision_validation is not None and decision.revision_validation.allowed is True
    assert any("拉取后验证" in warning for warning in decision.warnings)


@pytest.mark.parametrize(
    "url",
    [
        "http://gitcode.com/openharmony/repo",
        "https://evil.example/openharmony/repo",
        "https://gitcode.com/other-org/repo",
        "https://user:pass@gitcode.com/openharmony/repo",
        "https://gitcode.com/openharmony/repo?download=1",
        "https://gitcode.com/openharmony/repo#readme",
        "https://gitcode.com:443/openharmony/repo",
        "https://gitcode.com/openharmony/repo/extra",
        "https://gitcode.com//openharmony/repo",
        "https://gitcode.com/openharmony/../repo",
        "https://gitcode.com/openharmony/%2e%2e",
        "https://gitcode.com/openharmony/repo with-space",
        "https://gitcode.com/openharmony/repo/",
    ],
)
def test_untrusted_or_noncanonical_repository_urls_are_rejected(url: str):
    result = validate_gitcode_url(url)

    if url.endswith("/repo/"):
        assert result.allowed is True
    else:
        assert result.allowed is False
        assert result.status == "rejected"
        assert result.reasons


def test_expected_repository_name_prevents_same_host_same_org_confusion():
    result = validate_gitcode_url(
        "https://gitcode.com/openharmony/another_repo",
        expected_repository="startup_init",
    )

    assert result.allowed is False
    assert any("不一致" in reason for reason in result.reasons)


def test_gitcode_remote_requires_exactly_one_allowlisted_organization_segment():
    valid = validate_gitcode_remote("https://gitcode.com/openharmony/")
    invalid = validate_gitcode_remote("https://gitcode.com/openharmony/repo")

    assert valid.allowed is True
    assert valid.repository is None
    assert invalid.allowed is False


def test_custom_host_and_org_allowlists_are_applied_without_widening_defaults():
    config = GitCodeConfig(
        allowed_hosts=("git.example.invalid",),
        allowed_orgs=("ohos",),
    )

    accepted = validate_gitcode_url(
        "https://git.example.invalid/ohos/service",
        config,
    )
    default_rejected = validate_gitcode_url(
        "https://gitcode.com/openharmony/service",
        config,
    )

    assert accepted.allowed is True
    assert default_rejected.allowed is False


def test_redirect_must_resolve_to_the_same_canonical_repository():
    same = validate_gitcode_url(
        "https://gitcode.com/openharmony/service",
        observed_url="https://gitcode.com/openharmony/service/",
    )
    changed_repo = validate_gitcode_url(
        "https://gitcode.com/openharmony/service",
        observed_url="https://gitcode.com/openharmony/other",
    )

    assert same.allowed is True
    assert changed_repo.allowed is False
    assert any("重定向" in reason for reason in changed_repo.reasons)


@pytest.mark.parametrize(
    ("revision", "requested", "source", "status"),
    [
        ("OpenHarmony-6.1-LTS", None, "manifest", "allowed"),
        ("OpenHarmony-6.1-LTS", "OpenHarmony-6.1-LTS", "config", "allowed"),
        ("OpenHarmony-6.1-LTS", "OpenHarmony-5.0-LTS", "manifest", "version_mismatch"),
        (None, None, "manifest", "missing"),
        ("main..bad", None, "manifest", "rejected"),
        ("main", None, "llm", "rejected"),
        ("main", None, "bundle_fallback", "rejected"),
    ],
)
def test_revision_validation_distinguishes_missing_mismatch_and_untrusted_values(
    revision: str | None,
    requested: str | None,
    source: str,
    status: str,
):
    result = validate_revision(revision, requested, source=source)

    assert result.status == status
    assert result.allowed is (status == "allowed")


def test_invalid_requested_revision_is_rejected_instead_of_reported_as_alignment_only():
    result = validate_revision("main", "../../main", source="manifest")

    assert result.status == "rejected"
    assert result.allowed is False
    assert any("目标 revision 无效" in reason for reason in result.reasons)


def test_mapping_revision_mismatch_is_a_hard_non_clone_decision():
    mapping = _mapping(requested_revision="OpenHarmony-5.0-LTS")
    decision = validate_repository_mapping(mapping)

    assert decision.status == "version_mismatch"
    assert decision.allowed is False
    assert decision.revision_validation is not None
    assert decision.revision_validation.status == "version_mismatch"


@pytest.mark.parametrize("mapping_status", ["unresolved", "ambiguous", "needs_review"])
def test_non_resolved_manifest_states_never_enter_clone(mapping_status: str):
    mapping = RepositoryMapping(
        project_name="service",
        source_root="base/service",
        remote_name="gitcode",
        remote_fetch="https://gitcode.com/openharmony",
        repo_url="https://gitcode.com/openharmony/service",
        revision="OpenHarmony-6.1-LTS",
        source_path="base/service/a.cpp",
        manifest_path="ohos.xml",
        status=mapping_status,
    )
    decision = validate_repository_mapping(mapping)

    assert decision.allowed is False
    assert decision.status == "rejected"
    assert any("不能进入 clone" in reason for reason in decision.reasons)


def test_bundle_fallback_or_llm_mapping_source_is_rejected_even_with_safe_text():
    mapping = RepositoryMapping(
        project_name="service",
        source_root="base/service",
        remote_name="gitcode",
        remote_fetch="https://gitcode.com/openharmony",
        repo_url="https://gitcode.com/openharmony/service",
        revision="OpenHarmony-6.1-LTS",
        resolution_method="bundle_fallback",
        source_path="base/service/a.cpp",
        manifest_path="ohos.xml",
        status="resolved",
    )
    decision = validate_repository_mapping(mapping)

    assert decision.allowed is False
    assert decision.status == "rejected"
    assert any("可信" in reason for reason in decision.reasons)


def test_remote_host_or_organization_mismatch_is_rejected():
    mapping = RepositoryMapping(
        project_name="service",
        source_root="base/service",
        remote_name="mirror",
        remote_fetch="https://gitcode.com/not-openharmony",
        repo_url="https://gitcode.com/openharmony/service",
        revision="OpenHarmony-6.1-LTS",
        source_path="base/service/a.cpp",
        manifest_path="ohos.xml",
        status="resolved",
    )
    decision = validate_repository_mapping(mapping)

    assert decision.allowed is False
    assert any("组织" in reason for reason in decision.reasons)


def test_policy_serialization_is_safe_and_contains_nested_audit_results():
    decision = validate_repository_mapping(_mapping())
    payload = decision.to_dict()

    assert payload["schema_version"] == "openant.source-locator.repository-policy.v1"
    assert payload["can_clone"] is True
    assert payload["url_validation"]["canonical_url"] == decision.canonical_url
    assert payload["revision_validation"]["revision"] == "OpenHarmony-6.1-LTS"
    assert "token" not in json.dumps(payload, ensure_ascii=False).lower()


def test_policy_object_reuses_one_config_for_all_checks():
    policy = RepositoryPolicy()

    assert policy.validate_url("https://gitcode.com/openharmony/service").allowed is True
    assert policy.validate_remote("https://gitcode.com/openharmony").allowed is True
    assert policy.validate_revision("main", source="user_confirmed").allowed is True
    assert policy.validate_mapping(_mapping()).can_clone is True


def test_invalid_policy_api_types_raise_typed_error():
    with pytest.raises(RepositoryPolicyError):
        RepositoryPolicy(config="not-a-config")  # type: ignore[arg-type]
    with pytest.raises(RepositoryPolicyError):
        validate_repository_mapping("not-a-mapping")  # type: ignore[arg-type]
