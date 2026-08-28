"""SL-04B tests for post-clone verification and scanner handoff."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    CommandRecord,
    CommandResult,
    ManifestResolver,
    PostCloneVerificationRequest,
    PostCloneVerifier,
    PostCloneVerifierError,
    RepositoryAcquisitionResult,
    RepositoryMapping,
    parse_manifest,
    validate_repository_mapping,
)


FIXTURE = Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml"


def _mapping():
    document = parse_manifest(FIXTURE.read_text(encoding="utf-8"))
    return ManifestResolver(document).resolve(
        "/openharmony/base/startup/init/param_service.c",
        evidence_ids=("E-param-file", "E-param-socket"),
    )


class VerifierGit:
    def __init__(self, *, origin: str = "https://gitcode.com/openharmony/startup_init", head: str = "abc1234"):
        self.origin = origin
        self.head = head
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, *, cwd, timeout_seconds):
        command = tuple(argv)
        self.calls.append(command)
        if "get-url" in command:
            return CommandResult(0, stdout=f"{self.origin}\n")
        if "--verify" in command:
            return CommandResult(0, stdout=f"{self.head}\n")
        if command[-1] == "HEAD":
            return CommandResult(0, stdout=f"{self.head}\n")
        return CommandResult(0)


def _acquisition(tmp_path: Path, *, status: str = "cloned", commit: str | None = "abc1234"):
    mapping = _mapping()
    decision = validate_repository_mapping(mapping)
    assert decision.allowed
    destination = tmp_path / "source_code_base" / "startup_init"
    destination.mkdir(parents=True)
    return (
        RepositoryAcquisitionResult(
            status=status,
            project_name=mapping.project_name,
            destination=str(destination),
            repo_url=mapping.repo_url,
            canonical_url=decision.canonical_url,
            revision=mapping.revision,
            resolved_commit=commit,
            mapping=mapping,
            decision=decision,
            commands=(CommandRecord(("git", "clone"), 0, "ok"),),
        ),
        mapping,
        destination,
    )


def test_matching_origin_head_and_source_symbol_produce_ready_handoff(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    source = destination / "param_service.c"
    source.write_text(
        '#define PIPE_NAME "/dev/unix/socket/paramservice"\n'
        "int param_service(void) { return PIPE_NAME[0]; }\n",
        encoding="utf-8",
    )
    runner = VerifierGit()
    request = PostCloneVerificationRequest(
        symbols=("PIPE_NAME", "param_service"),
        literals=("/dev/unix/socket/paramservice",),
    )
    result = PostCloneVerifier(tmp_path, runner=runner).verify(
        acquisition,
        mapping,
        request=request,
    )

    assert result.status == "ready_for_analysis"
    assert result.ready is True
    assert result.handoff is not None
    assert result.handoff.status == "ready_for_analysis"
    assert result.handoff.repository_path == str(destination)
    assert result.handoff.source_paths == ("param_service.c",)
    assert result.handoff.evidence_ids == ("E-param-file", "E-param-socket")
    assert {check.kind for check in result.checks} >= {
        "directory",
        "origin",
        "head",
        "source_file",
        "symbol",
        "literal",
    }
    assert len(runner.calls) == 2


def test_missing_source_file_never_produces_ready_handoff(tmp_path):
    acquisition, mapping, _ = _acquisition(tmp_path)
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(acquisition, mapping)

    assert result.status == "post_clone_verify_failed"
    assert result.ready is False
    assert result.handoff is None
    assert any(check.kind == "source_file" and check.status == "missing" for check in result.checks)
    assert any("源码文件不存在" in reason for reason in result.reasons)


def test_mapping_without_source_path_fails_closed(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    (destination / "param_service.c").write_text("int param_service(void) {}\n", encoding="utf-8")
    incomplete_mapping = replace(mapping, source_path="")
    acquisition = replace(acquisition, mapping=incomplete_mapping)

    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(
        acquisition,
        incomplete_mapping,
    )

    assert result.status == "post_clone_verify_failed"
    assert result.handoff is None
    assert any("没有可验证的 Manifest 源码文件路径" in reason for reason in result.reasons)


def test_missing_symbol_or_literal_is_a_hard_failure(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    (destination / "param_service.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(
        acquisition,
        mapping,
        request=PostCloneVerificationRequest(
            symbols=("UnresolvedHandler",),
            literals=("/dev/missing",),
        ),
    )

    assert result.status == "post_clone_verify_failed"
    assert result.handoff is None
    assert sum(check.status == "missing" for check in result.checks) == 2


@pytest.mark.parametrize(
    "runner",
    [
        VerifierGit(origin="https://gitcode.com/openharmony/other"),
        VerifierGit(head="deadbeef"),
    ],
)
def test_wrong_origin_or_head_blocks_handoff(tmp_path, runner: VerifierGit):
    acquisition, mapping, destination = _acquisition(tmp_path)
    (destination / "param_service.c").write_text("int param_service(void) {}\n", encoding="utf-8")
    result = PostCloneVerifier(tmp_path, runner=runner).verify(acquisition, mapping)

    assert result.status == "post_clone_verify_failed"
    assert result.handoff is None
    assert any(check.kind in {"origin", "head"} and check.status == "error" for check in result.checks)


@pytest.mark.parametrize("status", ["rejected", "conflict", "failed", "cancelled"])
def test_unsuccessful_acquisition_is_rejected_without_git_or_file_reads(tmp_path, status: str):
    acquisition, mapping, destination = _acquisition(tmp_path, status=status)
    runner = VerifierGit()
    (destination / "param_service.c").write_text("should not be read", encoding="utf-8")
    result = PostCloneVerifier(tmp_path, runner=runner).verify(acquisition, mapping)

    assert result.status == "rejected"
    assert result.handoff is None
    assert runner.calls == []


def test_destination_outside_project_root_is_rejected(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    tampered = RepositoryAcquisitionResult(
        status="cloned",
        project_name=acquisition.project_name,
        destination=str(outside),
        repo_url=acquisition.repo_url,
        canonical_url=acquisition.canonical_url,
        revision=acquisition.revision,
        resolved_commit=acquisition.resolved_commit,
        mapping=mapping,
        decision=acquisition.decision,
    )
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(tampered, mapping)

    assert result.status == "rejected"
    assert result.handoff is None
    assert destination.is_dir()


def test_symlinked_source_file_is_not_followed(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    outside = tmp_path / "outside.c"
    outside.write_text("int secret(void) {}", encoding="utf-8")
    (destination / "param_service.c").symlink_to(outside)
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(acquisition, mapping)

    assert result.status == "post_clone_verify_failed"
    assert result.handoff is None
    assert any("符号链接" in reason for reason in result.reasons)


def test_internal_symlinked_source_file_is_not_followed(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    real_source = destination / "real_param_service.c"
    real_source.write_text("int param_service(void) {}", encoding="utf-8")
    (destination / "param_service.c").symlink_to(real_source)

    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(acquisition, mapping)

    assert result.status == "post_clone_verify_failed"
    assert result.handoff is None
    assert any("符号链接" in reason for reason in result.reasons)


def test_opengrok_prefixed_extra_search_path_is_normalized_and_searched(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    source = destination / "param_service.c"
    header = destination / "include" / "param_utils.h"
    source.write_text("int param_service(void) {}\n", encoding="utf-8")
    header.parent.mkdir()
    header.write_text("#define PIPE_NAME \"param\"\n", encoding="utf-8")
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(
        acquisition,
        mapping,
        request=PostCloneVerificationRequest(
            search_paths=("/openharmony/base/startup/init/include/param_utils.h",),
            symbols=("PIPE_NAME",),
        ),
    )

    assert result.status == "ready_for_analysis"
    assert result.handoff is not None
    assert "include/param_utils.h" not in result.handoff.source_paths
    assert any(check.target == "include/param_utils.h" and check.status == "verified" for check in result.checks)


def test_large_source_file_is_not_read_without_a_proof(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    source = destination / "param_service.c"
    source.write_bytes(b"x" * 32)
    result = PostCloneVerifier(
        tmp_path,
        runner=VerifierGit(),
        max_source_bytes=16,
    ).verify(acquisition, mapping)

    assert result.status == "post_clone_verify_failed"
    assert result.handoff is None
    assert any("读取上限" in reason for reason in result.reasons)


def test_acquisition_mapping_mismatch_is_rejected(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    (destination / "param_service.c").write_text("int param_service(void) {}", encoding="utf-8")
    other = RepositoryMapping(
        project_name="other",
        source_root="base/other",
        remote_name="gitcode",
        remote_fetch="https://gitcode.com/openharmony",
        repo_url="https://gitcode.com/openharmony/other",
        revision="OpenHarmony-6.1-LTS",
        source_path="base/other/a.c",
        manifest_path="ohos.xml",
        status="resolved",
    )
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(acquisition, other)

    assert result.status == "rejected"
    assert result.handoff is None


def test_missing_commit_uses_read_only_revision_ref_check(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path, commit=None)
    (destination / "param_service.c").write_text("int param_service(void) {}", encoding="utf-8")
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(acquisition, mapping)

    assert result.status == "ready_for_analysis"
    assert any(check.kind == "revision_ref" and check.status == "verified" for check in result.checks)


def test_request_rejects_unsafe_paths_and_unbounded_values():
    with pytest.raises(PostCloneVerifierError):
        PostCloneVerificationRequest(source_paths=("../outside.c",))
    with pytest.raises(PostCloneVerifierError):
        PostCloneVerificationRequest(symbols=("x" * 257,))


def test_result_serialization_keeps_checks_and_handoff_without_source_dump(tmp_path):
    acquisition, mapping, destination = _acquisition(tmp_path)
    (destination / "param_service.c").write_text("int param_service(void) {}", encoding="utf-8")
    result = PostCloneVerifier(tmp_path, runner=VerifierGit()).verify(acquisition, mapping)
    payload = result.to_dict()

    assert payload["schema_version"] == "openant.source-locator.post-clone-verification.v1"
    assert payload["handoff"]["status"] == "ready_for_analysis"
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "int param_service" not in encoded


def test_invalid_verifier_configuration_and_typed_inputs_raise():
    with pytest.raises(PostCloneVerifierError):
        PostCloneVerifier("/does/not/exist", max_source_bytes=0)
    with pytest.raises(PostCloneVerifierError):
        PostCloneVerifier("/does/not/exist", runner="not-callable")  # type: ignore[arg-type]
    with pytest.raises(PostCloneVerifierError):
        PostCloneVerifier("/does/not/exist").verify("not-an-acquisition", _mapping())  # type: ignore[arg-type]
