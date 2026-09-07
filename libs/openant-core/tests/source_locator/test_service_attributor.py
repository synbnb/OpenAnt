"""SL-05 tests for deterministic server attribution."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    AttributionCandidate,
    EvidenceStore,
    RepositoryMapping,
    ServerAttributionResult,
    SourceLocation,
    ServiceAttributionError,
    ServiceAttributor,
)


def _mapping(*, status: str = "resolved") -> RepositoryMapping:
    return RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        remote_name="gitcode",
        remote_fetch="https://gitcode.com/openharmony",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/param_service.c",
        manifest_path="ohos.xml",
        status=status,
    )


def _add(
    store: EvidenceStore,
    kind: str,
    line: int,
    *,
    symbol: str | None = None,
    relation_from: str | None = "/dev/unix/socket/paramservice",
    relation_to: str | None = "ParamService::HandleRequest",
    path: str = "/openharmony/base/startup/init/param_service.c",
) -> str:
    evidence = store.add_evidence(
        kind=kind,
        source_path=path,
        line_start=line,
        symbol=symbol,
        excerpt=f"{kind} evidence at {line}",
        tool_name="test.fixture",
        source_mode="fixture",
        relation_from=relation_from,
        relation_to=relation_to,
    )
    return evidence.evidence_id


def test_creator_only_is_partial_and_never_confirmed_server():
    store = EvidenceStore()
    _add(store, "literal_match", 10, symbol="PIPE_NAME")
    _add(store, "service_config", 20, relation_to="init.paramservice")
    _add(store, "socket_acquire", 30, relation_to="InitParamService")

    result = ServiceAttributor().attribute(store, mapping=_mapping())

    assert result.status == "PARTIAL"
    assert result.confirmed is False
    assert result.predicates["creator_only"] is True
    assert result.predicates["server_consumer"] is False
    assert result.server_repo == "startup_init"
    assert any("creator" in reason for reason in result.reasons)
    assert [candidate.role for candidate in result.candidates].count("socket_creator") == 2
    assert [candidate.role for candidate in result.candidates].count("service_owner") == 1


def test_cfg_socket_name_selects_repository_before_consumer_is_recovered():
    """init ``socket.name`` is enough to rank an ownership candidate.

    The complete receive chain remains PARTIAL, but a resolved Manifest path
    plus the configuration identity must still produce a usable repository
    answer instead of an empty/unknown result.
    """

    store = EvidenceStore()
    _add(
        store,
        "service_config",
        7,
        relation_to="init socket.name=paramservice",
        path="/openharmony/base/startup/init/services/param/paramservice.cfg",
    )

    result = ServiceAttributor(mapping=_mapping()).attribute(store)

    assert result.status == "PARTIAL"
    assert result.confirmed is False
    assert result.server_repo == "startup_init"
    assert result.best_candidate is not None
    assert result.repository_confidence == "HIGH"
    assert result.selection_confidence_score >= result.score
    assert "socket.name" in " ".join(result.selection_reasons)


def test_confirmed_semantic_owner_candidate_wins_over_noisy_mapping_candidate():
    """The confirmation view must preserve the validated semantic owner."""

    store = EvidenceStore()
    owner_id = _add(
        store,
        "socket_server_registration",
        313,
        symbol="hisysevent",
        path="/openharmony/base/hiviewdfx/hiview/plugins/sysevent_source/event_server.cpp",
    )
    noisy_id = _add(
        store,
        "service_config",
        30,
        symbol="hisysevent",
        path="/openharmony/foundation/distributedhardware/distributed_audio/common/dfx_utils/src/daudio_hisysevent.cpp",
    )
    result = ServerAttributionResult(
        status="HIGH",
        confirmed=True,
        score=90,
        predicates={},
        candidates=(
            AttributionCandidate(
                role="socket_creator",
                subject="hisysevent",
                source_locations=(SourceLocation(
                    "/openharmony/foundation/distributedhardware/distributed_audio/common/dfx_utils/src/daudio_hisysevent.cpp",
                    30,
                    30,
                    "hisysevent",
                ),),
                evidence_ids=(noisy_id,),
                score=300,
            ),
            AttributionCandidate(
                role="service_owner",
                subject='SocketDevice("hisysevent")',
                source_locations=(SourceLocation(
                    "/openharmony/base/hiviewdfx/hiview/plugins/sysevent_source/event_server.cpp",
                    313,
                    313,
                    "hisysevent",
                ),),
                evidence_ids=(owner_id,),
                score=90,
            ),
        ),
        semantic_decision={"status": "confirmed", "evidence_ids": [owner_id]},
    )

    assert result.best_candidate is not None
    assert result.best_candidate.role == "service_owner"
    assert result.best_candidate.subject == 'SocketDevice("hisysevent")'


def test_overfull_candidate_group_is_bounded_instead_of_failing():
    """Noisy repeated socket identities must not abort attribution."""

    store = EvidenceStore()
    for line in range(1, 301):
        _add(
            store,
            "service_config",
            line,
            relation_to="paramservice",
            path="/openharmony/base/startup/init/services/param/paramservice.cfg",
        )
    registration_id = _add(
        store,
        "socket_server_registration",
        400,
        relation_to="paramservice",
        path="/openharmony/base/startup/init/services/param/param_service.c",
    )

    result = ServiceAttributor().attribute(store)
    creator = next(candidate for candidate in result.candidates if candidate.role == "socket_creator")

    assert len(creator.evidence_ids) <= 256
    assert registration_id in creator.evidence_ids
    assert any("证据过多" in reason for reason in creator.reasons)


def test_fd_acquire_receive_and_dispatch_confirm_server():
    store = EvidenceStore()
    _add(store, "macro_definition", 10, symbol="PIPE_NAME")
    _add(store, "service_config", 20, relation_to="init.paramservice")
    _add(store, "socket_acquire", 30, relation_to="ParamService::Start")
    _add(store, "socket_accept_read", 40, relation_to="ParamService::ReadRequest")
    _add(store, "protocol_dispatch", 50, relation_to="ParamService::HandleRequest")

    result = ServiceAttributor(mapping=_mapping()).attribute(store)

    assert result.status == "HIGH"
    assert result.confirmed is True
    assert result.score == 100
    assert result.predicates == {
        "socket_identity": True,
        "service_relation": True,
        "socket_acquire_or_bind": True,
        "server_consumer": True,
        "protocol_dispatch": True,
        "manifest_mapping": True,
        "creator_only": False,
    }
    assert {candidate.role for candidate in result.candidates} == {
        "socket_creator",
        "service_owner",
        "server_consumer",
        "server_handler",
    }
    assert result.roles["server_handler"][0].subject == "ParamService::HandleRequest"


def test_server_registration_wrapper_can_confirm_server_without_posix_bind():
    store = EvidenceStore()
    _add(store, "macro_definition", 10, symbol="PIPE_NAME")
    _add(store, "socket_server_registration", 20, relation_to="ParamService::Start")
    _add(store, "socket_accept_read", 30, relation_to="ParamService::ReadRequest")
    _add(store, "protocol_dispatch", 40, relation_to="ParamService::HandleRequest")

    result = ServiceAttributor(mapping=_mapping()).attribute(store)

    assert result.status == "HIGH"
    assert result.confirmed is True
    assert result.predicates["socket_acquire_or_bind"] is True


def test_bind_and_dispatch_are_equivalent_consumer_path():
    store = EvidenceStore()
    _add(store, "literal_match", 10, symbol="PIPE_NAME")
    _add(store, "socket_bind_listen", 20, relation_to="ParamService::Listen")
    _add(store, "protocol_dispatch", 30, relation_to="ParamService::Dispatch")

    result = ServiceAttributor().attribute(store, mapping=_mapping())

    assert result.status == "HIGH"
    assert result.confirmed is True
    assert result.predicates["server_consumer"] is True


def test_missing_identity_or_consumer_never_becomes_high():
    store = EvidenceStore()
    _add(store, "socket_bind_listen", 10, relation_to="Unrelated::Listen")
    _add(store, "socket_accept_read", 20, relation_to="Unrelated::Read")

    result = ServiceAttributor().attribute(store, mapping=_mapping())

    assert result.status == "PARTIAL"
    assert result.confirmed is False
    assert result.predicates["socket_identity"] is False
    assert any("identity" in reason for reason in result.reasons)


def test_unresolved_mapping_downgrades_complete_code_evidence():
    store = EvidenceStore()
    _add(store, "literal_match", 10, symbol="PIPE_NAME")
    _add(store, "socket_acquire", 20, relation_to="ParamService::Start")
    _add(store, "socket_accept_read", 30, relation_to="ParamService::Read")
    _add(store, "manifest_mapping", 40, relation_to="ManifestResolver")

    result = ServiceAttributor().attribute(store, mapping=_mapping(status="needs_review"))

    assert result.status == "PARTIAL"
    assert result.confirmed is False
    assert result.predicates["manifest_mapping"] is False
    assert any("Manifest" in reason for reason in result.reasons)


def test_no_server_related_evidence_is_unresolved():
    store = EvidenceStore()
    _add(store, "client_send", 10, relation_to="ParamClient::Send")

    result = ServiceAttributor().attribute(store, mapping=_mapping())

    assert result.status == "UNRESOLVED"
    assert result.confirmed is False
    assert result.candidates == ()
    assert result.evidence_ids == ()


def test_duplicate_input_evidence_does_not_inflate_candidates_or_score():
    store = EvidenceStore()
    evidence_id = _add(store, "literal_match", 10, symbol="PIPE_NAME")
    evidence = store.get_evidence(evidence_id)
    result = ServiceAttributor().attribute([evidence, evidence], mapping=_mapping())

    assert result.evidence_ids == (evidence_id,)
    assert result.score == 25
    assert len(result.candidates) == 0


def test_serialization_contains_roles_and_no_unbounded_source_dump():
    store = EvidenceStore()
    _add(store, "literal_match", 10, symbol="PIPE_NAME")
    _add(store, "socket_bind_listen", 20, relation_to="ParamService::Listen")
    _add(store, "protocol_dispatch", 30, relation_to="ParamService::Dispatch")
    payload = ServiceAttributor().attribute(store, mapping=_mapping()).to_dict()

    assert payload["schema_version"] == "openant.source-locator.server-attribution.v1"
    assert payload["roles"]["server_handler"]
    assert "literal_match evidence" not in json.dumps(payload, ensure_ascii=False)


def test_invalid_evidence_and_mapping_input_fails_loudly():
    with pytest.raises(ServiceAttributionError):
        ServiceAttributor(mapping="not-a-mapping")  # type: ignore[arg-type]
    with pytest.raises(ServiceAttributionError):
        ServiceAttributor().attribute("not-evidence")  # type: ignore[arg-type]
    with pytest.raises(ServiceAttributionError, match="predicates 的值必须是布尔值"):
        ServerAttributionResult(
            status="UNRESOLVED",
            confirmed=False,
            score=0,
            predicates={"socket_identity": "false"},  # type: ignore[dict-item]
        )


def test_test_path_evidence_is_retained_but_cannot_confirm_server():
    store = EvidenceStore()
    production_id = _add(store, "literal_match", 10, symbol="PIPE_NAME")
    test_id = store.add_evidence(
        kind="socket_accept_read",
        source_path="/openharmony/kernel/linux/linux-6.6/tools/testing/selftests/bpf/prog_tests/sk_assign.c",
        line_start=20,
        excerpt="accept(fd, addr);",
        tool_name="test.fixture",
        source_mode="fixture",
        relation_from="/dev/unix/socket/paramservice",
        relation_to="FakeTestServer::accept",
    ).evidence_id
    result = ServiceAttributor().attribute(store, mapping=_mapping())

    assert test_id in result.excluded_evidence_ids
    assert test_id not in result.evidence_ids
    assert result.predicates["server_consumer"] is False
    assert production_id in result.evidence_ids
