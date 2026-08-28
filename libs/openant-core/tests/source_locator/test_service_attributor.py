"""SL-05 tests for deterministic server attribution."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    EvidenceStore,
    RepositoryMapping,
    ServerAttributionResult,
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
