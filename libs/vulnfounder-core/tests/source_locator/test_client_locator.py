"""SL-05 tests for the client communication boundary."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    ClientLocator,
    ClientAttributionResult,
    ClientLocatorError,
    EvidenceStore,
    RepositoryMapping,
    ServiceAttributor,
    combine_attributions,
)


def _mapping(*, status: str = "resolved") -> RepositoryMapping:
    return RepositoryMapping(
        project_name="communication_ipc",
        source_root="foundation/communication/ipc",
        remote_name="gitcode",
        remote_fetch="https://gitcode.com/openharmony",
        repo_url="https://gitcode.com/openharmony/communication_ipc",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/foundation/communication/ipc/param_client.cpp",
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
    relation_to: str | None = "ParamClient::SendRequest",
) -> str:
    evidence = store.add_evidence(
        kind=kind,
        source_path="/openharmony/foundation/communication/ipc/param_client.cpp",
        line_start=line,
        symbol=symbol,
        excerpt=f"{kind} evidence at {line}",
        tool_name="test.fixture",
        source_mode="fixture",
        relation_from=relation_from,
        relation_to=relation_to,
    )
    return evidence.evidence_id


def _complete_store() -> EvidenceStore:
    store = EvidenceStore()
    _add(store, "client_endpoint", 10, relation_to="ParamClient::Endpoint")
    _add(store, "client_connect", 20, relation_to="ParamClient::Connect")
    _add(store, "protocol_construction", 30, relation_to="ParamClient::BuildRequest")
    _add(store, "client_send", 40, relation_to="ParamClient::SendRequest")
    return store


def test_endpoint_connect_protocol_and_send_complete_client_boundary():
    result = ClientLocator(mapping=_mapping()).locate(_complete_store())

    assert result.status == "HIGH"
    assert result.completed is True
    assert result.score == 100
    assert result.client_repo == "communication_ipc"
    assert result.predicates == {
        "target_relation": True,
        "endpoint_or_connect": True,
        "client_connect": True,
        "protocol_construction": True,
        "client_send": True,
        "manifest_mapping": True,
    }
    assert {candidate.role for candidate in result.candidates} == {
        "client_transport",
        "client_protocol",
        "client_sender",
    }


def test_completed_client_rejects_business_caller_search():
    result = ClientLocator(mapping=_mapping()).locate(_complete_store())

    assert result.business_caller_search_allowed is False
    assert result.allows_action("read_file") is True
    assert result.allows_action("find_business_callers") is False
    with pytest.raises(ClientLocatorError, match="禁止继续执行 find_business_callers"):
        result.assert_action_allowed("find_business_callers")


def test_endpoint_is_an_explicit_equivalent_to_connect():
    store = EvidenceStore()
    _add(store, "client_endpoint", 10, relation_to="ParamClient::Connect")
    _add(store, "protocol_construction", 20, relation_to="ParamClient::BuildRequest")
    _add(store, "client_send", 30, relation_to="ParamClient::SendRequest")

    result = ClientLocator().locate(store, mapping=_mapping())

    assert result.status == "HIGH"
    assert result.completed is True
    assert result.predicates["client_connect"] is False
    assert result.predicates["endpoint_or_connect"] is True


def test_missing_target_relation_or_send_is_partial():
    store = EvidenceStore()
    _add(store, "client_connect", 10, relation_from=None, relation_to="ParamClient::Connect")
    _add(store, "protocol_construction", 20)

    result = ClientLocator().locate(store, mapping=_mapping())

    assert result.status == "PARTIAL"
    assert result.completed is False
    assert result.predicates["target_relation"] is False
    assert result.predicates["client_send"] is False
    assert any("目标 socket/service" in reason for reason in result.reasons)


def test_unresolved_mapping_downgrades_complete_client_evidence():
    store = _complete_store()
    _add(store, "manifest_mapping", 50, relation_to="ManifestResolver")
    result = ClientLocator().locate(store, mapping=_mapping(status="needs_review"))

    assert result.status == "PARTIAL"
    assert result.completed is False
    assert result.predicates["manifest_mapping"] is False


def test_no_client_evidence_is_unresolved():
    result = ClientLocator().locate(EvidenceStore(), mapping=_mapping())

    assert result.status == "UNRESOLVED"
    assert result.completed is False
    assert result.candidates == ()
    assert result.business_caller_search_allowed is True


def test_identity_relation_can_supply_target_relation_without_client_endpoint():
    store = EvidenceStore()
    _add(store, "literal_match", 10, symbol="PIPE_NAME", relation_to="ParamClient::Endpoint")
    _add(store, "client_connect", 20, relation_to="ParamClient::Connect")
    _add(store, "protocol_construction", 30, relation_to="ParamClient::BuildRequest")
    _add(store, "client_send", 40, relation_to="ParamClient::SendRequest")

    result = ClientLocator().locate(store, mapping=_mapping())

    assert result.status == "HIGH"
    assert result.completed is True


def test_connect_relation_can_supply_target_relation_without_endpoint_kind():
    store = EvidenceStore()
    _add(store, "client_connect", 10, relation_from="/dev/unix/socket/paramservice")
    _add(store, "protocol_construction", 20)
    _add(store, "client_send", 30)

    result = ClientLocator().locate(store, mapping=_mapping())

    assert result.status == "HIGH"
    assert result.completed is True


def test_combined_server_high_client_unresolved_is_partial():
    server_store = EvidenceStore()
    _add(server_store, "literal_match", 1, symbol="PIPE_NAME")
    _add(server_store, "socket_acquire", 2, relation_to="ParamService::Start")
    _add(server_store, "socket_accept_read", 3, relation_to="ParamService::Read")
    server = ServiceAttributor().attribute(server_store, mapping=_mapping())
    client = ClientLocator().locate(EvidenceStore(), mapping=_mapping())

    combined = combine_attributions(server, client)

    assert server.status == "HIGH"
    assert client.status == "UNRESOLVED"
    assert combined.status == "PARTIAL"
    assert combined.server_status == "HIGH"
    assert combined.client_status == "UNRESOLVED"


def test_client_combine_adapter_and_invalid_action_inputs():
    server_store = EvidenceStore()
    _add(server_store, "literal_match", 1, symbol="PIPE_NAME")
    _add(server_store, "socket_acquire", 2, relation_to="ParamService::Start")
    _add(server_store, "socket_accept_read", 3, relation_to="ParamService::Read")
    server = ServiceAttributor().attribute(server_store, mapping=_mapping())
    client = ClientLocator().locate(_complete_store(), mapping=_mapping())

    assert ClientLocator().combine(server, client).status == "HIGH"
    with pytest.raises(ClientLocatorError):
        client.allows_action("")
    with pytest.raises(ClientLocatorError, match="predicates 的值必须是布尔值"):
        ClientAttributionResult(
            status="UNRESOLVED",
            completed=False,
            score=0,
            predicates={"client_connect": "false"},  # type: ignore[dict-item]
        )


def test_test_path_evidence_is_retained_but_cannot_complete_client():
    store = _complete_store()
    test_id = store.add_evidence(
        kind="client_send",
        source_path="/openharmony/base/module/tests/fake_client_test.cpp",
        line_start=50,
        excerpt="send(fd, payload);",
        tool_name="test.fixture",
        source_mode="fixture",
        relation_from="/dev/unix/socket/paramservice",
        relation_to="FakeTestClient::send",
    ).evidence_id
    result = ClientLocator(mapping=_mapping()).locate(store)

    assert test_id in result.excluded_evidence_ids
    assert test_id not in result.evidence_ids
    assert result.status == "HIGH"
