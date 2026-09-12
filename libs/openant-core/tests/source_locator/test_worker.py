"""SL-09 worker 的离线端到端推进测试。

这里使用仿真的 OpenGrok 响应和仓库 Manifest，验证 worker 真的会把每一
个阶段产物写入 session，并在仓库确认前停住；测试不访问网络，也不执行
Git clone。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    CommandResult,
    EndpointCapability,
    EvidenceStore,
    LocatorSessionStore,
    OpenGrokHTTPError,
    ProbeResult,
    RepositoryMapping,
    SearchHit,
    SearchResponse,
    SourceDocument,
    SourceLocatorRuntime,
    SourceLocatorWorker,
    LLMSearchPlanner,
    PlannerBudget,
    LLMRoleAttributor,
    LLMRoleAttributionResult,
    LLMRoleDecision,
    LLMEntrypointAttributor,
    LLMCandidateReviewer,
    load_manifest,
    runtime_from_config,
)
from core.source_locator.target_normalizer import normalize_target  # noqa: E402
from core.source_locator.worker import (  # noqa: E402
    _budget_int,
    _candidate_metadata_paths,
    _client_kind,
    _compact_repository_mappings_payload,
    _infer_related_macros,
    _component_source_queries,
    _line_kind,
    _line_has_target_identity,
    _named_socket_path_has_conflict,
    _network_operation_matches_target,
    _network_path_priority,
    _path_contains_target_identity,
    _path_has_target_component_affinity,
    _target_component_tokens,
    _path_shares_target_context,
    _path_role_adjustment,
    _evidence_symbol_for_line,
    _target_bound_context_directories,
    _target_evidence_is_bound,
    _target_context_directories,
    _unix_path_priority,
    _mapping_role_score,
    _search_hit_is_target_evidence,
    _scope_llm_role_result_to_mapping,
    _extract_enclosing_function,
    _build_socket_entrypoint_sources,
    _network_function_matches_target,
    _target_local_entrypoint_lines,
    _compact_attribution_payload,
)
from core.source_locator.service_attributor import (  # noqa: E402
    AttributionCandidate,
    ServerAttributionResult,
    SourceLocation,
)


TARGET_PATH = "/openharmony/base/startup/init/services/param/param_service.c"


def test_extract_enclosing_socket_entry_function_returns_complete_source() -> None:
    source = """#include <sys/socket.h>\n\nstatic void Handle(int fd) {\n    char buf[16];\n    recv(fd, buf, sizeof(buf), 0);\n    dispatch(buf);\n}\n"""
    document = SourceDocument(
        path="/openharmony/base/test/socket.c",
        content=source,
        source="test",
    )

    result = _extract_enclosing_function(document, 5)

    assert result is not None
    assert result["function"] == "Handle"
    assert result["line_start"] == 3
    assert result["line_end"] == 7
    assert "recv(fd, buf" in result["source"]
    assert result["complete"] is True


def test_extract_enclosing_socket_entry_function_keeps_qualified_name_with_callback_parameter() -> None:
    source = """#include <sys/socket.h>
void UnixSocketServer::UnixSocketAccept(void (*callback)(int)) {
    callback(accept(fd, nullptr, nullptr));
}
"""
    document = SourceDocument(
        path="/openharmony/base/test/unix_socket_server.cpp",
        content=source,
        source="test",
    )

    result = _extract_enclosing_function(document, 3)

    assert result is not None
    assert result["function"] == "UnixSocketServer::UnixSocketAccept"


def test_extract_enclosing_socket_entry_function_rejects_header_type_body() -> None:
    """类声明中的 Recv/Accept 原型不能被当成入口函数源码。"""

    document = SourceDocument(
        path="/openharmony/base/test/sp_server_socket.h",
        content="""class SpServerSocket {
public:
    int Recvfrom();
    int Accept();
};
""",
        source="fixture",
    )

    assert _extract_enclosing_function(document, 3) is None


def test_network_function_transport_filter_keeps_only_matching_methods() -> None:
    udp = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    tcp = normalize_target("SP_daemon TCP 127.0.0.1:8284")

    assert _network_function_matches_target("SpServerSocket::Recvfrom", "recvfrom(fd, b, n, 0);", udp)
    assert not _network_function_matches_target("SpServerSocket::Accept", "accept(fd, nullptr, nullptr);", udp)
    assert not _network_function_matches_target("SpServerSocket::Recv", "recv(fd, b, n, 0);", udp)
    assert _network_function_matches_target("SpThreadSocket::TypeTcp", "spSocket.Accept();", tcp)
    assert _network_function_matches_target("SpThreadSocket::Process", "spSocket.Recvfrom();", tcp)
    assert not _network_function_matches_target("SpServerSocket::Recvfrom", "recvfrom(fd, b, n, 0);", tcp)


def test_socket_entrypoint_artifact_groups_source_and_keeps_evidence_ids() -> None:
    source = """#include <sys/socket.h>\nvoid Handle(int fd) {\n    char buffer[8];\n    recv(fd, buffer, sizeof(buffer), 0);\n}\n"""
    document = SourceDocument(
        path="/openharmony/base/test/socket.c",
        content=source,
        source="test",
    )
    store = EvidenceStore()
    evidence = store.add_source_excerpt(document, line_start=4, kind="socket_accept_read")
    candidate = AttributionCandidate(
        role="server_consumer",
        subject="Handle",
        source_locations=(SourceLocation(document.path, 4, 4),),
        evidence_ids=(evidence.evidence_id,),
        score=25,
    )
    server = ServerAttributionResult(
        status="PARTIAL",
        confirmed=False,
        score=50,
        predicates={"server_consumer": True},
        candidates=(candidate,),
        evidence_ids=(evidence.evidence_id,),
    )
    fake_client = type("FakeOpenGrok", (), {"read_source": lambda self, path, max_bytes=None: document})()

    payload = _build_socket_entrypoint_sources(
        normalize_target("/dev/unix/socket/test"),
        store,
        server,
        fake_client,
        max_source_bytes=1024,
    )

    assert payload["status"] == "complete"
    assert payload["entrypoint_count"] == 1
    assert payload["entries"][0]["function"] == "Handle"
    assert payload["entries"][0]["evidence_ids"] == [evidence.evidence_id]
    assert "recv(fd, buffer" in payload["entries"][0]["source"]


def test_socket_entrypoint_artifact_uses_llm_to_reject_setup_candidate() -> None:
    """规则只收窄候选，模型负责区分接收函数和同文件初始化函数。"""

    source = """#include <sys/socket.h>
void Init(int fd) {
    bind(fd, nullptr, 0);
    listen(fd, 8);
}
void Receive(int fd) {
    char buffer[8];
    recvfrom(fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
    dispatch(buffer);
}
void SetMark(int fd, int mark) {
    switch (mark) { case 1: break; default: break; }
}
"""
    document = SourceDocument(
        path="/openharmony/base/test/example/socket.cpp",
        content=source,
        source="fixture",
    )
    store = EvidenceStore()
    setup = store.add_source_excerpt(document, line_start=3, kind="socket_server_registration")
    receive = store.add_source_excerpt(document, line_start=8, kind="socket_accept_read")
    dispatch = store.add_source_excerpt(document, line_start=12, kind="protocol_dispatch")
    candidate = AttributionCandidate(
        role="server_consumer",
        subject="example socket service",
        source_locations=(
            SourceLocation(document.path, setup.line_start, setup.line_end),
            SourceLocation(document.path, receive.line_start, receive.line_end),
            SourceLocation(document.path, dispatch.line_start, dispatch.line_end),
        ),
        evidence_ids=(setup.evidence_id, receive.evidence_id, dispatch.evidence_id),
        score=40,
    )
    server = ServerAttributionResult(
        status="HIGH",
        confirmed=True,
        score=80,
        predicates={"server_consumer": True},
        candidates=(candidate,),
        evidence_ids=(setup.evidence_id, receive.evidence_id, dispatch.evidence_id),
    )
    target = normalize_target("/dev/unix/socket/example")
    fake_client = type("FakeOpenGrok", (), {"read_source": lambda self, path, max_bytes=None: document})()

    def model(prompt: str):
        payload = json.loads(prompt)
        decisions = []
        for row in payload["candidates"]:
            if row["function"] == "Receive":
                decisions.append(
                    {
                        "candidate_id": row["candidate_id"],
                        "role": "inbound_receive",
                        "status": "accepted",
                        "confidence": "high",
                        "evidence_ids": row["evidence_ids"],
                        "reason": "直接调用 recvfrom 接收外部数据并进入协议处理",
                    }
                )
            else:
                decisions.append(
                    {
                        "candidate_id": row["candidate_id"],
                        "role": "setup_only" if row["function"] == "Init" else "unrelated",
                        "status": "rejected",
                        "confidence": "high",
                        "evidence_ids": row["evidence_ids"],
                        "reason": "该函数不是外部消息接收入口",
                    }
                )
        return {"decisions": decisions}

    result = _build_socket_entrypoint_sources(
        target,
        store,
        server,
        fake_client,
        max_source_bytes=64 * 1024,
        llm_entrypoint_attributor=LLMEntrypointAttributor(model_call=model),
    )

    assert result["decision_source"] == "llm"
    # The registration line is an anchor used to discover local receivers;
    # only the derived Receive and protocol-dispatch candidates are submitted
    # as function candidates.
    assert result["candidate_count"] == 2
    assert [item["function"] for item in result["entries"]] == ["Receive"]
    assert result["entries"][0]["llm_decision"]["eligible"] is True
    assert result["llm_review"]["accepted_candidate_ids"]


def test_socket_entrypoint_artifact_expands_target_bound_registration_file() -> None:
    """A registration row also lets the artifact recover its receiver."""

    source = """#include <sys/socket.h>
void Register(void)
{
    AddDev(std::make_shared<SocketDevice>(\"hisysevent\", 0));
}
int ReceiveMsg(int fd)
{
    char buffer[8] = {};
    return recv(fd, buffer, sizeof(buffer), 0);
}
"""
    document = SourceDocument(
        path="/openharmony/base/hiviewdfx/hiview/plugins/sysevent_source/event_server.cpp",
        content=source,
        source="test",
    )
    store = EvidenceStore()
    evidence = store.add_source_excerpt(
        document,
        line_start=4,
        kind="socket_server_registration",
    )
    candidate = AttributionCandidate(
        role="service_owner",
        subject="hisysevent",
        source_locations=(SourceLocation(document.path, 4, 4),),
        evidence_ids=(evidence.evidence_id,),
        score=30,
    )
    server = ServerAttributionResult(
        status="PARTIAL",
        confirmed=False,
        score=30,
        predicates={"socket_server_registration": True},
        candidates=(candidate,),
        evidence_ids=(evidence.evidence_id,),
    )
    fake_client = type("FakeOpenGrok", (), {"read_source": lambda self, path, max_bytes=None: document})()

    payload = _build_socket_entrypoint_sources(
        normalize_target("/dev/unix/socket/hisysevent"),
        store,
        server,
        fake_client,
        max_source_bytes=1024,
    )

    assert payload["status"] == "complete"
    assert payload["entrypoint_count"] == 1
    assert payload["entries"][0]["function"] == "ReceiveMsg"
    assert "recv(fd, buffer" in payload["entries"][0]["source"]


def test_socket_entrypoint_artifact_bridges_config_identity_to_server_file() -> None:
    """A cfg-only identity must not hide a separately indexed server receiver."""

    source = """#include <sys/socket.h>
int AcceptFaultLogger(int listenFd)
{
    int clientFd = accept(listenFd, nullptr, nullptr);
    return recv(clientFd, buffer, sizeof(buffer), 0);
}
"""
    document = SourceDocument(
        path="/openharmony/base/hiviewdfx/faultloggerd/services/fault_logger_server.cpp",
        content=source,
        source="fixture",
    )
    config = SourceDocument(
        path="/openharmony/base/hiviewdfx/faultloggerd/services/config/faultloggerd.cfg",
        content='{"name":"faultloggerd.server"}',
        source="fixture",
    )
    store = EvidenceStore()
    identity = store.add_source_excerpt(config, line_start=1, kind="service_config")
    receive = store.add_source_excerpt(document, line_start=4, kind="socket_accept_read")
    candidate = AttributionCandidate(
        role="server_consumer",
        subject="faultloggerd server receiver",
        source_locations=(SourceLocation(document.path, 4, 4),),
        evidence_ids=(receive.evidence_id,),
        score=25,
    )
    server = ServerAttributionResult(
        status="PARTIAL",
        confirmed=False,
        score=40,
        predicates={"socket_identity": True, "server_consumer": True},
        candidates=(candidate,),
        evidence_ids=(identity.evidence_id, receive.evidence_id),
    )

    class FakeOpenGrok:
        def read_source(self, path, max_bytes=None):
            return document if path == document.path else config

    payload = _build_socket_entrypoint_sources(
        normalize_target("/dev/unix/socket/faultloggerd.server"),
        store,
        server,
        FakeOpenGrok(),
        max_source_bytes=1024,
    )

    assert payload["status"] == "complete"
    assert [item["function"] for item in payload["entries"]] == ["AcceptFaultLogger"]
    assert payload["selection"]["server_candidate_paths"] == [document.path]
    assert payload["entries"][0]["entry_scope"] == "transport_receive"


def test_socket_entrypoint_artifact_scans_verified_setup_when_role_review_keeps_sibling_receiver() -> None:
    """角色复核遗漏业务回调时，目标注册证据仍能恢复同文件入口。"""

    service_source = """int Register(void)
{
    return GetControlSocket(\"paramservice\");
}
int ProcessMessage(const Message *msg)
{
    switch (msg->type) {
        case MSG_SET_PARAM: return 0;
        default: return -1;
    }
}
"""
    sibling_source = """int GenericReceiver(int recvFd)
{
    return read(recvFd, buffer, sizeof(buffer));
}
"""
    service = SourceDocument(
        path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        content=service_source,
        source="fixture",
    )
    sibling = SourceDocument(
        path="/openharmony/base/startup/init/services/modules/init_context/init_context.c",
        content=sibling_source,
        source="fixture",
    )
    store = EvidenceStore()
    setup = store.add_source_excerpt(service, line_start=3, kind="socket_server_registration")
    sibling_receive = store.add_source_excerpt(sibling, line_start=3, kind="socket_accept_read")
    server = ServerAttributionResult(
        status="HIGH",
        confirmed=True,
        score=100,
        predicates={"socket_identity": True, "socket_acquire_or_bind": True, "server_consumer": True},
        candidates=(
            AttributionCandidate(
                role="server_consumer",
                subject="generic init receiver",
                source_locations=(SourceLocation(sibling.path, 3, 3),),
                evidence_ids=(sibling_receive.evidence_id,),
                score=25,
            ),
        ),
        # The setup fact is target-scoped but intentionally absent from the
        # reviewed role candidate, reproducing a semantic-review compaction.
        evidence_ids=(sibling_receive.evidence_id, setup.evidence_id),
    )

    class FakeOpenGrok:
        def read_source(self, path, max_bytes=None):
            return service if path == service.path else sibling

    payload = _build_socket_entrypoint_sources(
        normalize_target("/dev/unix/socket/paramservice"),
        store,
        server,
        FakeOpenGrok(),
        max_source_bytes=4096,
    )

    assert payload["status"] == "complete"
    assert any(item["function"] == "ProcessMessage" for item in payload["entries"])
    assert service.path not in payload["selection"]["excluded_target_mismatch_paths"]


def test_socket_entrypoint_artifact_reports_cfg_only_gap_explicitly() -> None:
    """A config identity without implementation evidence is a gap, not empty proof."""

    document = SourceDocument(
        path="/openharmony/base/example/services/example.cfg",
        content='{"name":"example"}',
        source="fixture",
    )
    store = EvidenceStore()
    identity = store.add_source_excerpt(document, line_start=1, kind="service_config")
    candidate = AttributionCandidate(
        role="socket_creator",
        subject="example",
        source_locations=(SourceLocation(document.path, 1, 1),),
        evidence_ids=(identity.evidence_id,),
        score=15,
    )
    server = ServerAttributionResult(
        status="PARTIAL",
        confirmed=False,
        score=15,
        predicates={"socket_identity": True},
        candidates=(candidate,),
        evidence_ids=(identity.evidence_id,),
    )
    fake_client = type("FakeOpenGrok", (), {"read_source": lambda self, path, max_bytes=None: document})()

    payload = _build_socket_entrypoint_sources(
        normalize_target("/dev/unix/socket/example"),
        store,
        server,
        fake_client,
        max_source_bytes=1024,
    )

    assert payload["status"] == "unavailable"
    assert payload["entrypoint_count"] == 0
    assert payload["selection"]["needs_source_entry_evidence"] is True
    assert "补充服务实现源码" in payload["errors"][0]


def test_target_component_affinity_does_not_bridge_unrelated_vpn_receiver() -> None:
    """同一 netmanager 模块内的 VPN 接收器不能冒充 dnsproxyd 服务端。"""

    assert _path_has_target_component_affinity(
        "/openharmony/foundation/communication/netmanager_base/services/netmanagernative/src/netsys/dns_resolv_listen.cpp",
        normalize_target("/dev/unix/socket/dnsproxyd"),
    )
    assert not _path_has_target_component_affinity(
        "/openharmony/foundation/communication/netmanager_base/services/netmanagernative/src/manager/vpn_manager.cpp",
        normalize_target("/dev/unix/socket/dnsproxyd"),
    )
    assert not _path_has_target_component_affinity(
        "/openharmony/foundation/communication/netmanager_base/services/netmanagernative/src/manager/vpn_manager.cpp",
        normalize_target("/dev/unix/socket/multivpnfd"),
    )


def test_socket_entrypoint_artifact_rejects_generic_cross_file_sibling() -> None:
    """目标只有 DNS 配置时，VPN 的通用 accept 行不能被跨文件提升。"""

    source = """#include <sys/socket.h>
int StartUnixSocketListen()
{
    int clientFd = accept(serverfd, nullptr, nullptr);
    return clientFd;
}
"""
    document = SourceDocument(
        path="/openharmony/foundation/communication/netmanager_base/services/netmanagernative/src/manager/vpn_manager.cpp",
        content=source,
        source="fixture",
    )
    config = SourceDocument(
        path="/openharmony/foundation/communication/netmanager_base/services/etc/init/netsysnative.cfg",
        content='{"name":"dnsproxyd"}',
        source="fixture",
    )
    store = EvidenceStore()
    identity = store.add_source_excerpt(config, line_start=1, kind="service_config")
    receive = store.add_source_excerpt(document, line_start=4, kind="socket_accept_read")
    candidate = AttributionCandidate(
        role="server_consumer",
        subject="VPN receiver",
        source_locations=(SourceLocation(document.path, 4, 4),),
        evidence_ids=(receive.evidence_id,),
        score=25,
    )
    server = ServerAttributionResult(
        status="PARTIAL",
        confirmed=False,
        score=40,
        predicates={"socket_identity": True, "server_consumer": True},
        candidates=(candidate,),
        evidence_ids=(identity.evidence_id, receive.evidence_id),
    )

    class FakeOpenGrok:
        def read_source(self, path, max_bytes=None):
            return document if path == document.path else config

    payload = _build_socket_entrypoint_sources(
        normalize_target("/dev/unix/socket/dnsproxyd"),
        store,
        server,
        FakeOpenGrok(),
        max_source_bytes=1024,
    )

    assert payload["status"] == "unavailable"
    assert payload["entrypoint_count"] == 0
    assert payload["selection"]["needs_source_entry_evidence"] is True


def test_socket_entrypoint_predicate_accepts_epoll_protocol_callback() -> None:
    """Epoll 框架把 recv 隐藏在 runner 时，协议回调仍是入口。"""

    from core.source_locator.worker import _function_source_is_socket_entrypoint

    source = """ReceiverRunner ProcCommand()
{
    return [this](FileDescriptor fd, const std::string &data) -> FixedLengthReceiverState {
        switch (info->command) {
            case GET_CONFIG:
                server_->AddReceiver(fd);
                return FixedLengthReceiverState::DATA_ENOUGH;
            default:
                return FixedLengthReceiverState::ONERROR;
        }
    };
}
"""
    assert _function_source_is_socket_entrypoint("ProcCommand", source)


def test_compact_attribution_payload_keeps_server_roles() -> None:
    """Role-balanced compaction must retain consumers behind noisy creators."""

    raw = [
        {
            "role": "socket_creator",
            "subject": f"creator-{index}",
            "source_locations": [],
            "evidence_ids": [],
            "reasons": [],
        }
        for index in range(40)
    ]
    raw.append(
        {
            "role": "server_consumer",
            "subject": "real-receiver",
            "source_locations": [],
            "evidence_ids": [],
            "reasons": [],
        }
    )
    compact = _compact_attribution_payload({"candidates": raw})
    assert len(compact["candidates"]) == 32
    assert any(item["role"] == "server_consumer" for item in compact["candidates"])


def test_local_entrypoint_scan_recovers_recvmsg_for_init_created_service() -> None:
    source = """#include <sys/socket.h>
static void ProcessRecvMsg(void *connection) {}
static int ProcessPreFork(int parentToChildFd)
{
    char buffer[8] = {};
    return read(parentToChildFd, buffer, sizeof(buffer));
}
static int CreateServer(const char *name)
{
    int fd = GetControlSocket(name);
    struct msghdr msg = {};
    return recvmsg(fd, &msg, 0);
}
"""
    document = SourceDocument(
        path="/openharmony/base/startup/appspawn/standard/appspawn_service.c",
        content=source,
        source="test",
    )

    result = _target_local_entrypoint_lines(
        document.path,
        document,
        normalize_target("/dev/unix/socket/CJAppSpawn"),
        ("/openharmony/base/startup/appspawn",),
    )

    assert (12, "socket_accept_read") in result
    assert not any(kind == "socket_accept_read" and line == 6 for line, kind in result)
    assert any(kind == "protocol_dispatch" for _, kind in result)


def test_local_entrypoint_scan_excludes_client_readback_helper() -> None:
    source = """static int GetClientSocket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ConnectServer(fd, CLIENT_PIPE_NAME);
    return recv(fd, buffer, sizeof(buffer), 0);
}
"""
    document = SourceDocument(
        path="/openharmony/base/startup/init/services/param/linux/param_request.c",
        content=source,
        source="test",
    )

    result = _target_local_entrypoint_lines(
        document.path,
        document,
        normalize_target("/dev/unix/socket/paramservice"),
        ("/openharmony/base/startup/init/services/param",),
    )

    assert result == ()


def test_component_source_probe_normalizes_cjappspawn_to_appspawn_service() -> None:
    target = normalize_target(
        "/dev/unix/socket/CJAppSpawn",
        target_revision="OpenHarmony-6.1-LTS",
    )
    executions = (
        {
            "status": "ok",
            "response": {
                "results": {
                    "/openharmony/base/startup/appspawn/cjappspawn.cfg": [
                        {"line": "...", "line_number": ""}
                    ]
                }
            }
        },
    )

    queries = _component_source_queries(
        executions,
        target,
        max_queries=1,
        start_index=2,
    )

    assert len(queries) == 1
    assert queries[0].kind == "path"
    assert queries[0].value == "appspawn_service.c"


def test_component_source_probe_normalizes_native_spawn_to_appspawn_service() -> None:
    target = normalize_target(
        "/dev/unix/socket/NativeSpawn",
        target_revision="OpenHarmony-6.1-LTS",
    )
    executions = (
        {
            "status": "ok",
            "response": {
                "results": {
                    "/openharmony/base/startup/appspawn/nativespawn.cfg": [
                        {"line": '"name" : "NativeSpawn"', "line_number": "14"}
                    ]
                }
            },
        },
    )

    queries = _component_source_queries(
        executions,
        target,
        max_queries=1,
        start_index=2,
    )

    assert len(queries) == 1
    assert queries[0].kind == "path"
    assert queries[0].value == "appspawn_service.c"


def test_candidate_metadata_paths_cover_split_src_implementation_layout() -> None:
    mapping = RepositoryMapping(
        project_name="developtools_smartperf_host",
        source_root="developtools/smartperf_host",
        source_path=(
            "/openharmony/developtools/smartperf_host/"
            "smartperf_device/device_command/services/ipc/include/sp_server_socket.h"
        ),
    )

    paths = _candidate_metadata_paths(mapping)

    assert (
        "/openharmony/developtools/smartperf_host/"
        "smartperf_device/device_command/services/ipc/src/sp_server_socket.cpp"
    ) in paths
    assert (
        "/openharmony/developtools/smartperf_host/"
        "smartperf_device/device_command/services/ipc/src/sp_thread_socket.cpp"
    ) in paths


def test_repository_mapping_checkpoint_is_bounded_but_artifact_rows_can_stay_full() -> None:
    evidence_ids = tuple(f"E-{index:016x}" for index in range(300))
    mappings = tuple(
        RepositoryMapping(
            project_name=f"project_{index}",
            source_root=f"base/project_{index}",
            repo_url=f"https://gitcode.com/openharmony/project_{index}",
            revision="OpenHarmony-6.1-LTS",
            source_path=f"/openharmony/base/project_{index}/service.c",
            evidence_ids=evidence_ids,
        )
        for index in range(56)
    )

    payload = _compact_repository_mappings_payload(mappings)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    assert len(encoded) < 64 * 1024
    assert len(payload["mappings"]) == 32
    assert len(payload["mappings"][0]["evidence_ids"]) == 64
    assert payload["truncated"] is True
    assert payload["total_mappings"] == 56


def test_generated_dependency_name_is_not_protocol_dispatch() -> None:
    """A generated dependency filename must not satisfy the dispatch predicate."""

    target = normalize_target("/dev/unix/socket/fd_holder")
    line = "build/base/startup/init/check_deps_handler.py: case data"
    assert _line_kind(line, target) != "protocol_dispatch"


def test_server_registration_wrapper_shape_is_generic_and_source_backed() -> None:
    target = normalize_target("/dev/unix/socket/paramservice")
    assert _line_kind('"name" : "paramservice",', target) == "service_config"
    assert _line_kind('socket.name = "paramservice";', target) == "service_config"
    assert _line_kind("info.server = PIPE_NAME;", target) == "socket_server_registration"
    assert _line_kind("info.server = NULL;", target) != "socket_server_registration"
    assert _line_kind("ret = ParamServerCreate(&task, &info);", target) == "socket_server_registration"
    assert _line_kind("CreateSocketListener(&listener, endpoint);", target) == "socket_server_registration"
    # OpenHarmony's init service has wrappers whose names are shorter than
    # ``*SocketCreate``.  They still establish the source-level registration
    # edge that connects a named socket macro to the returned descriptor.
    assert _line_kind("static int FdHolderSockInit(void)", target) == "socket_server_registration"
    assert _line_kind("CmdServiceInit(INIT_CONTROL_FD_SOCKET_PATH, ProcessControlFd, loop);", target) == "socket_server_registration"
    assert _line_kind("void CmdServiceInit(const char *socketPath, Callback func, LoopHandle loop)", target) == "socket_server_registration"
    assert _line_kind(
        'AddDev(std::make_shared<SocketDevice>("hisysevent", eventCount));',
        normalize_target("/dev/unix/socket/hisysevent"),
    ) == "socket_server_registration"
    # C++'s std::bind must not be confused with the POSIX socket bind API.
    assert _line_kind("std::function<void()> fn = std::bind(&Worker::Run, this);", target) != "socket_bind_listen"


def test_generic_socketdevice_from_other_component_is_not_paramservice_evidence() -> None:
    """A generic SocketDevice registration must not inherit another target's name."""

    target = normalize_target("/dev/unix/socket/paramservice")
    # A lowerCamel field/type parameter is not the named socket identity.  A
    # case-folded substring check would incorrectly anchor the whole hiview
    # component through ``paramService``.
    assert not _line_has_target_identity(
        "static void HandleInsert(const NotifyParamService &paramService);",
        target,
    )
    line = 'AddDev(std::make_shared<SocketDevice>("hisysevent", eventCountPerCycle));'
    path = "/openharmony/base/hiviewdfx/hiview/plugins/sysevent_source/event_server.cpp"
    assert not _target_evidence_is_bound(path, line, target, ())
    assert _evidence_symbol_for_line(line, target, query_value="SocketDevice") is None

    store = EvidenceStore()
    store.add_evidence(
        kind="literal_match",
        source_path="/openharmony/base/startup/init/services/param/include/param_utils.h",
        line_start=80,
        excerpt='#define PIPE_NAME "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    context = _target_bound_context_directories(store, target)
    assert _target_evidence_is_bound(
        "/openharmony/base/startup/init/services/param/linux/param_service.c",
        "ret = ParamServerCreate(&task, &info);",
        target,
        context,
    )
    assert not _target_evidence_is_bound(path, line, target, context)


def test_comments_and_unrelated_constants_do_not_become_socket_macro_evidence() -> None:
    target = normalize_target("/dev/unix/socket/hisysevent")
    assert _line_kind("static constexpr int ERR_SUCCESS = 0; // see hisysevent.h", target) != "constant_definition"
    # ``EventType::`` is a C++ scope-qualified enum, not a configuration
    # assignment.  The old unbounded ``type:`` pattern promoted these client
    # telemetry lines to service_config and could make an unrelated repository
    # outrank the actual SocketDevice owner.
    assert _line_kind("HiSysEvent::EventType::BEHAVIOR,", target) != "service_config"
    assert _line_kind(
        "OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,", target
    ) != "service_config"
    assert _line_kind(".sun_path = /dev/unix/socket/hisysevent", target) == "service_config"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "hisysevent"},
            "response": {
                "results": {
                    "/openharmony/base/hiviewdfx/hiview/include/hisysevent.h": [
                        {"line": "static constexpr int ERR_SUCCESS = 0; // hisysevent.h", "line_number": "12"},
                        {"line": "#define HISYSEVENT_SOCKET_NAME \"hisysevent\"", "line_number": "20"},
                    ]
                }
            },
        },
    )
    assert _infer_related_macros(executions, target) == ("HISYSEVENT_SOCKET_NAME",)


def test_socket_alias_use_bridges_init_path_without_assuming_server_role() -> None:
    target = normalize_target("/dev/unix/socket/fd_holder")
    # Filling ``sun_path`` only connects an alias to a sockaddr.  It is also a
    # normal client-side step before ``connect``; the actual server role must
    # be established by socket()/bind()/listen() or a server factory on the
    # same line/context.
    assert _line_kind(
        "addr.sun_path = INIT_HOLDER_SOCKET_PATH;",
        target,
        query_value="INIT_HOLDER_SOCKET_PATH",
    ) == "client_endpoint"
    assert _line_kind(
        "if (unlink(INIT_HOLDER_SOCKET_PATH) < 0) {}",
        target,
        query_value="INIT_HOLDER_SOCKET_PATH",
    ) == "service_config"


def test_network_address_only_hits_do_not_anchor_unrelated_repositories() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    # Loopback defaults and firewall rules are common, but they do not prove
    # that a file owns this endpoint without a socket/network operation.
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "127.0.0.1"},
            "path": "/openharmony/communication_netmanager_base/services/netmanagernative/include/netsys/dns_config_client.h",
        },
        {"line": '#define LOOP_BACK_ADDR1 "127.0.0.1"', "line_number": "44"},
        target,
    )
    # A target port held in a lower-case member is a useful bounded source
    # anchor and must be classified as a constant fact rather than discarded.
    assert _line_kind("const int udpPort = 8283;", target) == "constant_definition"
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "8283"},
            "path": "/openharmony/developtools_profiler/host/smartperf/client/client_command/include/sp_server_socket.h",
        },
        {"line": "const int udpPort = 8283;", "line_number": "52"},
        target,
    )


def test_network_socket_lines_distinguish_server_wrapper_and_client_direction() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    assert _line_kind("SpServerSocket::SpServerSocket()", target) == "socket_server_registration"
    assert _line_kind("int fd = socket(AF_INET, SOCK_DGRAM, 0);", target) == "socket_acquire"
    assert _line_kind("bind(fd, reinterpret_cast<const sockaddr *>(&addr), len);", target) == "socket_bind_listen"
    assert _line_kind("recvfrom(fd, buffer, size, 0, nullptr, nullptr);", target) == "socket_accept_read"
    assert _line_kind("connect(fd, reinterpret_cast<const sockaddr *>(&addr), len);", target) == "client_connect"
    assert _line_kind("sendto(fd, buffer, size, 0, addr, len);", target) == "client_send"
    assert _line_kind("SpThreadSocket::HandleMsg()", target) != "socket_server_registration"
    assert _line_kind("info.recvMessage = CmdOnRecvMessage;", target) == "protocol_dispatch"
    assert _line_kind("SpThreadSocket::HandleMsg();", target) == "protocol_dispatch"


def test_network_evidence_keeps_only_the_requested_transport_branch() -> None:
    udp = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    tcp = normalize_target("SP_daemon TCP 127.0.0.1:8284")
    assert _network_operation_matches_target("socket(AF_INET, SOCK_DGRAM, 0)", udp)
    assert not _network_operation_matches_target("socket(AF_INET, SOCK_STREAM, 0)", udp)
    assert _network_operation_matches_target("recvfrom(fd, buf, len, 0, addr, addrlen)", udp)
    # Connected UDP sockets may use recv()/send() instead of recvfrom()/sendto;
    # these calls are still valid UDP server/response operations and must not
    # be discarded as TCP evidence.
    assert _network_operation_matches_target("recv(fd, buf, len, 0)", udp)
    assert _network_operation_matches_target("send(fd, buf, len, 0)", udp)
    assert not _network_operation_matches_target("listen(fd, 5)", udp)
    assert _network_operation_matches_target("socket(AF_INET, SOCK_STREAM, 0)", tcp)
    assert not _network_operation_matches_target("socket(AF_INET, SOCK_DGRAM, 0)", tcp)
    assert _network_operation_matches_target("accept(fd, nullptr, nullptr)", tcp)
    assert not _network_operation_matches_target("recvfrom(fd, buf, len, 0, addr, addrlen)", tcp)


def test_network_generic_search_hits_do_not_become_identity_without_port_context() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    generic = {"query": {"kind": "full", "value": "recvfrom"}}
    assert not _search_hit_is_target_evidence(
        generic,
        {"line": "ssize_t recvfrom(int fd, void *buf, size_t len, int flags);"},
        target,
    )
    assert _search_hit_is_target_evidence(
        {"query": {"kind": "full", "value": "8283"}},
        {"line": "addr.sin_port = htons(8283);"},
        target,
    )
    assert _search_hit_is_target_evidence(
        {"query": {"kind": "full", "value": "8283"}},
        {"line": "const int udpPort = 8283;"},
        target,
    )
    assert not _search_hit_is_target_evidence(
        {"query": {"kind": "full", "value": "8283"}},
        {"line": "static const uint16_t table[] = {8283, 8284};"},
        target,
    )
    assert not _search_hit_is_target_evidence(
        {"query": {"kind": "full", "value": "SP_daemon"}, "path": "/openharmony/base/log.cpp"},
        {"line": 'LOGI("SP_daemon started");'},
        target,
    )
    assert _search_hit_is_target_evidence(
        {"query": {"kind": "full", "value": "SP_daemon"}, "path": "/openharmony/base/sp_server.cpp"},
        {"line": "int fd = socket(AF_INET, SOCK_DGRAM, 0); // SP_daemon"},
        target,
    )
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "8283"},
            "path": "/openharmony/kernel/linux/linux-6.6/tools/testing/selftests/net/udp_8283.c",
        },
        {"line": "server_fd = start_server(AF_INET, SOCK_DGRAM, NULL, 8283, 0);"},
        target,
    )


def test_network_generic_source_hit_can_follow_target_sibling_directory() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    context = "/openharmony/developtools/profiler/host/smartperf/client/client_command"
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "sin_port"},
            "path": context + "/sp_server_socket.cpp",
            "target_context_dirs": (context,),
        },
        {"line": "local.sin_port = htons(sockPort);"},
        target,
    )
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "sin_port"},
            "path": "/openharmony/.ccache/1/2/metadata.d",
            "target_context_dirs": ("/openharmony/.ccache/1/2",),
        },
        {"line": "local.sin_port = htons(8283);"},
        target,
    )


def test_network_generic_source_hit_can_follow_include_src_module_context() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    module = "/openharmony/developtools/smartperf_host/smartperf_device/device_command/services/ipc"
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "sin_port"},
            "path": module + "/src/sp_server_socket.cpp",
            "target_context_dirs": (module + "/include", module),
        },
        {"line": "local.sin_port = htons(sockPort);"},
        target,
    )


def test_named_socket_test_path_is_excluded_but_config_and_production_are_kept() -> None:
    target = normalize_target("/dev/unix/socket/dnsproxyd")
    config = {
        "query": {"kind": "full", "value": "dnsproxyd"},
        "path": "/openharmony/base/communication/netmanager_base/services/etc/init/netsysnative.cfg",
    }
    assert _search_hit_is_target_evidence(
        config,
        {"line": '{"name": "dnsproxyd", "family": "AF_UNIX"}'},
        target,
    )
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "GetControlSocket"},
            "path": "/openharmony/base/communication/netmanager_base/test/dnsproxyd_test.cpp",
            "target_context_dirs": ("/openharmony/base/communication/netmanager_base/services",),
        },
        {"line": 'fd = GetControlSocket("dnsproxyd");'},
        target,
    )


def test_named_socket_generic_probe_uses_bounded_context() -> None:
    target = normalize_target("/dev/unix/socket/dnsproxyd")
    module = "/openharmony/base/communication/netmanager_base/services/netmanagernative/src/netsys/dnsresolv"
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "GetControlSocket"},
            "path": module + "/dns_resolv_listen.cpp",
            "target_context_dirs": (module,),
        },
        {"line": 'fd = GetControlSocket("dnsproxyd");'},
        target,
    )
    assert _line_kind('{"name": "dnsproxyd", "family": "AF_UNIX"}', target) == "service_config"


def test_named_socket_generic_probe_rejects_other_transport_and_socket_name() -> None:
    target = normalize_target("/dev/unix/socket/dnsproxyd")
    context = "/openharmony/base/communication/netmanager_base/services/netmanagernative"
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "socket"},
            "path": context + "/src/dns_proxy_listen.cpp",
            "target_context_dirs": (context,),
        },
        {"line": "socketFd = socket(AF_INET, SOCK_DGRAM, 0);"},
        target,
    )
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "GetControlSocket"},
            "path": context + "/src/manager/multi_vpn_manager.cpp",
            "target_context_dirs": (context,),
        },
        {"line": 'fd = GetControlSocket("multivpnfd");'},
        target,
    )
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "GetControlSocket"},
            "path": context + "/src/netsys/dnsresolv/dns_resolv_listen.cpp",
            "target_context_dirs": (context,),
        },
        {"line": 'fd = GetControlSocket("dnsproxyd");'},
        target,
    )


def test_named_socket_conflict_signal_covers_entire_candidate_file() -> None:
    target = normalize_target("/dev/unix/socket/dnsproxyd")
    path = "/openharmony/base/communication/netmanager_base/src/dns_proxy.cpp"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "socket"},
            "response": {
                "results": {
                    path: [
                        {"line": "fd = socket(AF_INET, SOCK_DGRAM, 0);"},
                        {"line": "recv(fd, buffer, size, 0);"},
                    ]
                }
            },
        },
    )
    assert _named_socket_path_has_conflict(path, executions, target)


def test_context_matching_ignores_broad_structural_ancestors() -> None:
    """A repository/services ancestor must not bless every sibling API hit."""

    param_header = "/openharmony/base/startup/init/services/param/include"
    param_source = "/openharmony/base/startup/init/services/param/linux/param_service.c"
    unrelated_service = "/openharmony/base/startup/init/services/other/src/stream_task.c"
    assert _path_shares_target_context(param_source, (param_header, "/openharmony/base/startup/init/services"))
    assert not _path_shares_target_context(unrelated_service, (param_header, "/openharmony/base/startup/init/services"))


def test_context_matching_requires_component_overlap_for_sibling_network_services() -> None:
    """DNS/VPN siblings share a repository but not the target module."""

    target_context = "/openharmony/communication_netmanager_base/services/netmanagernative/include/netsys"
    dns_source = "/openharmony/communication_netmanager_base/services/netmanagernative/src/netsys/dnsresolv"
    vpn_source = "/openharmony/communication_netmanager_base/services/netmanagernative/src/manager/multi_vpn"
    assert _path_shares_target_context(dns_source, (target_context, "/openharmony/communication_netmanager_base/services"))
    assert not _path_shares_target_context(vpn_source, (target_context, "/openharmony/communication_netmanager_base/services"))


def test_named_socket_path_query_line_is_candidate_only_without_identity() -> None:
    target = normalize_target("/dev/unix/socket/AppSpawn")
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "path", "value": "AppSpawn"},
            "path": "/openharmony/base/startup/appspawn/standard/appspawn_service.c",
        },
        {"line": "/* source file summary */", "line_number": "1"},
        target,
    )
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "path", "value": "AppSpawn"},
            "path": "/openharmony/base/startup/appspawn/standard/appspawn_service.c",
        },
        {"line": 'const char *name = "AppSpawn";', "line_number": "42"},
        target,
    )


def test_named_socket_basename_query_does_not_anchor_unrelated_longer_symbol() -> None:
    target = normalize_target("/dev/unix/socket/AppSpawn")
    assert not _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "AppSpawn"},
            "path": "/openharmony/base/startup/appspawn/modules/module.c",
        },
        {"line": "void AddAppSpawnHookExecute() {}", "line_number": "8"},
        target,
    )


def test_named_socket_path_identity_recovers_normalized_service_filename() -> None:
    target = normalize_target("/dev/unix/socket/init_control_fd")
    assert _path_contains_target_identity(
        "/openharmony/base/startup/init/services/init/standard/init_control_fd_service.c",
        target,
    )
    assert _path_contains_target_identity(
        "/openharmony/base/startup/init/services/param/linux/param_service.c",
        normalize_target("/dev/unix/socket/paramservice"),
    )
    assert not _path_contains_target_identity(
        "/openharmony/base/startup/modules/module_engine/stub/appspawn_hook.cpp",
        normalize_target("/dev/unix/socket/AppSpawn"),
    )


def test_client_kind_uses_identifier_boundaries() -> None:
    target = normalize_target("/dev/unix/socket/AppSpawn")
    assert _client_kind('connect(fd, &addr, len); // AppSpawn', target) == "client_connect"
    assert _client_kind("void AppSpawnHookExecute();", target) is None


def test_named_socket_macro_alias_can_recover_descriptor_acquire() -> None:
    target = normalize_target("/dev/unix/socket/dnsproxyd")
    module = "/openharmony/base/communication/netmanager_base/services/netmanagernative"
    assert _search_hit_is_target_evidence(
        {
            "query": {"kind": "full", "value": "DNS_SOCKET_NAME"},
            "path": module + "/src/netsys/dnsresolv/dns_resolv_listen.cpp",
            "target_context_dirs": (module, ),
        },
        {"line": "serverSockFd_ = GetControlSocket(DNS_SOCKET_NAME);"},
        target,
    )


def test_unix_path_priority_prefers_socket_config_and_server_chain() -> None:
    target = normalize_target("/dev/unix/socket/dnsproxyd")
    module = "/openharmony/base/communication/netmanager_base/services/netmanagernative/src/netsys/dnsresolv"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "dnsproxyd"},
            "response": {
                "results": {
                    "/openharmony/base/communication/netmanager_base/services/etc/init/netsysnative.cfg": [
                        {"line": '{"name": "dnsproxyd", "family": "AF_UNIX"}'}
                    ],
                    module + "/dns_resolv_listen.cpp": [
                        {"line": 'fd = GetControlSocket("dnsproxyd");'}
                    ],
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "recv"},
            "response": {
                "results": {
                    module + "/dns_resolv_listen.cpp": [
                        {"line": "recvfrom(fd, buf, len, 0, nullptr, nullptr);"}
                    ],
                    "/openharmony/foundation/communication/foo.cpp": [
                        {"line": "recvfrom(fd, buf, len, 0, nullptr, nullptr);"}
                    ],
                }
            },
        },
    )
    assert _unix_path_priority(
        module + "/dns_resolv_listen.cpp", executions, target, (module,)
    ) > _unix_path_priority(
        "/openharmony/foundation/communication/foo.cpp", executions, target, (module,)
    )


def test_unix_path_priority_prefers_get_control_socket_over_sibling_proxy() -> None:
    """The init-created listener wins over a generic sibling socket helper."""

    target = normalize_target("/dev/unix/socket/dnsproxyd")
    module = "/openharmony/base/communication/netmanager_base/services/netmanagernative/src/netsys/dnsresolv"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "dnsproxyd"},
            "response": {
                "results": {
                    "/openharmony/base/communication/netmanager_base/services/etc/init/netsysnative.cfg": [
                        {"line": '{"name": "dnsproxyd", "family": "AF_UNIX"}'}
                    ]
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "DNS_SOCKET_NAME"},
            "response": {
                "results": {
                    module + "/dns_resolv_listen.cpp": [
                        {"line": "serverSockFd_ = GetControlSocket(DNS_SOCKET_NAME);"}
                    ]
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "socket"},
            "response": {
                "results": {
                    module + "/dns_proxy_listen.cpp": [
                        {"line": "proxySockFd_ = socket(AF_INET, SOCK_DGRAM, 0);"},
                        {"line": "bind(proxySockFd_, (sockaddr *)&proxyAddr, sizeof(proxyAddr));"},
                    ]
                }
            },
        },
    )
    resolver_score = _unix_path_priority(
        module + "/dns_resolv_listen.cpp", executions, target, (module,)
    )
    proxy_score = _unix_path_priority(
        module + "/dns_proxy_listen.cpp", executions, target, (module,)
    )
    assert resolver_score > proxy_score


def test_unix_path_priority_keeps_init_created_socket_server_in_context() -> None:
    target = normalize_target("/dev/unix/socket/fd_holder")
    module = "/openharmony/base/startup/init/services/init/standard"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "fd_holder"},
            "response": {
                "results": {
                    "/openharmony/base/startup/init/services/init/include/fd_holder_service.h": [
                        {"line": "typedef struct FdHolderService fd_holder;"}
                    ]
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "socket"},
            "response": {
                "results": {
                    module + "/init.c": [
                        {"line": "sock = socket(AF_UNIX, SOCK_DGRAM, 0);"},
                        {"line": "if (bind(sock, (struct sockaddr *)&addr, len) < 0) {}"},
                    ],
                    "/openharmony/base/startup/init/interfaces/innerkits/fd_holder/fd_holder.c": [
                        {"line": "sockFd = socket(AF_UNIX, SOCK_DGRAM, 0);"}
                    ],
                }
            },
        },
    )
    # The init implementation is in the target module context and carries a
    # bind path; a client helper that only calls socket() must not outrank it.
    assert _unix_path_priority(module + "/init.c", executions, target, (module,)) > _unix_path_priority(
        "/openharmony/base/startup/init/interfaces/innerkits/fd_holder/fd_holder.c",
        executions,
        target,
        (module,),
    )


def test_target_context_ignores_policy_literal_but_keeps_socket_config_anchor() -> None:
    target = normalize_target("/dev/unix/socket/paramservice")
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "paramservice"},
            "response": {
                "results": {
                    "/openharmony/base/security/selinux/paramservice.te": [
                        {"line": "type paramservice_socket, file_type;"}
                    ],
                    "/openharmony/base/startup/init/services/param/include/param_utils.h": [
                        {"line": '#define PIPE_NAME "/dev/unix/socket/paramservice"'}
                    ],
                }
            },
        },
    )
    contexts = _target_context_directories(executions, target)
    assert "/openharmony/base/security/selinux" not in contexts
    assert "/openharmony/base/startup/init/services/param/include" in contexts
    assert _path_role_adjustment("/openharmony/base/security/selinux/paramservice.te", target) < 0


def test_network_path_priority_prefers_socket_server_module_over_generic_source() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    module = "/openharmony/developtools/smartperf_host/smartperf_device/device_command/services/ipc"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "8283"},
            "response": {
                "results": {
                    module + "/include/sp_server_socket.h": [
                        {"line": "const int udpPort = 8283;"}
                    ]
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "socket"},
            "response": {
                "results": {
                    module + "/src/sp_server_socket.cpp": [
                        {"line": "int fd = socket(AF_INET, SOCK_DGRAM, 0);"}
                    ],
                    "/openharmony/foundation/communication/foo.cpp": [
                        {"line": "int fd = socket(AF_INET, SOCK_DGRAM, 0);"}
                    ],
                }
            },
        },
    )
    server_score = _network_path_priority(
        module + "/src/sp_server_socket.cpp", executions, target, (module + "/include", module)
    )
    unrelated_score = _network_path_priority(
        "/openharmony/foundation/communication/foo.cpp", executions, target, (module + "/include", module)
    )
    assert server_score > unrelated_score


def test_network_path_priority_does_not_promote_client_only_port_usage() -> None:
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    module = "/openharmony/developtools/smartperf"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "8283"},
            "response": {
                "results": {
                    module + "/client.cpp": [
                        {"line": "const int serverPort = 8283;"},
                        {"line": "sendto(fd, buf, len, 0, &addr, addrLen);"},
                    ],
                    module + "/server.cpp": [
                        {"line": "addr.sin_port = htons(8283);"},
                        {"line": "bind(fd, (sockaddr *)&addr, sizeof(addr));"},
                        {"line": "recvfrom(fd, buf, len, 0, nullptr, nullptr);"},
                    ],
                }
            },
        },
    )
    assert _network_path_priority(module + "/server.cpp", executions, target, (module,)) > _network_path_priority(
        module + "/client.cpp", executions, target, (module,)
    )


def test_network_path_priority_ignores_rejected_generic_hits() -> None:
    """排序不得重新计入证据门禁已经拒绝的跨模块 API 命中。"""

    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    module = "/openharmony/developtools_profiler/host/smartperf/client/client_command"
    unrelated = "/openharmony/foundation/communication/netmanager/dnsproxy.cpp"
    executions = (
        {
            "status": "ok",
            "query": {"kind": "full", "value": "8283"},
            "response": {
                "results": {
                    module + "/include/sp_server_socket.h": [
                        {"line": "const int udpPort = 8283;"}
                    ],
                    unrelated: [{"line": "const int tablePort = 8283;"}],
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "socket"},
            "response": {
                "results": {
                    module + "/sp_server_socket.cpp": [
                        {"line": "int fd = socket(AF_INET, SOCK_DGRAM, 0);"}
                    ],
                    unrelated: [
                        {"line": "int fd = socket(AF_INET, SOCK_DGRAM, 0);"}
                    ],
                }
            },
        },
        {
            "status": "ok",
            "query": {"kind": "full", "value": "bind"},
            "response": {
                "results": {
                    module + "/sp_server_socket.cpp": [
                        {"line": "bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local));"}
                    ],
                    unrelated: [
                        {"line": "bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local));"}
                    ],
                }
            },
        },
    )
    server_score = _network_path_priority(
        module + "/sp_server_socket.cpp", executions, target, (module,)
    )
    unrelated_score = _network_path_priority(unrelated, executions, target, (module,))
    assert server_score > unrelated_score
    assert unrelated_score < 100


def test_repository_mapping_ranking_prefers_server_roles_over_noisy_text_hits() -> None:
    from core.source_locator import EvidenceStore

    store = EvidenceStore()
    server_ids = [
        store.add_evidence(
            kind="service_config",
            source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
            line_start=441,
            excerpt="info.server = PIPE_NAME;",
            tool_name="fixture",
        ).evidence_id,
        store.add_evidence(
            kind="socket_server_registration",
            source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
            line_start=445,
            excerpt="ret = ParamServerCreate(&task, &info);",
            tool_name="fixture",
        ).evidence_id,
        store.add_evidence(
            kind="socket_accept_read",
            source_path="/openharmony/base/startup/init/services/param/linux/param_request.c",
            line_start=101,
            excerpt="recv(fd, buffer, size, 0);",
            tool_name="fixture",
        ).evidence_id,
        store.add_evidence(
            kind="protocol_dispatch",
            source_path="/openharmony/base/startup/init/services/param/linux/param_request.c",
            line_start=76,
            excerpt="switch (recvMsg->type) {",
            tool_name="fixture",
        ).evidence_id,
    ]
    noisy_ids = [
        store.add_evidence(
            kind="literal_match",
            source_path=f"/openharmony/foundation/filemanagement/dfs_service/src/noisy_{index}.cpp",
            line_start=index + 1,
            excerpt="NotifyParamService paramservice;",
            tool_name="fixture",
        ).evidence_id
        for index in range(40)
    ]
    startup = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=tuple(server_ids),
    )
    noisy = RepositoryMapping(
        project_name="filemanagement_dfs_service",
        source_root="foundation/filemanagement/dfs_service",
        repo_url="https://gitcode.com/openharmony/filemanagement_dfs_service",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/foundation/filemanagement/dfs_service/src/noisy_0.cpp",
        evidence_ids=tuple(noisy_ids),
    )

    startup_score, _ = _mapping_role_score(startup, store)
    noisy_score, _ = _mapping_role_score(noisy, store)
    assert startup_score > noisy_score


def test_repository_mapping_ranking_prefers_target_bound_consumer_source_over_isolated_bind() -> None:
    """The actual endpoint consumer must beat an unrelated generic bind hit."""

    from core.source_locator import EvidenceStore

    target = normalize_target("/dev/unix/socket/fd_holder")
    store = EvidenceStore()
    consumer = store.add_evidence(
        kind="socket_accept_read",
        source_path=(
            "/openharmony/base/startup/init/interfaces/innerkits/fd_holder/"
            "fd_holder_internal.c"
        ),
        line_start=137,
        excerpt="ssize_t rc = TEMP_FAILURE_RETRY(recvmsg(sock, &msghdr, flags));",
        tool_name="fixture",
    )
    generic_bind = store.add_evidence(
        kind="socket_bind_listen",
        source_path=(
            "/openharmony/foundation/communication/netmanager_base/"
            "services/netmanagernative/src/manager/vpn_manager.cpp"
        ),
        line_start=200,
        excerpt="bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));",
        tool_name="fixture",
    )
    startup = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path=consumer.source_path,
        evidence_ids=(consumer.evidence_id,),
    )
    netmanager = RepositoryMapping(
        project_name="communication_netmanager_base",
        source_root="foundation/communication/netmanager_base",
        repo_url="https://gitcode.com/openharmony/communication_netmanager_base",
        revision="OpenHarmony-6.1-LTS",
        source_path=generic_bind.source_path,
        evidence_ids=(generic_bind.evidence_id,),
    )

    startup_score, startup_counts = _mapping_role_score(startup, store, target=target)
    netmanager_score, _ = _mapping_role_score(netmanager, store, target=target)

    assert startup_score > netmanager_score
    assert startup_counts["target_server_source_anchor"] == 1


def test_repository_mapping_ranking_prefers_confirmed_semantic_server_owner() -> None:
    """A model-confirmed registration must beat telemetry API basename hits."""

    target = normalize_target("/dev/unix/socket/hisysevent")
    store = EvidenceStore()
    owner = store.add_evidence(
        kind="socket_server_registration",
        source_path="/openharmony/base/hiviewdfx/hiview/plugins/sysevent_source/event_server.cpp",
        line_start=313,
        excerpt='AddDev(std::make_shared<SocketDevice>("hisysevent", eventCountPerCycle));',
        tool_name="fixture",
    )
    noisy_ids = [
        store.add_evidence(
            kind="service_config",
            source_path=f"/openharmony/foundation/distributedhardware/distributed_audio/common/dfx_utils/src/daudio_{index}.cpp",
            line_start=index + 1,
            excerpt="HiSysEvent::EventType::BEHAVIOR,",
            tool_name="fixture",
        ).evidence_id
        for index in range(12)
    ]
    semantic_mapping = RepositoryMapping(
        project_name="hiviewdfx_hiview",
        source_root="base/hiviewdfx/hiview",
        repo_url="https://gitcode.com/openharmony/hiviewdfx_hiview",
        revision="OpenHarmony-6.1-LTS",
        source_path=owner.source_path,
        evidence_ids=(owner.evidence_id,),
    )
    noisy_mapping = RepositoryMapping(
        project_name="distributedhardware_distributed_audio",
        source_root="foundation/distributedhardware/distributed_audio",
        repo_url="https://gitcode.com/openharmony/distributedhardware_distributed_audio",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/foundation/distributedhardware/distributed_audio/common/dfx_utils/src/daudio_0.cpp",
        evidence_ids=tuple(noisy_ids),
    )

    owner_score, owner_counts = _mapping_role_score(
        semantic_mapping,
        store,
        target=target,
        semantic_server_evidence_ids=(owner.evidence_id,),
    )
    noisy_score, noisy_counts = _mapping_role_score(
        noisy_mapping,
        store,
        target=target,
        semantic_server_evidence_ids=(owner.evidence_id,),
    )
    assert owner_score > noisy_score
    assert owner_counts["llm_server_owner_anchor"] == 1
    assert "llm_server_owner_anchor" not in noisy_counts


def test_repository_mapping_ranking_preserves_case_sensitive_socket_identity() -> None:
    """LowerCamel socket names must remain ownership anchors during ranking."""

    from core.source_locator import EvidenceStore

    target = normalize_target("/dev/unix/socket/hilogControl")
    store = EvidenceStore()
    owner_rows = [
        store.add_evidence(
            kind="service_config",
            source_path="/openharmony/base/hiviewdfx/hilog/services/hilogd/etc/hilogd.cfg",
            line_start=47,
            excerpt='"name" : "hilogControl",',
            tool_name="fixture",
        ),
        store.add_evidence(
            kind="socket_accept_read",
            source_path="/openharmony/base/hiviewdfx/hilog/frameworks/libhilog/socket/socket_server.cpp",
            line_start=75,
            excerpt="return TEMP_FAILURE_RETRY(recv(socketHandler, buffer, bufferLen, flags));",
            tool_name="fixture",
        ),
    ]
    generic = store.add_evidence(
        kind="socket_bind_listen",
        source_path="/openharmony/foundation/communication/netmanager_base/services/netmanagernative/src/manager/vpn_manager.cpp",
        line_start=200,
        excerpt="bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));",
        tool_name="fixture",
    )
    owner = RepositoryMapping(
        project_name="hiviewdfx_hilog",
        source_root="base/hiviewdfx/hilog",
        repo_url="https://gitcode.com/openharmony/hiviewdfx_hilog",
        revision="OpenHarmony-6.1-LTS",
        source_path=owner_rows[1].source_path,
        evidence_ids=tuple(item.evidence_id for item in owner_rows),
    )
    noisy = RepositoryMapping(
        project_name="communication_netmanager_base",
        source_root="foundation/communication/netmanager_base",
        repo_url="https://gitcode.com/openharmony/communication_netmanager_base",
        revision="OpenHarmony-6.1-LTS",
        source_path=generic.source_path,
        evidence_ids=(generic.evidence_id,),
    )

    owner_score, owner_counts = _mapping_role_score(owner, store, target=target)
    generic_score, _ = _mapping_role_score(noisy, store, target=target)

    assert owner_counts["target_identity_anchor"] == 1
    assert owner_score > generic_score


def test_repository_mapping_ranking_prefers_target_bound_registration_over_client_api_use() -> None:
    """A named service registration must beat a client-side socket writer."""

    from core.source_locator import EvidenceStore

    target = normalize_target("/dev/unix/socket/hisysevent")
    store = EvidenceStore()
    registration = store.add_evidence(
        kind="socket_server_registration",
        source_path="/openharmony/base/hiviewdfx/hiview/plugins/sysevent_source/event_server.cpp",
        line_start=313,
        excerpt='AddDev(std::make_shared<SocketDevice>("hisysevent", eventCountPerCycle));',
        tool_name="fixture",
    )
    client_rows = [
        store.add_evidence(
            kind="service_config",
            source_path="/openharmony/base/hiviewdfx/hisysevent/interfaces/native/innerkits/hisysevent/event_socket_factory.cpp",
            line_start=38,
            excerpt='.sun_path = "/dev/unix/socket/hisysevent",',
            tool_name="fixture",
        ),
        store.add_evidence(
            kind="socket_acquire",
            source_path="/openharmony/base/hiviewdfx/hisysevent/interfaces/native/innerkits/hisysevent_easy/easy_socket_writer.c",
            line_start=67,
            excerpt="int socketId = TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_DGRAM, 0));",
            tool_name="fixture",
        ),
    ]
    owner = RepositoryMapping(
        project_name="hiviewdfx_hiview",
        source_root="base/hiviewdfx/hiview",
        repo_url="https://gitcode.com/openharmony/hiviewdfx_hiview",
        revision="OpenHarmony-6.1-LTS",
        source_path=registration.source_path,
        evidence_ids=(registration.evidence_id,),
    )
    client = RepositoryMapping(
        project_name="hiviewdfx_hisysevent",
        source_root="base/hiviewdfx/hisysevent",
        repo_url="https://gitcode.com/openharmony/hiviewdfx_hisysevent",
        revision="OpenHarmony-6.1-LTS",
        source_path=client_rows[0].source_path,
        evidence_ids=tuple(item.evidence_id for item in client_rows),
    )

    owner_score, owner_counts = _mapping_role_score(owner, store, target=target)
    client_score, _ = _mapping_role_score(client, store, target=target)

    assert owner_counts["target_server_source_anchor"] == 1
    assert owner_score > client_score


def test_mapping_identity_ranking_does_not_treat_hisysevent_api_name_as_socket_owner() -> None:
    """The HiSysEvent API class is not the named hisysevent socket."""

    from core.source_locator import EvidenceStore

    target = normalize_target("/dev/unix/socket/hisysevent")
    store = EvidenceStore()
    api = store.add_evidence(
        kind="service_config",
        source_path="/openharmony/foundation/multimodalinput/input/service/dfx/src/dfx_hisysevent.cpp",
        line_start=93,
        excerpt="if (type == OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR) {",
        tool_name="fixture",
    )
    mapping = RepositoryMapping(
        project_name="multimodalinput_input",
        source_root="foundation/multimodalinput/input",
        repo_url="https://gitcode.com/openharmony/multimodalinput_input",
        revision="OpenHarmony-6.1-LTS",
        source_path=api.source_path,
        evidence_ids=(api.evidence_id,),
    )

    score, counts = _mapping_role_score(mapping, store, target=target)

    assert counts["target_identity_anchor"] == 0
    assert score <= 180


def test_llm_search_default_budget_is_forty_rounds_and_hard_capped() -> None:
    from core.source_locator import (
        LLM_SEARCH_DEFAULT_MAX_ACTIONS,
        LLM_SEARCH_DEFAULT_MAX_MODEL_CALLS,
        LLM_SEARCH_MAX_MODEL_CALLS,
        PlannerBudget,
    )

    assert _budget_int(
        {},
        "max_llm_actions",
        default=LLM_SEARCH_DEFAULT_MAX_ACTIONS,
        maximum=LLM_SEARCH_DEFAULT_MAX_ACTIONS,
        minimum=0,
    ) == 40
    assert _budget_int(
        {"max_llm_actions": 99},
        "max_llm_actions",
        default=LLM_SEARCH_DEFAULT_MAX_ACTIONS,
        maximum=LLM_SEARCH_DEFAULT_MAX_ACTIONS,
        minimum=0,
    ) == 40
    assert PlannerBudget(max_actions=40, max_model_calls=LLM_SEARCH_DEFAULT_MAX_MODEL_CALLS).max_actions == 40
    assert PlannerBudget(max_actions=40, max_model_calls=48).max_model_calls == 48
    assert LLM_SEARCH_MAX_MODEL_CALLS >= 48


class _FakeOpenGrok:
    def __init__(self) -> None:
        self.search_calls = 0
        self.document = SourceDocument(
            path=TARGET_PATH,
            source="fixture",
            content=(
                '#define PARAM_SERVICE "/dev/unix/socket/paramservice"\n'
                'service_name = "/dev/unix/socket/paramservice"\n'
                "int bind(int fd, void *addr) { return 0; }\n"
                "int accept(int fd, void *addr) { return 0; }\n"
                "int dispatch_request(int fd) { return 0; }\n"
                'request_payload = "/dev/unix/socket/paramservice";\n'
                "int connect(int fd, void *addr) { return 0; }\n"
                "int send(int fd, void *buf) { return 0; }\n"
            ),
        )
        self.response = SearchResponse(
            time_ms=1,
            result_count=1,
            start_document=0,
            end_document=0,
            results={
                TARGET_PATH: tuple(
                    SearchHit(line=line, line_number=str(number))
                    for number, line in enumerate(self.document.content.splitlines(), 1)
                )
            },
        )

    def probe(self, *, probe_path: str | None = None) -> ProbeResult:
        del probe_path
        capabilities = {
            name: EndpointCapability(name=name, available=True, status_code=200)
            for name in ("search", "raw", "file_content", "xref")
        }
        return ProbeResult(
            base_url="https://fixture.example/source",
            api_prefix="/api/v1",
            reachable=True,
            version="1.14.11",
            capabilities=capabilities,
        )

    def search(self, **kwargs) -> SearchResponse:
        self.search_calls += 1
        del kwargs
        return self.response

    def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
        if path != TARGET_PATH:
            raise OpenGrokHTTPError(
                "fixture path not found",
                status_code=404,
                endpoint="/raw/" + path.lstrip("/"),
            )
        del max_bytes
        return self.document


def test_worker_reaches_confirmation_with_all_audit_artifacts(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    machine = LocatorSessionStore(sessions).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 12, "max_results": 8, "max_hits_per_file": 8},
        session_id="loc_worker123456",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    runtime = SourceLocatorRuntime(client=_FakeOpenGrok(), manifest=manifest)

    session = SourceLocatorWorker(machine, runtime=runtime).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert session.repository_mappings is not None
    mapping = session.repository_mappings["mappings"][0]
    assert mapping["project_name"] == "startup_init"
    assert mapping["status"] == "resolved"
    assert session.server_attribution is not None
    assert session.server_attribution["status"] == "HIGH"
    assert session.client_attribution is not None
    assert session.client_attribution["status"] == "HIGH"

    session_dir = sessions / session.session_id
    expected = {
        "target.json",
        "probe.json",
        "search_plan.json",
        "evidence.json",
        "path_classification.json",
        "server_attribution.json",
        "client_attribution.json",
        "repository_resolutions.json",
        "verification.json",
        "confirmation_summary.json",
        "session.json",
        "events.jsonl",
    }
    assert expected <= {path.name for path in session_dir.iterdir()}
    evidence = json.loads((session_dir / "evidence.json").read_text(encoding="utf-8"))
    kinds = {item["kind"] for item in evidence["evidence"]}
    assert {"service_config", "socket_bind_listen", "socket_accept_read", "protocol_dispatch"} <= kinds
    summary = json.loads((session_dir / "confirmation_summary.json").read_text(encoding="utf-8"))
    assert summary["repository"]["project_name"] == "startup_init"
    assert summary["repository"]["repo_url"] == "https://gitcode.com/openharmony/startup_init"
    assert summary["repository"]["destination"].endswith("source_code_base/startup_init")
    assert summary["server"]["confirmed"] is True
    assert summary["evidence"]
    assert all("source_path" in item and "excerpt" in item for item in summary["evidence"])
    role_evidence = summary["server"]["roles"][0]["source_evidence"]
    assert role_evidence
    assert all(
        "source_path" in item
        and "line_start" in item
        and "line_end" in item
        and "excerpt" in item
        for item in role_evidence
    )
    role_ids = {
        evidence_id
        for role in summary["server"]["roles"]
        for evidence_id in role["evidence_ids"]
    }
    assert role_ids <= {item["evidence_id"] for item in summary["evidence"]}


def test_worker_follows_source_defined_alias_to_cpp_listener(tmp_path: Path) -> None:
    """A target path should discover a related macro without an LLM call."""

    fake = _FakeOpenGrok()
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 20, "max_results": 8, "max_hits_per_file": 8},
        session_id="loc_workermacro1",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest),
    ).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    plan = json.loads(
        (tmp_path / "sessions" / session.session_id / "search_plan.json").read_text(encoding="utf-8")
    )
    assert plan["follow_up"]["related_macros"] == ["PARAM_SERVICE"]
    assert any(
        action.startswith("full:cxx:PARAM_SERVICE")
        for action in session.executed_actions
    )


def test_worker_stops_safely_without_opengrok_configuration(tmp_path: Path) -> None:
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/unknown",
        session_id="loc_worker987654",
    )
    session = SourceLocatorWorker(machine).run_until_pause(max_steps=32)
    assert session.state == "OPENGROK_UNAVAILABLE"
    assert session.last_error == "未配置 source_locator.opengrok"


def test_runtime_from_explicit_config_loads_manifest_without_network(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "source_locator": {
                    "enabled": True,
                    "target_revision": "OpenHarmony-6.1-LTS",
                    "opengrok": {
                        "base_url": "https://fixture.example/source",
                        "project": "openharmony",
                        "api_prefix": "/api/v1",
                        "max_retries": 0,
                    },
                    "manifest": {"source": "local", "path": "tests/source_locator/fixtures/manifests/ohos.xml"},
                    "gitcode": {"destination_root": "source_code_base"},
                }
            }
        ),
        encoding="utf-8",
    )

    runtime = runtime_from_config(config, project_root=CORE_ROOT)
    assert runtime.client is not None
    assert runtime.manifest is not None
    assert runtime.manifest.projects[0].name == "communication"
    assert runtime.target_revision == "OpenHarmony-6.1-LTS"


def test_feedback_keeps_old_evidence_and_does_not_repeat_initial_queries(tmp_path: Path) -> None:
    fake = _FakeOpenGrok()
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerfeedback1",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    worker = SourceLocatorWorker(machine, runtime=SourceLocatorRuntime(client=fake, manifest=manifest))
    first = worker.run_until_pause(max_steps=32)
    assert first.state == "AWAIT_USER_CONFIRMATION"
    first_evidence = json.loads(
        (tmp_path / "sessions" / first.session_id / "evidence.json").read_text(encoding="utf-8")
    )
    first_calls = fake.search_calls

    machine.reject("这是错误候选，请重新检查服务端", required_role="server_consumer")
    machine.resume_after_feedback()
    after = worker.run_until_pause(max_steps=32)

    assert after.state == "PARTIAL"
    assert fake.search_calls == first_calls
    second_evidence = json.loads(
        (tmp_path / "sessions" / first.session_id / "evidence.json").read_text(encoding="utf-8")
    )
    assert second_evidence == first_evidence


def test_worker_executes_one_validated_llm_search_action_and_keeps_raw_response_out(tmp_path: Path) -> None:
    fake = _FakeOpenGrok()

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        evidence_id = context["evidence_ids"][0]
        return {
            "kind": "search_definition",
            "query": "PARAM_SERVICE_SOCKET",
            "justification": "验证初始命中对应的宏定义",
            "expected_relation": "macro_definition",
            "purpose": "normal",
            "evidence_used": [evidence_id],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerllm1234",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(model_call=model)
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    )

    session = worker.run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert "llm_search.json" in session.artifacts
    payload = json.loads((tmp_path / "sessions" / session.session_id / "llm_search.json").read_text(encoding="utf-8"))
    assert payload["plan"]["status"] == "READY"
    assert payload["execution"]["status"] == "ok"
    assert "raw model response" not in json.dumps(payload, ensure_ascii=False)
    assert any(item.startswith("search_definition:") for item in session.executed_actions)
    events = LocatorSessionStore(tmp_path / "sessions").events(session.session_id).load()
    llm_events = [event for event in events if event.type == "llm.search.round"]
    assert len(llm_events) == 2
    event_details = llm_events[0].details
    assert event_details["round"] == 1
    assert event_details["plan"]["action"]["kind"] == "search_definition"
    assert event_details["execution"]["query"]["params"]["def"] == "PARAM_SERVICE_SOCKET"
    assert event_details["evidence_ids"]
    assert "raw model response" not in json.dumps(event_details, ensure_ascii=False)
    assert llm_events[1].details["plan"]["status"] == "REPEATED"


def test_worker_persists_one_evidence_constrained_llm_role_review(tmp_path: Path) -> None:
    fake = _FakeOpenGrok()
    calls: list[str] = []

    def role_model(prompt: str):
        calls.append(prompt)
        context = json.loads(prompt)
        evidence_id = context["evidence"][0]["evidence_id"]
        return {
            "server": {
                "status": "confirmed",
                "confidence": "high",
                "subject": "ParamService",
                "evidence_ids": [evidence_id],
                "reason": "模型依据已读取的服务端源码证据确认角色",
            },
            "client": {
                "status": "unresolved",
                "confidence": "low",
                "subject": "",
                "evidence_ids": [],
                "reason": "当前证据没有确认客户端边界",
            },
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerrole1234",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    role_attributor = LLMRoleAttributor(model_call=role_model)
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_role_attributor=role_attributor),
    )

    session = worker.run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert len(calls) == 1
    assert "llm_role_attribution.json" in session.artifacts
    role_payload = json.loads(
        (tmp_path / "sessions" / session.session_id / "llm_role_attribution.json").read_text(encoding="utf-8")
    )
    assert role_payload["server"]["status"] == "confirmed"
    assert "raw model response" not in json.dumps(role_payload, ensure_ascii=False)
    server_payload = json.loads(
        (tmp_path / "sessions" / session.session_id / "server_attribution.json").read_text(encoding="utf-8")
    )
    assert server_payload["predicates"]["llm_server_confirmed"] is True
    assert server_payload["semantic_decision"]["status"] == "confirmed"


def test_worker_candidate_pk_can_override_noisy_high_score_copy(tmp_path: Path) -> None:
    class _MetadataOpenGrok(_FakeOpenGrok):
        def __init__(self) -> None:
            super().__init__()
            self.metadata = {
                "/openharmony/developtools/profiler/host/smartperf/client/client_command/BUILD.gn": SourceDocument(
                    path="/openharmony/developtools/profiler/host/smartperf/client/client_command/BUILD.gn",
                    source="fixture",
                    content='ohos_executable("SP_daemon") {\n  "sp_server_socket.cpp",\n}\n',
                ),
                "/openharmony/developtools/smartperf_host/smartperf_device/device_command/services/ipc/BUILD.gn": SourceDocument(
                    path="/openharmony/developtools/smartperf_host/smartperf_device/device_command/services/ipc/BUILD.gn",
                    source="fixture",
                    content='ohos_shared_library("smartperf_ipc") {\n  "sp_server_socket.cpp",\n}\n',
                ),
            }

        def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
            if path in self.metadata:
                return self.metadata[path]
            return super().read_source(path, max_bytes=max_bytes)

    client = _MetadataOpenGrok()
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "SP_daemon UDP 127.0.0.1:8283",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_candidatepk01",
    )
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    machine.transition(
        "NORMALIZE_TARGET",
        summary_zh="fixture target normalized",
        updates={"target": target.to_dict()},
    )
    store = EvidenceStore()
    profiler_source = "/openharmony/developtools/profiler/host/smartperf/client/client_command/sp_server_socket.cpp"
    smartperf_source = "/openharmony/developtools/smartperf_host/smartperf_device/device_command/services/ipc/sp_server_socket.cpp"
    profiler_evidence = store.add_evidence(
        kind="socket_accept_read",
        source_path=profiler_source,
        line_start=10,
        excerpt="recvfrom(fd, buffer, size, 0, nullptr, nullptr);",
        tool_name="fixture",
    )
    smartperf_evidence = store.add_evidence(
        kind="socket_accept_read",
        source_path=smartperf_source,
        line_start=10,
        excerpt="recvfrom(fd, buffer, size, 0, nullptr, nullptr);",
        tool_name="fixture",
    )
    profiler = RepositoryMapping(
        project_name="developtools_profiler",
        source_root="developtools/profiler",
        repo_url="https://gitcode.com/openharmony/developtools_profiler",
        revision="OpenHarmony-6.1-LTS",
        source_path=profiler_source,
        evidence_ids=(profiler_evidence.evidence_id,),
    )
    smartperf = RepositoryMapping(
        project_name="developtools_smartperf_host",
        source_root="developtools/smartperf_host",
        repo_url="https://gitcode.com/openharmony/developtools_smartperf_host",
        revision="OpenHarmony-6.1-LTS",
        source_path=smartperf_source,
        evidence_ids=(smartperf_evidence.evidence_id,),
    )

    def model(prompt: str):
        payload = json.loads(prompt)
        profiler_row = next(item for item in payload["candidates"] if item["project_name"] == "developtools_profiler")
        build_id = profiler_row["source_facts"][0]["evidence_id"]
        return {
            "primary_repository": "developtools_profiler",
            "primary_role": "process_owner",
            "confidence": "high",
            "reason": "BUILD.gn 明确声明 SP_daemon，另一仓库只有共享库副本",
            "evidence_ids": [build_id],
            "related_repositories": [
                {
                    "project_name": "developtools_smartperf_host",
                    "role": "duplicate_or_split_source",
                    "evidence_ids": [smartperf_evidence.evidence_id],
                }
            ],
        }

    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(
            client=client,
            llm_candidate_reviewer=LLMCandidateReviewer(model_call=model),
        ),
    )
    selected, review, artifacts = worker._run_candidate_review((smartperf, profiler), store, target)
    assert selected.project_name == "developtools_profiler"
    assert review["status"] == "complete"
    assert review["selected_by"] == "llm_candidate_review"
    assert review["decision"]["primary_role"] == "process_owner"
    assert "repository_candidate_review.json" in artifacts
    assert (tmp_path / "sessions" / machine.session.session_id / "repository_candidate_review.json").exists()
    selected_row = next(
        item for item in review["candidates"] if item["project_name"] == "developtools_profiler"
    )
    metadata_ids = {
        fact["evidence_id"]
        for fact in selected_row["source_facts"]
        if isinstance(fact, dict) and isinstance(fact.get("evidence_id"), str)
    }
    assert metadata_ids & set(selected.evidence_ids)


def test_final_role_review_ignores_evidence_from_losing_repository() -> None:
    mapping = RepositoryMapping(
        project_name="developtools_profiler",
        source_root="developtools/profiler",
        repo_url="https://gitcode.com/openharmony/developtools_profiler",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/developtools/profiler/sp_server_socket.cpp",
        evidence_ids=("E-prof-build",),
    )
    result = LLMRoleAttributionResult(
        server=LLMRoleDecision(
            role="server",
            status="confirmed",
            confidence="high",
            subject="SpServerSocket",
            evidence_ids=("E-smart-bind",),
            reason="模型依据另一候选仓库中的 bind/recvfrom 证据确认服务端。",
        ),
        client=LLMRoleDecision(
            role="client",
            status="unresolved",
            confidence="low",
            subject="",
            evidence_ids=(),
            reason="未发现客户端连接证据。",
        ),
    )

    scoped = _scope_llm_role_result_to_mapping(result, mapping)

    assert scoped is not None
    assert scoped.server.status == "unresolved"
    assert scoped.server.evidence_ids == ()
    assert "其他候选仓库" in scoped.server.reason


def test_worker_feeds_each_llm_tool_result_into_next_round(tmp_path: Path) -> None:
    """Semantic rounds must observe evidence produced by the prior tool call."""

    fake = _FakeOpenGrok()
    contexts: list[dict[str, object]] = []

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        contexts.append(context)
        evidence_id = context["evidence_ids"][0]
        if len(contexts) == 1:
            return {
                "kind": "read_file",
                # The live OpenGrok index returns /openharmony/... paths,
                # while a model may use the tree-relative /base/... spelling.
                # The worker should resolve that alias from existing evidence.
                "query": "/base/startup/init/services/param/param_service.c",
                "justification": "读取初始命中的服务文件，确认源码操作",
                "expected_relation": "socket_accept_read",
                "purpose": "normal",
                "evidence_used": [evidence_id],
            }
        return {
            "kind": "search_full",
            "query": "ReceiveFds",
            "justification": "根据刚读取的源码继续找消费函数",
            "expected_relation": "socket_accept_read",
            "purpose": "normal",
            "evidence_used": [evidence_id],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 20, "max_results": 8, "max_hits_per_file": 8, "max_llm_actions": 2},
        session_id="loc_workerllmround",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(model_call=model)
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    ).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert len(contexts) == 2
    assert len(contexts[1]["evidence_ids"]) > len(contexts[0]["evidence_ids"])
    payload = json.loads(
        (tmp_path / "sessions" / session.session_id / "llm_search.json").read_text(encoding="utf-8")
    )
    assert payload["round_count"] == 2
    assert [item["plan"]["action"]["kind"] for item in payload["rounds"]] == ["read_file", "search_full"]
    assert payload["rounds"][0]["execution"]["requested_path"].startswith("/base/")
    assert payload["rounds"][0]["execution"]["path"] == TARGET_PATH
    search_plan = json.loads(
        (tmp_path / "sessions" / session.session_id / "search_plan.json").read_text(encoding="utf-8")
    )
    assert any(
        execution.get("kind") == "read_file" and execution.get("path") == TARGET_PATH
        for execution in search_plan["executions"]
    )


def test_worker_continues_after_transient_llm_tool_failure(tmp_path: Path) -> None:
    """A failed OpenGrok action is fed back instead of ending the loop."""

    class _FailOnceOpenGrok(_FakeOpenGrok):
        def search(self, **kwargs) -> SearchResponse:
            if kwargs.get("full") == "bind":
                raise OpenGrokHTTPError(
                    "fixture rejects the broad bind probe",
                    status_code=400,
                    endpoint="/api/v1/search",
                )
            return super().search(**kwargs)

    store = EvidenceStore()
    evidence = store.add_evidence(
        kind="service_config",
        source_path="/openharmony/base/startup/init/services/param/param_utils.h",
        line_start=1,
        excerpt='#define PARAM_SERVICE "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    target = normalize_target("/dev/unix/socket/paramservice")
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        budget={"max_llm_actions": 2},
        session_id="loc_workerllmfail1",
    )
    contexts: list[dict[str, object]] = []

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        contexts.append(context)
        query = "bind(" if len(contexts) == 1 else "GetControlSocket"
        return {
            "kind": "search_full",
            "query": query,
            "justification": "补充服务端通信证据",
            "expected_relation": "socket_acquire_or_bind",
            "purpose": "normal",
            "evidence_used": [evidence.evidence_id],
        }

    planner = LLMSearchPlanner(
        model_call=model,
        budget=PlannerBudget(max_actions=2, max_model_calls=2),
    )
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=_FailOnceOpenGrok(), llm_planner=planner),
    )

    audits, action_keys, _queries = worker._run_llm_actions(
        target=target,
        store=store,
        search_payload={"executions": []},
    )

    assert len(audits) == 2
    assert action_keys == ["search_full:bind", "search_full:GetControlSocket"]
    assert audits[0]["execution"]["status"] == "error"
    assert audits[1]["execution"]["status"] == "ok"
    assert "执行失败" in contexts[1]["recovery"]["last_feedback"]


class _RecoveryOpenGrok:
    """OpenGrok fixture whose first evidence set misses registration.

    The recovery planner must find the second source file, after which the
    ordinary trace/attribution stages—not model prose—confirm the server.
    """

    def __init__(self) -> None:
        self.path = "/openharmony/base/startup/init/services/param/linux/param_server.c"
        self.document = SourceDocument(
            path=self.path,
            source="fixture",
            content=(
                '#define PARAM_SERVICE "/dev/unix/socket/paramservice"\n'
                'service_name = "/dev/unix/socket/paramservice"\n'
                "int start_service(void) {\n"
                "    return CreateSocketListener(&listener, endpoint);\n"
                "}\n"
                "int handle_request(int fd) {\n"
                "    recv(fd, buffer, size, 0);\n"
                "    switch (request_type) { case 1: return 0; default: return -1; }\n"
                "}\n"
            ),
        )
        self.response = SearchResponse(
            time_ms=1,
            result_count=1,
            start_document=0,
            end_document=0,
            results={
                self.path: (
                    SearchHit(
                        line="ret = CreateSocketListener(&listener, endpoint);",
                        line_number="4",
                    ),
                )
            },
        )

    def search(self, **kwargs) -> SearchResponse:
        del kwargs
        return self.response

    def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
        if path != self.path:
            raise OpenGrokHTTPError("fixture path not found", status_code=404, endpoint="/raw/" + path.lstrip("/"))
        del max_bytes
        return self.document


def test_worker_recovers_missing_server_predicate_with_bounded_llm_round(tmp_path: Path) -> None:
    """A missing acquire/bind predicate enters recovery and returns to trace."""

    from core.source_locator import EvidenceStore
    from core.source_locator.worker import _json_write

    root = tmp_path / "sessions"
    machine = LocatorSessionStore(root).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_llm_actions": 2, "max_llm_recovery_runs": 1},
        session_id="loc_workerrecovery",
    )
    target = normalize_target("/dev/unix/socket/paramservice", target_revision="OpenHarmony-6.1-LTS")
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    evidence = EvidenceStore()
    identity = evidence.add_evidence(
        kind="literal_match",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=1,
        excerpt='#define PARAM_SERVICE "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="service_config",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=2,
        excerpt='service_name = "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="socket_accept_read",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=4,
        excerpt="recv(fd, buffer, size, 0);",
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="protocol_dispatch",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=5,
        excerpt="switch (request_type)",
        tool_name="fixture",
    )
    session_dir = root / machine.session.session_id
    _json_write(session_dir / "evidence.json", evidence.to_dict())
    _json_write(session_dir / "search_plan.json", {"executions": []})
    mapping = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=tuple(item.evidence_id for item in evidence.evidence),
    )
    for state, updates in (
        ("NORMALIZE_TARGET", {"target": target.to_dict()}),
        ("PROBE_OPENGROK", {}),
        ("SEARCH_INITIAL", {}),
        ("TRACE_EVIDENCE", {}),
        ("ATTRIBUTION_SERVER", {}),
        ("LOCATE_CLIENT_COMM", {}),
        ("RESOLVE_REPOSITORIES", {"repository_mappings": {"mappings": [mapping.to_dict()]}}),
        ("VERIFY_EVIDENCE", {}),
    ):
        machine.transition(state, summary_zh=state, updates=updates)

    contexts: list[dict[str, object]] = []

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        contexts.append(context)
        return {
            "kind": "search_full",
            "query": "CreateSocketListener",
            "justification": "补充缺失的服务端注册证据",
            "expected_relation": "socket_server_registration",
            "purpose": "recovery",
            "evidence_used": [context["evidence_ids"][0] or identity.evidence_id],
        }

    planner = LLMSearchPlanner(model_call=model, budget=PlannerBudget(max_actions=2, max_model_calls=2))
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=_RecoveryOpenGrok(), manifest=manifest, llm_planner=planner),
    )

    recovered = worker.advance()
    assert recovered.state == "RECOVER_EVIDENCE"
    after_recovery = worker.advance()
    assert after_recovery.state == "TRACE_EVIDENCE"
    assert contexts and contexts[0]["phase"] == "verification_recovery"
    assert "socket_acquire_or_bind" in contexts[0]["recovery"]["missing_predicates"]
    assert (session_dir / "evidence_recovery.json").exists()
    assert json.loads((session_dir / "llm_search.json").read_text(encoding="utf-8"))["round_count"] >= 1
    final = worker.run_until_pause(max_steps=16)
    assert final.state == "AWAIT_USER_CONFIRMATION"
    assert final.server_attribution and final.server_attribution["status"] == "HIGH"


def test_worker_enters_confirmation_when_server_predicate_remains_missing(tmp_path: Path) -> None:
    """A resolved mapping remains confirmable when attribution is incomplete.

    The missing predicate is deliberately kept in the persisted attribution
    and confirmation summary.  It is an advisory warning, not a terminal
    ``PARTIAL`` gate; cloning can only start after the explicit state-machine
    confirmation operation.
    """

    from core.source_locator import EvidenceStore
    from core.source_locator.worker import _json_write

    root = tmp_path / "sessions"
    machine = LocatorSessionStore(root).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workeradvisory",
    )
    target = normalize_target("/dev/unix/socket/paramservice", target_revision="OpenHarmony-6.1-LTS")
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    evidence = EvidenceStore()
    evidence.add_evidence(
        kind="literal_match",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=1,
        excerpt='#define PARAM_SERVICE "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="service_config",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=2,
        excerpt='service_name = "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="socket_accept_read",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=4,
        excerpt="recv(fd, buffer, size, 0);",
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="protocol_dispatch",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=5,
        excerpt="switch (request_type)",
        tool_name="fixture",
    )
    session_dir = root / machine.session.session_id
    _json_write(session_dir / "evidence.json", evidence.to_dict())
    mapping = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=tuple(item.evidence_id for item in evidence.evidence),
    )
    for state, updates in (
        ("NORMALIZE_TARGET", {"target": target.to_dict()}),
        ("PROBE_OPENGROK", {}),
        ("SEARCH_INITIAL", {}),
        ("TRACE_EVIDENCE", {}),
        ("ATTRIBUTION_SERVER", {}),
        ("LOCATE_CLIENT_COMM", {}),
        ("RESOLVE_REPOSITORIES", {"repository_mappings": {"mappings": [mapping.to_dict()]}}),
        ("VERIFY_EVIDENCE", {}),
    ):
        machine.transition(state, summary_zh=state, updates=updates)

    session = SourceLocatorWorker(
        machine,
        # No planner is configured: this directly exercises the post-recovery
        # fallback and makes sure it still presents the resolved mapping.
        runtime=SourceLocatorRuntime(manifest=manifest),
    ).advance()

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert session.last_error is None
    assert session.server_attribution
    assert session.server_attribution["confirmed"] is False
    assert session.server_attribution["predicates"]["socket_acquire_or_bind"] is False

    summary = json.loads((session_dir / "confirmation_summary.json").read_text(encoding="utf-8"))
    assert summary["repository"]["project_name"] == "startup_init"
    assert summary["server"]["missing_predicates"] == ["socket_acquire_or_bind"]
    assert summary["server"]["predicate_gate"] == "advisory"
    assert any("socket_acquire_or_bind" in warning for warning in summary["warnings"])

    events = LocatorSessionStore(root).events(session.session_id).load()
    assert events[-1].type == "verification.await_confirmation"
    assert events[-1].details["predicate_gate"] == "advisory"

    # A confirmation is still an explicit state-machine operation; advancing
    # alone never enters CLONE.
    assert SourceLocatorWorker(machine, runtime=SourceLocatorRuntime(manifest=manifest)).advance().state == "AWAIT_USER_CONFIRMATION"
    machine.confirm(confirmation_id="test-confirmation")
    assert machine.session.state == "CLONE"


def test_worker_retries_duplicate_llm_action_before_accepting_novel_action(tmp_path: Path) -> None:
    """Duplicate model proposals are fed back instead of terminating the loop."""

    fake = _FakeOpenGrok()
    calls = 0
    prompts: list[dict[str, object]] = []

    def model(prompt: str):
        nonlocal calls
        calls += 1
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        prompts.append(context)
        evidence_id = context["evidence_ids"][0]
        query = "PARAM_SERVICE" if calls < 3 else "CreateSocketListener"
        return {
            "kind": "search_full",
            "query": query,
            "justification": "寻找下一条源码证据",
            "expected_relation": "socket_server_registration",
            "purpose": "normal",
            "evidence_used": [evidence_id],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_llm_actions": 2},
        session_id="loc_workerretry01",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(
        model_call=model,
        budget=PlannerBudget(max_actions=2, max_model_calls=3),
    )
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    ).run_until_pause(max_steps=32)
    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert calls == 3
    assert len(prompts) == 3
    assert prompts[2]["recovery"]["last_feedback"]
    assert prompts[2]["executed_actions"]


def test_worker_allows_different_search_semantics_for_same_query(tmp_path: Path) -> None:
    """A full-text and definition search for one term are not the same action."""

    fake = _FakeOpenGrok()
    calls = 0

    def model(prompt: str):
        nonlocal calls
        calls += 1
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        return {
            "kind": "search_full" if calls == 1 else "search_definition",
            "query": "same_semantic_term",
            "justification": "分别检查全文引用和定义位置",
            "expected_relation": "symbol_reference",
            "purpose": "normal",
            "evidence_used": [context["evidence_ids"][0]],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_llm_actions": 2},
        session_id="loc_workersemmode",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(model_call=model, budget=PlannerBudget(max_actions=2, max_model_calls=2))
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    ).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert calls == 2
    assert "search_full:same_semantic_term" in session.executed_actions
    assert "search_definition:same_semantic_term" in session.executed_actions


def test_worker_turns_clone_failure_into_version_selection_pause(tmp_path: Path, monkeypatch) -> None:
    """A failed Git attempt exposes safe remote refs instead of ending the session."""

    from core.source_locator import EvidenceStore, RepositoryAcquisitionResult, validate_repository_mapping
    from core.source_locator import worker as worker_module
    from core.source_locator.worker import _json_write

    project_root = tmp_path / "project"
    project_root.mkdir()
    sessions = tmp_path / "sessions"
    machine = LocatorSessionStore(sessions).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerclonefail",
    )
    target = normalize_target("/dev/unix/socket/paramservice", target_revision="OpenHarmony-6.1-LTS")
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    mapping = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        remote_fetch="https://gitcode.com/openharmony",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
    )
    session_dir = sessions / machine.session.session_id
    _json_write(session_dir / "evidence.json", EvidenceStore().to_dict())
    for state, updates in (
        ("NORMALIZE_TARGET", {"target": target.to_dict()}),
        ("PROBE_OPENGROK", {}),
        ("SEARCH_INITIAL", {}),
        ("TRACE_EVIDENCE", {}),
        ("ATTRIBUTION_SERVER", {}),
        ("LOCATE_CLIENT_COMM", {}),
        ("RESOLVE_REPOSITORIES", {"repository_mappings": {"mappings": [{**mapping.to_dict(), "status": "resolved"}]}}),
        ("VERIFY_EVIDENCE", {}),
        ("AWAIT_USER_CONFIRMATION", {}),
    ):
        machine.transition(state, summary_zh=state, updates=updates)
    machine.confirm(confirmation_id="test-confirmation")

    decision = validate_repository_mapping(mapping)

    class FailingManager:
        def __init__(self, project_root, *, config, runner=None, on_log=None):
            del project_root, config, runner, on_log

        def ensure_repository(self, mapping, *, confirmation=None):
            del confirmation
            return RepositoryAcquisitionResult(
                status="failed",
                project_name=mapping.project_name,
                destination=str(project_root / "source_code_base" / mapping.project_name),
                repo_url=mapping.repo_url,
                canonical_url=decision.canonical_url,
                revision=mapping.revision,
                mapping=mapping,
                decision=decision,
                reasons=("测试模拟 HTTP 301",),
            )

    monkeypatch.setattr(worker_module, "RepositoryManager", FailingManager)

    def refs_runner(argv, *, cwd, timeout_seconds):
        del argv, cwd, timeout_seconds
        return CommandResult(
            0,
            stdout=(
                "a" * 40 + "\trefs/heads/OpenHarmony-6.1-LTS\n"
                + "b" * 40 + "\trefs/heads/OpenHarmony-6.0-LTS\n"
            ),
        )

    session = worker_module.SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(
            manifest=manifest,
            project_root=project_root,
            git_runner=refs_runner,
        ),
    ).advance()

    assert session.state == "VERSION_SELECTION_REQUIRED"
    assert session.version_selection["candidate_count"] == 2
    artifact = json.loads((session_dir / "repository_version_candidates.json").read_text(encoding="utf-8"))
    assert artifact["status"] == "ok"
    assert artifact["failure"]["stage"] == "clone"
    assert [item["revision"] for item in artifact["candidates"]] == [
        "OpenHarmony-6.1-LTS",
        "OpenHarmony-6.0-LTS",
    ]
    events = LocatorSessionStore(sessions).events(machine.session.session_id).load()
    assert events[-1].type == "clone.version_selection_required"
