"""Tests for deterministic OpenHarmony target normalization and query planning."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    LocatorQuery,
    TargetNormalizationError,
    build_initial_queries,
    normalize_and_plan,
    normalize_target,
)


def test_full_socket_path_with_chinese_punctuation_is_normalized():
    target = normalize_target("我想分析‘/dev/unix/socket/paramservice’。", target_revision="OpenHarmony-6.1-LTS")
    assert target.target_type == "unix_socket"
    assert target.socket_path == "/dev/unix/socket/paramservice"
    assert target.basename == "paramservice"
    assert target.service_hint == "paramservice"
    assert target.path_components == ("dev", "unix", "socket", "paramservice")
    assert target.target_revision == "OpenHarmony-6.1-LTS"
    assert json.loads(json.dumps(target.to_dict(), ensure_ascii=False))["schema_version"].endswith("target.v2")


def test_macro_assignment_keeps_macro_hint_and_socket_value():
    target = normalize_target('配置中的 PIPE_NAME = "/dev/unix/socket/paramservice"')
    assert target.target_type == "unix_socket"
    assert target.macro_hint == "PIPE_NAME"
    assert target.socket_path == "/dev/unix/socket/paramservice"
    assert any("PIPE_NAME" in note for note in target.normalization_notes)


@pytest.mark.parametrize(
    "socket_name",
    ["faultloggerd.server", "faultloggerd.sdkdump.server", "faultloggerd.crash.server"],
)
def test_socket_service_names_may_contain_dots(socket_name: str):
    target = normalize_target(f"/dev/unix/socket/{socket_name}")
    assert target.basename == socket_name
    assert target.service_hint == socket_name


def test_bare_macro_and_service_name_are_distinguished_without_guessing_repo():
    macro = normalize_target("请定位 PIPE_NAME")
    assert macro.target_type == "macro"
    assert macro.macro_hint == "PIPE_NAME"
    assert macro.socket_path is None

    service = normalize_target("请分析 ParamService 服务")
    assert service.target_type == "service_name"
    assert service.service_hint == "ParamService"
    assert service.target_revision == "unknown"
    assert any("尚未推断" in note for note in service.normalization_notes)


def test_local_absolute_path_is_not_misclassified_as_remote_socket():
    with pytest.raises(TargetNormalizationError, match="本地源码/工程路径"):
        normalize_target("/Users/shiyu/学习/hyl/new/VulnFounder/source_code_base/foo")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "不能为空"),
        ("   ", "不能为空"),
        ("https://example.invalid/source", "URL"),
        ("/dev/unix/socket/../secret", "穿越"),
        ("/dev/unix/socket/paramservice\nnext", "控制字符"),
        ("没有可识别目标", "未识别"),
    ],
)
def test_invalid_or_ambiguous_input_fails_closed(value, message):
    with pytest.raises(TargetNormalizationError, match=message):
        normalize_target(value)


def test_initial_queries_are_stable_bounded_deduplicated_and_use_cxx():
    target = normalize_target("/dev/unix/socket/paramservice")
    first, second = build_initial_queries(target), build_initial_queries(target)
    assert first == second
    assert len(first) <= 12
    assert [query.query_id for query in first] == [f"Q-{index:04d}" for index in range(1, len(first) + 1)]
    assert len({(query.kind, query.value, query.file_type) for query in first}) == len(first)
    assert all(query.file_type in {"c", "cxx", "all"} for query in first)
    assert all("cpp" not in query.to_dict()["params"].values() for query in first)
    assert first[0].kind == "full"
    assert first[0].value == "/dev/unix/socket/paramservice"
    assert first[0].file_type == "c"
    assert first[1].file_type == "cxx"
    assert any(query.kind == "full" and query.value == "/dev/unix/socket/paramservice" for query in first)
    assert any(query.kind == "full" and query.value == '"name" : "paramservice"' for query in first)
    assert all(len(query.value) <= 512 for query in first)


def test_unix_query_plan_includes_config_and_bounded_server_probes():
    """命名 Socket 覆盖 cfg/descriptor 线索，不发送全仓通用 API 词。"""

    target = normalize_target("/dev/unix/socket/dnsproxyd")
    queries = build_initial_queries(target)
    values = {(query.kind, query.value, query.file_type) for query in queries}
    assert ("full", "/dev/unix/socket/dnsproxyd", "all") in values
    assert ("path", "dnsproxyd", "all") in values
    assert ("full", "dnsproxyd", "all") in values
    assert ("full", "GetControlSocket", "all") in values
    assert ("full", "GetServerSocket", "all") in values
    assert ("full", "SocketDevice", "all") in values
    assert not any(query.kind == "full" and query.value in {"socket", "bind", "listen", "recv"} for query in queries)
    assert any(query.value in {"ohos_executable", "bundle.json"} and query.file_type == "all" for query in queries)
    assert any(query.value == '"name" : "dnsproxyd"' and query.file_type == "all" for query in queries)
    extended_values = [query.value for query in build_initial_queries(target, max_queries=32)]
    assert "GetServerSocket" in extended_values
    assert "SocketDevice" in extended_values


def test_macro_queries_prioritize_macro_then_include_path_evidence():
    target = normalize_target("PIPE_NAME=/dev/unix/socket/paramservice")
    queries = build_initial_queries(target)
    assert [(query.kind, query.value) for query in queries[:4]] == [
        ("definition", "PIPE_NAME"),
        ("definition", "PIPE_NAME"),
        ("symbol", "PIPE_NAME"),
        ("symbol", "PIPE_NAME"),
    ]
    assert any(query.kind == "path" and query.value == "paramservice" for query in queries)


def test_service_query_plan_has_no_unbounded_full_text_search():
    target, queries = normalize_and_plan("paramservice", max_queries=3)
    assert target.target_type == "service_name"
    assert len(queries) == 3
    assert [query.query_id for query in queries] == ["Q-0001", "Q-0002", "Q-0003"]
    assert queries[-1].kind == "symbol"


def test_target_revision_and_query_limit_are_validated():
    with pytest.raises(TargetNormalizationError, match="revision"):
        normalize_target("paramservice", target_revision="../../main")
    target = normalize_target("paramservice")
    with pytest.raises(TargetNormalizationError, match="max_queries"):
        build_initial_queries(target, max_queries=0)
    with pytest.raises(TargetNormalizationError, match="file_type"):
        LocatorQuery("Q-0001", "path", "paramservice", "cpp", "bad")


@pytest.mark.parametrize(
    ("raw", "transport", "address", "port", "process"),
    [
        ("SP_daemon UDP 127.0.0.1:8283", "UDP", "127.0.0.1", 8283, "SP_daemon"),
        ("SP_daemon TCP 127.0.0.1:8284", "TCP", "127.0.0.1", 8284, "SP_daemon"),
        ("UDP 127.0.0.1:8285", "UDP", "127.0.0.1", 8285, None),
        ("分析 TCP [2001:db8::1]:443", "TCP", "2001:db8::1", 443, None),
    ],
)
def test_network_socket_target_preserves_protocol_endpoint_and_process_hint(
    raw: str, transport: str, address: str, port: int, process: str | None
):
    target = normalize_target(raw)
    assert target.target_type == "network_socket"
    assert target.transport == transport
    assert target.address == address
    assert target.port == port
    assert target.process_hint == process
    assert target.service_hint == process
    assert target.basename == process


def test_network_query_plan_prioritizes_endpoint_port_and_process_without_bare_bind():
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    queries = build_initial_queries(target)
    values = [query.value for query in queries]
    assert "127.0.0.1:8283" in values
    assert "8283" in values
    assert "htons(8283)" in values
    assert "SP_daemon" in values
    assert "recvfrom" in values
    assert "SOCK_DGRAM" in values
    # Network probes must see both C/C++ listeners and init/build metadata
    # without spending two budget slots per semantic query.
    assert all(query.file_type == "all" for query in queries)
    assert any(query.file_type == "all" and query.value == "BUILD.gn" for query in queries)
    assert any(query.file_type == "all" and query.value == "bundle.json" for query in queries)
    assert len(queries) <= 12


def test_network_extended_query_plan_covers_loopback_address_forms():
    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    queries = build_initial_queries(target, max_queries=32)
    values = [query.value for query in queries]
    assert "127.0.0.1" in values
    assert "INADDR_LOOPBACK" in values
    assert "inet_addr" in values
    assert "inet_pton" in values
    assert "htonl" in values
    assert "ServerSocket" in values
    assert "ThreadSocket" in values
    assert "HandleMsg" in values


@pytest.mark.parametrize(
    "raw",
    [
        "TCP/UDP 127.0.0.1:8283",
        "TCP 127.0.0.1:0",
        "UDP 127.0.0.1:65536",
        "TCP 999.1.1.1:80",
        "TCP 127.0.0.1:1 127.0.0.2:2",
        "UDP 8283",
        "TCP 127.0.0.1:8283 TCP",
    ],
)
def test_invalid_network_target_fails_closed(raw: str):
    with pytest.raises(TargetNormalizationError):
        normalize_target(raw)


def test_target_identity_and_relation_include_network_endpoint():
    from core.source_locator.target_normalizer import network_endpoint, target_identity_terms, target_relation

    target = normalize_target("SP_daemon UDP 127.0.0.1:8283")
    assert network_endpoint(target) == "127.0.0.1:8283"
    assert "127.0.0.1:8283" in target_identity_terms(target)
    assert "8283" in target_identity_terms(target)
    assert "UDP" not in target_identity_terms(target)
    assert target_relation(target) == "127.0.0.1:8283"
