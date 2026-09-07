"""暴露面识别的纯逻辑和安全边界测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from utilities.llm import CompletionResult, PhaseBinding, TextBlock

from core.exposure_surface import (
    ExposureCollector,
    ExposureCommandError,
    ExposureTargetError,
    ExposureSessionStore,
    HDCClient,
    HDCResult,
    decline_exposure_service,
    normalize_exposure_target,
    _decode_proc_ipv6,
    _parse_network_observations,
    run_exposure_session,
    start_exposure_service,
    _parse_proc_unix_line,
    _parse_unix_netstat_line,
)


def test_parse_ipv6_proc_network_endpoint():
    # /proc/net/tcp6 stores each 32-bit word in little-endian order.  This is
    # ::1:8284 (0x205c) bound and listening.
    assert _decode_proc_ipv6("00000000000000000000000001000000") == "::1"
    observations = _parse_network_observations(
        "   0: 00000000000000000000000001000000:205C "
        "00000000000000000000000000000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 1000 0 42 1 0000000000000000 100 0 0 10 0\n",
        "TCP",
        "::1",
        8284,
        proc_table=True,
    )
    assert observations
    assert observations[0]["address_family"] == "AF_INET6"
    assert observations[0]["state"] == "LISTENING"


def test_parse_unix_netstat_line_extracts_listening_owner():
    observation = _parse_unix_netstat_line(
        "unix 2 [ ACC ] STREAM LISTENING 10492 1/init /dev/unix/socket/paramservice",
        "/dev/unix/socket/paramservice",
    )
    assert observation is not None
    assert observation["socket_type"] == "STREAM"
    assert observation["state"] == "LISTENING"
    assert observation["inode"] == "10492"
    assert observation["pid"] == "1"
    assert observation["process_name"] == "init"


def test_parse_proc_unix_line_extracts_type_and_state_without_owner():
    observation = _parse_proc_unix_line(
        "0000: 00000002 00000000 00010000 0001 01 10492 /dev/unix/socket/paramservice",
        "/dev/unix/socket/paramservice",
    )
    assert observation is not None
    assert observation["socket_type"] == "STREAM"
    assert observation["state"] == "LISTENING"
    assert observation["inode"] == "10492"
    assert observation["pid"] is None


def test_evidence_line_numbers_follow_matching_device_row(tmp_path: Path):
    collector = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
    )
    result = HDCResult(
        "network_status",
        ("/opt/hdc", "shell", "netstat", "-anp"),
        0,
        "header\nTCP 127.0.0.1:8284 target row\n",
        "",
        1,
    )
    evidence_id = collector._add_evidence("network_status", result, ":8284")
    assert evidence_id == "EV-0001"
    assert collector._evidence[0]["line_start"] == 2
    assert collector._evidence[0]["line_end"] == 2
    assert collector._evidence[0]["excerpt"] == "TCP 127.0.0.1:8284 target row"


def test_network_process_domain_stays_with_selected_endpoint_owner(tmp_path: Path):
    def runner(argv, timeout):
        command = argv[4:]
        if command == ["id"]:
            return 0, "uid=0(root) gid=0(root)\n", ""
        if command == ["ss", "-lntup"]:
            return 0, (
                "Netid State Local Address:Port Peer Address:Port Process\n"
                'tcp LISTEN 0 128 127.0.0.1:9000 0.0.0.0:* users:(("owner",pid=10,fd=3))\n'
                'tcp ESTAB 0 0 127.0.0.1:9000 127.0.0.1:40000 users:(("other",pid=20,fd=4))\n'
            ), ""
        if command == ["netstat", "-anp"]:
            return 0, "Active Internet connections (established and servers)\nProto Local Address\n", ""
        if command == ["cat", "/proc/net/tcp"]:
            return 0, "  sl local_address rem_address st uid inode\n", ""
        if command == ["ps", "-A"]:
            return 0, "  PID CMD\n 10 owner\n 20 other\n", ""
        if command == ["cat", "/proc/10/status"]:
            return 0, "Name:\towner\nUid:\t1000\n", ""
        if command == ["cat", "/proc/20/status"]:
            return 0, "Name:\tother\nUid:\t2000\n", ""
        if command == ["cat", "/proc/10/attr/current"]:
            return 0, "u:r:owner:s0\n", ""
        if command == ["cat", "/proc/20/attr/current"]:
            return 0, "u:r:other:s0\n", ""
        raise AssertionError(argv)

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    ).collect("TCP 127.0.0.1:9000")
    surface = result["surfaces"][0]
    assert surface["关联进程"] == "owner (PID: 10, UID: 1000)"
    assert surface["权限配置"]["进程SELinux域"] == "u:r:owner:s0"
    domain_ids = result["field_evidence"]["0"]["进程SELinux域"]
    assert len(domain_ids) == 1
    domain_evidence = next(item for item in result["evidence"] if item["evidence_id"] == domain_ids[0])
    assert domain_evidence["excerpt"] == "u:r:owner:s0"


def test_normalize_socket_path_and_natural_language():
    normalized = normalize_exposure_target(
        "我想分析 /dev/unix/socket/hiprofiler_unix_socket 这个服务"
    )

    assert normalized.target_kind == "unix_socket"
    assert normalized.candidate_paths == (
        "/dev/unix/socket/hiprofiler_unix_socket",
    )
    assert "hiprofiler_unix_socket" in normalized.candidate_names


def test_normalize_socket_basename_does_not_execute_input():
    normalized = normalize_exposure_target("hiprofiler_unix_socket")

    assert normalized.candidate_paths == (
        "/dev/unix/socket/hiprofiler_unix_socket",
    )
    assert ";" not in normalized.candidate_paths[0]


@pytest.mark.parametrize(
    ("raw", "transport", "address", "port", "process"),
    [
        ("SP_daemon UDP 127.0.0.1:8283", "UDP", "127.0.0.1", 8283, "SP_daemon"),
        ("分析 TCP [::1]:8284", "TCP", "::1", 8284, None),
        ("UDP 0.0.0.0:53", "UDP", "0.0.0.0", 53, None),
    ],
)
def test_normalize_network_socket_target(raw, transport, address, port, process):
    normalized = normalize_exposure_target(raw)

    assert normalized.target_kind == "network_socket"
    assert normalized.transport == transport
    assert normalized.address == address
    assert normalized.port == port
    assert normalized.process_name == process
    assert normalized.candidate_paths == ()
    assert normalized.to_dict()["transport"] == transport


@pytest.mark.parametrize(
    "raw",
    [
        "SP_daemon UDP 127.0.0.1",
        "SP_daemon 127.0.0.1:8283",
        "SP_daemon UDP 127.0.0.1:0",
        "SP_daemon TCP 127.0.0.1:65536",
        "SP_daemon UDP 999.0.0.1:8283",
        "SP_daemon TCP/UDP 127.0.0.1:8283",
        "SP_daemon TCP 127.0.0.1:8283 and 127.0.0.1:8284",
    ],
)
def test_normalize_network_socket_target_rejects_incomplete_or_invalid_endpoint(raw):
    with pytest.raises(ExposureTargetError):
        normalize_exposure_target(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "../etc/passwd",
        "/dev/unix/socket/a;touch /tmp/pwned",
        "/dev/unix/socket/a\ncat /etc/shadow",
        "/dev/unix/socket/" + "x" * 600,
    ],
)
def test_normalize_rejects_unsafe_or_empty_target(raw):
    with pytest.raises(ExposureTargetError):
        normalize_exposure_target(raw)


def test_hdc_client_uses_argument_vector_and_records_output():
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        return 0, "srw------- 1 hiprofiler shell 0 /dev/unix/socket/demo\n", ""

    client = HDCClient(
        "/opt/hdc",
        "serial-123",
        runner=runner,
        timeout_seconds=3,
    )
    result = client.run("socket_stat", ["ls", "-l", "/dev/unix/socket/demo"])

    assert result.returncode == 0
    assert result.stdout.startswith("srw-------")
    assert calls == [
        (
            [
                "/opt/hdc",
                "-t",
                "serial-123",
                "shell",
                "ls",
                "-l",
                "/dev/unix/socket/demo",
            ],
            3,
        )
    ]


def test_hdc_client_uses_default_device_without_serial():
    calls = []

    def runner(argv, timeout):
        calls.append(argv)
        return 0, "device default\n", ""

    result = HDCClient("/opt/hdc", "", runner=runner).run("preflight", ["id"])

    assert result.ok
    assert calls == [["/opt/hdc", "shell", "id"]]


def test_hdc_client_rejects_shell_syntax_and_unknown_probe():
    client = HDCClient("/opt/hdc", "serial-123", runner=lambda *_: (0, "", ""))

    with pytest.raises(ExposureCommandError):
        client.run("socket_stat", ["ls", ";", "id"])
    with pytest.raises(ExposureCommandError):
        client.run("arbitrary", ["id"])


def test_collector_builds_example_compatible_surface_and_evidence(tmp_path: Path):
    outputs = {
        "preflight": (0, "device serial-123\n", ""),
        "socket_stat": (
            0,
            "srw------- 1 hiprofiler shell 0 /dev/unix/socket/demo\n",
            "",
        ),
        "selinux_context": (
            0,
            "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n",
            "",
        ),
        "unix_table": (
            0,
            "0000000000000000: 00000002 00000000 00010000 0001 01 12345 /dev/unix/socket/demo\n",
            "",
        ),
        "netstat": (0, "unix 2 [ ACC ] STREAM LISTENING 12345 /dev/unix/socket/demo\n", ""),
        "process_list": (0, "demo 2157\n", ""),
        "process_status": (0, "Name:\tdemo\nUid:\t1000\n", ""),
        "service_config": (0, '"name": "hiprofilerd"\n"permissions": "0600"\n', ""),
    }

    def runner(argv, timeout):
        command = argv[4:]
        if command[:1] == ["id"]:
            probe = "preflight"
        elif command[:2] == ["ls", "-l"]:
            probe = "socket_stat"
        elif command[:2] == ["ls", "-Z"]:
            probe = "selinux_context"
        elif command[:2] == ["cat", "/proc/net/unix"]:
            probe = "unix_table"
        elif command[:2] == ["netstat", "-an"]:
            probe = "netstat"
        elif command[:2] == ["ps", "-A"]:
            probe = "process_list"
        elif command[:1] == ["cat"] and "/proc/" in command[-1]:
            probe = "process_status"
        elif command[:1] == ["cat"]:
            probe = "service_config"
        else:
            probe = None
        assert probe is not None, argv
        return outputs[probe]

    collector = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    )
    result = collector.collect("/dev/unix/socket/demo")

    assert result["collection_status"] == "complete"
    surface = result["surfaces"][0]
    assert surface["暴露面类型"] == "Unix Domain Socket (UDS)"
    assert surface["套接字路径"] == "/dev/unix/socket/demo"
    assert surface["套接字类型"] == "STREAM"
    assert surface["运行状态"] == "LISTENING"
    assert surface["关联进程"].startswith("demo")
    assert result["evidence_summary"]["total"] >= 3
    assert Path(result["artifacts"]["exposure_surface.json"]).is_file()

    payload = json.loads(
        Path(result["artifacts"]["exposure_surface.json"]).read_text(
            encoding="utf-8"
        )
    )
    assert payload["surfaces"][0]["权限配置"]["DAC权限"].startswith("0600")


def test_collector_builds_udp_surface_from_network_endpoint(tmp_path: Path):
    def runner(argv, timeout):
        command = argv[4:]
        if command == ["id"]:
            return 0, "uid=0(root) gid=0(root)\n", ""
        if command == ["ss", "-lntup"]:
            return 0, (
                "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                'udp UNCONN 0 0 127.0.0.1:8283 0.0.0.0:* users:(("SP_daemon",pid=123,fd=4))\n'
            ), ""
        if command == ["netstat", "-anp"]:
            return 127, "", "netstat: not found\n"
        if command == ["cat", "/proc/net/udp"]:
            return 0, (
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                "   0: 0100007F:205B 00000000:0000 07 00000000:00000000 00:00000000 00000000   3063        0 12345 2 abc\n"
            ), ""
        if command == ["ps", "-A"]:
            return 0, "  PID CMD\n 123 SP_daemon\n", ""
        if command == ["cat", "/proc/123/status"]:
            return 0, "Name:\tSP_daemon\nUid:\t3063\n", ""
        if command == ["cat", "/proc/123/attr/current"]:
            return 0, "u:r:sp_daemon:s0\n", ""
        raise AssertionError(argv)

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    ).collect("SP_daemon UDP 127.0.0.1:8283")

    assert result["collection_status"] == "complete"
    surface = result["surfaces"][0]
    assert surface["暴露面类型"] == "UDP Socket"
    assert surface["套接字路径"] is None
    assert surface["监听地址"] == "127.0.0.1"
    assert surface["监听端口"] == 8283
    assert surface["套接字类型"] == "DGRAM"
    assert surface["传输协议"] == "UDP"
    assert surface["通信协议"] == "AF_INET"
    assert surface["运行状态"] == "BOUND"
    assert surface["关联进程"] == "SP_daemon (PID: 123, UID: 3063)"
    assert surface["权限配置"]["SELinux标签"] == "不适用（网络 socket 无独立文件标签）"
    assert surface["权限配置"]["进程SELinux域"] == "u:r:sp_daemon:s0"
    assert result["field_evidence"]["0"]["监听端口"]
    assert result["field_evidence"]["0"]["关联进程"]
    assert result["field_evidence"]["0"]["进程SELinux域"]
    markdown = Path(result["artifacts"]["exposure_surface.md"]).read_text(encoding="utf-8")
    assert "UDP 127.0.0.1:8283" in markdown
    assert "监听端口：8283" in markdown


def test_collector_builds_tcp_surface_and_not_found_state(tmp_path: Path):
    def runner(argv, timeout):
        command = argv[4:]
        if command == ["id"]:
            return 0, "uid=0(root) gid=0(root)\n", ""
        if command in (["ss", "-lntup"], ["netstat", "-anp"]):
            return 0, "Netid State Local Address:Port Peer Address:Port Process\n", ""
        if command == ["cat", "/proc/net/tcp"]:
            return 0, "Num\n", ""
        if command == ["ps", "-A"]:
            return 0, "  PID CMD\n", ""
        raise AssertionError(argv)

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    ).collect("TCP 127.0.0.1:8284")

    surface = result["surfaces"][0]
    assert surface["暴露面类型"] == "TCP Socket"
    assert surface["套接字类型"] == "STREAM"
    assert surface["运行状态"] == "NOT_FOUND"
    assert surface["监听端口"] == 8284


def test_network_not_found_does_not_attribute_same_named_process(tmp_path: Path):
    """A process name alone is not evidence that the requested port exists."""

    def runner(argv, timeout):
        command = argv[4:]
        if command == ["id"]:
            return 0, "uid=0(root) gid=0(root)\n", ""
        if command in (["ss", "-lntup"], ["netstat", "-anp"]):
            return 0, "Netid State Local Address:Port Peer Address:Port Process\n", ""
        if command == ["cat", "/proc/net/udp"]:
            return 0, "sl local_address rem_address st tx_queue rx_queue uid inode\n", ""
        if command == ["ps", "-A"]:
            # The daemon is running, but it did not open the requested port.
            return 0, "  PID CMD\n 123 SP_daemon\n", ""
        raise AssertionError(argv)

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    ).collect("SP_daemon UDP 127.0.0.1:8283")

    surface = result["surfaces"][0]
    assert surface["运行状态"] == "NOT_FOUND"
    assert surface["关联进程"] == "未知"


def test_parse_network_tool_line_extracts_netstat_tcp_owner():
    observations = _parse_network_observations(
        "tcp 0 0 127.0.0.1:8284 0.0.0.0:* LISTEN 3389/SP_daemon\n",
        "TCP",
        "127.0.0.1",
        8284,
    )
    assert observations == [
        {
            "transport": "TCP",
            "address_family": "AF_INET",
            "address": "127.0.0.1",
            "port": 8284,
            "state": "LISTENING",
            "process_name": "SP_daemon",
            "pid": "3389",
            "fd": None,
            "line": "tcp 0 0 127.0.0.1:8284 0.0.0.0:* LISTEN 3389/SP_daemon",
        }
    ]


class _ExposureExtractionAdapter:
    """Minimal adapter used to exercise the LLM result-extraction boundary."""

    name = "test-exposure"
    supports_tools = False
    pricing = {}

    def __init__(self, response: str):
        self.response = response
        self.prompts: list[str] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.prompts.append(messages[-1].content[0].text)
        return CompletionResult(
            content=[TextBlock(self.response)],
            input_tokens=20,
            output_tokens=10,
            stop_reason="end_turn",
        )

    def validate(self, model):  # pragma: no cover - required by the adapter shape
        return None


def _exposure_binding(adapter: _ExposureExtractionAdapter) -> PhaseBinding:
    return PhaseBinding(
        phase="app_context",
        adapter=adapter,
        model="test-exposure-model",
        provider_name="test-exposure",
    )


def _running_exposure_runner(argv, timeout):
    """A compact running-socket fixture with a differently named daemon."""

    command = argv[4:]
    if command == ["id"]:
        return 0, "uid=0(root) gid=0(root)\n", ""
    if command[:2] == ["ls", "-l"]:
        return 0, "srw------- 1 hiprofiler shell 0 /dev/unix/socket/demo\n", ""
    if command[:2] == ["ls", "-Z"]:
        return 0, "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n", ""
    if command == ["cat", "/proc/net/unix"]:
        return 0, "0000: 00000002 00000000 00010000 0001 01 123 /dev/unix/socket/demo\n", ""
    if command == ["netstat", "-an"]:
        return 0, "unix 2 [ ACC ] STREAM LISTENING 123 /dev/unix/socket/demo\n", ""
    if command == ["ps", "-A"]:
        return 0, "  PID CMD\n 2157 hiprofilerd\n", ""
    if command == ["cat", "/proc/2157/status"]:
        return 0, "Name:\thiprofilerd\nUid:\t1000\n", ""
    if command[:3] == ["grep", "-R", "-l"]:
        return 0, "", ""
    raise AssertionError(argv)


def test_llm_result_extraction_applies_evidence_backed_fields(tmp_path: Path):
    adapter = _ExposureExtractionAdapter(
        json.dumps(
            {
                "surfaces": [
                    {
                        "index": 0,
                        "fields": {
                            "associated_process": {
                                "value": "hiprofilerd (PID: 2157)",
                                "evidence_ids": ["EV-0004"],
                            }
                        },
                    }
                ]
            }
        )
    )
    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=_running_exposure_runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    ).collect("/dev/unix/socket/demo")

    assert adapter.prompts
    assert "hiprofilerd" in adapter.prompts[0]
    assert result["llm_extraction"]["status"] == "applied"
    assert "associated_process" in result["llm_extraction"]["accepted_fields"]
    assert result["surfaces"][0]["关联进程"] == "hiprofilerd (PID: 2157)"
    assert "EV-0004" in result["field_evidence"]["0"]["关联进程"]
    assert "exposure_llm_extraction.json" in result["artifacts"]


def test_agent_evidence_is_visible_to_semantic_extraction(tmp_path: Path):
    adapter = _ExposureExtractionAdapter(
        json.dumps(
            {
                "surfaces": [
                    {
                        "index": 0,
                        "fields": {
                            "associated_process": {
                                "value": "hiprofilerd (PID: 2157, UID: 1000)",
                                "evidence_ids": ["AG-EV-0001"],
                            }
                        },
                    }
                ]
            }
        )
    )
    collector = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=_running_exposure_runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    )
    collector.attach_agent_evidence(
        {
            "evidence": [
                {
                    "evidence_id": "AG-EV-0001",
                    "kind": "device_command",
                    "command_kind": "agent_command",
                    "excerpt": "2157 hiprofilerd",
                    "line_start": 1,
                    "line_end": 1,
                }
            ],
            "commands": [],
        }
    )
    result = collector.collect("/dev/unix/socket/demo")

    assert "AG-EV-0001" in adapter.prompts[0]
    assert "AG-EV-0001" in {item["evidence_id"] for item in result["evidence"]}
    assert result["surfaces"][0]["关联进程"] == "hiprofilerd (PID: 2157, UID: 1000)"


def test_llm_result_extraction_rejects_unknown_evidence_and_keeps_baseline(tmp_path: Path):
    adapter = _ExposureExtractionAdapter(
        json.dumps(
            {
                "surfaces": [
                    {
                        "index": 0,
                        "fields": {
                            "associated_process": {
                                "value": "made-up-daemon",
                                "evidence_ids": ["EV-9999"],
                            }
                        },
                    }
                ]
            }
        )
    )
    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=_running_exposure_runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    ).collect("/dev/unix/socket/demo")

    assert result["llm_extraction"]["status"] == "applied"
    assert "associated_process" in result["llm_extraction"]["rejected_fields"]
    assert result["surfaces"][0]["关联进程"] == "未知"


def test_llm_unknown_value_does_not_erase_observed_baseline(tmp_path: Path):
    adapter = _ExposureExtractionAdapter(
        json.dumps(
            {
                "surfaces": [
                    {
                        "index": 0,
                        "fields": {
                            "risk_level": {
                                "value": "未知",
                                "evidence_ids": ["EV-0001"],
                            }
                        },
                    }
                ]
            }
        )
    )
    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=_running_exposure_runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    ).collect("/dev/unix/socket/demo")

    assert result["surfaces"][0]["风险等级"] == "低"
    assert "risk_level" in result["llm_extraction"]["rejected_fields"]


def test_llm_cannot_reclassify_unix_socket_as_network_socket(tmp_path: Path):
    adapter = _ExposureExtractionAdapter(
        json.dumps(
            {
                "surfaces": [
                    {
                        "index": 0,
                        "fields": {
                            "transport": {
                                "value": "TCP",
                                "evidence_ids": ["EV-0001"],
                            },
                            "listen_port": {
                                "value": "443",
                                "evidence_ids": ["EV-0001"],
                            },
                        },
                    }
                ]
            }
        )
    )
    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=_running_exposure_runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    ).collect("/dev/unix/socket/demo")

    surface = result["surfaces"][0]
    assert surface["套接字路径"] == "/dev/unix/socket/demo"
    assert "传输协议" not in surface
    assert "监听端口" not in surface
    assert {"transport", "listen_port"}.issubset(
        set(result["llm_extraction"]["rejected_fields"])
    )


def test_llm_does_not_drop_richer_process_baseline(tmp_path: Path):
    adapter = _ExposureExtractionAdapter(
        json.dumps(
            {
                "surfaces": [
                    {
                        "index": 0,
                        "fields": {
                            "associated_process": {
                                "value": "hiprofilerd (PID: 2157)",
                                "evidence_ids": ["EV-0004"],
                            }
                        },
                    }
                ]
            }
        )
    )
    # The deterministic probe includes the UID; a shorter semantic answer must
    # not erase that already observed detail.
    def runner(argv, timeout):
        result = _running_exposure_runner(argv, timeout)
        return result[0], result[1].replace("/dev/unix/socket/demo", "/dev/unix/socket/hiprofiler_unix_socket"), result[2]

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    ).collect("/dev/unix/socket/hiprofiler_unix_socket")

    assert result["surfaces"][0]["关联进程"] == "hiprofilerd (PID: 2157, UID: 1000)"
    assert "associated_process" in result["llm_extraction"]["rejected_fields"]


def test_llm_result_extraction_falls_back_on_malformed_response(tmp_path: Path):
    adapter = _ExposureExtractionAdapter("not-json")
    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=_running_exposure_runner),
        output_dir=tmp_path,
        llm_binding=_exposure_binding(adapter),
    ).collect("/dev/unix/socket/demo")

    assert result["llm_extraction"]["status"] == "fallback"
    # The model response is malformed and the differently named process is not
    # inferable from the deterministic basename matcher; fallback must keep the
    # conservative unknown value rather than inventing an association.
    assert result["surfaces"][0]["关联进程"] == "未知"


def test_collector_preserves_partial_unknown_when_probe_fails(tmp_path: Path):
    def runner(argv, timeout):
        if argv[4:] == ["id"]:
            return 0, "device serial-123\n", ""
        return 127, "", "tool unavailable"

    collector = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    )
    result = collector.collect("/dev/unix/socket/demo")

    assert result["collection_status"] == "partial"
    surface = result["surfaces"][0]
    assert surface["运行状态"] in {"UNKNOWN", "未观测"}
    assert result["errors"]


def test_collector_does_not_turn_missing_socket_errors_into_selinux_evidence(tmp_path: Path):
    missing = "ls: /dev/unix/socket/demo: No such file or directory\n"

    def runner(argv, timeout):
        command = argv[4:]
        if command == ["id"]:
            return 0, "uid=0(root) gid=0(root)\n", ""
        if command[:2] in (["ls", "-l"], ["ls", "-Z"]):
            return 0, missing, ""
        if command == ["cat", "/proc/net/unix"]:
            return 0, "Num RefCount Protocol Flags Type St Inode Path\n", ""
        if command == ["netstat", "-an"]:
            return 0, "Active UNIX domain sockets (established and servers)\n", ""
        if command == ["ps", "-A"]:
            return 0, "  PID CMD\n    1 init\n", ""
        raise AssertionError(argv)

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    ).collect("/dev/unix/socket/demo")

    surface = result["surfaces"][0]
    assert result["collection_status"] == "complete"
    assert surface["运行状态"] == "NOT_FOUND"
    assert surface["权限配置"]["DAC权限"] == "未知"
    assert surface["权限配置"]["SELinux标签"] == "未知"
    assert {item["kind"] for item in result["evidence"]} == {"socket_absence"}
    assert result["field_evidence"]["0"]["运行状态"]
    assert "SELinux标签" not in result["field_evidence"]["0"]


def test_collector_detects_configured_stopped_service_and_emits_start_option(tmp_path: Path):
    config = json.dumps(
        {
            "services": [
                {
                    "name": "hiprofilerd",
                    "path": ["/system/bin/hiprofilerd"],
                    "socket": [{"name": "hiprofiler_unix_socket", "type": "SOCK_STREAM"}],
                }
            ],
            "jobs": [
                {
                    "condition": "hiviewdfx.hiprofiler.profilerd.start=1",
                    "cmds": ["start hiprofilerd"],
                },
                {
                    "condition": "hiviewdfx.hiprofiler.profilerd.start=0",
                    "cmds": ["stop hiprofilerd"],
                },
            ],
        }
    )

    def runner(argv, timeout):
        command = argv[4:]
        if command == ["id"]:
            return 0, "uid=0(root) gid=0(root)\n", ""
        if command[:2] == ["ls", "-l"] or command[:2] == ["ls", "-Z"]:
            return 0, "ls: /dev/unix/socket/hiprofiler_unix_socket: No such file or directory\n", ""
        if command == ["cat", "/proc/net/unix"]:
            return 0, "Num RefCount Protocol Flags Type St Inode Path\n", ""
        if command == ["netstat", "-an"]:
            return 0, "Active UNIX domain sockets (established and servers)\n", ""
        if command == ["ps", "-A"]:
            return 0, "  PID CMD\n    1 init\n", ""
        if command[:3] == ["grep", "-R", "-l"]:
            return 0, "/system/etc/init/hiprofilerd.cfg\n", ""
        if command == ["cat", "/system/etc/init/hiprofilerd.cfg"]:
            return 0, config, ""
        if command[:2] == ["param", "get"]:
            return 0, "0\n", ""
        raise AssertionError(argv)

    result = ExposureCollector(
        HDCClient("/opt/hdc", "serial-123", runner=runner),
        output_dir=tmp_path,
    ).collect("/dev/unix/socket/hiprofiler_unix_socket")

    assert result["surfaces"][0]["运行状态"] == "NOT_FOUND"
    assert result["service_observations"][0]["service_name"] == "hiprofilerd"
    assert result["service_observations"][0]["state"] == "STOPPED"
    assert len(result["start_options"]) == 1
    option = result["start_options"][0]
    assert option["parameter"] == "hiviewdfx.hiprofiler.profilerd.start"
    assert option["current_value"] == "0"
    assert option["requested_value"] == "1"


def test_start_service_requires_pending_confirmation_and_reprobes_after_explicit_start(tmp_path: Path):
    marker = tmp_path / "started"
    config = json.dumps(
        {
            "services": [
                {
                    "name": "hiprofilerd",
                    "path": ["/system/bin/hiprofilerd"],
                    "socket": [{"name": "hiprofiler_unix_socket", "type": "SOCK_STREAM"}],
                }
            ],
            "jobs": [
                {"condition": "hiviewdfx.hiprofiler.profilerd.start=1", "cmds": ["start hiprofilerd"]},
                {"condition": "hiviewdfx.hiprofiler.profilerd.start=0", "cmds": ["stop hiprofilerd"]},
            ],
        }
    )
    fake_hdc = tmp_path / "hdc"
    fake_hdc.write_text(
        f'''#!/bin/sh
if [ "$4" = "id" ]; then printf 'uid=0(root) gid=0(root)\\n'; exit 0; fi
if [ "$4" = "grep" ]; then printf '/system/etc/init/hiprofilerd.cfg\\n'; exit 0; fi
if [ "$4" = "cat" ] && [ "$5" = "/system/etc/init/hiprofilerd.cfg" ]; then printf '%s'; exit 0; fi
if [ "$4" = "param" ] && [ "$5" = "get" ]; then if [ -f "{marker}" ]; then printf '1\\n'; else printf '0\\n'; fi; exit 0; fi
if [ "$4" = "param" ] && [ "$5" = "set" ]; then touch "{marker}"; printf 'ok\\n'; exit 0; fi
if [ "$4" = "ls" ] && [ "$5" = "-l" ]; then if [ -f "{marker}" ]; then printf 'srw------- 1 hiprofiler shell 0 /dev/unix/socket/hiprofiler_unix_socket\\n'; else printf 'ls: /dev/unix/socket/hiprofiler_unix_socket: No such file or directory\\n'; fi; exit 0; fi
if [ "$4" = "ls" ] && [ "$5" = "-Z" ]; then if [ -f "{marker}" ]; then printf 'u:object_r:hiprofiler_socket:s0 /dev/unix/socket/hiprofiler_unix_socket\\n'; else printf 'ls: /dev/unix/socket/hiprofiler_unix_socket: No such file or directory\\n'; fi; exit 0; fi
if [ "$4" = "cat" ] && [ "$5" = "/proc/net/unix" ]; then if [ -f "{marker}" ]; then printf '0000: 00000002 00000000 00010000 0001 01 123 /dev/unix/socket/hiprofiler_unix_socket\\n'; else printf 'Num RefCount Protocol Flags Type St Inode Path\\n'; fi; exit 0; fi
if [ "$4" = "netstat" ]; then if [ -f "{marker}" ]; then printf 'unix 2 [ ACC ] STREAM LISTENING 123 /dev/unix/socket/hiprofiler_unix_socket\\n'; else printf 'Active UNIX domain sockets (established and servers)\\n'; fi; exit 0; fi
if [ "$4" = "ps" ]; then if [ -f "{marker}" ]; then printf 'hiprofilerd 2157\\n'; else printf '  PID CMD\\n    1 init\\n'; fi; exit 0; fi
if [ "$4" = "cat" ] && [ "$5" = "/proc/2157/status" ]; then printf 'Name:\\thiprofilerd\\nUid:\\t1000\\n'; exit 0; fi
exit 0
''' % config,
        encoding="utf-8",
    )
    fake_hdc.chmod(0o700)
    store = ExposureSessionStore(tmp_path / "sessions")
    session = store.create(
        "/dev/unix/socket/hiprofiler_unix_socket",
        device_serial="serial-123",
        session_id="exp_start123456",
    )
    first = run_exposure_session(store.root, session["session_id"], hdc_path=str(fake_hdc))
    assert first["state"] == "AWAIT_START_CONFIRMATION"
    assert first["summary"]["start_options"]

    with pytest.raises(ValueError):
        start_exposure_service(store.root, session["session_id"], option_id="wrong", hdc_path=str(fake_hdc))

    started = start_exposure_service(
        store.root,
        session["session_id"],
        option_id=first["summary"]["start_options"][0]["option_id"],
        hdc_path=str(fake_hdc),
    )
    assert started["state"] == "DONE"
    assert started["summary"]["surfaces"][0]["运行状态"] == "LISTENING"
    assert started["summary"]["start_action"]["requested_value"] == "1"
    assert "exposure_start_action.json" in started["artifacts"]


def test_decline_service_start_records_user_choice_without_device_write(tmp_path: Path):
    store = ExposureSessionStore(tmp_path / "sessions")
    session = store.create(
        "/dev/unix/socket/demo",
        device_serial="serial-123",
        session_id="exp_decline1234",
    )
    store.update(
        session["session_id"],
        state="AWAIT_START_CONFIRMATION",
        summary={"start_options": [{"option_id": "start-0", "service_name": "demo"}]},
    )
    declined = decline_exposure_service(store.root, session["session_id"], "用户选择保持停止")
    assert declined["state"] == "DONE"
    assert declined["summary"]["start_decision"] == "declined"
    assert declined["summary"]["start_options"]


def test_exposure_session_store_persists_events_and_deletes_only_its_session(tmp_path: Path):
    store = ExposureSessionStore(tmp_path)
    session = store.create(
        "hiprofilerd",
        device_serial="serial-123",
        llm_assist=False,
        session_id="exp_test123456",
    )

    assert session["state"] == "INTAKE"
    events = store.events(session["session_id"])
    assert events[0]["type"] == "session.created"
    assert events[0]["seq"] == 1

    store.update(session["session_id"], state="RUNNING", summary_zh="正在采集")
    events = store.events(session["session_id"])
    assert [event["seq"] for event in events] == [1, 2]
    assert events[-1]["summary_zh"] == "正在采集"

    other = store.create("other", device_serial="serial-123", session_id="exp_other123456")
    store.delete(session["session_id"])
    assert not (tmp_path / session["session_id"]).exists()
    assert (tmp_path / other["session_id"]).is_dir()


def test_exposure_session_store_persists_batch_metadata_and_validates_order(tmp_path: Path):
    store = ExposureSessionStore(tmp_path)
    session = store.create(
        "/dev/unix/socket/demo",
        device_serial="serial-123",
        session_id="exp_batch123456",
        batch_id="batch_test123456",
        batch_index=2,
        batch_total=3,
    )

    assert session["batch_id"] == "batch_test123456"
    assert session["batch_index"] == 2
    assert session["batch_total"] == 3
    persisted = store.list_sessions()[0]
    assert persisted["batch_id"] == "batch_test123456"
    assert persisted["batch_index"] == 2
    assert persisted["batch_total"] == 3

    with pytest.raises(ValueError):
        store.create(
            "/dev/unix/socket/demo",
            device_serial="serial-123",
            session_id="exp_batchbad1234",
            batch_id="batch_test123456",
            batch_index=4,
            batch_total=3,
        )


def test_exposure_session_store_rejects_unsafe_session_id(tmp_path: Path):
    store = ExposureSessionStore(tmp_path)
    with pytest.raises(ValueError):
        store.create("demo", device_serial="serial-123", session_id="../escape")


def test_run_exposure_session_writes_result_and_is_idempotent(tmp_path: Path):
    fake_hdc = tmp_path / "hdc"
    fake_hdc.write_text(
        """#!/bin/sh
if [ "$4" = "id" ]; then printf 'uid=0(root) gid=0(root)\n'; exit 0; fi
if [ "$4" = "ls" ] && [ "$5" = "-l" ]; then printf 'srw-rw---- 1 root shell 0 /dev/unix/socket/demo\n'; exit 0; fi
if [ "$4" = "ls" ] && [ "$5" = "-Z" ]; then printf 'u:object_r:demo_socket:s0 /dev/unix/socket/demo\n'; exit 0; fi
if [ "$4" = "cat" ] && [ "$5" = "/proc/net/unix" ]; then printf '0000: 00000002 00000000 00010000 0001 01 123 /dev/unix/socket/demo\n'; exit 0; fi
if [ "$4" = "netstat" ]; then printf 'unix 2 [ ACC ] STREAM LISTENING 123 /dev/unix/socket/demo\n'; exit 0; fi
if [ "$4" = "ps" ]; then printf 'demo 42\n'; exit 0; fi
if [ "$4" = "cat" ] && printf '%s' "$6" | grep -q '/proc/42/status'; then printf 'Name:\tdemo\nUid:\t0\t0\t0\t0\n'; exit 0; fi
if [ "$4" = "cat" ]; then printf 'service demo\n'; exit 0; fi
exit 0
""",
        encoding="utf-8",
    )
    fake_hdc.chmod(0o700)
    store = ExposureSessionStore(tmp_path / "sessions")
    session = store.create("/dev/unix/socket/demo", device_serial="serial-123", session_id="exp_run123456")

    result = run_exposure_session(store.root, session["session_id"], hdc_path=str(fake_hdc))

    assert result["state"] == "DONE"
    assert result["summary"]["surfaces"][0]["运行状态"] == "LISTENING"
    assert "exposure_surface.json" in result["artifacts"]
    assert store.events(session["session_id"])[-1]["type"] == "state.changed"
    second = run_exposure_session(store.root, session["session_id"], hdc_path=str(fake_hdc))
    assert second["updated_at"] == result["updated_at"]


def test_run_exposure_session_marks_damaged_target_failed(tmp_path: Path):
    store = ExposureSessionStore(tmp_path / "sessions")
    session = store.create(
        "/dev/unix/socket/demo",
        device_serial="serial-123",
        session_id="exp_badtarget123",
    )
    session_path = store._session_dir(session["session_id"]) / "session.json"
    payload = json.loads(session_path.read_text(encoding="utf-8"))
    payload["raw_target"] = "/dev/unix/socket/bad;touch /tmp/pwned"
    session_path.write_text(json.dumps(payload), encoding="utf-8")

    result = run_exposure_session(
        store.root,
        session["session_id"],
        hdc_path="/does/not/need/to/start",
    )

    assert result["state"] == "FAILED"
    assert "目标包含控制字符或 shell 元字符" in result["summary"]["errors"][0]


def test_run_exposure_session_resumes_interrupted_running_session(tmp_path: Path):
    fake_hdc = tmp_path / "hdc"
    fake_hdc.write_text(
        """#!/bin/sh
if [ "$4" = "id" ]; then printf 'uid=0(root) gid=0(root)\\n'; exit 0; fi
if [ "$4" = "ls" ] && [ "$5" = "-l" ]; then printf 'srw------- 1 root shell 0 /dev/unix/socket/demo\\n'; exit 0; fi
if [ "$4" = "ls" ] && [ "$5" = "-Z" ]; then printf 'u:object_r:demo_socket:s0 /dev/unix/socket/demo\\n'; exit 0; fi
if [ "$4" = "cat" ] && [ "$5" = "/proc/net/unix" ]; then printf '0000: 00000002 00000000 00010000 0001 01 123 /dev/unix/socket/demo\\n'; exit 0; fi
if [ "$4" = "netstat" ]; then printf 'unix 2 [ ACC ] STREAM LISTENING 123 /dev/unix/socket/demo\\n'; exit 0; fi
if [ "$4" = "ps" ]; then printf 'demo 42\\n'; exit 0; fi
exit 0
""",
        encoding="utf-8",
    )
    fake_hdc.chmod(0o700)
    store = ExposureSessionStore(tmp_path / "sessions")
    session = store.create(
        "/dev/unix/socket/demo",
        device_serial="serial-123",
        session_id="exp_resume12345",
    )
    store.update(session["session_id"], state="RUNNING", summary_zh="旧进程已中断")

    result = run_exposure_session(
        store.root,
        session["session_id"],
        hdc_path=str(fake_hdc),
    )

    assert result["state"] == "DONE"
    assert any("恢复未完成" in event["summary_zh"] for event in store.events(session["session_id"]))


def test_exposure_cli_parser_exposes_standalone_commands():
    from openant import cli

    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "exposure-surface",
            "create",
            "/dev/unix/socket/demo",
            "--root",
            "/tmp/exposure",
            "--device-serial",
            "serial-123",
        ]
    )
    assert args.command == "exposure-surface"
    assert args.exposure_surface_command == "create"
    assert args.target == "/dev/unix/socket/demo"

    args = parser.parse_args(
        [
            "exposure-surface",
            "create",
            "SP_daemon UDP 127.0.0.1:8283",
            "--root",
            "/tmp/exposure",
        ]
    )
    assert args.target == "SP_daemon UDP 127.0.0.1:8283"

    args = parser.parse_args(
        [
            "exposure-surface",
            "create",
            "/dev/unix/socket/demo",
            "--root",
            "/tmp/exposure",
            "--batch-id",
            "batch_test123456",
            "--batch-index",
            "2",
            "--batch-total",
            "3",
        ]
    )
    assert args.batch_id == "batch_test123456"
    assert args.batch_index == 2
    assert args.batch_total == 3

    args = parser.parse_args(
        [
            "exposure-surface",
            "start-service",
            "exp_test123456",
            "--root",
            "/tmp/exposure",
            "--option-id",
            "start-0000",
        ]
    )
    assert args.exposure_surface_command == "start-service"
    assert args.option_id == "start-0000"
