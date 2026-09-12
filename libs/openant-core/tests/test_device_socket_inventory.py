"""设备级 Socket 资产 Agent 的离线契约测试。"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from utilities.llm import CompletionResult, ToolUseBlock

from core.device_socket_inventory import (
    DeviceSocketAssetStore,
    SocketExposureProvider,
    SocketInventoryConfig,
    _canonicalise_dac_permissions,
    _compact_device_output,
    _enrich_assets_from_evidence,
    _enumerate_socket_records,
    _mode_code_from_text,
    _normalise_assets,
    _normalise_task_findings,
    initial_socket_inventory_task_tree,
)
from core.exposure_surface import HDCClient


class _InventoryAdapter:
    name = "offline"
    supports_tools = True

    def __init__(self):
        self.calls = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls.append({"model": model, "messages": messages, "tools": tools})
        if len(self.calls) == 1:
            return CompletionResult(
                content=[
                    ToolUseBlock(
                        id="tree",
                        name="update_task_tree",
                        input={
                            "updates": [{"task_id": "scan_all_socket_exposures", "status": "in_progress"}],
                            "new_nodes": [
                                {
                                    "task_id": "observe_unix_endpoints",
                                    "parent_id": "scan_all_socket_exposures",
                                    "title": "按需观测 Unix 端点",
                                    "required_fields": ["socket_name", "runtime_state"],
                                }
                            ],
                            "summary": "由模型根据设备情况拆分首个观测任务",
                        },
                    ),
                    ToolUseBlock(
                        id="cmd-1",
                        name="device_exec",
                        input={"command": "netstat -anp; ps -A; ls -l /dev/unix/socket/demo; ls -Z /dev/unix/socket/demo", "purpose": "确认端点和字段"},
                    ),
                ],
                input_tokens=3,
                output_tokens=4,
                stop_reason="tool_use",
            )
        return CompletionResult(
            content=[
                ToolUseBlock(
                    id="finish",
                    name="finish_inventory",
                    input={
                        "assets": [
                            {
                                "socket_name": "/dev/unix/socket/demo",
                                "transport": "UNIX",
                                "address_family": "AF_UNIX",
                                "socket_type": "STREAM",
                                "runtime_state": "LISTENING",
                                "process": "demo",
                                "pid": "1",
                                "uid": "0",
                                "process_selinux_domain": "u:r:demo:s0",
                                "dac_permissions": "srw-rw---- (0660)",
                                "selinux_label": "u:object_r:demo_socket:s0",
                                "evidence_ids": ["DA-EV-0001"],
                            }
                        ],
                        "coverage": {"unix": "observed", "network": "not_observed"},
                    },
                )
            ],
            input_tokens=5,
            output_tokens=6,
            stop_reason="tool_use",
        )


def test_inventory_task_tree_starts_with_single_root():
    tree = initial_socket_inventory_task_tree()
    assert [node["task_id"] for node in tree["nodes"]] == [
        "scan_all_socket_exposures",
    ]
    assert tree["nodes"][0]["title"] == "扫描所有socket暴露面"
    assert tree["planning_policy"] == "single_root_model_planned_children"


def test_inventory_task_tree_uses_custom_goal_without_static_child_nodes():
    tree = initial_socket_inventory_task_tree("检查 SP_daemon 的 UDP 8283 监听端点")
    assert tree["root_goal"] == "检查 SP_daemon 的 UDP 8283 监听端点"
    assert len(tree["nodes"]) == 1
    assert tree["nodes"][0]["task_id"] == "scan_all_socket_exposures"
    assert tree["nodes"][0]["title"] == "检查 SP_daemon 的 UDP 8283 监听端点"


def test_custom_task_findings_are_bounded_and_bound_to_device_evidence():
    summary, findings, error = _normalise_task_findings(
        {
            "task_summary": "设备上观测到目标进程。",
            "task_findings": [
                {
                    "title": "目标进程",
                    "summary": "进程处于运行状态。",
                    "status": "observed",
                    "evidence_ids": ["DA-EV-0001"],
                }
            ],
        },
        {"DA-EV-0001"},
    )
    assert error is None
    assert summary == "设备上观测到目标进程。"
    assert findings[0]["evidence_ids"] == ["DA-EV-0001"]


def test_custom_task_findings_reject_unknown_device_evidence():
    _, findings, error = _normalise_task_findings(
        {"task_findings": [{"title": "目标", "evidence_ids": ["DA-EV-9999"]}]},
        {"DA-EV-0001"},
    )
    assert findings[0]["evidence_ids"] == []
    assert error == "task_findings 引用了未知证据：DA-EV-9999"


def test_compaction_keeps_late_named_endpoint_and_permission_records():
    """大段 netstat 输出不能把末尾命名 Socket 的权限证据截掉。"""
    noise = "\n".join(
        f"unix  2 [ ] DGRAM CONNECTED {1000 + i} 1/noise_{i}"
        for i in range(500)
    )
    output = (
        noise
        + "\nunix  2 [ ACC ] STREAM LISTENING 4242 190/hilogd /dev/unix/socket/hilogInput"
        + "\nPATH=/dev/unix/socket/hilogInput"
        + "\nsrw-rw-rw- 1 logd log 0 2021-01-01 /dev/unix/socket/hilogInput"
        + "\nu:object_r:dev_unix_file:s0 /dev/unix/socket/hilogInput"
    )
    compact = _compact_device_output(output, 1200)
    assert "/dev/unix/socket/hilogInput" in compact
    assert "srw-rw-rw-" in compact
    assert "u:object_r:dev_unix_file:s0 /dev/unix/socket/hilogInput" in compact


def test_enumerate_socket_records_keeps_all_unix_rows_and_merges_sources():
    commands = [
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "netstat -anp"],
            "stdout": (
                "Active UNIX domain sockets (established and servers)\n"
                "Proto RefCnt Flags Type State PID/Program Name Path\n"
                "unix  2 [ ACC ] STREAM LISTENING 100 1/init /dev/unix/socket/demo\n"
                "unix  2 [ ] DGRAM CONNECTED 101 2/worker\n"
                "unix  3 [ ACC ] STREAM LISTENING 102 3/daemon @abstract\n"
            ),
        },
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "cat /proc/net/unix"],
            "stdout": (
                "Num RefCount Protocol Flags Type St Inode Path\n"
                "ffff: 00000002 00000000 00010000 0001 01 100 /dev/unix/socket/demo\n"
                "fffe: 00000002 00000000 00000000 0002 03 101\n"
                "fffd: 00000003 00000000 00010000 0001 01 102 @abstract\n"
            ),
        },
    ]
    evidence = [
        {"evidence_id": "DA-EV-0001", "command": "netstat -anp"},
        {"evidence_id": "DA-EV-0002", "command": "cat /proc/net/unix"},
    ]
    rows, summary = _enumerate_socket_records(commands, evidence)
    assert summary["total"] == 3
    assert summary["raw_rows"] == 6
    assert summary["merged_duplicates"] == 3
    assert summary["unix"] == 3
    assert summary["anonymous"] == 1
    by_inode = {row.get("inode"): row for row in rows}
    assert by_inode["100"]["state"] == "LISTENING"
    assert by_inode["100"]["evidence_ids"] == ["DA-EV-0001", "DA-EV-0002"]
    assert len(by_inode["100"]["raw_lines"]) == 2
    assert by_inode["102"]["endpoint"] == "@abstract"


def test_enumerate_socket_records_parses_tcp_and_udp_proc_rows():
    command = {
        "probe_kind": "agent_command",
        "argv": ["hdc", "shell", "cat /proc/net/tcp; cat /proc/net/tcp6; cat /proc/net/udp; cat /proc/net/udp6"],
        "stdout": (
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            "0: 0100007F:205B 00000000:0000 0A 0:0 0:0 0:0 0 0 100 0 12345\n"
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
            "0: 0100007F:205B 00000000:0000 07 0:0 0:0 0:0 0 0 101 0 12346\n"
            "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        ),
    }
    rows, summary = _enumerate_socket_records([command])
    assert summary["network"] == 2
    assert summary["by_transport"] == {"TCP": 1, "UDP": 1}
    tcp = next(row for row in rows if row["transport"] == "TCP")
    udp = next(row for row in rows if row["transport"] == "UDP")
    assert tcp["endpoint"] == "127.0.0.1:8283"
    assert tcp["state"] == "LISTENING"
    assert udp["state"] == "BOUND"
    assert udp["uid"] == "101"


def test_enumerate_socket_records_joins_standard_proc_status_attr_and_permissions():
    """真实 toybox 输出没有 PID= 标记且 attr/current 可能无换行。"""

    commands = [
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "netstat -anp"],
            "stdout": (
                "unix 2 [ ACC ] STREAM LISTENING 100 1/init /dev/unix/socket/demo\n"
                "unix 2 [ ] DGRAM CONNECTED 101 2/worker\n"
            ),
        },
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "cat /proc/1/status; cat /proc/2/status"],
            "stdout": (
                "Name:\tinit\nPid:\t1\nUid:\t0\t0\t0\t0\n"
                "Name:\tworker\nPid:\t2\nUid:\t1000\t1000\t1000\t1000\n"
            ),
        },
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "cat /proc/1/attr/current; cat /proc/2/attr/current"],
            "stdout": "u:r:init:s0u:r:worker:s0",
        },
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "ls -lZ /dev/unix/socket/demo"],
            "stdout": (
                "srw-rw---- 1 root root 0 2026-01-01 /dev/unix/socket/demo\n"
                "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n"
            ),
        },
    ]
    evidence = [
        {"evidence_id": "DA-EV-0001", "command": "netstat -anp", "excerpt": commands[0]["stdout"]},
        {"evidence_id": "DA-EV-0002", "command": "cat /proc/1/status; cat /proc/2/status", "excerpt": commands[1]["stdout"]},
        {"evidence_id": "DA-EV-0003", "command": "cat /proc/1/attr/current; cat /proc/2/attr/current", "excerpt": commands[2]["stdout"]},
        {"evidence_id": "DA-EV-0004", "command": "ls -lZ /dev/unix/socket/demo", "excerpt": commands[3]["stdout"]},
    ]
    rows, summary = _enumerate_socket_records(commands, evidence)
    by_inode = {row["inode"]: row for row in rows}

    assert by_inode["100"]["uid"] == "0"
    assert by_inode["100"]["process"] == "init"
    assert by_inode["100"]["process_selinux_domain"] == "u:r:init:s0"
    assert by_inode["100"]["dac_permissions"] == "srw-rw---- (0660)"
    assert by_inode["100"]["owner"] == "root"
    assert by_inode["100"]["group"] == "root"
    assert by_inode["100"]["selinux_label"] == "u:object_r:demo_socket:s0"
    assert by_inode["100"]["metadata"]["process"]["status"] == "confirmed"
    assert by_inode["100"]["metadata"]["permissions"]["status"] == "confirmed"
    assert by_inode["100"]["evidence_ids"] == ["DA-EV-0001", "DA-EV-0002", "DA-EV-0003", "DA-EV-0004"]

    # Anonymous CONNECTED rows have process facts but no Unix file object.
    assert by_inode["101"]["uid"] == "1000"
    assert by_inode["101"]["process_selinux_domain"] == "u:r:worker:s0"
    assert by_inode["101"]["dac_permissions"] == "NOT_APPLICABLE"
    assert by_inode["101"]["selinux_label"] == "NOT_APPLICABLE"
    assert by_inode["101"]["metadata"]["permissions"]["status"] == "not_applicable"
    assert summary["metadata_complete_records"] == 2
    assert summary["metadata_incomplete_records"] == 0


def test_enumerate_socket_records_marks_missing_process_metadata_explicitly():
    commands = [
        {
            "probe_kind": "agent_command",
            "argv": ["hdc", "shell", "cat /proc/net/unix"],
            "stdout": "ffff: 00000002 00000000 00010000 0001 01 100 /dev/unix/socket/demo\n",
        }
    ]
    rows, summary = _enumerate_socket_records(commands)
    row = rows[0]
    assert row["pid"] == "UNKNOWN"
    assert row["uid"] == "UNKNOWN"
    assert row["process_selinux_domain"] == "UNKNOWN"
    assert row["dac_permissions"] == "UNKNOWN"
    assert row["metadata"]["process"]["status"] == "unknown"
    assert row["metadata"]["permissions"]["status"] == "unknown"
    assert summary["metadata_incomplete_records"] == 1
    assert summary["metadata_missing_by_field"]["uid"] == 1


def test_normalise_assets_uses_concrete_state_when_runtime_state_is_unknown():
    assets = _normalise_assets(
        [
            {
                "socket_name": "/dev/unix/socket/demo",
                "state": "LISTENING",
                "runtime_state": "UNKNOWN",
            }
        ],
        "serial-1",
        10,
    )
    assert assets[0]["state"] == "LISTENING"
    assert assets[0]["runtime_state"] == "LISTENING"


def test_enrich_assets_only_uses_cited_endpoint_evidence():
    assets = [
        {
            "socket_name": "/dev/unix/socket/demo",
            "runtime_state": "LISTENING",
            "socket_type": "STREAM",
            "pid": "1",
            "process": "init",
            "inode": "UNKNOWN",
            "evidence_ids": ["DA-EV-0001"],
        }
    ]
    evidence = [
        {
            "evidence_id": "DA-EV-0001",
            "command": "netstat -anp",
            "excerpt": "unix  2 [ ACC ] STREAM LISTENING 42 1/init /dev/unix/socket/demo\n",
        },
        {
            "evidence_id": "DA-EV-0002",
            "command": "netstat -anp",
            "excerpt": "unix  2 [ ACC ] STREAM LISTENING 99 2/other /dev/unix/socket/demo\n",
        },
    ]
    enriched = _enrich_assets_from_evidence(assets, evidence)
    assert enriched[0]["inode"] == "42"
    assert enriched[0]["pid"] == "1"


def test_resume_migrates_legacy_static_roots_to_one_model_planned_root(tmp_path: Path):
    legacy_tree = {
        "schema_version": "openant.device-socket-assets.task-tree.v1",
        "nodes": [
            {"task_id": "device_preflight", "parent_id": None, "title": "旧预检", "status": "completed", "evidence_ids": ["DA-EV-0001"]},
            {"task_id": "unix_inventory", "parent_id": None, "title": "旧 Unix 枚举", "status": "pending", "evidence_ids": []},
        ],
    }
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
        binding=SimpleNamespace(adapter=_InventoryAdapter(), model="offline-model", provider_name="offline"),
        checkpoint={"plan": {"task_tree": legacy_tree}, "evidence": [{"evidence_id": "DA-EV-0001"}]},
    )
    nodes = provider.task_tree["nodes"]
    assert [node["task_id"] for node in nodes] == ["scan_all_socket_exposures"]
    assert nodes[0]["status"] == "in_progress"
    assert nodes[0]["evidence_ids"] == ["DA-EV-0001"]
    assert provider.task_tree["migrated_from_schema"] == "openant.device-socket-assets.task-tree.v1"


def test_socket_exposure_provider_uses_dynamic_commands_and_persists_artifacts(tmp_path: Path):
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        return 0, (
            "unix 2 [ ACC ] STREAM LISTENING 1 1/demo /dev/unix/socket/demo\n"
            "Name:\tdemo\nPid:\t1\nUid:\t0\t0\t0\t0\n"
            "u:r:demo:s0\n"
            "srw-rw---- 1 root root 0 2026-01-01 /dev/unix/socket/demo\n"
            "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n"
        ), ""

    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=runner),
        output_dir=tmp_path / "run",
        binding=binding,
        config=SocketInventoryConfig(max_rounds=2, max_commands=2),
    )
    result = provider.run()

    assert result["status"] == "complete"
    assert result["assets"][0]["socket_name"] == "/dev/unix/socket/demo"
    assert result["assets"][0]["asset_id"].startswith("socket-")
    assert result["socket_record_count"] == 1
    assert result["observed_socket_records"][0]["endpoint"] == "/dev/unix/socket/demo"
    assert result["socket_record_summary"]["complete"] is True
    assert [node["task_id"] for node in result["task_tree"]["nodes"]] == [
        "scan_all_socket_exposures",
        "observe_unix_endpoints",
    ]
    assert result["task_tree"]["nodes"][0]["status"] == "completed"
    assert result["evidence"][0]["evidence_id"] == "DA-EV-0001"
    assert calls[0][0][-1] == "netstat -anp; ps -A; ls -l /dev/unix/socket/demo; ls -Z /dev/unix/socket/demo"
    assert [tool.name for tool in adapter.calls[0]["tools"]] == [
        "update_task_tree",
        "device_exec",
        "finish_inventory",
    ]
    assert Path(result["artifacts"]["socket_inventory_plan.json"]).is_file()
    assert Path(result["artifacts"]["socket_inventory_trace.jsonl"]).read_text(encoding="utf-8").strip()
    trace_events = [item["event"] for item in result["trace"]]
    assert trace_events[0] == "agent.started"
    assert "model.requested" in trace_events
    assert "model.turn" in trace_events
    assert "tool.call" in trace_events
    assert "tool.result" in trace_events
    requested = next(item for item in result["trace"] if item["event"] == "model.requested")
    assert requested["details"]["message_count"] >= 1
    assert isinstance(requested["details"]["messages"], list)
    rag_events = [item for item in result["trace"] if item["event"] == "rag.retrieved"]
    assert [item["details"]["round"] for item in rag_events] == [1, 2]
    assert [item["details"]["top_k"] for item in rag_events] == [16, 8]
    assert rag_events[0]["details"]["query"] != rag_events[1]["details"]["query"]
    assert "netstat" in rag_events[1]["details"]["query"]
    assert isinstance(rag_events[0]["details"]["snippets"], list)
    requested_rounds = [item for item in result["trace"] if item["event"] == "model.requested"]
    assert [item["details"]["rag_round"] for item in requested_rounds] == [1, 2]
    assert "本轮动态知识参考" in requested_rounds[1]["details"]["system"]
    progress_plan = json.loads((tmp_path / "run" / "socket_inventory_plan.json").read_text(encoding="utf-8"))
    assert progress_plan["status"] == "complete"
    assert progress_plan["trace_count"] == len(result["trace"])
    assert progress_plan["socket_record_count"] == 1


def test_inventory_rag_off_is_explicitly_recorded_for_each_model_turn(tmp_path: Path):
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")

    def runner(argv, timeout):
        return 0, "unix 2 [ ACC ] STREAM LISTENING 1 1/demo /dev/unix/socket/demo\n", ""

    result = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=runner),
        output_dir=tmp_path / "run",
        binding=binding,
        config=SocketInventoryConfig(max_rounds=2, max_commands=2, rag_mode="off"),
    ).run()

    skipped = [item for item in result["trace"] if item["event"] == "rag.skipped"]
    assert [item["details"]["round"] for item in skipped] == [1, 2]
    requests = [item for item in result["trace"] if item["event"] == "model.requested"]
    assert all(item["details"]["rag_snippet_count"] == 0 for item in requests)


def test_inventory_store_isolates_device_snapshots(tmp_path: Path):
    store = DeviceSocketAssetStore(tmp_path)
    payload = store.save({"status": "complete", "assets": [{"runtime_state": "LISTENING"}]}, "serial-a")
    assert payload["device_serial"] == "serial-a"
    assert payload["run_id"]
    assert payload["latest_updated"] is True
    assert store.load("serial-a")["asset_count"] == 1
    assert store.list_devices()[0]["device_serial"] == "serial-a"
    assert not (store.device_dir("serial-b") / "latest.json").exists()


def test_custom_task_snapshot_does_not_replace_full_device_latest_inventory(tmp_path: Path):
    store = DeviceSocketAssetStore(tmp_path)
    baseline = store.save(
        {
            "status": "complete",
            "task_goal": "扫描所有socket暴露面",
            "task_scope": "full_socket_inventory",
            "socket_inventory_required": True,
            "assets": [{"socket_name": "/dev/unix/socket/baseline", "runtime_state": "LISTENING"}],
        },
        "serial-a",
    )
    scoped = store.save(
        {
            "status": "complete",
            "task_goal": "检查设备系统版本",
            "task_scope": "custom_read_only",
            "socket_inventory_required": False,
            "task_summary": "已读取版本",
            "assets": [],
        },
        "serial-a",
    )
    assert baseline["latest_updated"] is True
    assert scoped["latest_updated"] is False
    assert store.load("serial-a")["assets"][0]["socket_name"] == "/dev/unix/socket/baseline"
    assert scoped["task_goal"] == "检查设备系统版本"


def test_failed_inventory_keeps_last_confirmed_snapshot(tmp_path: Path):
    store = DeviceSocketAssetStore(tmp_path)
    confirmed = store.save(
        {"status": "complete", "assets": [{"socket_name": "/dev/unix/socket/known", "runtime_state": "LISTENING"}]},
        "serial-a",
    )
    failed = store.save({"status": "error", "assets": [], "error": "device offline"}, "serial-a")
    assert failed["latest_updated"] is False
    assert store.load("serial-a")["run_id"] == confirmed["run_id"]
    assert store.load("serial-a")["asset_count"] == 1


def test_store_loads_checkpoint_for_resume_without_replaying_commands(tmp_path: Path):
    store = DeviceSocketAssetStore(tmp_path)
    serial = "serial-a"
    run_id = "20260912T010203000000Z-a1b2c3"
    run_dir = store.device_dir(serial) / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "socket_inventory_plan.json").write_text(
        json.dumps(
            {
                "device_serial": serial,
                "status": "incomplete",
                "rounds": 2,
                "task_tree": initial_socket_inventory_task_tree(),
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "socket_inventory_evidence.json").write_text(
        json.dumps({"evidence": [{"evidence_id": "DA-EV-0001", "command": "cat /proc/net/unix"}]}),
        encoding="utf-8",
    )
    (run_dir / "socket_inventory_commands.jsonl").write_text(
        json.dumps(
            {
                "probe_kind": "agent_command",
                "argv": ["/opt/hdc", "-t", serial, "shell", "cat /proc/net/unix"],
                "returncode": 0,
                "stdout": "ok",
                "stderr": "",
                "elapsed_ms": 1,
                "truncated": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "socket_inventory_trace.jsonl").write_text("{\"event\":\"agent.started\"}\n", encoding="utf-8")

    checkpoint = store.load_run(serial, run_id)
    assert checkpoint["run_id"] == run_id
    assert checkpoint["plan"]["status"] == "incomplete"
    assert checkpoint["evidence"][0]["evidence_id"] == "DA-EV-0001"
    assert checkpoint["commands"][0]["argv"][-1] == "cat /proc/net/unix"
    assert checkpoint["trace"][0]["event"] == "agent.started"


def test_provider_resume_reuses_state_and_continues_model_loop(tmp_path: Path):
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient(
            "/opt/hdc",
            "serial-1",
            runner=lambda *_: (
                0,
                "unix 2 [ ACC ] STREAM LISTENING 1 1/demo /dev/unix/socket/demo\n"
                "srw-rw---- 1 root root 0 2026-01-01 /dev/unix/socket/demo\n"
                "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n",
                "",
            ),
        ),
        output_dir=tmp_path / "resume-run",
        binding=binding,
        config=SocketInventoryConfig(max_rounds=3, max_commands=2),
        checkpoint={
            "run_id": "20260912T010203000000Z-a1b2c3",
            "plan": {"rounds": 0, "status": "incomplete", "task_tree": initial_socket_inventory_task_tree()},
            "evidence": [],
            "commands": [],
            "trace": [],
        },
    )
    result = provider.run()
    assert result["status"] == "complete"
    assert provider._resume_run_id == "20260912T010203000000Z-a1b2c3"
    assert "resumed_from_run" in adapter.calls[0]["messages"][0].content[0].text


def test_finish_inventory_rejects_unknown_evidence(tmp_path: Path):
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "ok\n", "")),
        output_dir=tmp_path,
        binding=binding,
        config=SocketInventoryConfig(max_rounds=1, max_commands=1),
    )
    outcome = provider._finish({"assets": [{"socket_name": "/dev/unix/socket/demo", "evidence_ids": ["DA-EV-9999"]}]})
    assert outcome["status"] == "rejected"
    assert provider.finish_payload is None


def test_custom_task_finish_accepts_non_socket_fact_with_cited_evidence(tmp_path: Path):
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
        binding=binding,
        task_goal="检查设备系统版本",
        config=SocketInventoryConfig(max_rounds=1, max_commands=1),
    )
    provider.evidence = [
        {
            "evidence_id": "DA-EV-0001",
            "command": "getprop ro.build.version.os",
            "excerpt": "OpenHarmony\n",
        }
    ]
    outcome = provider._finish(
        {
            "assets": [],
            "task_summary": "已读取设备系统版本。",
            "task_findings": [
                {
                    "title": "系统版本",
                    "summary": "设备输出为 OpenHarmony。",
                    "status": "observed",
                    "evidence_ids": ["DA-EV-0001"],
                }
            ],
        }
    )
    assert outcome["status"] == "complete"
    assert provider.finish_payload["task_findings"][0]["title"] == "系统版本"
    assert provider.socket_inventory_required is False


def test_finish_inventory_accepts_documented_nested_process_and_permissions(tmp_path: Path):
    """计划 schema 的嵌套字段与历史扁平字段应得到同一内部结果。"""

    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
        binding=binding,
        config=SocketInventoryConfig(max_rounds=1, max_commands=1),
    )
    provider.evidence = [
        {
            "evidence_id": "DA-EV-0001",
            "command": "netstat -anp; ps -A; ls -lZ /dev/unix/socket/demo",
            "excerpt": (
                "unix 2 [ ACC ] STREAM LISTENING 1 1/demo /dev/unix/socket/demo\n"
                "srw-rw---- 1 root root 0 2026-01-01 /dev/unix/socket/demo\n"
                "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n"
                "1 demo u:r:demo:s0\n"
            ),
        }
    ]
    outcome = provider._finish(
        {
            "assets": [
                {
                    "socket_name": "/dev/unix/socket/demo",
                    "transport": "UNIX",
                    "address_family": "AF_UNIX",
                    "socket_type": "STREAM",
                    "runtime_state": "LISTENING",
                    "inode": "1",
                    "process": {"name": "demo", "pid": "1", "uid": "0", "selinux_domain": "u:r:demo:s0"},
                    "permissions": {"dac": "srw-rw---- (0660)", "selinux_label": "u:object_r:demo_socket:s0"},
                    "evidence_ids": ["DA-EV-0001"],
                }
            ]
        }
    )
    assert outcome["status"] == "complete"
    assert provider.finish_payload is not None


def test_finish_inventory_rejects_connected_inode_for_listening_state(tmp_path: Path):
    """同一命名端点同时有 CONNECTED/LISTENING 行时必须选监听 inode。"""
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
        binding=binding,
        config=SocketInventoryConfig(max_rounds=1, max_commands=1),
    )
    provider.evidence = [
        {
            "evidence_id": "DA-EV-0001",
            "command": "netstat -anp; ps -A; ls -l /dev/unix/socket/demo; ls -Z /dev/unix/socket/demo",
            "excerpt": (
                "unix 3 [ ] STREAM CONNECTED 2 1/demo /dev/unix/socket/demo\n"
                "unix 2 [ ACC ] STREAM LISTENING 1 1/demo /dev/unix/socket/demo\n"
                "srw-rw---- 1 root root 0 2026-01-01 /dev/unix/socket/demo\n"
                "u:object_r:demo_socket:s0 /dev/unix/socket/demo\n"
                "PID=1\nName:\tdemo\nUid:\t0\t0\t0\t0\nu:r:demo:s0\n"
            ),
        }
    ]
    outcome = provider._finish(
        {
            "assets": [
                {
                    "socket_name": "/dev/unix/socket/demo",
                    "transport": "UNIX",
                    "address_family": "AF_UNIX",
                    "socket_type": "STREAM",
                    "state": "LISTENING",
                    "inode": "2",
                    "pid": "1",
                    "process": "demo",
                    "uid": "0",
                    "process_selinux_domain": "u:r:demo:s0",
                    "dac_permissions": "srw-rw---- (0660)",
                    "selinux_label": "u:object_r:demo_socket:s0",
                    "evidence_ids": ["DA-EV-0001"],
                }
            ]
        }
    )
    assert outcome["status"] == "rejected"
    assert outcome["observation_mismatches"][0]["fields"]["inode"]["expected"] == "1"


def test_finish_inventory_rejects_connected_or_present_rows(tmp_path: Path):
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
        binding=binding,
        config=SocketInventoryConfig(max_rounds=1, max_commands=1),
    )
    outcome = provider._finish(
        {
            "assets": [
                {"socket_name": "/dev/unix/socket/demo", "runtime_state": "PRESENT", "evidence_ids": []}
            ]
        }
    )
    assert outcome["status"] == "rejected"
    assert provider.finish_payload is None


def test_normalise_assets_accepts_endpoint_uri_and_chinese_path():
    assets = _normalise_assets(
        [
            {"endpoint": "unix:///dev/unix/socket/demo", "runtime_state": "LISTENING"},
            {"套接字路径": "/dev/unix/socket/other", "socket_family": "AF_UNIX", "状态": "BOUND"},
        ],
        "serial-a",
        8,
    )
    assert [item["socket_name"] for item in assets] == [
        "/dev/unix/socket/demo",
        "/dev/unix/socket/other",
    ]
    assert assets[0]["transport"] == "UNIX"
    assert assets[0]["address_family"] == "AF_UNIX"
    assert assets[1]["transport"] == "UNIX"


def test_normalise_assets_flattens_documented_nested_fields():
    assets = _normalise_assets(
        [
            {
                "endpoint": "/dev/unix/socket/demo",
                "runtime_state": "LISTENING",
                "process": {"name": "demo", "pid": 7, "uid": 1000, "selinux_domain": "u:r:demo:s0"},
                "permissions": {"dac": "srw-rw---- (0600)", "selinux_label": "u:object_r:demo_socket:s0"},
            }
        ],
        "serial-a",
        8,
    )
    assert assets[0]["process"] == "demo"
    assert assets[0]["pid"] == "7"
    assert assets[0]["uid"] == "1000"
    assert assets[0]["process_selinux_domain"] == "u:r:demo:s0"
    assert assets[0]["dac_permissions"] == "srw-rw---- (0660)"
    assert assets[0]["selinux_label"] == "u:object_r:demo_socket:s0"
    assert assets[0]["kind"] == "unix_socket"
    assert assets[0]["provenance"] == "observed"


def test_normalise_assets_merges_proc_duplicate_and_prefers_listening():
    assets = _normalise_assets(
        [
            {"endpoint": "/dev/unix/socket/demo", "runtime_state": "BOUND", "socket_type": "DGRAM"},
            {"endpoint": "/dev/unix/socket/demo", "runtime_state": "LISTENING", "socket_type": "STREAM", "pid": 1},
            {"endpoint": "UNKNOWN", "runtime_state": "BOUND"},
        ],
        "serial-a",
        8,
    )
    assert len(assets) == 1
    assert assets[0]["runtime_state"] == "LISTENING"
    assert assets[0]["socket_type"] == "DGRAM"
    assert assets[0]["pid"] == "1"


def test_canonicalise_dac_permissions_uses_symbolic_socket_mode():
    assert _canonicalise_dac_permissions("srw-rw--w- (0622)") == "srw-rw--w- (0662)"
    assert _canonicalise_dac_permissions("s-w--w--w- (0622)") == "s-w--w--w- (0222)"
    assert _canonicalise_dac_permissions("srw-rw---- (0600) root:root (0600)") == "srw-rw---- (0660) root:root"
    assert _canonicalise_dac_permissions("0660 root:root") == "srw-rw---- (0660) root:root"
    assert _mode_code_from_text("s-w--w--w-") == "0222"
    assert _mode_code_from_text("0633 logd:log") == "0633"


def test_proc_net_unix_keeps_named_bound_datagram_state_three(tmp_path: Path):
    """OpenHarmony reports a bound named DGRAM as state 03 in procfs."""
    adapter = _InventoryAdapter()
    binding = SimpleNamespace(adapter=adapter, model="offline-model", provider_name="offline")
    provider = SocketExposureProvider(
        HDCClient("/opt/hdc", "serial-1", runner=lambda *_: (0, "", "")),
        output_dir=tmp_path,
        binding=binding,
        config=SocketInventoryConfig(max_rounds=1, max_commands=1),
    )
    provider.evidence = [
        {
            "command": "cat /proc/net/unix",
            "excerpt": (
                "Num RefCount Protocol Flags Type St Inode Path\n"
                "ffff 000000A0 00000000 0002 03 583 /dev/unix/socket/hilogInput\n"
                "ffff 00000002 00000000 00010000 0001 03 10375 /dev/unix/socket/paramservice\n"
            ),
        }
    ]
    candidates = provider._observed_endpoint_candidates()
    by_name = {item["endpoint"]: item["state"] for item in candidates}
    assert by_name["/dev/unix/socket/hilogInput"] == "BOUND"
    assert "/dev/unix/socket/paramservice" not in by_name
