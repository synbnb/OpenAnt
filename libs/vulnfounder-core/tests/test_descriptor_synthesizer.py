"""协议描述符自动补证、反馈重试和合法探测报文测试。"""

from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

ds = importlib.import_module("utilities.openharmony_dynamic.descriptor_synthesizer")
cc = importlib.import_module("utilities.openharmony_dynamic.contract_compiler")


class ScriptedLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def __call__(self, binding, prompt, system=None, max_tokens=0):
        self.prompts.append((prompt, system))
        return self.replies.pop(0)


def _descriptor(fields, *, probe=None):
    return {
        "descriptor_id": "demo_protocol",
        "endianness": "ascii",
        "framing": "single_message",
        "transports": ["udp"],
        "fields": fields,
        "known_guards": [],
        "on_send_transforms": [],
        "structure_evidence": "handler parses key=value",
        "encoder_kind": "key_value",
        "wire_format": {"pair_separator": "=", "record_separator": "&", "terminator": "\\n"},
        "legal_probe": probe or {
            "mode": "udp", "host": "127.0.0.1", "port": 9999,
            "first": "command=ping", "second": "", "third": "",
            "evidence": "server.cpp:12",
        },
    }


def test_route_dispatch_prefers_literal_over_enum_case_variant() -> None:
    """枚举名与线路字面量同时出现时，不能误拒合法线路帧。"""
    skeleton = {
        "route_binding": {
            "evidence": (
                'MessageType::CATCH_NETWORK_TRAFFIC maps to '
                'std::string("catch_network_traffic")'
            )
        }
    }
    draft = {
        "protocol": {
            "frame_sequence": ["frame_first"],
            "field_values": {"frame_first": "catch_network_traffic:::TOKEN"},
        }
    }
    assert cc._validate_route_dispatch_spelling(draft, skeleton) == []


def test_descriptor_synthesis_retries_after_field_evidence_feedback(tmp_path):
    source = tmp_path / "handler.cpp"
    source.write_text("void Handle() { parse(command); }\n", encoding="utf-8")
    common = tmp_path / "protocol.h"
    common.write_text("static constexpr char COMMAND[] = \"command\";\n", encoding="utf-8")
    (tmp_path / "server.cpp").write_text("void Parse() { /* legal command */ }\n", encoding="utf-8")
    llm = ScriptedLLM([
        json.dumps({"tool": "finalize", "args": {"descriptor": _descriptor([
            {"name": "missing_field", "type": "string", "order": 0,
             "evidence": "handler.cpp:1"},
        ])}}),
        json.dumps({"tool": "grep", "args": {"pattern": "COMMAND|command", "path": "."}}),
        json.dumps({"tool": "finalize", "args": {"descriptor": _descriptor([
            {"name": "command", "type": "string", "order": 0,
             "evidence": "protocol.h:1"},
        ])}}),
    ])

    events = []
    result = ds.synthesize_descriptor(
        ["handler.cpp"], repo_root=str(tmp_path), route_context={"route_id": "r1"},
        binding_pair=("binding", llm), auto_approve=True, max_turns=5,
        on_event=events.append,
    )

    assert result.status == "APPROVED"
    assert result.descriptor is not None
    assert result.descriptor.fields[0].name == "command"
    assert result.attempts == 2
    assert result.evidence_paths and "protocol.h" in result.evidence_paths
    assert any("missing_field" in item for item in result.feedback_history)
    assert any(item[0] == "grep" for item in llm.prompts) is False
    assert len(llm.prompts) == 3
    assert any(e["event"] == "descriptor_synthesis_turn" and
               e["record"].get("kind") == "feedback" for e in events)
    assert any(e["record"].get("kind") == "approved" for e in events)


def test_descriptor_agent_can_read_same_route_startup_guard_source(tmp_path):
    """守卫 setter 可位于接收循环同目录的另一个实现文件，不能被证据范围静默丢掉。"""
    handler = tmp_path / "handler.cpp"
    handler.write_text(
        'bool CheckToken(const char* frame) { return isNeedToken; }\n'
        'void Handle() { parse(command); }\n', encoding="utf-8"
    )
    startup = tmp_path / "startup.cpp"
    startup.write_text(
        'void StartWithoutToken() { SetNeedToken(false); }\n', encoding="utf-8"
    )
    descriptor = _descriptor([], probe={
        "mode": "udp", "host": "127.0.0.1", "port": 8283,
        "first": "ping", "second": "", "third": "",
        "evidence": "handler.cpp:2",
    })
    descriptor["encoder_kind"] = "raw_text"
    descriptor["wire_format"] = {}
    llm = ScriptedLLM([
        json.dumps({"tool": "grep", "args": {"pattern": "SetNeedToken", "path": "."}}),
        json.dumps({"tool": "read_file", "args": {"path": "startup.cpp"}}),
        json.dumps({"tool": "finalize", "args": {"descriptor": descriptor}}),
    ])

    result = ds.synthesize_descriptor(
        ["handler.cpp"], repo_root=str(tmp_path),
        route_context={"handler": "Handle", "target_sink": "sink"},
        binding_pair=("binding", llm), auto_approve=True, max_turns=4,
    )

    assert result.status == "APPROVED"
    assert "startup.cpp" in result.evidence_paths
    assert any(item["tool"] == "read_file" and item["args"].get("path") == "startup.cpp"
               for item in result.audit)


def test_descriptor_rejects_empty_raw_text_for_key_value_parser(tmp_path):
    """源码已经显示键值拆包时，空字段 raw_text 必须反馈给 Agent 继续补证。"""
    handler = tmp_path / "handler.cpp"
    handler.write_text(
        'auto key = recvBuf.find("::");\n'
        'auto value = SplitMsg(recvBuf);\n', encoding="utf-8"
    )
    table = tmp_path / "messages.h"
    table.write_text('static constexpr char COMMAND[] = "command";\n', encoding="utf-8")
    first = _descriptor([], probe={
        "mode": "udp", "host": "127.0.0.1", "port": 9999,
        "first": "command::ping", "second": "", "third": "",
        "evidence": "handler.cpp:1",
    })
    first["encoder_kind"] = "raw_text"
    first["wire_format"] = {}
    second = _descriptor([
        {"name": "command", "type": "string", "order": 0,
         "evidence": "messages.h:1"},
    ], probe={
        "mode": "udp", "host": "127.0.0.1", "port": 9999,
        "first": "command::ping", "second": "", "third": "",
        "evidence": "handler.cpp:1",
    })
    llm = ScriptedLLM([
        json.dumps({"tool": "finalize", "args": {"descriptor": first}}),
        json.dumps({"tool": "read_file", "args": {"path": "messages.h"}}),
        json.dumps({"tool": "finalize", "args": {"descriptor": second}}),
    ])

    result = ds.synthesize_descriptor(
        ["handler.cpp"], repo_root=str(tmp_path),
        route_context={"handler": "Handle", "target_sink": "sink"},
        binding_pair=("binding", llm), auto_approve=True, max_turns=4,
    )

    assert result.status == "APPROVED"
    assert result.descriptor is not None
    assert result.descriptor.encoder_kind == "key_value"
    assert any("键值分帧证据" in item for item in result.feedback_history)


def test_recon_route_observations_keep_source_order_without_domain_keyword_bias():
    """路由索引不应因历史服务/危险 API 词表重排源码观察。"""
    recon = importlib.import_module("utilities.openharmony_dynamic.agent.recon_loop")
    finding = SimpleNamespace(
        sink="unrelated_sink",
        candidate_attack_chains=[],
        source_paths=[],
    )
    excerpts = [{
        "path": "service.cpp",
        "line_range": "1-3",
        "reason": "target_evidence",
        "text": "1: recv(buffer);\n2: loadcmd(command); invoke();\n3: parse(field);",
    }]

    observations = recon._current_route_observations(finding, excerpts)

    # 观察顺序由源码摘录及其来源决定；不能因为第二行恰好包含某个历史样本
    # 的函数名，就被一个全局 hard-coded score 提到第一行。
    assert [item["line"] for item in observations] == ["1", "2", "3"]


def test_recon_route_rejects_repeated_key_value_separator():
    """未声明 token 后缀时，key:::value 不能伪装成 key::value。"""
    errors = cc._validate_recon_protocol_route({
        "protocol": {
            "frame_sequence": ["frame_first", "frame_second"],
            "field_values": {
                "frame_first": "set_pkgName::smartperf",
                "frame_second": "catch_network_traffic:::smartperf",
            },
            "descriptor_snapshot": {
                "encoder_kind": "key_value",
                "wire_format": {"pair_separator": "::"},
                "fields": [
                    {"name": "set_pkgName", "order": 0},
                    {"name": "catch_network_traffic", "order": 1},
                ],
            },
        }
    })
    assert errors and "重复分隔符" in errors[0]


def test_recon_route_accepts_declared_token_suffix_separator():
    """协议显式声明 token 后缀时，command:::token 应被保留。"""
    errors = cc._validate_recon_protocol_route({
        "protocol": {
            "frame_sequence": ["frame_first", "frame_second"],
            "field_values": {
                "frame_first": "set_pkgName::smartperf",
                "frame_second": "catch_network_traffic:::smartperf",
            },
            "descriptor_snapshot": {
                "encoder_kind": "key_value",
                "wire_format": {"pair_separator": "::", "token_separator": ":::"},
                "fields": [
                    {"name": "set_pkgName", "order": 0},
                    {"name": "catch_network_traffic", "order": 1},
                ],
            },
        }
    })
    assert errors == []


def test_descriptor_route_accepts_absolute_path_for_existing_route_file(tmp_path):
    """绝对/相对路径表示同一 route 文件时，不应被越界保护误拒。"""
    source = tmp_path / "handler.cpp"
    source.write_text("void Handle() { recv(payload); }\n", encoding="utf-8")
    absolute = str(source.resolve())
    llm = ScriptedLLM([
        json.dumps({"tool": "read_file", "args": {"path": absolute, "offset": 0, "limit": 20}}),
        json.dumps({"tool": "finalize", "args": {"descriptor": {
            "descriptor_id": "absolute_route",
            "endianness": "ascii",
            "framing": "single_message",
            "transports": ["udp"],
            "fields": [],
            "known_guards": [],
            "on_send_transforms": [],
            "structure_evidence": "handler receives one raw frame",
            "encoder_kind": "raw_text",
            "wire_format": {"record_separator": "\\n", "terminator": ""},
            "legal_probe": {
                "mode": "udp", "host": "127.0.0.1", "port": 9999,
                "first": "ping", "evidence": f"{absolute}:1",
            },
        }}}),
    ])
    result = ds.synthesize_descriptor(
        ["handler.cpp"], repo_root=str(tmp_path), route_context={"handler": "Handle"},
        binding_pair=("binding", llm), auto_approve=True, max_turns=3,
    )
    assert result.status == "APPROVED"
    assert len(llm.prompts) == 2


def test_descriptor_evidence_requires_each_declared_source_reference(tmp_path):
    source = tmp_path / "protocol.cpp"
    source.write_text("const char COMMAND[] = \"command\";\n", encoding="utf-8")
    descriptor = ds._descriptor_from_draft(_descriptor([
        {"name": "command", "type": "string", "order": 0,
         "evidence": "protocol.cpp:1"},
    ], probe={
        "mode": "udp", "host": "127.0.0.1", "port": 9999,
        "first": "command=ping", "second": "", "third": "",
        "evidence": "protocol.cpp:1",
    }))
    check = ds.verify_descriptor_evidence(descriptor, ["protocol.cpp"], repo_root=str(tmp_path))
    assert check["evidence_failures"] == []
    descriptor.legal_probe["evidence"] = "missing.cpp:3"
    check = ds.verify_descriptor_evidence(descriptor, ["protocol.cpp"], repo_root=str(tmp_path))
    assert any("legal_probe" in failure for failure in check["evidence_failures"])


def test_auto_descriptor_retry_replaces_same_stable_registry_entry(monkeypatch):
    """同一自动描述符身份的重试结果必须能更新残缺快照。"""
    from utilities.openharmony_dynamic.models import ProtocolDescriptor
    from utilities.openharmony_dynamic.protocols import descriptors as registry

    isolated = dict(registry._REGISTRY)
    monkeypatch.setattr(registry, "_REGISTRY", isolated)
    first = ProtocolDescriptor(descriptor_id="auto_stable_route", structure_evidence="partial")
    second = ProtocolDescriptor(descriptor_id="auto_stable_route", structure_evidence="complete")
    registry.register(first)
    registry.register(second)
    assert registry.get_descriptor("auto_stable_route").structure_evidence == "complete"


def test_builtin_descriptor_registration_keeps_first_snapshot(monkeypatch):
    """手写协议仍保持先注册者优先，避免自动逻辑覆盖稳定内置协议。"""
    from utilities.openharmony_dynamic.models import ProtocolDescriptor
    from utilities.openharmony_dynamic.protocols import descriptors as registry

    isolated = dict(registry._REGISTRY)
    monkeypatch.setattr(registry, "_REGISTRY", isolated)
    first = ProtocolDescriptor(descriptor_id="stable_builtin", structure_evidence="first")
    second = ProtocolDescriptor(descriptor_id="stable_builtin", structure_evidence="second")
    registry.register(first)
    registry.register(second)
    assert registry.get_descriptor("stable_builtin").structure_evidence == "first"


def test_verify_fields_accepts_line_ranged_evidence_paths(tmp_path):
    source = tmp_path / "socket.cpp"
    source.write_text("\n".join(["x"] * 10 + ["const char command[] = \"command\";"]) + "\n", encoding="utf-8")
    descriptor = ds._descriptor_from_draft(_descriptor([
        {"name": "command", "type": "string", "order": 0, "evidence": "socket.cpp:11-12"},
    ]))
    check = ds.verify_fields_against_source(descriptor, ["socket.cpp:1-20"], repo_root=str(tmp_path))
    assert check["missing"] == []
    assert check["verified"] == ["command"]


def test_legal_probe_accepts_cli_argv_but_rejects_shell_form():
    assert ds._validate_legal_probe({
        "mode": "cli",
        "command_argv": ["hidumper", "-s", "123", "-a", "status"],
        "evidence": "cli_handler.cpp:10",
    }) == []
    errors = ds._validate_legal_probe({
        "mode": "event_bus",
        "command_argv": ["sh", "-c", "event-publisher"],
        "evidence": "event_handler.cpp:10",
    })
    assert any("command_argv" in error for error in errors)


def test_cli_legal_probe_uses_declared_device_command(monkeypatch):
    from utilities.openharmony_dynamic.models import (
        CleanupSpec, Contract, EntrySpec, FaultSpec, IdentitySpec, OracleSpec,
        ProtocolSpec, RiskSpec,
    )

    contract = Contract(
        contract_id="cli-selftest",
        finding_ids=["finding"],
        unit_id="unit",
        vuln_class="command_injection",
        entry=EntrySpec(kind="cli"),
        identity=IdentitySpec(),
        protocol=ProtocolSpec(
            descriptor_id="sp_daemon_text",
            descriptor_snapshot={
                "descriptor_id": "sp_daemon_text",
                "legal_probe": {
                    "mode": "cli",
                    "command_argv": ["hidumper", "-s", "123", "-a", "status"],
                    "evidence": "cli_handler.cpp:10",
                },
            },
        ),
        fault=FaultSpec(operator="payload_value_substitution"),
        oracle=OracleSpec(),
        risk=RiskSpec(target_process="demo"),
        cleanup=CleanupSpec(),
    )

    class FakeHdc:
        def __init__(self):
            self.commands = []

        def shell(self, argv, *, purpose="", **kwargs):
            self.commands.append((list(argv), purpose))
            return SimpleNamespace(
                returncode=0, stdout="status=ok", stderr="",
                to_dict=lambda: {"argv": list(argv), "returncode": 0, "purpose": purpose},
            )

    hdc = FakeHdc()
    notes = []
    errors = cc._run_legal_protocol_self_test(contract, hdc, notes)
    assert errors == []
    assert hdc.commands == [(
        ["hidumper", "-s", "123", "-a", "status"],
        "descriptor-selftest:command-send",
    )]
    assert any("cli command returncode=0" in note for note in notes)


def test_legal_probe_is_separate_from_attack_payload():
    probe = cc._legal_probe_values({
        "descriptor_id": "auto_demo",
        "encoder_kind": "key_value",
        "fields": [{"name": "command", "type": "string", "order": 0}],
        "legal_probe": {
            "mode": "udp", "host": "127.0.0.1", "port": 9999,
            "first": "command=ping", "second": "", "third": "",
        },
    })
    assert probe["first"] == "command=ping"
    assert ";" not in probe["first"]
    assert "echo" not in probe["first"]


def test_unsafe_legal_probe_is_rejected():
    with pytest.raises(ValueError, match="无害"):
        cc._legal_probe_values({
            "descriptor_id": "auto_bad",
            "encoder_kind": "raw_text",
            "fields": [],
            "legal_probe": {"mode": "udp", "host": "127.0.0.1", "port": 9999,
                            "first": "ping;echo bad"},
        })


def test_device_self_test_uses_only_descriptor_probe(monkeypatch):
    class FakeHdc:
        def shell(self, argv, *, purpose="", timeout_seconds=None):
            if argv == ["cat", "/proc/net/udp"]:
                return type("R", (), {"returncode": 0, "stdout": "127.0.0.1:205B LISTEN\n"})()
            if argv == ["hilog", "-r"]:
                return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "HAP_POC_SENT SELFTEST-GEN-auto-demo\n", "stderr": ""})()

    calls = []

    class FakeTransport:
        def __init__(self, hdc):
            self.hdc = hdc

        def build_and_run(self, fields, *, contract_id, wait_seconds):
            calls.append((fields, contract_id, wait_seconds))
            return type("S", (), {"reachability": "INPUT_DELIVERED", "detail": "sent"})()

        def cleanup(self):
            pass

    import utilities.openharmony_dynamic.transports.hap as hap
    monkeypatch.setattr(hap, "HapTransport", FakeTransport)
    contract = type("C", (), {
        "contract_id": "GEN-auto-demo",
        "entry": type("E", (), {"endpoint": "127.0.0.1:8283"})(),
        "protocol": type("P", (), {"descriptor_snapshot": {
            "descriptor_id": "auto_demo",
            "legal_probe": {
                "mode": "udp", "host": "127.0.0.1", "port": 8283,
                "first": "command=ping", "second": "", "third": "",
            },
        }})(),
    })()
    notes = []
    errors = cc._run_legal_protocol_self_test(contract, FakeHdc(), notes)
    assert errors == []
    assert calls and calls[0][0]["first"] == "command=ping"
    assert all("echo" not in str(v) for v in calls[0][0].values())
    assert any("自证通过" in note for note in notes)


def test_hap_transport_waits_for_real_send_signal_not_fixed_sleep():
    """启动请求返回不等于 HAP 已发送；延迟信号必须被等待到。"""
    import utilities.openharmony_dynamic.transports.hap as hap

    class FakeHdc:
        def __init__(self):
            self.calls = 0

        def shell(self, argv, *, purpose="", timeout_seconds=None):
            assert argv == ["hilog", "-x", "-T", "VulnFounderHapPoc"]
            self.calls += 1
            text = "" if self.calls == 1 else "HAP_POC_SENT DELAYED-TARGET transport=udp"
            return type("R", (), {"stdout": text, "returncode": 0})()

    transport = hap.HapTransport(FakeHdc())
    sent, detail = transport.wait_completion(
        target="DELAYED-TARGET", seconds=1.0, poll_interval=0.01,
    )
    assert sent is True
    assert detail == "HAP_POC_SENT DELAYED-TARGET"
    assert transport.hdc.calls == 2


def test_recon_protocol_route_rejects_empty_declared_frame():
    errors = cc._validate_recon_protocol_route({
        "protocol": {
            "frame_sequence": ["frame_first", "frame_second"],
            "field_values": {"frame_first_template": "command=one"},
            "param_space": {"frame_second": ""},
        }
    })
    assert errors and "frame_second" in errors[0]


def test_mutation_route_rejects_case_changed_dispatch_token():
    finding = cc.FindingInput(
        finding_id="route-001", unit_id="route", vuln_class="command_injection",
        description="route", sink="sink", entry_hints=["hap_udp 127.0.0.1:8283"],
    )
    skeleton = {
        "entry": {"kind": "hap_udp"},
        "route_binding": {
            "dispatch_conditions": ["MESSAGE_MAP token 'catch_network_traffic'"],
        },
    }
    draft = {
        "protocol": {
            "frame_sequence": ["frame_first"],
            "field_values": {"frame_first": "CATCH_NETWORK_TRAFFIC::x;echo __RUN_PATTERN__"},
            "param_space": {},
        },
        "oracle": {"artifact_forms": [{"form": "create", "path": "__MARKER__",
                                         "content_contains": "__RUN_PATTERN__"}]},
    }
    errors = cc._validate_mutation_route(draft, finding, skeleton)
    assert errors and "大小写" in errors[0]


def test_mutation_route_rejects_source_token_spelling_change(tmp_path):
    """协议帧不能把源码中的命令 token 改成近似拼写。"""
    source = tmp_path / "sp_thread_socket.cpp"
    source.write_text(
        'if (recvBuf.find("set_pkgName::") != std::string::npos) return OK;\n',
        encoding="utf-8",
    )
    header = tmp_path / "include" / "common.h"
    header.parent.mkdir()
    header.write_text(
        '{ MessageType::SET_PKG_NAME, std::string("set_pkgName") },\n',
        encoding="utf-8",
    )
    finding = cc.FindingInput(
        finding_id="route-source-token", unit_id="route", vuln_class="command_injection",
        description="route", sink="sink", repo_root=str(tmp_path),
        source_paths=["sp_thread_socket.cpp"],
    )
    skeleton = {"entry": {"kind": "hap_udp"}, "route_binding": {}}
    draft = {
        "protocol": {
            "frame_sequence": ["frame_first"],
            "field_values": {
                "frame_first": "set_pkg_name::smartperf;echo __RUN_PATTERN__ > __MARKER__",
            },
            "param_space": {},
        },
        "oracle": {"artifact_forms": [{"form": "create", "path": "__MARKER__",
                                         "content_contains": "__RUN_PATTERN__"}]},
    }
    errors = cc._validate_mutation_route(draft, finding, skeleton)
    assert errors and "set_pkgName" in errors[0]
    assert "set_pkg_name" in errors[0]


def test_mutation_route_accepts_exact_source_token(tmp_path):
    """实际源码采用何种大小写/下划线，校验器就接受何种精确字面量。"""
    source = tmp_path / "handler.cpp"
    source.write_text(
        'if (recvBuf.find("custom_cmd::") != std::string::npos) return OK;\n',
        encoding="utf-8",
    )
    finding = cc.FindingInput(
        finding_id="route-source-token-ok", unit_id="route", vuln_class="command_injection",
        description="route", sink="sink", repo_root=str(tmp_path),
        source_paths=["handler.cpp"],
    )
    skeleton = {"entry": {"kind": "hap_udp"}, "route_binding": {}}
    draft = {
        "protocol": {
            "frame_sequence": ["frame_first"],
            "field_values": {
                "frame_first": "custom_cmd::x;echo __RUN_PATTERN__ > __MARKER__",
            },
            "param_space": {},
        },
        "oracle": {"artifact_forms": [{"form": "create", "path": "__MARKER__",
                                         "content_contains": "__RUN_PATTERN__"}]},
    }
    assert cc._validate_mutation_route(draft, finding, skeleton) == []


def test_merge_recon_draft_drops_descriptive_preplant_scalar():
    finding = cc.FindingInput(
        finding_id="demo-001", unit_id="demo", vuln_class="command_injection",
        description="demo", sink="demo sink",
    )
    skeleton = {
        "entry": {"kind": "hap_udp"},
        "protocol": {
            "descriptor_id": "sp_daemon_text",
            "descriptor_snapshot": {},
        }
    }
    draft = {
        "protocol": {
            "field_values": {},
            "param_space": {
                "preplant": "marker 由注入命令创建，不预埋；目录需按设备权限决定",
            },
        },
        "oracle": {
            "kind": "artifact_differential",
            "artifact_forms": [],
        },
    }
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    assert merged is not None
    assert merged["protocol"]["param_space"].get("preplant", []) == []


def test_merge_recon_draft_normalizes_boolean_preplant_flag():
    """LLM 将“无需预埋”写成 false 时，运行器不能把 bool 当可迭代路径。"""
    finding = cc.FindingInput(
        finding_id="demo-boolean-preplant", unit_id="demo", vuln_class="command_injection",
        description="demo", sink="demo sink",
    )
    skeleton = {
        "entry": {"kind": "hap_udp"},
        "protocol": {"descriptor_id": "sp_daemon_text", "descriptor_snapshot": {}},
    }
    draft = {
        "protocol": {
            "field_values": {},
            "param_space": {"preplant": False},
        },
        "oracle": {"kind": "artifact_differential", "artifact_forms": []},
    }
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    assert merged is not None
    assert merged["protocol"]["param_space"]["preplant"] == []


def test_merge_recon_draft_normalizes_runtime_preplant_paths():
    finding = cc.FindingInput(
        finding_id="demo-002", unit_id="demo", vuln_class="command_injection",
        description="demo", sink="demo sink",
    )
    skeleton = {
        "entry": {"kind": "hap_udp"},
        "protocol": {"descriptor_id": "sp_daemon_text", "descriptor_snapshot": {}},
    }
    draft = {
        "protocol": {
            "field_values": {},
            "param_space": {
                "preplant": [{"path": "__RUN_DIR__/dependency.txt"}, "/data/log/eventlog/input.txt"],
            },
        },
        "oracle": {"kind": "artifact_differential", "artifact_forms": []},
    }
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    assert merged["protocol"]["param_space"]["preplant"] == [
        "__RUN_DIR__/dependency.txt", "/data/log/eventlog/input.txt"
    ]


def test_retry_repairs_incomplete_artifact_forms_from_class_shape():
    """重试只修复观测形状，不凭空生成服务帧。"""
    finding = cc.FindingInput(
        finding_id="demo-artifact-repair", unit_id="demo", vuln_class="command_injection",
        description="demo", sink="demo sink",
    )
    draft = {
        "protocol": {"field_values": {}, "param_space": {}},
        "oracle": {
            "kind": "artifact_differential",
            "artifact_forms": [{"path": "__MARKER__"}, {"form": "not-a-form"}],
            "hilog_expectations": [{}, "not-an-object"],
        },
    }
    merged = cc._merge_recon_draft(draft, finding, {
        "entry": {"kind": "hap_udp"},
        "protocol": {"descriptor_id": "sp_daemon_text", "descriptor_snapshot": {}},
    }, repair_missing_oracle=True)
    forms = merged["oracle"]["artifact_forms"]
    assert forms and all(item.get("form") in {"create", "exfil", "delete", "attr"} for item in forms)
    assert merged["oracle"]["hilog_expectations"] == []
    assert "retry-shape-repair" in merged["oracle"]["evidence"]


def test_missing_oracle_is_structured_review_error(monkeypatch):
    finding = cc.FindingInput(
        finding_id="demo-003", unit_id="demo", vuln_class="command_injection",
        description="demo", sink="demo sink", entry_hints=["hap_udp 127.0.0.1:8283"],
    )
    monkeypatch.setattr(cc, "_llm_binding", lambda: ("binding", lambda *a, **k: "{}"))
    entry_module = importlib.import_module(
        "utilities.openharmony_dynamic.agent.entry_discovery_loop"
    )
    recon_module = importlib.import_module(
        "utilities.openharmony_dynamic.agent.recon_loop"
    )
    monkeypatch.setattr(
        entry_module, "run_entry_discovery_loop",
        lambda **kwargs: SimpleNamespace(
            status="finalized", turns_used=1, device_commands_used=0,
            candidates=[], missing_evidence=[], notes=[], error="", audit=[],
            to_dict=lambda: {"status": "finalized", "candidates": []},
        ),
    )
    monkeypatch.setattr(
        recon_module, "run_recon_loop",
        lambda **kwargs: SimpleNamespace(
            status="finalized", turns_used=1, device_commands_used=0,
            notes=[], error="", audit=[], facts={},
            draft={"protocol": {"field_values": {}}},
        ),
    )
    result = cc.compile_contract(finding, hdc=None)
    assert result.compile_status == "REQUIRES_PROTOCOL_REVIEW"
    assert any("缺少 oracle" in error for error in result.errors)
