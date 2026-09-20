"""入口发现 Agent Loop 的行为测试。

这些测试不连接真实设备，也不依赖真实 LLM；使用脚本化模型和 FakeHdc
验证入口发现阶段的边界、证据门槛以及它位于协议匹配之前。
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

ed = importlib.import_module("utilities.openharmony_dynamic.agent.entry_discovery_loop")
cc = importlib.import_module("utilities.openharmony_dynamic.contract_compiler")
from utilities.openharmony_dynamic.finding_input import FindingInput  # noqa: E402
from utilities.openharmony_dynamic.models import ProtocolDescriptor, FieldSpec  # noqa: E402
from utilities.openharmony_dynamic.protocols.codec import encode  # noqa: E402


class ScriptedLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def __call__(self, binding, prompt, system=None, max_tokens=0):
        self.prompts.append((prompt, system))
        return self.replies.pop(0)


class FakeHdc:
    serial = "FAKE-ENTRY-SERIAL"

    def __init__(self, stdout="LISTEN 127.0.0.1:8283"):
        self.stdout = stdout
        self.calls = []

    def shell(self, argv, *, purpose="", timeout_seconds=None):
        self.calls.append((argv, purpose))
        return type("Rec", (), {"stdout": self.stdout, "returncode": 0, "stderr": ""})()


def _finding(repo_root: Path, hints=None):
    return FindingInput(
        finding_id="DP-02",
        unit_id="sp_dp02",
        vuln_class="command_injection",
        description="外部包名进入命令执行点",
        source_paths=["sp_thread_socket.cpp"],
        evidence_lines=[[1, 3]],
        sink="SPUtils::LoadCmd at Network.cpp:153",
        entry_hints=list(hints or []),
        repo_root=str(repo_root),
        analysis_context={
            "完整攻击链": "SpThreadSocket::HandleMsg -> Network::ItemData -> SPUtils::LoadCmd",
            "证据": ["sp_thread_socket.cpp:2"],
        },
    )


def _bind(replies):
    llm = ScriptedLLM(replies)
    return ("fake-binding", llm)


def test_entry_discovery_finds_and_validates_source_candidate(tmp_path):
    (tmp_path / "sp_thread_socket.cpp").write_text(
        "void HandleMsg() {}\nvoid Bind() { bind(8283); }\nvoid Recv() {}\n",
        encoding="utf-8",
    )
    replies = [
        json.dumps({"tool": "grep", "args": {"pattern": "8283|recvfrom|bind", "path": "."}}),
        json.dumps({"tool": "hdc_shell", "args": {"argv": ["cat", "/proc/net/udp"]}}),
        json.dumps({
            "tool": "finalize",
            "args": {
                "candidates": [{
                    "kind": "hap_udp",
                    "endpoint": "127.0.0.1:8283",
                    "confidence": "high",
                    "source_evidence": ["sp_thread_socket.cpp:2"],
                    "device_evidence": ["device socket inventory: UDP 127.0.0.1:8283"],
                    "reason": "源码绑定和设备监听端点一致",
                }],
                "missing_evidence": [],
            },
        }),
    ]
    result = ed.run_entry_discovery_loop(
        finding=_finding(tmp_path), repo_root=tmp_path, hdc=FakeHdc(),
        binding_pair=_bind(replies), max_turns=4,
    )
    assert result.status == "finalized"
    assert result.candidates[0].hint == "hap_udp 127.0.0.1:8283"
    assert result.candidates[0].confidence == "high"
    assert result.candidates[0].source_evidence == ["sp_thread_socket.cpp:2"]
    assert result.device_commands_used == 1


def test_entry_discovery_rejects_candidate_without_evidence(tmp_path):
    (tmp_path / "sp_thread_socket.cpp").write_text("void HandleMsg() {}\n", encoding="utf-8")
    bind = _bind([
        json.dumps({"tool": "grep", "args": {"pattern": "bind|recvfrom|socket", "path": "."}}),
        json.dumps({
            "tool": "finalize",
            "args": {
                "candidates": [{
                    "kind": "hap_udp",
                    "endpoint": "127.0.0.1:8283",
                    "confidence": "high",
                    "source_evidence": [],
                    "device_evidence": [],
                }],
                "missing_evidence": ["没有找到 bind/监听证据"],
            },
        }),
        json.dumps({"tool": "finalize", "args": {"candidates": [], "missing_evidence": ["仍缺证据"]}}),
    ])
    result = ed.run_entry_discovery_loop(
        finding=_finding(tmp_path), repo_root=tmp_path, hdc=None, binding_pair=bind, max_turns=3,
    )
    assert result.status == "no_candidate"
    assert result.candidates == []
    assert any("证据" in item for item in result.missing_evidence)


def test_entry_discovery_cannot_finalize_empty_before_any_evidence(tmp_path):
    (tmp_path / "sp_thread_socket.cpp").write_text("void HandleMsg() {}\n", encoding="utf-8")
    bind = _bind([
        json.dumps({"tool": "finalize", "args": {"candidates": [], "missing_evidence": ["先查证"]}}),
        json.dumps({"tool": "grep", "args": {"pattern": "recv|bind|socket", "path": "."}}),
        json.dumps({"tool": "finalize", "args": {"candidates": [], "missing_evidence": ["未发现入口"]}}),
    ])
    result = ed.run_entry_discovery_loop(
        finding=_finding(tmp_path), repo_root=tmp_path, hdc=None, binding_pair=bind, max_turns=4,
    )
    assert result.status == "no_candidate"
    assert result.turns_used == 3
    assert result.audit and result.audit[0]["tool"] == "grep"


def test_source_evidence_ranges_are_normalized(tmp_path):
    (tmp_path / "socket.cpp").write_text("\n".join(["void f() {}"] * 60) + "\n", encoding="utf-8")
    bind = _bind([
        json.dumps({"tool": "grep", "args": {"pattern": "socket", "path": "."}}),
        json.dumps({
            "tool": "finalize",
            "args": {"candidates": [{
                "kind": "unix_stream", "endpoint": "/dev/unix/socket/demo",
                "confidence": "high", "source_evidence": ["socket.cpp:10-12,30-32"],
                "device_evidence": [],
            }]},
        }),
    ])
    result = ed.run_entry_discovery_loop(
        finding=_finding(tmp_path), repo_root=tmp_path, hdc=None,
        binding_pair=bind, max_turns=3,
    )
    assert result.status == "finalized"
    assert result.candidates[0].source_evidence == ["socket.cpp:10-12", "socket.cpp:30-32"]


def test_compile_runs_entry_discovery_before_descriptor_match(monkeypatch, tmp_path):
    (tmp_path / "sp_thread_socket.cpp").write_text("void HandleMsg() {}\n", encoding="utf-8")
    finding = _finding(tmp_path, hints=[])
    order = []

    fake_result = type("EntryResult", (), {
        "status": "finalized",
        "candidates": [type("Candidate", (), {"hint": "hap_udp 127.0.0.1:8283"})()],
        "notes": [],
        "turns_used": 1,
        "device_commands_used": 0,
        "missing_evidence": [],
        "to_dict": lambda self: {"status": self.status, "candidates": [{"hint": self.candidates[0].hint}]},
    })()

    class FakeCompilerBinding:
        pass

    monkeypatch.setattr(cc, "_llm_binding", lambda: (FakeCompilerBinding(), lambda *a, **k: "{}"))
    monkeypatch.setattr(
        "utilities.openharmony_dynamic.agent.entry_discovery_loop.run_entry_discovery_loop",
        lambda **kwargs: (order.append("entry_discovery") or fake_result),
    )
    original_match = cc._match_descriptor

    def wrapped_match(value):
        order.append("match_descriptor")
        return original_match(value)

    monkeypatch.setattr(cc, "_match_descriptor", wrapped_match)
    # 后续侦查 loop 即使使用 fake binding 也不影响本测试；这里只验证入口发现
    # 已经发生在描述符匹配之前。
    result = cc.compile_contract(finding, hdc=None)
    assert order[:2] == ["entry_discovery", "match_descriptor"]
    assert "hap_udp 127.0.0.1:8283" in finding.entry_hints
    assert result.descriptor_hit == "sp_daemon_text"


def test_compile_does_not_silently_choose_ambiguous_endpoints(monkeypatch, tmp_path):
    (tmp_path / "sp_thread_socket.cpp").write_text("void HandleMsg() {}\n", encoding="utf-8")
    finding = _finding(tmp_path, hints=[])
    candidates = [
        type("Candidate", (), {"hint": "hap_udp 127.0.0.1:8283"})(),
        type("Candidate", (), {"hint": "hap_tcp 127.0.0.1:8284"})(),
    ]
    fake_result = type("EntryResult", (), {
        "status": "finalized", "candidates": candidates, "notes": [],
        "turns_used": 2, "device_commands_used": 2,
        "to_dict": lambda self: {"status": self.status, "candidates": [c.hint for c in self.candidates]},
    })()
    monkeypatch.setattr(cc, "_llm_binding", lambda: ("binding", lambda *a, **k: "{}"))
    monkeypatch.setattr(
        "utilities.openharmony_dynamic.agent.entry_discovery_loop.run_entry_discovery_loop",
        lambda **kwargs: fake_result,
    )
    result = cc.compile_contract(finding, hdc=None)
    assert result.compile_status == "REQUIRES_PROTOCOL_REVIEW"
    assert "多个可验证端点" in result.errors[0]
    assert result.descriptor_hit == ""
    assert len(finding.entry_hints) == 2


def test_compile_retry_does_not_bypass_ambiguous_entry_gate(monkeypatch, tmp_path):
    finding = _finding(tmp_path, hints=[])
    fake = type("CompileResult", (), {
        "compile_status": "REQUIRES_PROTOCOL_REVIEW",
        "errors": ["入口发现得到多个可验证端点，不能自动选择"],
        "notes": [], "llm_used": True,
    })()
    calls = []

    def fake_compile(*args, **kwargs):
        calls.append(1)
        return fake

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    result = cc.compile_contract_with_retry(finding, hdc=None, failure_log={})
    assert result is fake
    assert len(calls) == 1


def test_route_binding_keeps_finding_specific_handler_and_state(tmp_path):
    (tmp_path / "socket.cpp").write_text("void HandleMsg() {}\n", encoding="utf-8")
    candidate, error = ed._validate_candidate({
        "kind": "hap_udp",
        "endpoint": "127.0.0.1:8283",
        "confidence": "high",
        "source_evidence": ["socket.cpp:1"],
        "device_evidence": ["udp 8283 LISTEN"],
        "route_relevance": "direct",
        "handler": "SpThreadSocket::HandleMsg",
        "target_sink": "SPUtils::LoadCmd",
        "dispatch_conditions": ["CATCH_NETWORK_TRAFFIC"],
        "state_flow": ["set_pkgName 写入 dubaiPkgName", "ItemData 读取 dubaiPkgName"],
        "route_evidence": ["socket.cpp:1"],
    }, tmp_path)
    assert error == ""
    assert candidate is not None
    route = cc._route_binding_from_candidate(_finding(tmp_path), candidate)
    assert route["relevance"] == "direct"
    assert route["handler"] == "SpThreadSocket::HandleMsg"
    assert route["state_flow"]
    assert route["route_id"].startswith("route-")


def test_generic_key_value_descriptor_is_not_protocol_name_hardcoded():
    descriptor = ProtocolDescriptor(
        descriptor_id="auto_demo_protocol",
        encoder_kind="key_value",
        wire_format={"pair_separator": "=", "record_separator": "&", "terminator": "\\n"},
        fields=[FieldSpec(name="command", type="string", order=0)],
    )
    payload = encode(descriptor, {"command": "ping", "value": "42"})
    assert payload == b"command=ping&value=42\\n"


def test_route_selection_does_not_promote_unrelated_endpoint_hint(tmp_path):
    (tmp_path / "socket.cpp").write_text("void HandleMsg() {}\n", encoding="utf-8")
    direct, error = ed._validate_candidate({
        "kind": "hap_udp",
        "endpoint": "127.0.0.1:8285",
        "confidence": "high",
        "source_evidence": ["socket.cpp:1"],
        "device_evidence": ["udp 8285 LISTEN"],
        "route_relevance": "unrelated",
    }, tmp_path)
    assert error == ""
    assert direct is not None
    assert cc._select_route_candidate(["hap_udp 127.0.0.1:8285"], [direct]) is None
