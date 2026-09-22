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


def test_entry_discovery_preserves_explicit_stage1_hint_when_llm_unavailable(monkeypatch, tmp_path):
    """模型拒绝/断网时不能把已有 endpoint 静默变成“无入口”。"""
    (tmp_path / "sp_thread_socket.cpp").write_text(
        "void HandleMsg() {}\nvoid Recv() { recvfrom(fd, buf, n, 0, 0, 0); }\n// evidence\n",
        encoding="utf-8",
    )
    recon_loop = importlib.import_module("utilities.openharmony_dynamic.agent.recon_loop")
    monkeypatch.setattr(recon_loop, "_llm_binding", lambda: None)
    result = ed.run_entry_discovery_loop(
        finding=_finding(tmp_path, hints=["hap_udp 127.0.0.1:8283"]),
        repo_root=tmp_path,
        hdc=FakeHdc(stdout="00000000:205B 00000000:0000 07"),
        binding_pair=None,
        max_turns=2,
    )
    assert result.status == "stage1_hint_fallback"
    assert result.candidates and result.candidates[0].route_relevance == "possible"
    assert result.candidates[0].endpoint == "127.0.0.1:8283"
    assert result.device_commands_used == 1
    assert any(item["tool"] == "hdc_shell" for item in result.audit)


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


def test_route_selection_keeps_explicit_stage1_endpoint_among_multiple_candidates():
    """多个端点并存时，明确的 Stage1 hint 必须稳定选中对应路由。"""
    candidates = [
        type("Candidate", (), {
            "hint": "hap_udp 127.0.0.1:8283",
            "endpoint": "127.0.0.1:8283",
            "route_relevance": "possible",
        })(),
        type("Candidate", (), {
            "hint": "hap_tcp 127.0.0.1:8284",
            "endpoint": "127.0.0.1:8284",
            "route_relevance": "unknown",
        })(),
        type("Candidate", (), {
            "hint": "hap_udp 127.0.0.1:8285",
            "endpoint": "127.0.0.1:8285",
            "route_relevance": "unknown",
        })(),
    ]
    selected = cc._select_route_candidate(["hap_udp 127.0.0.1:8283"], candidates)
    assert selected is candidates[0]


def test_retry_candidate_cache_recovers_the_same_route_after_fresh_session():
    """fresh session 只返回一个候选时，不能丢失首场已选的 8283 路由。"""
    first = type("Candidate", (), {
        "hint": "hap_udp 127.0.0.1:8283",
        "endpoint": "127.0.0.1:8283",
        "route_relevance": "possible",
        "candidate_id": "entry-8283",
    })()
    fresh_only = type("Candidate", (), {
        "hint": "hap_udp 127.0.0.1:8283",
        "endpoint": "127.0.0.1:8283",
        "route_relevance": "possible",
        "candidate_id": "entry-8283",
    })()
    recovered = cc._recover_cached_route_candidate(
        [fresh_only], {"candidate_id": first.candidate_id, "hint": first.hint},
    )
    assert recovered is fresh_only


def test_compile_result_exposes_library_fallback_source():
    """内置描述符回退必须带来源字段，不能只显示 descriptor_id。"""
    result = cc.CompileResult(
        contract=None,
        compile_status="REQUIRES_PROTOCOL_REVIEW",
        descriptor_hit="sp_daemon_text",
        descriptor_resolution={
            "source": "library_fallback",
            "auto_attempted": True,
            "fallback_descriptor_id": "sp_daemon_text",
            "errors": ["缺少设备侧 token"],
        },
    )
    payload = result.to_dict()
    assert payload["descriptor_resolution"]["source"] == "library_fallback"
    assert payload["descriptor_resolution"]["auto_attempted"] is True


def test_descriptor_match_does_not_guess_from_sink_or_port(tmp_path):
    finding = _finding(
        tmp_path,
        hints=["UDP 127.0.0.1:8283"],
    )
    assert cc._match_descriptor(finding) == ""
    finding.sink = "hisysevent event handler calls popen(cmd, \"r\")"
    assert cc._match_descriptor(finding) == ""


def test_descriptor_match_accepts_explicit_context_only(tmp_path):
    finding = _finding(tmp_path, hints=["Unix datagram /dev/unix/socket/custom"])
    finding.analysis_context["protocol_descriptor_id"] = "hisysevent_eventraw"
    assert cc._match_descriptor(finding) == "hisysevent_eventraw"


def test_strict_auto_descriptor_rejects_silent_builtin_fallback(monkeypatch, tmp_path):
    """严格模式不允许在自动合成失败后继续使用手写协议执行。"""
    source = tmp_path / "sp_thread_socket.cpp"
    source.write_text("void HandleMsg() { recvfrom(fd, buf, 1, 0, 0, 0); }\n", encoding="utf-8")
    finding = _finding(tmp_path, hints=["hap_udp 127.0.0.1:8283"])
    candidate = type("Candidate", (), {
        "hint": "hap_udp 127.0.0.1:8283",
        "endpoint": "127.0.0.1:8283",
        "route_relevance": "possible",
        "candidate_id": "entry-demo",
        "source_evidence": ["sp_thread_socket.cpp:1"],
        "route_evidence": ["sp_thread_socket.cpp:1"],
        "handler": "HandleMsg",
        "target_sink": finding.sink,
        "dispatch_conditions": [],
        "state_flow": [],
        "reason": "candidate",
    })()
    fake_result = type("EntryResult", (), {
        "status": "finalized", "candidates": [candidate], "notes": [],
        "turns_used": 1, "device_commands_used": 0,
        "to_dict": lambda self: {"status": self.status, "candidates": [candidate.to_dict()]}
        if hasattr(candidate, "to_dict") else {"status": self.status},
    })()
    monkeypatch.setattr(cc, "_llm_binding", lambda: ("binding", lambda *a, **k: "{}"))
    monkeypatch.setattr(
        "utilities.openharmony_dynamic.agent.entry_discovery_loop.run_entry_discovery_loop",
        lambda **kwargs: fake_result,
    )
    monkeypatch.setattr(cc, "_try_auto_descriptor", lambda *a, **k: "")
    result = cc.compile_contract(
        finding, hdc=None, clean_room=True, require_auto_descriptor=True,
    )
    assert result.compile_status == "REQUIRES_PROTOCOL_REVIEW"
    assert "严格自动描述符模式拒绝内置回退" in result.errors[0]
    assert result.descriptor_resolution["source"] == "library_fallback"


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


def test_compile_runs_route_arbitration_before_ambiguous_gate(monkeypatch, tmp_path):
    """多端点场景先交给路由复核，复核选择后才进入描述符匹配。"""
    (tmp_path / "sp_thread_socket.cpp").write_text(
        "void HandleA() {}\nvoid HandleB() {}\n", encoding="utf-8"
    )
    finding = _finding(tmp_path, hints=[])
    first = ed.EntryCandidate(
        kind="hap_udp", endpoint="127.0.0.1:8283", confidence="high",
        source_evidence=["sp_thread_socket.cpp:1-2"],
        route_relevance="possible", handler="HandleA",
        target_sink=finding.sink, route_evidence=["sp_thread_socket.cpp:1-2"],
    )
    second = ed.EntryCandidate(
        kind="hap_udp", endpoint="127.0.0.1:8285", confidence="high",
        source_evidence=["sp_thread_socket.cpp:1-2"],
        route_relevance="possible", handler="HandleB",
        target_sink=finding.sink, route_evidence=["sp_thread_socket.cpp:1-2"],
    )
    fake_entry = type("EntryResult", (), {
        "status": "finalized", "candidates": [first, second], "notes": [],
        "turns_used": 2, "device_commands_used": 0,
        "to_dict": lambda self: {
            "status": self.status,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        },
    })()
    fake_arbitration = type("Arbitration", (), {
        "status": "selected",
        "selected_candidate_id": first.candidate_id,
        "evidence": ["sp_thread_socket.cpp:1-2"],
        "reason": "HandleA 是当前候选中唯一关联 sink 的处理函数",
        "turns_used": 2,
        "to_dict": lambda self: {
            "status": self.status,
            "selected_candidate_id": self.selected_candidate_id,
            "evidence": self.evidence,
            "reason": self.reason,
        },
    })()
    monkeypatch.setattr(cc, "_llm_binding", lambda: ("binding", lambda *a, **k: "{}"))
    monkeypatch.setattr(
        "utilities.openharmony_dynamic.agent.entry_discovery_loop.run_entry_discovery_loop",
        lambda **kwargs: fake_entry,
    )
    monkeypatch.setattr(
        "utilities.openharmony_dynamic.agent.route_arbitration_loop.run_route_arbitration_loop",
        lambda **kwargs: fake_arbitration,
    )
    monkeypatch.setattr(cc, "_try_auto_descriptor", lambda *a, **k: "")
    result = cc.compile_contract(finding, hdc=None)
    assert result.compile_status == "REQUIRES_PROTOCOL_REVIEW"
    assert result.entry_discovery["route_arbitration"]["status"] == "selected"
    assert result.entry_discovery["selected_candidate_id"] == first.candidate_id
    assert any("候选路由复核 loop: selected" in note for note in result.notes)
    assert "hap_udp 127.0.0.1:8283" in finding.entry_hints


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


def test_route_selection_prefers_full_transport_hint_over_same_port_candidate():
    """同端口的错误传输候选不能遮蔽 finding 明确给出的 UDP 路由。"""
    udp = type("Candidate", (), {
        "hint": "hap_udp 127.0.0.1:8283",
        "endpoint": "127.0.0.1:8283",
        "route_relevance": "possible",
    })()
    tcp = type("Candidate", (), {
        "hint": "hap_tcp 127.0.0.1:8283",
        "endpoint": "127.0.0.1:8283",
        "route_relevance": "possible",
    })()
    selected = cc._select_route_candidate(["hap_udp 127.0.0.1:8283"], [udp, tcp])
    assert selected is udp
