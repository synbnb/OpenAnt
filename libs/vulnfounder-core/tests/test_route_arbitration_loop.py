"""候选路由复核 Agent Loop 测试。"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

arb = importlib.import_module(
    "utilities.openharmony_dynamic.agent.route_arbitration_loop"
)
ed = importlib.import_module(
    "utilities.openharmony_dynamic.agent.entry_discovery_loop"
)
from utilities.openharmony_dynamic.finding_input import FindingInput  # noqa: E402


class ScriptedLLM:
    def __init__(self, replies):
        self.replies = list(replies)

    def __call__(self, binding, prompt, system=None, max_tokens=0):
        return self.replies.pop(0)


def _finding(repo_root: Path) -> FindingInput:
    return FindingInput(
        finding_id="ROUTE-TEST",
        unit_id="unit",
        vuln_class="command_injection",
        description="外部消息进入命令执行点",
        source_paths=["socket.cpp"],
        evidence_lines=[[1, 3]],
        sink="Target::Sink at socket.cpp:3",
        entry_hints=[],
        repo_root=str(repo_root),
    )


def _candidate(repo_root: Path, endpoint: str, handler: str) -> ed.EntryCandidate:
    return ed.EntryCandidate(
        kind="hap_udp",
        endpoint=endpoint,
        confidence="high",
        source_evidence=["socket.cpp:1-3"],
        route_relevance="possible",
        handler=handler,
        target_sink="Target::Sink",
        route_evidence=["socket.cpp:2-3"],
    )


def test_route_arbitration_selects_only_existing_candidate_with_verified_evidence(tmp_path):
    (tmp_path / "socket.cpp").write_text(
        "void HandleA() {}\nvoid Sink() {}\nvoid HandleB() {}\n",
        encoding="utf-8",
    )
    candidates = [
        _candidate(tmp_path, "127.0.0.1:8283", "HandleA"),
        _candidate(tmp_path, "127.0.0.1:8285", "HandleB"),
    ]
    selected = candidates[0].candidate_id
    binding = (
        "fake-binding",
        ScriptedLLM([
            json.dumps({"tool": "read_file", "args": {
                "path": "socket.cpp", "offset": 0, "limit": 20,
            }}),
            json.dumps({"tool": "finalize", "args": {
                "decision": "select",
                "selected_candidate_id": selected,
                "evidence": ["socket.cpp:2-3"],
                "rejected": [{
                    "candidate_id": candidates[1].candidate_id,
                    "reason": "该候选未出现到目标 sink 的调用证据",
                }],
                "reason": "HandleA 的分派源码指向目标 sink",
            }}),
        ]),
    )
    result = arb.run_route_arbitration_loop(
        finding=_finding(tmp_path),
        candidates=candidates,
        repo_root=tmp_path,
        binding_pair=binding,
    )
    assert result.status == "selected"
    assert result.selected_candidate_id == selected
    assert result.evidence == ["socket.cpp:2-3"]
    assert result.rejected[0]["candidate_id"] == candidates[1].candidate_id


def test_route_arbitration_defers_when_model_cannot_distinguish_candidates(tmp_path):
    (tmp_path / "socket.cpp").write_text(
        "void HandleA() {}\nvoid HandleB() {}\n",
        encoding="utf-8",
    )
    candidates = [
        _candidate(tmp_path, "127.0.0.1:8283", "HandleA"),
        _candidate(tmp_path, "127.0.0.1:8285", "HandleB"),
    ]
    binding = (
        "fake-binding",
        ScriptedLLM([
            json.dumps({"tool": "grep", "args": {
                "pattern": "Handle", "path": "socket.cpp",
            }}),
            json.dumps({"tool": "finalize", "args": {
                "decision": "defer",
                "evidence": ["socket.cpp:1-2"],
                "reason": "两个入口均只有接收证据，无法区分 sink 分派",
            }}),
        ]),
    )
    result = arb.run_route_arbitration_loop(
        finding=_finding(tmp_path),
        candidates=candidates,
        repo_root=tmp_path,
        binding_pair=binding,
    )
    assert result.status == "deferred"
    assert result.selected_candidate_id == ""
    assert "无法区分" in result.reason


def test_route_arbitration_rejects_evidence_outside_selected_candidate_scope(tmp_path):
    (tmp_path / "socket.cpp").write_text("void HandleA() {}\n", encoding="utf-8")
    (tmp_path / "other.cpp").write_text("void Other() {}\n", encoding="utf-8")
    candidates = [_candidate(tmp_path, "127.0.0.1:8283", "HandleA")]
    # 需要两个候选才会进入 loop；第二个只作为无关候选存在。
    candidates.append(_candidate(tmp_path, "127.0.0.1:8285", "Other"))
    binding = (
        "fake-binding",
        ScriptedLLM([
            json.dumps({"tool": "read_file", "args": {
                "path": "socket.cpp", "offset": 0, "limit": 10,
            }}),
            json.dumps({"tool": "finalize", "args": {
                "decision": "select",
                "selected_candidate_id": candidates[0].candidate_id,
                "evidence": ["other.cpp:1"],
                "reason": "不应接受脱离候选证据范围的选择",
            }}),
            json.dumps({"tool": "finalize", "args": {
                "decision": "defer",
                "evidence": ["socket.cpp:1"],
                "reason": "证据需要重新核对",
            }}),
        ]),
    )
    result = arb.run_route_arbitration_loop(
        finding=_finding(tmp_path),
        candidates=candidates,
        repo_root=tmp_path,
        binding_pair=binding,
    )
    assert result.status == "deferred"
    assert any(item["kind"] == "invalid" for item in result.audit)
