from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from utilities.llm import CompletionResult, ToolUseBlock
from core.socket_scope import (
    SocketScopeError,
    discover_socket_scope,
    load_selected_scope,
    select_socket_scope,
    write_scope_manifest,
)


class _SocketScopeAdapter:
    supports_tools = True
    name = "fake-socket-scope"

    def __init__(self):
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools):
        self.calls += 1
        if self.calls == 1:
            return CompletionResult(
                content=[ToolUseBlock(id="search-1", name="search", input={"contains": "SP_daemon"})],
                input_tokens=1,
                output_tokens=1,
                stop_reason="tool_use",
            )
        return CompletionResult(
            content=[ToolUseBlock(
                id="finish-1",
                name="finish",
                input={
                    "summary": "服务端目录包含 Socket 身份和接收处理代码。",
                    "candidates": [{
                        "scan_root": "service",
                        "confidence": "high",
                        "reason": "同一生产目录包含 Socket 标识、UDP 接收和服务端处理函数。",
                        "evidence": [{
                            "path": "service/sp_thread_socket.cpp",
                            "start_line": 2,
                            "end_line": 8,
                            "role": "server_receive",
                            "why": "服务端接收并处理数据。",
                        }],
                    }],
                },
            )],
            input_tokens=1,
            output_tokens=1,
            stop_reason="tool_use",
        )


def _discover(repo):
    binding = SimpleNamespace(model="fake-model", adapter=_SocketScopeAdapter())
    return discover_socket_scope(
        repo,
        "SP_daemon UDP 127.0.0.1:8283",
        llm_binding=binding,
    )


def _write_fixture(repo):
    service = repo / "service"
    service.mkdir(parents=True)
    (service / "BUILD.gn").write_text(
        'ohos_executable("sp_daemon") { sources = [ "sp_thread_socket.cpp" ] }\n',
        encoding="utf-8",
    )
    (service / "sp_thread_socket.cpp").write_text(
        """
        static constexpr const char *SOCKET_NAME = "SP_daemon";
        void SpThreadSocket::HandleMsg(int fd) {
            recvfrom(fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        }
        void SpServerSocket::Init() { bind(fd, nullptr, 0); listen(fd, 8); }
        """,
        encoding="utf-8",
    )
    (service / "client.cpp").write_text(
        "void Client::Send() { connect(fd, nullptr, 0); sendto(fd, data, 1, 0, nullptr, 0); }\n",
        encoding="utf-8",
    )


def test_agentic_discover_select_and_load_socket_scope(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)

    manifest = _discover(repo)
    assert manifest["kind"] == "openant_socket_scan_scope"
    assert manifest["target"]["target_type"] == "network_socket"
    assert manifest["discovery"]["method"] == "llm_agentic_repository_exploration"
    assert manifest["candidates"]
    top = manifest["candidates"][0]
    assert top["scan_root"] == "service"
    assert top["confidence"] == "high"
    assert top["model_rank"] == 1
    assert top["evidence_validation"]["valid_count"] == 1

    selected = select_socket_scope(manifest, top["candidate_id"])
    path = tmp_path / "scan_scope.json"
    write_scope_manifest(selected, path)
    loaded_root, loaded = load_selected_scope(repo, path)
    assert loaded_root == repo / "service"
    assert loaded["selected_candidate_id"] == top["candidate_id"]


def test_scope_manifest_cannot_be_reused_for_another_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    manifest = _discover(repo)
    selected = select_socket_scope(manifest, manifest["candidates"][0]["candidate_id"])
    path = tmp_path / "scan_scope.json"
    path.write_text(json.dumps(selected), encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(SocketScopeError, match="不匹配"):
        load_selected_scope(other, path)


def test_unconfirmed_scope_is_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)
    manifest = _discover(repo)
    path = tmp_path / "scan_scope.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SocketScopeError, match="尚未确认"):
        load_selected_scope(repo, path)


def test_model_candidate_outside_repository_is_not_accepted(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)

    class _OutsideAdapter(_SocketScopeAdapter):
        def complete(self, **kwargs):
            self.calls += 1
            return CompletionResult(
                content=[ToolUseBlock(
                    id="finish-1",
                    name="finish",
                    input={
                        "summary": "bad candidate",
                        "candidates": [{
                            "scan_root": "../outside",
                            "confidence": "high",
                            "reason": "fabricated",
                            "evidence": [],
                        }],
                    },
                )],
                input_tokens=1,
                output_tokens=1,
                stop_reason="tool_use",
            )

    binding = SimpleNamespace(model="fake-model", adapter=_OutsideAdapter())
    with pytest.raises(SocketScopeError, match="没有返回任何可验证"):
        discover_socket_scope(repo, "SP_daemon UDP 127.0.0.1:8283", llm_binding=binding)


def test_model_candidate_without_validated_source_evidence_is_not_accepted(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_fixture(repo)

    class _NoEvidenceAdapter(_SocketScopeAdapter):
        def complete(self, **kwargs):
            self.calls += 1
            return CompletionResult(
                content=[ToolUseBlock(
                    id="finish-1",
                    name="finish",
                    input={
                        "summary": "directory guess only",
                        "candidates": [{
                            "scan_root": "service",
                            "confidence": "high",
                            "reason": "仅凭模型判断，没有源码片段。",
                            "evidence": [],
                        }],
                    },
                )],
                input_tokens=1,
                output_tokens=1,
                stop_reason="tool_use",
            )

    binding = SimpleNamespace(model="fake-model", adapter=_NoEvidenceAdapter())
    with pytest.raises(SocketScopeError, match="没有返回任何可验证"):
        discover_socket_scope(repo, "SP_daemon UDP 127.0.0.1:8283", llm_binding=binding)
