"""暴露面 Agentic Loop 与本地知识检索的离线测试。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from utilities.llm import CompletionResult, TextBlock, ToolUseBlock

from core.exposure_agent import ExposureAgentConfig, ExposureAgentRunner
from core.exposure_knowledge import KnowledgeRetriever
from core.exposure_surface import HDCClient, normalize_exposure_target


class _FakeAdapter:
    name = "fake"
    supports_tools = True

    def __init__(self) -> None:
        self.calls = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls.append((model, system, messages, max_tokens, tools))
        if len(self.calls) == 1:
            return CompletionResult(
                content=[
                    ToolUseBlock(
                        id="tree-1",
                        name="update_task_tree",
                        input={
                            "updates": [
                                {"task_id": "device_preflight", "status": "in_progress"},
                            ],
                            "summary": "先确认设备和目标属性",
                        },
                    ),
                    ToolUseBlock(
                        id="cmd-1",
                        name="device_exec",
                        input={
                            "command": "printf 'srw------- 1 root shell 0 /dev/unix/socket/demo\\n'",
                            "purpose": "读取目标 socket 的文件模式和路径",
                        },
                    ),
                ],
                input_tokens=10,
                output_tokens=12,
                stop_reason="tool_use",
            )
        return CompletionResult(
            content=[
                ToolUseBlock(
                    id="finish-1",
                    name="finish_exposure",
                    input={
                        "surfaces": [
                            {
                                "index": 0,
                                "fields": {
                                    "socket_path": {
                                        "value": "/dev/unix/socket/demo",
                                        "evidence_ids": ["AG-EV-0001"],
                                    }
                                },
                            }
                        ],
                        "notes": "已获得路径证据",
                    },
                )
            ],
            input_tokens=14,
            output_tokens=10,
            stop_reason="tool_use",
        )


def test_knowledge_retriever_is_local_and_stable():
    retriever = KnowledgeRetriever()
    assert retriever.available
    first = retriever.retrieve("TCP UDP /proc/net 端口", top_k=3)
    second = retriever.retrieve("TCP UDP /proc/net 端口", top_k=3)
    assert [item.to_dict() for item in first] == [item.to_dict() for item in second]
    assert first
    assert all(item.doc_id.endswith(".md") and item.content_sha256 for item in first)


def test_hdc_agent_command_does_not_use_fixed_probe_whitelist():
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        return 0, "agent output\n", ""

    client = HDCClient("/opt/hdc", "serial-1", runner=runner)
    result = client.run_agent("printf 'a;b'", timeout_seconds=4)
    assert result.ok
    assert calls == [
        (
            ["/opt/hdc", "-t", "serial-1", "shell", "printf 'a;b'"],
            4,
        )
    ]


def test_hdc_agent_preserves_remote_shell_assignments_and_quotes():
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        return 0, "P=/dev/unix/socket/demo\n", ""

    client = HDCClient("/opt/hdc", "serial-1", runner=runner)
    result = client.run_agent(
        "p='/dev/unix/socket/demo'; printf 'P=%s\\n' \"$p\"",
        timeout_seconds=4,
    )
    assert result.ok
    assert calls == [
        (
            [
                "/opt/hdc",
                "-t",
                "serial-1",
                "shell",
                "p='/dev/unix/socket/demo'; printf 'P=%s\\n' \"$p\"",
            ],
            4,
        )
    ]


def test_agent_loop_updates_task_tree_executes_command_and_finishes(tmp_path: Path):
    adapter = _FakeAdapter()
    binding = SimpleNamespace(adapter=adapter, model="fake-model", provider_name="offline")

    def runner(argv, timeout):
        assert argv[-1:] == ["printf 'srw------- 1 root shell 0 /dev/unix/socket/demo\\n'"]
        assert timeout == 30
        return 0, "srw------- 1 root shell 0 /dev/unix/socket/demo\n", ""

    result = ExposureAgentRunner(
        normalize_exposure_target("/dev/unix/socket/demo"),
        HDCClient("/opt/hdc", "serial-1", runner=runner),
        output_dir=tmp_path,
        binding=binding,
        config=ExposureAgentConfig(max_rounds=2, max_commands=2),
    ).run()

    assert result["status"] == "complete"
    assert result["rounds"] == 2
    assert len(result["commands"]) == 1
    assert result["evidence"][0]["evidence_id"] == "AG-EV-0001"
    assert result["task_tree"]["nodes"][0]["status"] == "in_progress"
    assert Path(result["artifacts"]["exposure_agent_plan.json"]).is_file()
    assert Path(result["artifacts"]["exposure_agent_trace.jsonl"]).read_text(encoding="utf-8").strip()
    assert len(adapter.calls) == 2
