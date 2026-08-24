"""Regression tests for Chinese summary generation."""

from report.generator import generate_summary_report, load_prompt
from utilities.llm import CompletionResult, PhaseBinding, TextBlock


class _CaptureAdapter:
    name = "offline"
    supports_tools = False
    pricing = {"offline-model": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.prompt = ""

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        del model, system, max_tokens, tools
        self.prompt = messages[0].content[0].text
        return CompletionResult(
            content=[TextBlock("# 测试摘要")],
            input_tokens=1,
            output_tokens=1,
            stop_reason="end_turn",
        )


def _binding(adapter):
    return PhaseBinding(
        phase="report",
        adapter=adapter,
        model="offline-model",
        provider_name="offline",
    )


def test_chinese_summary_uses_dedicated_prompt():
    adapter = _CaptureAdapter()
    report, usage = generate_summary_report(
        {
            "repository": {"name": "openharmony/health", "language": "cpp"},
            "findings": [],
        },
        _binding(adapter),
        language="zh-CN",
    )

    assert report == "# 测试摘要"
    assert usage["total_tokens"] == 2
    assert "简体中文" in adapter.prompt
    assert "结果概览" in adapter.prompt
    assert "## Results" not in adapter.prompt


def test_chinese_summary_prompt_is_packaged():
    prompt = load_prompt("summary.zh-CN")
    assert "安全分析报告" in prompt
    assert "OpenHarmony 平台上下文" in prompt
