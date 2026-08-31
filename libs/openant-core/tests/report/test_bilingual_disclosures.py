"""Regression tests for bilingual vulnerability disclosure artifacts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from report import generator  # noqa: E402
from utilities.llm import CompletionResult, PhaseBinding, TextBlock  # noqa: E402


class _ChineseCaptureAdapter:
    name = "offline"
    supports_tools = False
    pricing = {"offline-model": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.prompts: list[str] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        del model, system, max_tokens, tools
        self.prompts.append(messages[0].content[0].text)
        # Deliberately use English headings: the deterministic report layer
        # must still normalize known headings for the Chinese artifact.
        return CompletionResult(
            content=[TextBlock(
                "# Security Disclosure: unchecked descriptor\n\n"
                "**Product:** audio\n"
                "**Type:** CWE-400 (Resource Consumption)\n\n"
                "## Summary\n\n服务可能因异常输入而中断。\n\n"
                "## Steps to Reproduce\n\n[需要动态验证]\n\n"
                "## Impact\n\n- 服务不可用\n"
            )],
            input_tokens=2,
            output_tokens=4,
            stop_reason="end_turn",
        )


def _binding(adapter) -> PhaseBinding:
    return PhaseBinding(
        phase="report",
        adapter=adapter,
        model="offline-model",
        provider_name="offline",
    )


def _finding() -> dict:
    return {
        "id": "VULN-001",
        "name": "Unchecked descriptor",
        "short_name": "unchecked-descriptor",
        "location": {
            "file": "services/audio.cpp",
            "function": "AudioService::Enable",
            "start_line": 10,
            "end_line": 18,
        },
        "cwe_id": 400,
        "cwe_name": "Uncontrolled Resource Consumption",
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "confirmed",
        "description": "异常输入可造成服务资源消耗。",
        "preconditions": "调用者可访问本地 IPC 接口。",
        "suggested_fix": "if (descriptors.size() > 20) return ERR_INVALID_PARAM;",
        "vulnerable_code_section": (
            "## Vulnerable Code\n\n"
            "`services/audio.cpp` (第 10-18 行)：\n\n"
            "```cpp\n"
            "int Enable(const Descriptors &descriptors) { return delegate(descriptors); }\n"
            "```"
        ),
        "report_context": {
            "target": {"source_location": {
                "file": "services/audio.cpp",
                "function": "AudioService::Enable",
                "start_line": 10,
                "end_line": 18,
                "route_key": "services/audio.cpp:AudioService::Enable",
            }},
            "source_to_sink": {
                "entry_point": "AudioStub::OnRemoteRequest -> AudioService::Enable",
                "ordered_steps": ["IPC 输入进入目标函数", "目标函数调用 delegate"],
                "sink_reached": True,
            },
            "call_chain": {"nodes": []},
            "call_graph": {"native_edges": []},
            "provenance": {"artifacts": ["dataset_enhanced.json"]},
        },
    }


def test_chinese_disclosure_localizes_contract_and_keeps_evidence():
    adapter = _ChineseCaptureAdapter()
    disclosure, usage = generator.generate_disclosure(
        _finding(),
        "openharmony/audio",
        _binding(adapter),
        pipeline_data={
            "application_type": "openharmony_component",
            "repository": {"name": "audio", "commit_sha": "abc123"},
            "analysis_date": "2026-08-31",
        },
        language="zh-CN",
    )

    prompt = adapter.prompts[0]
    assert "所有说明文字、字段标签、章节标题和结论都必须使用简体中文" in prompt
    assert "## 摘要" in prompt and "## 建议修复" in prompt
    assert "{preconditions}" not in prompt
    assert not re.search(r"\{(?:影响|操作|必要时)", prompt)

    assert "# 安全漏洞披露：unchecked descriptor" in disclosure
    for heading in ("## 摘要", "## 漏洞代码", "## 复现步骤", "## 影响", "## 建议修复", "## 证据上下文"):
        assert heading in disclosure
    assert "**产品：** audio" in disclosure
    assert "**类型：** CWE-400" in disclosure
    assert "services/audio.cpp" in disclosure
    assert "AudioStub::OnRemoteRequest" in disclosure
    assert "## Summary" not in disclosure
    assert usage["total_tokens"] == 6


def test_generate_all_writes_english_and_chinese_directories(tmp_path, monkeypatch):
    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline_path.write_text(json.dumps({
        "repository": {"name": "audio", "language": "cpp"},
        "findings": [_finding()],
    }), encoding="utf-8")

    monkeypatch.setattr(generator, "validate_pipeline_output", lambda *a, **k: None)
    monkeypatch.setattr(generator, "generate_summary_report", lambda *a, **k: ("summary", {}))
    calls: list[str] = []

    def fake_disclosure(*args, language="en", **kwargs):
        del args, kwargs
        calls.append(language)
        return f"# {language}", {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
            "cost_cny": 0.0,
            "costs_by_currency": {},
        }

    monkeypatch.setattr(generator, "generate_disclosure", fake_disclosure)

    class _Registry:
        def get(self, phase):
            assert phase == "report"
            return object()

    out_dir = tmp_path / "report"
    generator.generate_all(str(pipeline_path), str(out_dir), registry=_Registry())

    english = out_dir / "disclosures" / "DISCLOSURE_01_UNCHECKED-DESCRIPTOR.md"
    chinese = out_dir / "disclosures.zh-CN" / "DISCLOSURE_01_UNCHECKED-DESCRIPTOR.md"
    assert english.read_text(encoding="utf-8") == "# en"
    assert chinese.read_text(encoding="utf-8") == "# zh-CN"
    assert calls == ["en", "zh-CN"]


def test_core_reporter_wrapper_writes_bilingual_directories(tmp_path, monkeypatch):
    """The scanner-facing wrapper must use the same bilingual contract."""
    from core import reporter
    from report import schema

    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline_path.write_text(json.dumps({
        "repository": {"name": "audio", "language": "cpp"},
        "findings": [_finding()],
    }), encoding="utf-8")

    monkeypatch.setattr(schema, "validate_pipeline_output", lambda *a, **k: None)
    monkeypatch.setattr(generator, "generate_disclosure", lambda *args, language="en", **kwargs: (
        f"# {language}", {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
            "cost_cny": 0.0,
            "costs_by_currency": {},
        }
    ))

    class _Registry:
        def get(self, _phase):
            return object()

    import utilities.llm as llm
    monkeypatch.setattr(llm, "load_config_file", lambda: {})
    monkeypatch.setattr(llm, "resolve_llm_config", lambda *args: None)
    monkeypatch.setattr(llm, "build_phase_registry", lambda *args: _Registry())
    monkeypatch.setattr(llm, "probe_registry_or_raise", lambda *args: None)

    output_dir = tmp_path / "disclosures"
    result = reporter.generate_disclosure_docs(str(pipeline_path), str(output_dir))

    assert result.output_path == str(output_dir)
    assert (output_dir / "DISCLOSURE_01_UNCHECKED-DESCRIPTOR.md").is_file()
    assert (tmp_path / "disclosures.zh-CN" / "DISCLOSURE_01_UNCHECKED-DESCRIPTOR.md").is_file()
