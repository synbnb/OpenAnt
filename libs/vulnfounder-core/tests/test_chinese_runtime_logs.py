"""Regression tests for the additive Chinese Web runtime explanations."""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import scanner as scanner_mod  # noqa: E402
from core.schemas import AnalysisMetrics  # noqa: E402
from core.step_report import step_context  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_registry_probe(monkeypatch):
    """Keep the orchestration test offline; the real probe is tested elsewhere."""
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *args, **kwargs: None
    )


def test_chinese_log_is_a_separate_flushed_line(capsys):
    scanner_mod._print_chinese_log("这是一个阶段决策")

    captured = capsys.readouterr().err
    assert "【运行说明】这是一个阶段决策\n" in captured


def test_step_report_emits_chinese_record_without_removing_english(tmp_path, capsys):
    with step_context("parse", str(tmp_path)) as report:
        report.summary = {"total_units": 1}

    captured = capsys.readouterr().err
    assert "[parse] Report:" in captured
    assert "【阶段记录】parse 阶段的结构化记录已写入" in captured


def test_scan_orchestrator_keeps_raw_output_and_adds_chinese(monkeypatch, tmp_path, capsys):
    """A small offline scan must expose both kinds of log to the Web stream."""
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    import core.reporter as reporter

    class ParseResult:
        dataset_path = str(tmp_path / "dataset.json")
        analyzer_output_path = str(tmp_path / "analyzer_output.json")
        units_count = 1
        language = "python"
        processing_level = "all"

    def fake_parse(*, output_dir, **_kwargs):
        result = ParseResult()
        Path(result.dataset_path).write_text('{"units": []}', encoding="utf-8")
        Path(result.analyzer_output_path).write_text("{}", encoding="utf-8")
        return result

    class AnalyzeResult:
        results_path = str(tmp_path / "results.json")
        metrics = AnalysisMetrics(total=1, safe=1)

    def fake_analysis(*, output_dir, **_kwargs):
        result = AnalyzeResult()
        result.results_path = str(Path(output_dir) / "results.json")
        Path(result.results_path).write_text("[]", encoding="utf-8")
        return result

    def fake_build_output(*, output_path, **_kwargs):
        Path(output_path).write_text("{}", encoding="utf-8")
        return output_path

    monkeypatch.setattr(parser_adapter, "parse_repository", fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", fake_analysis)
    monkeypatch.setattr(reporter, "build_pipeline_output", fake_build_output)

    scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        language="python",
        platform="generic",
        processing_level="all",
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )

    captured = capsys.readouterr().err
    assert "[1/3] Parsing repository..." in captured
    assert "【运行说明】阶段 1/解析" in captured
    assert "【运行说明】漏洞检测结果" in captured
    assert "【运行说明】扫描完成" in captured
