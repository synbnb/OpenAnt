"""Regression tests for multi-currency stage reports."""

import json

from core.step_report import step_context
from utilities.llm_client import TokenTracker


def test_step_report_records_cny_delta_without_usd_alias(tmp_path, monkeypatch):
    tracker = TokenTracker()
    monkeypatch.setattr("utilities.llm_client._global_tracker", tracker)

    with step_context("analyze", str(tmp_path)):
        tracker.record_call(
            "gpt-5.6-luna",
            1_000_000,
            1_000_000,
            pricing={"input": 0.812, "output": 4.872, "currency": "CNY"},
        )

    report = json.loads((tmp_path / "analyze.report.json").read_text())
    assert report["cost_currency"] == "CNY"
    assert report["cost_amount"] == 5.684
    assert report["cost_cny"] == 5.684
    assert report["cost_usd"] == 0.0
    assert report["costs_by_currency"] == {"CNY": 5.684}
