"""
Step report context manager.

Wraps a pipeline step to automatically capture timing, cost, and errors
into a StepReport, then writes {step}.report.json to the output directory.

Usage::

    with step_context("parse", output_dir, inputs={...}) as ctx:
        # do work ...
        ctx.summary = {"total_units": 123, "reachable_units": 79}
        ctx.outputs = {"dataset_path": "/tmp/out/dataset.json"}
"""

import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone

from core.observability import print_chinese_log
from core.schemas import StepReport


@contextmanager
def step_context(step: str, output_dir: str, inputs: dict | None = None):
    """Context manager that builds a StepReport around a pipeline step.

    Automatically captures:
    - timestamp (UTC ISO 8601)
    - duration (wall-clock seconds)
    - cost / token usage (from ``core.tracking`` if available)
    - errors (any exception that propagates)

    The caller should set ``ctx.summary`` and ``ctx.outputs`` inside the
    ``with`` block. On exit the report is written to ``{output_dir}/{step}.report.json``.

    Yields a StepReport instance (mutable — set summary/outputs on it).
    """
    report = StepReport(
        step=step,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        inputs=inputs or {},
    )

    start = time.monotonic()

    # Snapshot starting costs so we can compute per-currency deltas.
    start_costs, start_tokens = _snapshot_usage()

    try:
        yield report
    except Exception as exc:
        report.status = "error"
        report.errors.append(str(exc))
        print(f"[{step}] ERROR: {exc}", file=sys.stderr)
        print_chinese_log(
            f"{step} 阶段发生异常：{exc}；"
            "上游已完成的产物会保留，是否能继续由扫描编排器的降级策略决定。",
            category="阶段错误",
        )
        traceback.print_exc(file=sys.stderr)
        raise
    finally:
        report.duration_seconds = round(time.monotonic() - start, 2)

        # Capture cost delta
        end_costs, end_tokens = _snapshot_usage()
        currencies = set(start_costs) | set(end_costs)
        deltas = {
            currency: round(end_costs.get(currency, 0.0) - start_costs.get(currency, 0.0), 6)
            for currency in currencies
        }
        report.costs_by_currency = {k: v for k, v in deltas.items() if v}
        report.cost_usd = report.costs_by_currency.get("USD", 0.0)
        report.cost_cny = report.costs_by_currency.get("CNY", 0.0)
        if len(report.costs_by_currency) == 1:
            report.cost_currency, report.cost_amount = next(
                iter(report.costs_by_currency.items())
            )
        report.token_usage = {
            "input_tokens": end_tokens.get("input", 0) - start_tokens.get("input", 0),
            "output_tokens": end_tokens.get("output", 0) - start_tokens.get("output", 0),
            "total_tokens": end_tokens.get("total", 0) - start_tokens.get("total", 0),
        }

        report.write(output_dir)
        print(
            f"[{step}] Report: {output_dir}/{step}.report.json "
            f"({report.duration_seconds}s, {_format_costs(report.costs_by_currency)})",
            file=sys.stderr,
        )
        print_chinese_log(
            f"{step} 阶段的结构化记录已写入 "
            f"{output_dir}/{step}.report.json；耗时 {report.duration_seconds}s，"
            f"模型用量 {report.token_usage.get('total_tokens', 0)} tokens，"
            f"成本 {_format_costs(report.costs_by_currency)}，状态={report.status}。",
            category="阶段记录",
        )


def _snapshot_usage() -> tuple[dict, dict]:
    """Return (costs_by_currency, {input, output, total}) from the tracker.

    Returns zeroes if the tracker isn't available (e.g. for local-only steps).
    """
    try:
        from core.tracking import get_usage
        usage = get_usage()
        return dict(usage.costs_by_currency), {
            "input": usage.total_input_tokens,
            "output": usage.total_output_tokens,
            "total": usage.total_tokens,
        }
    except Exception:
        return {}, {"input": 0, "output": 0, "total": 0}


def _format_costs(costs: dict) -> str:
    """Format a per-currency cost map for human-readable stderr output."""
    if not costs:
        return "$0.0000"
    parts = []
    for currency, amount in sorted(costs.items()):
        symbol = {"USD": "$", "CNY": "¥"}.get(currency, f"{currency} ")
        parts.append(f"{symbol}{amount:.4f}")
    return " / ".join(parts)
