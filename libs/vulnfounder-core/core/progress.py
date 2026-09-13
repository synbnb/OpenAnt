"""
Progress reporting for long-running pipeline steps.

Prints per-unit progress lines and periodic summaries to stderr,
which the Go CLI streams to the terminal in real-time.
"""

import sys
import threading
import time
from typing import Optional


def _fmt_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m{s:02d}s"
    h, rem = divmod(int(seconds), 3600)
    m, _ = divmod(rem, 60)
    return f"{h}h{m:02d}m"


def _fmt_costs(costs: dict[str, float]) -> str:
    """Format declared-currency costs without implicit conversion."""
    if not costs:
        return "$0.0000"
    symbols = {"USD": "$", "CNY": "¥"}
    parts = []
    for currency, amount in sorted(costs.items()):
        symbol = symbols.get(currency, currency + " ")
        if amount < 0.01:
            parts.append(f"{symbol}{amount:.4f}")
        elif amount < 10:
            parts.append(f"{symbol}{amount:.2f}")
        else:
            parts.append(f"{symbol}{amount:,.2f}")
    return " / ".join(parts)


class ProgressReporter:
    """Tracks and prints per-unit progress for a pipeline step.

    Prints one line per unit to stderr, plus periodic summary lines.
    All output goes to stderr so it streams through the Go CLI
    without corrupting the stdout JSON envelope.

    Args:
        step_name: Display name for the step (e.g. "Enhance", "Verify").
        total: Total number of units to process.
        tracker: Optional TokenTracker for cost reporting.
        summary_interval: Print a summary line every N units.
            Defaults to every 50 units or 10% of total, whichever is smaller.
    """

    def __init__(
        self,
        step_name: str,
        total: int,
        tracker=None,
        summary_interval: int | None = None,
        completed: int = 0,
    ):
        self.step_name = step_name
        self.total = total
        self.tracker = tracker
        self.start_time = time.monotonic()
        self.completed = completed
        self._lock = threading.Lock()
        self._last_costs = self._get_costs()  # snapshot for per-unit deltas

        # Width for the counter so alignment stays consistent
        self._width = len(str(total))

        # Summary interval: every 50 units or 10% of total, whichever is smaller
        if summary_interval is not None:
            self._summary_interval = summary_interval
        else:
            ten_pct = max(1, total // 10)
            self._summary_interval = min(50, ten_pct)

    def _get_costs(self) -> dict[str, float]:
        """Get current cumulative per-currency costs from the tracker."""
        if not self.tracker:
            return {}
        totals = self.tracker.get_totals()
        costs = totals.get("costs_by_currency") or {}
        if costs:
            return {str(k): float(v or 0) for k, v in costs.items()}
        usd = totals.get("total_cost_usd", 0.0)
        return {"USD": usd} if usd else {}

    def _estimate_remaining(self, elapsed: float) -> str:
        """Estimate time remaining based on average per-unit time."""
        if self.completed == 0:
            return "~?"
        avg = elapsed / self.completed
        # Floor at 0: retries can double-count `completed` past `total`, which would otherwise
        # make remaining_units negative and render the ETA as a negative duration.
        remaining_units = max(0, self.total - self.completed)
        remaining_secs = avg * remaining_units
        return f"~{_fmt_duration(remaining_secs)}"

    def report(
        self,
        unit_label: str,
        detail: str = "",
        unit_elapsed: float = 0.0,
    ) -> None:
        """Report completion of one unit.

        Call this after each unit finishes processing.

        Args:
            unit_label: Short identifier for the unit (unit_id, route_key, etc.).
            detail: Extra info (e.g. classification, verdict).
            unit_elapsed: How long this specific unit took, in seconds.
        """
        with self._lock:
            self.completed += 1
            elapsed = time.monotonic() - self.start_time
            eta = self._estimate_remaining(elapsed)
            total_costs = self._get_costs()
            currencies = set(self._last_costs) | set(total_costs)
            unit_costs = {
                currency: total_costs.get(currency, 0.0) - self._last_costs.get(currency, 0.0)
                for currency in currencies
            }
            self._last_costs = total_costs

            # Truncate label if too long
            if len(unit_label) > 50:
                unit_label = unit_label[:47] + "..."

            # Build the progress line — show per-unit cost, not cumulative
            parts = [
                f"[{self.step_name}]",
                f"{self.completed:>{self._width}}/{self.total}",
                unit_label,
            ]
            if detail:
                parts.append(detail)
            if unit_elapsed > 0:
                parts.append(f"{unit_elapsed:.1f}s")

            meta = f"(elapsed {_fmt_duration(elapsed)}, ETA {eta}, {_fmt_costs(unit_costs)})"
            parts.append(meta)

            line = "  ".join(parts)
            print(line, file=sys.stderr, flush=True)

            # Periodic summary — shows cumulative total
            if (
                self.completed % self._summary_interval == 0
                and self.completed < self.total
            ):
                self._print_summary(elapsed, total_costs)

    def _print_summary(self, elapsed: float, costs: dict[str, float]) -> None:
        """Print a highlighted summary line."""
        pct = (self.completed / self.total) * 100
        avg = elapsed / self.completed if self.completed else 0
        eta = self._estimate_remaining(elapsed)

        line = (
            f"[{self.step_name}] --- "
            f"{self.completed}/{self.total} ({pct:.1f}%) | "
            f"avg {avg:.1f}s/unit | "
            f"elapsed {_fmt_duration(elapsed)} | "
            f"ETA {eta} | "
            f"cost {_fmt_costs(costs)}"
            f" ---"
        )
        print(line, file=sys.stderr, flush=True)

    def finish(self) -> None:
        """Print a final summary line when the step is done."""
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            costs = self._get_costs()
            avg = elapsed / self.completed if self.completed else 0

            line = (
                f"[{self.step_name}] Done: "
                f"{self.completed}/{self.total} units in {_fmt_duration(elapsed)} | "
                f"avg {avg:.1f}s/unit | "
                f"cost {_fmt_costs(costs)}"
            )
            print(line, file=sys.stderr, flush=True)
