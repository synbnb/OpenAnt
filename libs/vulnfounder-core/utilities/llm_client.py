"""
Token tracker.

This module used to host the ``AnthropicClient`` wrapper plus its pricing
table. Issue #65 moved actual LLM IO to the pluggable
:mod:`utilities.llm` package (one adapter per provider, behind a
unified Protocol). What's left here is the cross-thread
:class:`TokenTracker` that adapters call ``record_call`` on — kept in
its own module because the pipeline records prior usage on resume and
several layers depend on the singleton accessor.

Classes:
    TokenTracker: Tracks token usage and costs across LLM calls

Usage:
    from utilities.llm_client import TokenTracker, get_global_tracker

    tracker = get_global_tracker()
    print(f"Total cost: ${tracker.total_cost_usd:.4f}")
"""

import importlib
import sys
import threading

from core.model_registry import pricing_entry, pricing_map


# Pricing per million tokens. LEGACY fallback: issue #65 moved pricing onto
# each adapter, and ``config/models.json`` (read by core.model_registry) is now
# the source of truth for BOTH the adapters and this global. ``MODEL_PRICING``
# still backstops call sites that don't pass an adapter-provided ``pricing``
# (record_call's fallback, report/generator) and the drift guard, but it is
# served LAZILY from the registry via module ``__getattr__`` below — never a
# frozen import-time snapshot — so it can neither drift from the adapter table
# nor price from a stale copy, and a missing config fails LOUD at first use
# instead of pricing every model at $0. Retired/unknown ids are omitted
# (lookup miss -> warn + $0).


def __getattr__(name: str):
    # PEP 562 hook: resolve MODEL_PRICING on demand. Fires for attribute access
    # and ``from utilities.llm_client import MODEL_PRICING`` — but NOT for a bare
    # ``MODEL_PRICING`` reference inside this module, which is why record_call
    # calls ``pricing_map("anthropic")`` directly.
    if name == "MODEL_PRICING":
        return pricing_map("anthropic")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

_unknown_pricing_warned: set[str] = set()
_unknown_pricing_lock = threading.Lock()


def _normalise_currency(value: object) -> str:
    """Return a safe ISO-like currency code for accounting metadata."""
    currency = str(value or "USD").strip().upper()
    return currency if currency.isalpha() and len(currency) == 3 else "USD"


def pricing_entry_for_any_provider(model: str) -> dict | None:
    """Find a priced registry record without a binding/provider hint.

    This is only a compatibility fallback for old call sites.  Normal LLM
    calls pass adapter-owned pricing through ``lookup_pricing`` and therefore
    retain the exact provider association.
    """
    from core.model_registry import require_models

    for record in require_models():
        if record.get("id") != model or not record.get("price"):
            continue
        price = record["price"]
        return {
            "input": float(price["input"]),
            "output": float(price["output"]),
            "currency": record.get("currency", "USD"),
        }
    return None


def _warn_unknown_pricing(model: str) -> None:
    """Emit a one-time stderr warning the first time we cost an unknown model."""
    with _unknown_pricing_lock:
        if model in _unknown_pricing_warned:
            return
        _unknown_pricing_warned.add(model)
    sys.stderr.write(
        f"warning: no pricing for model {model!r}; cost will be reported as $0. "
        f"Add it to config/models.json (the shared model registry) for accurate totals.\n"
    )


class TokenTracker:
    """
    Tracks token usage and costs across LLM calls.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self.reset()

    def reset(self):
        """Reset all counters."""
        with self._lock:
            self.calls = []
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_usd = 0.0
            self.total_cost_cny = 0.0
            self.total_cost_by_currency = {}

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.total_input_tokens + self.total_output_tokens

    def record_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        pricing: dict | None = None,
    ) -> dict:
        """
        Record a single LLM call.

        Args:
            model: Model identifier.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            pricing: Optional ``{"input": rate/Mtok, "output": rate/Mtok,
                "currency": "USD"}``
                from the adapter that made the call. When provided,
                this is authoritative — adapters own their rates per
                issue #65. When omitted, we fall back to the legacy
                global ``MODEL_PRICING`` so call sites that haven't
                been threaded through yet still produce a number
                (with a one-time stderr warning on miss). New code
                should always pass ``pricing`` via
                ``binding.adapter.pricing.get(binding.model)``.

        Returns:
            Dict with call details including cost.
        """
        if pricing is None:
            pricing = pricing_map("anthropic").get(model)
            if pricing is None:
                # A few legacy/reporting call sites do not have a binding to
                # pass through. Resolve a registry entry before treating the
                # model as unknown, so a configured OpenAI-compatible model
                # still receives its declared (possibly CNY) rate.
                pricing = pricing_entry_for_any_provider(model)

        currency = None
        if pricing is None:
            _warn_unknown_pricing(model)
            total_cost = 0.0
        else:
            input_cost = (input_tokens / 1_000_000) * pricing["input"]
            output_cost = (output_tokens / 1_000_000) * pricing["output"]
            total_cost = input_cost + output_cost
            currency = _normalise_currency(pricing.get("currency", "USD"))

        call_record = {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            # ``cost_usd`` remains for consumers of historical artifacts.  It
            # is populated only for USD calls; non-USD calls use the explicit
            # amount/currency fields below and cannot be mistaken for dollars.
            "cost_usd": round(total_cost if currency == "USD" else 0.0, 6),
            "cost_amount": round(total_cost, 6),
        }
        if currency:
            call_record["cost_currency"] = currency
            if currency == "CNY":
                call_record["cost_cny"] = round(total_cost, 6)

        # Update totals (thread-safe)
        with self._lock:
            self.calls.append(call_record)
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            if currency:
                self.total_cost_by_currency[currency] = (
                    self.total_cost_by_currency.get(currency, 0.0) + total_cost
                )
                if currency == "USD":
                    self.total_cost_usd += total_cost
                elif currency == "CNY":
                    self.total_cost_cny += total_cost

        # Accumulate to thread-local unit tracking if active
        tl = self._thread_local
        if hasattr(tl, "unit_input"):
            tl.unit_input += input_tokens
            tl.unit_output += output_tokens
            tl.unit_cost += total_cost if currency == "USD" else 0.0
            unit_costs = getattr(tl, "unit_costs", {})
            if currency:
                unit_costs[currency] = unit_costs.get(currency, 0.0) + total_cost
            tl.unit_costs = unit_costs

        return call_record

    def add_prior_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float = 0.0,
        *,
        currency: str = "USD",
        cost_amount: float | None = None,
        costs_by_currency: dict[str, float] | None = None,
    ):
        """Inject usage from a prior run (e.g. restored checkpoints).

        This ensures step reports capture the total cost across all runs,
        not just the current run's API calls.
        """
        if costs_by_currency:
            prior_costs = {
                _normalise_currency(k): float(v)
                for k, v in costs_by_currency.items()
                if v is not None
            }
        else:
            prior_costs = {
                _normalise_currency(currency): float(
                    cost_usd if cost_amount is None else cost_amount
                )
            }
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            for prior_currency, amount in prior_costs.items():
                self.total_cost_by_currency[prior_currency] = (
                    self.total_cost_by_currency.get(prior_currency, 0.0) + amount
                )
                if prior_currency == "USD":
                    self.total_cost_usd += amount
                elif prior_currency == "CNY":
                    self.total_cost_cny += amount

    def start_unit_tracking(self):
        """Start tracking usage for the current unit on this thread.

        Call before processing a unit, then call ``get_unit_usage()``
        after to get the accumulated usage for just that unit. Thread-safe
        because each thread has its own ``threading.local()`` storage.
        """
        tl = self._thread_local
        tl.unit_input = 0
        tl.unit_output = 0
        tl.unit_cost = 0.0
        tl.unit_costs = {}

    def get_unit_usage(self) -> dict:
        """Return usage accumulated since ``start_unit_tracking()`` on this thread."""
        tl = self._thread_local
        costs = {
            currency: round(amount, 6)
            for currency, amount in getattr(tl, "unit_costs", {}).items()
        }
        nonzero = {k: v for k, v in costs.items() if v}
        cost_currency = next(iter(nonzero)) if len(nonzero) == 1 else None
        cost_amount = next(iter(nonzero.values())) if cost_currency else 0.0
        return {
            "input_tokens": getattr(tl, "unit_input", 0),
            "output_tokens": getattr(tl, "unit_output", 0),
            "cost_usd": round(getattr(tl, "unit_cost", 0.0), 6),
            "cost_cny": costs.get("CNY", 0.0),
            "cost_amount": round(cost_amount, 6),
            "cost_currency": cost_currency,
            "costs_by_currency": costs,
        }

    def get_summary(self) -> dict:
        """
        Get summary of all tracked calls.

        Returns:
            Dict with totals and per-call breakdown
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "total_cost_cny": round(self.total_cost_cny, 6),
                "costs_by_currency": {
                    currency: round(amount, 6)
                    for currency, amount in self.total_cost_by_currency.items()
                },
                "calls": list(self.calls),
            }

    def get_totals(self) -> dict:
        """
        Get just the totals (without per-call breakdown).

        Returns:
            Dict with totals only
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "total_cost_cny": round(self.total_cost_cny, 6),
                "costs_by_currency": {
                    currency: round(amount, 6)
                    for currency, amount in self.total_cost_by_currency.items()
                },
            }


# Global tracker instance for session-wide tracking
_global_tracker = TokenTracker()


def get_global_tracker() -> TokenTracker:
    """Get the global token tracker instance."""
    return _global_tracker


def reset_warning_state() -> None:
    """Clear all one-time-warning memory so a fresh scan (or test) re-warns.

    The pricing-warning set here plus each adapter's warn sets (unknown
    stop/finish reasons, dropped block kinds, malformed tool JSON) are
    intentionally process-global, so production prints one line per
    novel value. Tests asserting "warned once" — and a brand-new scan —
    want a clean slate. Adapter modules are imported lazily and guarded
    so this stays safe even if a provider SDK isn't installed.
    """
    with _unknown_pricing_lock:
        _unknown_pricing_warned.clear()
    for modname in ("anthropic", "openai", "google"):
        try:
            mod = importlib.import_module(f"utilities.llm.providers.{modname}")
        except Exception:
            continue
        reset = getattr(mod, "reset_warnings", None)
        if callable(reset):
            reset()


def reset_global_tracker():
    """Reset the global token tracker (and one-time-warning state)."""
    _global_tracker.reset()
    reset_warning_state()


# NOTE: the ``AnthropicClient`` class that used to live here was deleted
# as part of issue #65. Every call site now goes through
# :mod:`utilities.llm` (Protocol-based adapter layer). See
# ``docs/features/llm-providers/plan.wip.md`` for the migration map.
