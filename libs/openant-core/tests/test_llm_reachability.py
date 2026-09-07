"""Tests for the LLM reachability review stage (issue #17).

The stage is opt-in and advisory: signals may PROMOTE a unit's
reachability but never demote one that the structural analysis kept.
These tests pin that behavior down with a fully mocked LLM client so they
run without network access or an API key.
"""

from __future__ import annotations

import json
from typing import List, TYPE_CHECKING

import pytest

from core.llm_reachability import (
    ReachabilitySignal,
    analyze_reachability,
    apply_signals,
    build_prompt,
    parse_response,
    signals_to_json,
)

if TYPE_CHECKING:
    from utilities.llm import PhaseBinding


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class FakeAdapter:
    """Minimal stand-in for :class:`LLMAdapter`.

    Records calls and replays a fixed sequence of canned text replies.
    Used to build a :class:`PhaseBinding` test callers can hand to
    ``analyze_reachability``.
    """

    name = "anthropic"
    supports_tools = True

    def __init__(self, responses: List[str]):
        self._responses = list(responses)
        self.calls: List[dict] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        from utilities.llm import CompletionResult, TextBlock

        # ``simple_text`` builds a single TextBlock user message, so
        # the prompt the test cares about is the .text of the only
        # block of the only message.
        prompt = messages[0].content[0].text
        self.calls.append(
            {"prompt": prompt, "max_tokens": max_tokens, "model": model}
        )
        if not self._responses:
            text = '{"signals": []}'
        else:
            text = self._responses.pop(0)
        return CompletionResult(
            content=[TextBlock(text)],
            input_tokens=10,
            output_tokens=10,
            stop_reason="end_turn",
        )

    def validate(self, model):
        pass


def _binding(adapter: "FakeAdapter") -> "PhaseBinding":
    from utilities.llm import PhaseBinding

    return PhaseBinding(
        phase="llm_reach",
        adapter=adapter,
        model="claude-test",
        provider_name="anthropic",
    )


def _make_unit(unit_id: str, code: str = "pass", **kw) -> dict:
    unit = {
        "id": unit_id,
        "unit_type": kw.pop("unit_type", "function"),
        "code": {"primary_code": code},
    }
    unit.update(kw)
    return unit


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_parses_well_formed_signal(self):
        text = json.dumps(
            {
                "signals": [
                    {
                        "unit_id": "app.py:handler",
                        "kind": "entry_point",
                        "confidence": "high",
                        "reason": "Express handler",
                    }
                ]
            }
        )
        sigs = parse_response(text, valid_unit_ids={"app.py:handler"})
        assert len(sigs) == 1
        assert sigs[0].unit_id == "app.py:handler"
        assert sigs[0].kind == "entry_point"
        assert sigs[0].confidence == "high"
        assert "Express" in sigs[0].reason

    def test_strips_markdown_fences(self):
        text = "```json\n" + json.dumps(
            {"signals": [
                {"unit_id": "x.py:f", "kind": "external_input",
                 "confidence": "medium", "reason": "reads argv"}]}
        ) + "\n```"
        sigs = parse_response(text, valid_unit_ids={"x.py:f"})
        assert len(sigs) == 1
        assert sigs[0].kind == "external_input"

    def test_malformed_structured_fields_are_skipped_without_raising(self):
        text = json.dumps({
            "signals": [
                {
                    "unit_id": "x:f",
                    "kind": [],
                    "confidence": "high",
                    "reason": "bad kind",
                },
                {
                    "unit_id": "x:f",
                    "kind": "cross_process",
                    "confidence": "high",
                    "direction": {},
                    "boundary": "binder",
                    "reason": "bad direction",
                },
            ]
        })
        assert parse_response(text, valid_unit_ids={"x:f"}) == []

    def test_falls_back_to_first_object(self):
        text = "Sure! Here you go:\n" + json.dumps(
            {"signals": [
                {"unit_id": "a.py:g", "kind": "cross_process",
                 "confidence": "low", "reason": "queue"}]}
        ) + "\nEnd."
        sigs = parse_response(text, valid_unit_ids={"a.py:g"})
        assert len(sigs) == 1

    def test_malformed_json_returns_empty(self):
        errors: List[str] = []
        sigs = parse_response(
            "not json at all",
            valid_unit_ids={"x"},
            on_error=errors.append,
        )
        assert sigs == []
        assert any("malformed" in e for e in errors)

    def test_invalid_kind_skipped(self):
        text = json.dumps(
            {"signals": [
                {"unit_id": "x.py:f", "kind": "garbage",
                 "confidence": "high", "reason": "n/a"}]}
        )
        errors: List[str] = []
        sigs = parse_response(
            text, valid_unit_ids={"x.py:f"}, on_error=errors.append
        )
        assert sigs == []
        assert any("invalid kind" in e for e in errors)

    def test_unknown_unit_id_skipped(self):
        text = json.dumps(
            {"signals": [
                {"unit_id": "ghost.py:f", "kind": "entry_point",
                 "confidence": "high", "reason": "n/a"}]}
        )
        errors: List[str] = []
        sigs = parse_response(
            text, valid_unit_ids={"real.py:f"}, on_error=errors.append
        )
        assert sigs == []

    def test_signals_not_a_list_returns_empty(self):
        text = json.dumps({"signals": "nope"})
        errors: List[str] = []
        sigs = parse_response(text, on_error=errors.append)
        assert sigs == []

    def test_external_input_does_not_require_direction(self):
        text = json.dumps({
            "signals": [{
                "unit_id": "a:f",
                "kind": "external_input",
                "confidence": "high",
                "boundary": "socket",
                "evidence": "reads the received request",
                "evidence_excerpt": "recv(fd, buf, len, 0)",
                "evidence_line_start": 12,
                "evidence_line_end": 12,
                "reason": "socket input",
            }]
        })
        sigs = parse_response(text, valid_unit_ids={"a:f"})
        assert len(sigs) == 1
        assert sigs[0].direction == ""
        assert sigs[0].boundary == "socket"
        assert sigs[0].evidence_excerpt == "recv(fd, buf, len, 0)"

    def test_cross_process_requires_valid_direction(self):
        text = json.dumps({
            "signals": [{
                "unit_id": "a:f",
                "kind": "cross_process",
                "confidence": "high",
                "boundary": "binder",
                "direction": "sideways",
                "reason": "bad direction",
            }]
        })
        errors: List[str] = []
        sigs = parse_response(
            text, valid_unit_ids={"a:f"}, on_error=errors.append
        )
        assert sigs == []
        assert any("invalid direction" in item for item in errors)


# ---------------------------------------------------------------------------
# build_prompt / app_context threading
# ---------------------------------------------------------------------------


class TestBuildPrompt:
    def test_includes_unit_ids_and_code(self):
        units = [_make_unit("app.py:handler", code="def handler(): ...")]
        prompt = build_prompt(units)
        assert "app.py:handler" in prompt
        assert "def handler()" in prompt

    def test_no_app_context_marker(self):
        prompt = build_prompt([_make_unit("a:f")])
        assert "(none provided)" in prompt

    def test_includes_app_context_when_provided(self):
        ctx = {"application_type": "web_app", "framework": "Express"}
        prompt = build_prompt([_make_unit("a:f")], app_context=ctx)
        assert "web_app" in prompt
        assert "Express" in prompt

    def test_truncates_overly_long_code(self):
        big = "x = 1\n" * 5000
        prompt = build_prompt([_make_unit("a:f", code=big)])
        assert "[truncated]" in prompt

    def test_max_code_bytes_override_keeps_more_context(self):
        """Larger max_code_bytes should preserve content past the default cutoff."""
        # 3000 bytes of unique markers — past default 1500, within 4096
        big = ("# unique-marker\n" * 3) + ("x = 1\n" * 600) + "FINAL_MARKER = True\n"
        # default 1500: FINAL_MARKER is past the cutoff and should be missing
        default_prompt = build_prompt([_make_unit("a:f", code=big)])
        assert "FINAL_MARKER" not in default_prompt
        assert "[truncated]" in default_prompt
        # 4096: FINAL_MARKER fits and should appear
        wide_prompt = build_prompt(
            [_make_unit("a:f", code=big)], max_code_bytes=4096
        )
        assert "FINAL_MARKER" in wide_prompt


# ---------------------------------------------------------------------------
# analyze_reachability — full call with a mocked client
# ---------------------------------------------------------------------------


class TestAnalyzeReachability:
    def test_parses_signals_from_mocked_llm(self):
        dataset = {
            "units": [
                _make_unit("app.py:handler"),
                _make_unit("util.py:helper"),
            ]
        }
        canned = json.dumps(
            {
                "signals": [
                    {
                        "unit_id": "app.py:handler",
                        "kind": "entry_point",
                        "confidence": "high",
                        "reason": "Express handler",
                    },
                    {
                        "unit_id": "util.py:helper",
                        "kind": "external_input",
                        "confidence": "medium",
                        "reason": "reads file",
                    },
                ]
            }
        )
        adapter = FakeAdapter([canned])
        signals = analyze_reachability(dataset, binding=_binding(adapter))
        assert len(signals) == 2
        assert {s.kind for s in signals} == {"entry_point", "external_input"}
        assert len(adapter.calls) == 1

    def test_app_context_threaded_into_prompt(self):
        dataset = {"units": [_make_unit("a:f")]}
        adapter = FakeAdapter(['{"signals": []}'])
        ctx = {"application_type": "web_app", "framework": "Flask"}
        analyze_reachability(dataset, app_context=ctx, binding=_binding(adapter))
        assert "Flask" in adapter.calls[0]["prompt"]
        assert "web_app" in adapter.calls[0]["prompt"]

    def test_malformed_response_handled_gracefully(self):
        dataset = {"units": [_make_unit("a:f")]}
        errors: List[str] = []
        adapter = FakeAdapter(["this is not JSON"])
        sigs = analyze_reachability(
            dataset, binding=_binding(adapter), on_error=errors.append
        )
        assert sigs == []
        assert errors  # at least one error logged

    def test_empty_dataset_returns_empty(self):
        adapter = FakeAdapter([])
        sigs = analyze_reachability({"units": []}, binding=_binding(adapter))
        assert sigs == []
        assert adapter.calls == []  # no LLM calls when nothing to review

    def test_batch_size_chunks_units(self):
        dataset = {"units": [_make_unit(f"a:{i}") for i in range(7)]}
        adapter = FakeAdapter(['{"signals": []}'] * 5)
        analyze_reachability(dataset, binding=_binding(adapter), batch_size=3)
        # 7 units / 3 per batch = 3 calls
        assert len(adapter.calls) == 3

    def test_non_positive_batch_size_uses_single_batch(self):
        """``batch_size <= 0`` historically tripped a NameError. Guard the
        contract: non-positive size collapses to a single batch covering all
        units (and never raises)."""
        dataset = {"units": [_make_unit(f"a:{i}") for i in range(4)]}
        adapter = FakeAdapter(['{"signals": []}'])
        analyze_reachability(dataset, binding=_binding(adapter), batch_size=0)
        assert len(adapter.calls) == 1

    def test_adapter_exception_does_not_crash(self):
        class Boom:
            name = "anthropic"
            supports_tools = True

            def complete(self, **kw):
                raise RuntimeError("api boom")

            def validate(self, model):
                pass

        errors: List[str] = []
        sigs = analyze_reachability(
            {"units": [_make_unit("a:f")]},
            binding=_binding(Boom()),
            on_error=errors.append,
        )
        assert sigs == []
        assert any("api boom" in e for e in errors)


# ---------------------------------------------------------------------------
# apply_signals — promote-only semantics
# ---------------------------------------------------------------------------


class TestApplySignals:
    def test_high_confidence_entry_point_promotes(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        sigs = [
            ReachabilitySignal("a:f", "entry_point", "high", "framework hook")
        ]
        summary = apply_signals(dataset, sigs)
        assert dataset["units"][0]["is_entry_point"] is True
        assert summary["entry_points_promoted"] == 1
        assert summary["signals_applied"] == 1
        assert summary["units_touched"] == 1

    def test_medium_confidence_does_not_promote(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        sigs = [
            ReachabilitySignal("a:f", "entry_point", "medium", "maybe")
        ]
        summary = apply_signals(dataset, sigs)
        assert dataset["units"][0]["is_entry_point"] is False
        assert summary["entry_points_promoted"] == 0
        # but the signal is still attached for the reviewer
        assert summary["signals_applied"] == 1

    def test_external_input_does_not_set_entry_point(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        sigs = [
            ReachabilitySignal("a:f", "external_input", "high", "argv")
        ]
        apply_signals(dataset, sigs)
        # external_input never sets is_entry_point regardless of confidence
        assert dataset["units"][0]["is_entry_point"] is False

    def test_does_not_demote_existing_entry_point(self):
        """Crucial promote-only invariant: a unit the structural pass
        already marked as an entry point must never be unmarked, even if
        the LLM emits no signal (or a low-confidence one) for it."""
        dataset = {"units": [_make_unit("a:f", is_entry_point=True)]}
        # Empty signal list — apply_signals must not flip the flag.
        apply_signals(dataset, [])
        assert dataset["units"][0]["is_entry_point"] is True

        # Even a stray "low" entry_point signal must not flip it back.
        sigs = [ReachabilitySignal("a:f", "entry_point", "low", "weak")]
        apply_signals(dataset, sigs)
        assert dataset["units"][0]["is_entry_point"] is True

    def test_signal_attached_to_unit(self):
        dataset = {"units": [_make_unit("a:f")]}
        sigs = [
            ReachabilitySignal("a:f", "external_input", "medium", "reads stdin")
        ]
        summary = apply_signals(dataset, sigs)
        unit = dataset["units"][0]
        assert "llm_reachability_signals" in unit
        assert len(unit["llm_reachability_signals"]) == 1
        attached = unit["llm_reachability_signals"][0]
        assert attached["kind"] == "external_input"
        assert attached["reason"] == "reads stdin"
        assert attached["seed_status"] == "reachable_only"
        assert unit["semantic_reachability_retain_only"] is True
        assert "semantic_reachability_seed" not in unit
        assert summary["semantic_retain_only_ids"] == ["a:f"]
        assert summary["retained_only"] == 1

    def test_medium_cross_process_is_retained_without_bfs_seed(self):
        dataset = {"units": [_make_unit("a:f")]}
        signal = ReachabilitySignal(
            "a:f", "cross_process", "medium", "maybe receives a queue message",
            boundary="queue", direction="receive",
        )
        summary = apply_signals(dataset, [signal])
        unit = dataset["units"][0]
        assert unit["semantic_reachability_retain_only"] is True
        assert unit.get("semantic_reachability_seed") is not True
        assert summary["semantic_seed_ids"] == []
        assert summary["semantic_retain_only_ids"] == ["a:f"]
        assert summary["retained_only_counts"]["cross_process"] == 1
        assert unit["llm_reachability_signals"][0]["seed_status"] == "reachable_only"

    def test_medium_entry_point_is_retained_without_bfs_seed(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        summary = apply_signals(dataset, [
            ReachabilitySignal("a:f", "entry_point", "medium", "possible hook")
        ])
        unit = dataset["units"][0]
        assert unit["reachability_retain_only"] is True
        assert unit.get("semantic_reachability_seed") is not True
        assert unit["is_entry_point"] is False
        assert summary["reachable_only_ids"] == ["a:f"]
        assert summary["semantic_retain_only_ids"] == []
        assert unit["llm_reachability_signals"][0]["seed_status"] == "reachable_only"

    def test_multiple_signals_accumulate_on_same_unit(self):
        dataset = {"units": [_make_unit("a:f")]}
        sigs = [
            ReachabilitySignal("a:f", "external_input", "medium", "argv"),
            ReachabilitySignal("a:f", "cross_process", "low", "queue"),
        ]
        apply_signals(dataset, sigs)
        attached = dataset["units"][0]["llm_reachability_signals"]
        assert len(attached) == 2

    def test_unknown_unit_id_skipped(self):
        dataset = {"units": [_make_unit("a:f")]}
        sigs = [ReachabilitySignal("ghost:x", "entry_point", "high", "n/a")]
        summary = apply_signals(dataset, sigs)
        assert summary["signals_applied"] == 0
        assert summary["entry_points_promoted"] == 0

    def test_high_external_input_becomes_semantic_seed(self):
        dataset = {
            "units": [_make_unit(
                "a:f",
                code="void f() { recv(fd, buf, len, 0); }",
                is_entry_point=False,
            )]
        }
        sigs = [ReachabilitySignal(
            "a:f",
            "external_input",
            "high",
            "socket input",
            boundary="unknown",
            evidence="reads from socket",
            evidence_excerpt="recv(fd, buf, len, 0)",
        )]
        summary = apply_signals(dataset, sigs)
        unit = dataset["units"][0]
        assert unit["is_entry_point"] is False
        assert unit["semantic_reachability_seed"] is True
        assert summary["semantic_seed_ids"] == ["a:f"]
        assert summary["seed_counts"]["external_input"] == 1
        assert unit["llm_reachability_signals"][0]["evidence_status"] == "provided"
        assert unit["llm_reachability_signals"][0]["seed_status"] == "accepted_seed"

    def test_high_external_input_without_source_evidence_becomes_semantic_seed(self):
        dataset = {"units": [_make_unit("a:f", code="void f(int input) {}") ]}
        sigs = [ReachabilitySignal(
            "a:f", "external_input", "high", "parameter named input",
            boundary="socket",
        )]
        summary = apply_signals(dataset, sigs)
        unit = dataset["units"][0]
        assert unit["semantic_reachability_seed"] is True
        assert summary["semantic_seed_ids"] == ["a:f"]
        record = unit["llm_reachability_signals"][0]
        assert record["seed_status"] == "accepted_seed"
        assert record["evidence_status"] == "missing"

    def test_high_external_input_with_model_only_excerpt_becomes_semantic_seed(self):
        dataset = {"units": [_make_unit("a:f", code="void f() { recv(fd, buf, len, 0); }") ]}
        sigs = [ReachabilitySignal(
            "a:f",
            "external_input",
            "high",
            "socket input",
            evidence_excerpt="recv(fd, buf, len, 0); ...",
        )]
        summary = apply_signals(dataset, sigs)
        assert summary["semantic_seed_ids"] == ["a:f"]
        record = dataset["units"][0]["llm_reachability_signals"][0]
        assert record["seed_status"] == "accepted_seed"
        assert record["evidence_status"] == "provided"

    def test_high_cross_process_with_any_direction_becomes_seed(self):
        code = "void f() { MessageParcel data; data.ReadInt32(); }"
        receive = ReachabilitySignal(
            "a:receive", "cross_process", "high", "binder receive",
            boundary="unknown", direction="receive",
            evidence_excerpt="data.ReadInt32()",
        )
        send = ReachabilitySignal(
            "a:send", "cross_process", "high", "binder send",
            boundary="unknown", direction="send",
            evidence_excerpt="data.ReadInt32()",
        )
        dataset = {
            "units": [
                _make_unit("a:receive", code=code),
                _make_unit("a:send", code=code),
            ]
        }
        summary = apply_signals(dataset, [receive, send])
        assert summary["semantic_seed_ids"] == ["a:receive", "a:send"]
        assert summary["seed_counts"]["cross_process"] == 2
        assert summary["seed_counts"]["cross_process_receive"] == 1
        assert dataset["units"][0]["semantic_reachability_seed"] is True
        assert dataset["units"][1]["semantic_reachability_seed"] is True

    def test_high_cross_process_unknown_direction_with_verified_evidence_becomes_seed(self):
        code = "void f() { auto *pipe = popen(cmd.c_str(), \"r\"); fgets(buf, n, pipe); }"
        signal = ReachabilitySignal(
            "a:f", "cross_process", "high", "child-process pipe",
            boundary="unknown", direction="unknown",
            evidence_excerpt="popen(cmd.c_str(), \"r\")",
        )
        dataset = {"units": [_make_unit("a:f", code=code)]}
        summary = apply_signals(dataset, [signal])
        assert summary["semantic_seed_ids"] == ["a:f"]
        record = dataset["units"][0]["llm_reachability_signals"][0]
        assert record["seed_status"] == "accepted_seed"
        assert record["seed_reason"] == "high-confidence semantic signal"

    def test_duplicate_signals_keep_stronger_confidence(self):
        dataset = {"units": [_make_unit(
            "a:f", code="void f() { read(fd, buf, len); }"
        )]}
        sigs = [
            ReachabilitySignal(
                "a:f", "external_input", "medium", "maybe",
                boundary="socket", evidence_excerpt="read(fd, buf, len)",
            ),
            ReachabilitySignal(
                "a:f", "external_input", "high", "confirmed",
                boundary="socket", evidence_excerpt="read(fd, buf, len)",
            ),
        ]
        summary = apply_signals(dataset, sigs)
        assert summary["duplicates_removed"] == 1
        assert summary["signals_applied"] == 1
        assert summary["semantic_seed_ids"] == ["a:f"]

    def test_duplicate_equal_confidence_prefers_evidence_bearing_signal(self):
        dataset = {"units": [_make_unit(
            "a:f", code="void f() { recv(fd, buf, len, 0); }"
        )]}
        sigs = [
            ReachabilitySignal(
                "a:f", "external_input", "high", "model guess",
                boundary="socket",
            ),
            ReachabilitySignal(
                "a:f", "external_input", "high", "source confirmed",
                boundary="socket", evidence_excerpt="recv(fd, buf, len, 0)",
            ),
        ]
        summary = apply_signals(dataset, sigs)
        assert summary["duplicates_removed"] == 1
        assert summary["semantic_seed_ids"] == ["a:f"]


class TestSerialization:
    def test_signals_to_json_roundtrip(self):
        sigs = [
            ReachabilitySignal("a:f", "entry_point", "high", "r1"),
            ReachabilitySignal("b:g", "external_input", "low", "r2"),
        ]
        out = signals_to_json(sigs)
        assert isinstance(out, list)
        assert all(isinstance(item, dict) for item in out)
        assert "direction" not in out[0]
        assert "direction" not in out[1]
        # Round-trips through JSON cleanly.
        json.loads(json.dumps(out))


# ---------------------------------------------------------------------------
# CLI flag plumbing — mock scan_repository to confirm wiring without API
# ---------------------------------------------------------------------------


class TestCliPlumbing:
    """Confirms that the --llm-reachability flag exists in scan --help and
    that, by default (no flag), the LLM reachability path is not invoked.

    These tests exercise the Python CLI directly (no Go binary required), so
    they always run in the basic pytest suite.
    """

    def test_flag_appears_in_scan_help(self, capsys):
        from openant.cli import main

        with pytest.raises(SystemExit):
            import sys
            old = sys.argv
            try:
                sys.argv = ["openant", "scan", "--help"]
                main()
            finally:
                sys.argv = old
        out = capsys.readouterr().out + capsys.readouterr().err
        assert "--llm-reachability" in out

    def test_default_does_not_invoke_llm_reachability(self, monkeypatch, tmp_path):
        """When --llm-reachability is NOT passed, ``analyze_reachability`` in
        the scanner module must not be called.

        We achieve this by monkey-patching ``scan_repository`` to a stub
        that records its kwargs, then driving ``cmd_scan`` through it.
        """
        captured = {}

        from openant import cli as cli_mod

        def fake_scan(**kwargs):
            captured.update(kwargs)
            from core.schemas import ScanResult
            r = ScanResult(output_dir=str(tmp_path))
            return r

        monkeypatch.setattr(
            "core.scanner.scan_repository", fake_scan, raising=True
        )

        # Drive cmd_scan via argparse
        import argparse
        # `-l auto` now runs language detection by default (it used to defer
        # to the dominant-language path without walking), so the fixture must
        # contain real source or detection fails before the plumbing under
        # test is reached. These tests stub scan_repository and care only
        # about llm_reachability pass-through.
        (tmp_path / "app.py").write_text("def handler():\n    return 1\n")
        ns = argparse.Namespace(
            repo=str(tmp_path),
            output=str(tmp_path / "out"),
            language="auto",
            level="reachable",
            verify=False,
            no_context=True,
            no_enhance=True,
            enhance_mode="agentic",
            no_report=True,
            dynamic_test=False,
            no_skip_tests=False,
            limit=None,
            llm_config=None,
            workers=1,
            repo_name=None,
            repo_url=None,
            commit_sha=None,
            backoff=30,
            diff_manifest=None,
            llm_reachability=False,
        )
        rc = cli_mod.cmd_scan(ns)
        # rc 0 or 1 acceptable; we only care about plumbing.
        assert rc in (0, 1)
        assert captured.get("llm_reachability") is False

    def test_flag_passes_through_when_set(self, monkeypatch, tmp_path):
        captured = {}
        from openant import cli as cli_mod

        def fake_scan(**kwargs):
            captured.update(kwargs)
            from core.schemas import ScanResult
            return ScanResult(output_dir=str(tmp_path))

        monkeypatch.setattr(
            "core.scanner.scan_repository", fake_scan, raising=True
        )

        import argparse
        # `-l auto` now runs language detection by default (it used to defer
        # to the dominant-language path without walking), so the fixture must
        # contain real source or detection fails before the plumbing under
        # test is reached. These tests stub scan_repository and care only
        # about llm_reachability pass-through.
        (tmp_path / "app.py").write_text("def handler():\n    return 1\n")
        ns = argparse.Namespace(
            repo=str(tmp_path),
            output=str(tmp_path / "out"),
            language="auto",
            level="reachable",
            verify=False,
            no_context=True,
            no_enhance=True,
            enhance_mode="agentic",
            no_report=True,
            dynamic_test=False,
            no_skip_tests=False,
            limit=None,
            llm_config=None,
            workers=1,
            repo_name=None,
            repo_url=None,
            commit_sha=None,
            backoff=30,
            diff_manifest=None,
            llm_reachability=True,
        )
        cli_mod.cmd_scan(ns)
        assert captured.get("llm_reachability") is True
