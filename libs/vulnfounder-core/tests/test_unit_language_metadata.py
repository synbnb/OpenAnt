"""Contract tests for C/C++ unit language metadata and prompt selection."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[1]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from parsers.c.unit_generator import UnitGenerator  # noqa: E402
import core.analysis_core as analysis_core  # noqa: E402


def _call_graph_data() -> dict:
    return {
        "repository": "/repo",
        "functions": {
            "src/health.c:read_value": {
                "name": "read_value",
                "file_path": "src/health.c",
                "code": "int read_value(void) { return 1; }",
                "unit_type": "function",
            },
            "src/health.cpp:HealthService::OnRemoteRequest": {
                "name": "HealthService::OnRemoteRequest",
                "file_path": "src/health.cpp",
                "code": "int HealthService::OnRemoteRequest() { return 0; }",
                "unit_type": "method",
            },
            "include/health.hpp:HealthService::Start": {
                "name": "HealthService::Start",
                "file_path": "include/health.hpp",
                "code": "void HealthService::Start() {}",
                "unit_type": "method",
            },
        },
        "call_graph": {},
        "reverse_call_graph": {},
    }


def test_unit_generator_infers_c_and_cpp_language_from_source_path():
    generator = UnitGenerator(_call_graph_data())
    dataset = generator.generate_units()
    units = {unit["id"]: unit for unit in dataset["units"]}

    assert units["src/health.c:read_value"]["language"] == "c"
    assert units["src/health.cpp:HealthService::OnRemoteRequest"]["language"] == "cpp"
    assert units["include/health.hpp:HealthService::Start"]["language"] == "cpp"


def test_analyzer_output_carries_the_same_language_metadata():
    generator = UnitGenerator(_call_graph_data())
    functions = generator.generate_analyzer_output()["functions"]

    assert functions["src/health.c:read_value"]["language"] == "c"
    assert functions["src/health.cpp:HealthService::OnRemoteRequest"]["language"] == "cpp"


def test_analysis_prompt_uses_unit_language(monkeypatch):
    captured: dict[str, str] = {}

    def fake_simple_text(_binding, prompt, **_kwargs):
        captured["prompt"] = prompt
        return '{"verdict":"SAFE"}'

    monkeypatch.setattr(analysis_core, "simple_text", fake_simple_text)
    analysis_core.analyze_unit(
        object(),
        {
            "id": "src/health.cpp:HealthService::Start",
            "language": "cpp",
            "code": {"primary_code": "void HealthService::Start() {}"},
        },
    )

    assert "```cpp" in captured["prompt"]


def test_legacy_unit_without_language_keeps_generic_prompt_fallback(monkeypatch):
    captured: dict[str, str] = {}

    def fake_simple_text(_binding, prompt, **_kwargs):
        captured["prompt"] = prompt
        return '{"verdict":"SAFE"}'

    monkeypatch.setattr(analysis_core, "simple_text", fake_simple_text)
    analysis_core.analyze_unit(
        object(),
        {"id": "legacy:fn", "code": {"primary_code": "return 0;"}},
    )

    assert "```code" in captured["prompt"]
