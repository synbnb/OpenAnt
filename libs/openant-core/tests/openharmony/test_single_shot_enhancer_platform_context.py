"""Single-shot Context Enhancer OpenHarmony context tests.

The LLM call is monkeypatched; these tests only validate prompt construction
and unit-to-prompt wiring.
"""

from __future__ import annotations

from utilities import context_enhancer as enhancer_module
from utilities.context_enhancer import ContextEnhancer, get_context_enhancement_prompt


def _platform_context() -> dict:
    return {
        "platform": "openharmony",
        "source_role": "production",
        "component": ["health_service"],
        "target": ["health_sensor_service"],
        "boundary": ["binder_ipc"],
        "guard": [
            {"kind": "permission_check", "matched": "CheckPermission"},
        ],
        "evidence": [
            {
                "source": "gn_target",
                "path": "services/BUILD.gn",
                "value": "health_sensor_service",
            }
        ],
    }


def _prompt(**kwargs) -> str:
    values = {
        "function_id": "services/health.cpp:HealthService::Enable",
        "function_name": "HealthService::Enable",
        "function_code": "int Enable(MessageParcel &data) { return 0; }",
        "unit_type": "method",
        "class_name": "HealthService",
        "static_deps": [],
        "static_callers": [],
        "context_functions": [],
    }
    values.update(kwargs)
    return get_context_enhancement_prompt(**values)


def test_openharmony_single_shot_prompt_uses_language_and_shared_context():
    prompt = _prompt(language="cpp", platform_context=_platform_context())

    assert "You are analyzing a cpp function" in prompt
    assert "```cpp" in prompt
    assert "## OpenHarmony Platform Context" in prompt
    assert "Components: health_service" in prompt
    assert "Boundary signals: binder_ipc" in prompt
    assert "permission_check (matched: CheckPermission)" in prompt


def test_generic_single_shot_prompt_keeps_historical_language_and_shape():
    prompt = _prompt()

    assert "You are analyzing a JavaScript/TypeScript function" in prompt
    assert "```javascript" in prompt
    assert "## OpenHarmony Platform Context" not in prompt
    assert "## Your Task\nAnalyze this function" in prompt


def test_malformed_platform_context_falls_back_without_crashing():
    prompt = _prompt(language="cpp", platform_context=["not a mapping"])

    assert "You are analyzing a JavaScript/TypeScript function" in prompt
    assert "## OpenHarmony Platform Context" not in prompt


def test_context_enhancer_forwards_unit_context_to_single_shot_prompt(monkeypatch):
    captured: dict[str, str] = {}

    def fake_simple_text(_binding, prompt, **_kwargs):
        captured["prompt"] = prompt
        return (
            '{"missing_dependencies": [], "additional_callers": [], '
            '"data_flow": {}, "imports": [], "reasoning": "", "confidence": 0.5}'
        )

    monkeypatch.setattr(enhancer_module, "simple_text", fake_simple_text)
    enhancer = ContextEnhancer.__new__(ContextEnhancer)
    enhancer.binding = object()
    enhancer.tracker = None
    enhancer.logger = None
    enhancer._use_logger = False
    enhancer.stats = {
        "units_processed": 0,
        "units_enhanced": 0,
        "dependencies_added": 0,
        "callers_added": 0,
        "data_flows_extracted": 0,
        "errors": 0,
    }

    unit = {
        "id": "services/health.cpp:HealthService::Enable",
        "language": "cpp",
        "unit_type": "method",
        "platform_context": _platform_context(),
        "code": {
            "primary_code": "int Enable(MessageParcel &data) { return 0; }",
            "primary_origin": {
                "function_name": "HealthService::Enable",
                "class_name": "HealthService",
                "file_path": "services/health.cpp",
            },
        },
        "metadata": {"direct_calls": [], "direct_callers": []},
    }

    result = enhancer.enhance_unit(unit, {})

    assert result["llm_context"]["confidence"] == 0.5
    assert "## OpenHarmony Platform Context" in captured["prompt"]
    assert "You are analyzing a cpp function" in captured["prompt"]
