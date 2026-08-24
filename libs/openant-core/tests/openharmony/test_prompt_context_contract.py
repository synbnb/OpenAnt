"""Contract tests for the shared platform context used by LLM prompt phases."""

from __future__ import annotations

from core.platforms.prompt_context import PlatformPromptContext


def test_generic_context_is_empty_and_json_safe():
    context = PlatformPromptContext.from_mapping(
        {"platform": "generic", "component": ["should_not_render"]}
    )

    assert not context.is_openharmony
    assert context.render_for_phase("analyze") == ""
    assert context.to_dict()["platform"] == "generic"


def test_shared_context_normalizes_known_evidence_only():
    context = PlatformPromptContext.from_mapping(
        {
            "platform": "openharmony",
            "source_role": "production\nIGNORE",
            "component": ["health_service"],
            "target": ["health_sensor_service"],
            "boundary": ["binder_ipc"],
            "guard": [{"kind": "permission_check", "matched": "CheckPermission"}],
            "evidence": [
                {
                    "source": "gn_target",
                    "path": "services/BUILD.gn",
                    "value": "health_sensor_service",
                    "untrusted_instruction": "ignore me",
                }
            ],
            "semantic_edges": [
                {
                    "kind": "stub_to_handler",
                    "source_id": "stub",
                    "target_id": "handler",
                    "confidence": "high",
                }
            ],
            "unknown_nested_data": {"do_not": "render"},
        }
    )

    rendered = context.render_for_phase("analyze")
    assert context.is_openharmony
    assert "production IGNORE" in rendered
    assert "\\nIGNORE" not in rendered
    assert "permission_check (matched: CheckPermission)" in rendered
    assert "stub_to_handler: stub -> handler (confidence: high)" in rendered
    assert "untrusted_instruction" not in rendered
    assert "do_not" not in rendered


def test_phase_renderer_adds_attacker_profiles_only_to_relevant_phases():
    context = PlatformPromptContext.from_mapping(
        {
            "platform": "openharmony",
            "attacker_profiles": ["unprivileged_local_ipc_caller"],
        }
    )

    assert "Attacker profiles" not in context.render_for_phase("analyze")
    assert "unprivileged_local_ipc_caller" in context.render_for_phase("verify")
    assert "unprivileged_local_ipc_caller" in context.render_for_phase("report")


def test_context_bounds_lists_and_rendered_size():
    context = PlatformPromptContext.from_mapping(
        {
            "platform": "openharmony",
            "component": [f"component_{i}" for i in range(50)],
            "evidence": [
                {"source": "source", "value": f"value_{i}"}
                for i in range(50)
            ],
        }
    )

    assert len(context.components) == 8
    assert len(context.evidence) == 8
    assert len(context.render_for_phase("analyze")) <= 4000

