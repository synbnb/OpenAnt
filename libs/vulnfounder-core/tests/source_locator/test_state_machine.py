"""SL-07 状态机、事件日志和恢复测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    FLOW_STATES,
    LocatorEvent,
    LocatorEventError,
    LocatorSessionStore,
    LocatorStateError,
    SourceLocatorOrchestrator,
    SourceLocatorStateMachine,
    StageResult,
)


def _machine(tmp_path: Path) -> SourceLocatorStateMachine:
    return SourceLocatorStateMachine.create(
        tmp_path / "sessions",
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 2},
        session_id="loc_test123456",
    )


def test_create_writes_checkpoint_and_initial_event(tmp_path):
    machine = _machine(tmp_path)
    loaded = LocatorSessionStore(tmp_path / "sessions").load(machine.session.session_id)
    events = loaded.store.events(machine.session.session_id).load()

    assert machine.session.state == "INTAKE"
    assert loaded.session == machine.session
    assert [(event.seq, event.type, event.state) for event in events] == [(1, "session.created", "INTAKE")]
    assert (tmp_path / "sessions" / machine.session.session_id / "session.json").exists()


def test_delete_removes_only_one_session_directory(tmp_path):
    root = tmp_path / "sessions"
    store = LocatorSessionStore(root)
    removed = store.create("/dev/unix/socket/paramservice", session_id="loc_delete123456")
    kept = store.create("/dev/unix/socket/other", session_id="loc_keep123456")
    removed_dir = root / removed.session.session_id
    kept_dir = root / kept.session.session_id
    (removed_dir / "artifact.json").write_text("{}", encoding="utf-8")

    assert store.delete(removed.session.session_id) is True
    assert not removed_dir.exists()
    assert (kept_dir / "session.json").exists()
    with pytest.raises(LocatorStateError, match="不存在"):
        store.delete(removed.session.session_id)


def test_orchestrator_follows_strict_flow_and_pauses_for_confirmation(tmp_path):
    machine = _machine(tmp_path)
    states = list(FLOW_STATES)
    next_states = {
        "PROBE_OPENGROK": "SEARCH_INITIAL",
        "SEARCH_INITIAL": "TRACE_EVIDENCE",
        "TRACE_EVIDENCE": "ATTRIBUTION_SERVER",
        "ATTRIBUTION_SERVER": "LOCATE_CLIENT_COMM",
        "LOCATE_CLIENT_COMM": "RESOLVE_REPOSITORIES",
        "RESOLVE_REPOSITORIES": "VERIFY_EVIDENCE",
        "VERIFY_EVIDENCE": "AWAIT_USER_CONFIRMATION",
    }

    def handler(state):
        def run(session):
            return StageResult(next_states[state], f"完成 {state}")

        return run

    handlers = {state: handler(state) for state in next_states}
    result = SourceLocatorOrchestrator.with_normalizer(machine, handlers).run()

    assert result.state == "AWAIT_USER_CONFIRMATION"
    events = machine.store.events(machine.session.session_id).load()
    assert [event.state for event in events] == [
        "INTAKE",
        "NORMALIZE_TARGET",
        "PROBE_OPENGROK",
        "SEARCH_INITIAL",
        "TRACE_EVIDENCE",
        "ATTRIBUTION_SERVER",
        "LOCATE_CLIENT_COMM",
        "RESOLVE_REPOSITORIES",
        "VERIFY_EVIDENCE",
        "AWAIT_USER_CONFIRMATION",
    ]


def test_normalize_failure_enters_review_instead_of_throwing(tmp_path):
    machine = SourceLocatorStateMachine.create(tmp_path / "sessions", "not a target", session_id="loc_bad123456")
    result = SourceLocatorOrchestrator.with_normalizer(machine).run()

    assert result.state == "NEEDS_REVIEW"
    assert "标准化" in (result.last_error or "") or result.last_error


def test_illegal_transition_and_terminal_resume_are_rejected(tmp_path):
    machine = _machine(tmp_path)
    with pytest.raises(LocatorStateError, match="非法状态转换"):
        machine.transition("CLONE", summary_zh="skip")
    machine.cancel()
    assert machine.session.state == "CANCELLED"
    with pytest.raises(LocatorStateError, match="终态"):
        machine.transition("NORMALIZE_TARGET", summary_zh="late")


def test_recovery_transition_is_explicit_and_returns_to_trace(tmp_path):
    machine = _machine(tmp_path)
    for state in (
        "NORMALIZE_TARGET",
        "PROBE_OPENGROK",
        "SEARCH_INITIAL",
        "TRACE_EVIDENCE",
        "ATTRIBUTION_SERVER",
        "LOCATE_CLIENT_COMM",
        "RESOLVE_REPOSITORIES",
        "VERIFY_EVIDENCE",
    ):
        machine.transition(state, summary_zh=state)
    machine.transition(
        "RECOVER_EVIDENCE",
        summary_zh="补充缺失证据",
        details={"missing_predicates": ["socket_acquire_or_bind"]},
    )
    machine.transition("TRACE_EVIDENCE", summary_zh="重新追踪")
    assert machine.session.state == "TRACE_EVIDENCE"
    events = machine.store.events(machine.session.session_id).load()
    assert events[-2].state == "RECOVER_EVIDENCE"
    assert events[-2].details["missing_predicates"] == ["socket_acquire_or_bind"]


def test_query_history_survives_reload_and_duplicates_never_execute(tmp_path):
    machine = _machine(tmp_path)
    machine.transition("NORMALIZE_TARGET", summary_zh="进入标准化")
    machine.transition("PROBE_OPENGROK", summary_zh="进入探测")
    assert machine.record_query("search_definition:PARAM_SERVICE_SOCKET") == "accepted"
    assert machine.record_query("search_definition:PARAM_SERVICE_SOCKET") == "repeated"

    restored = machine.store.load(machine.session.session_id)
    assert restored.session.executed_queries == ("search_definition:PARAM_SERVICE_SOCKET",)
    assert restored.record_query("search_definition:OTHER") == "accepted"
    assert restored.session.executed_queries == (
        "search_definition:PARAM_SERVICE_SOCKET",
        "search_definition:OTHER",
    )


def test_query_budget_transitions_to_partial_without_loop(tmp_path):
    machine = _machine(tmp_path)
    machine.transition("NORMALIZE_TARGET", summary_zh="进入标准化")
    machine.transition("PROBE_OPENGROK", summary_zh="进入探测")
    assert machine.record_query("first") == "accepted"
    assert machine.record_query("second") == "accepted"
    assert machine.record_query("third") == "budget_exhausted"
    assert machine.session.state == "PARTIAL"
    with pytest.raises(LocatorStateError, match="终态"):
        machine.record_query("fourth")


def test_rejection_preserves_evidence_graph_and_adds_constraints(tmp_path):
    machine = _machine(tmp_path)
    machine.transition(
        "NORMALIZE_TARGET",
        summary_zh="标准化完成",
        updates={"evidence_ids": ("E-00001",), "evidence_graph": {"edges": ["G-1"]}},
    )
    machine.transition("PROBE_OPENGROK", summary_zh="探测完成")
    machine.transition("SEARCH_INITIAL", summary_zh="搜索完成")
    machine.transition("TRACE_EVIDENCE", summary_zh="证据完成")
    machine.transition("ATTRIBUTION_SERVER", summary_zh="服务端完成")
    machine.transition("LOCATE_CLIENT_COMM", summary_zh="客户端完成")
    machine.transition("RESOLVE_REPOSITORIES", summary_zh="仓库完成")
    machine.transition("VERIFY_EVIDENCE", summary_zh="验证完成")
    machine.transition("AWAIT_USER_CONFIRMATION", summary_zh="等待确认")
    before = machine.session.evidence_graph

    machine.reject(
        "这是 creator，不是 consumer",
        excluded_paths=("/openharmony/old/service.c",),
        excluded_repos=("old_repo",),
        required_role="server_consumer",
    )

    assert machine.session.state == "APPLY_FEEDBACK"
    assert machine.session.evidence_graph == before
    assert machine.session.evidence_ids == ("E-00001",)
    assert machine.session.excluded_paths == ("/openharmony/old/service.c",)
    assert machine.session.excluded_repos == ("old_repo",)
    assert machine.session.feedback_round == 1
    machine.resume_after_feedback()
    assert machine.session.state == "SEARCH_INITIAL"


def test_fourth_rejection_enters_review_and_keeps_round_bound(tmp_path):
    machine = _machine(tmp_path)
    # Move to confirmation without invoking any external worker.
    for state in (
        "NORMALIZE_TARGET",
        "PROBE_OPENGROK",
        "SEARCH_INITIAL",
        "TRACE_EVIDENCE",
        "ATTRIBUTION_SERVER",
        "LOCATE_CLIENT_COMM",
        "RESOLVE_REPOSITORIES",
        "VERIFY_EVIDENCE",
        "AWAIT_USER_CONFIRMATION",
    ):
        machine.transition(state, summary_zh=state)
        if state == "AWAIT_USER_CONFIRMATION":
            break
    for index in range(3):
        machine.reject(f"reason {index}")
        machine.resume_after_feedback()
        # Run the deterministic path back to confirmation for the next round.
        for state in (
            "TRACE_EVIDENCE",
            "ATTRIBUTION_SERVER",
            "LOCATE_CLIENT_COMM",
            "RESOLVE_REPOSITORIES",
            "VERIFY_EVIDENCE",
            "AWAIT_USER_CONFIRMATION",
        ):
            machine.transition(state, summary_zh=state)
    machine.reject("fourth reason")
    assert machine.session.state == "NEEDS_REVIEW"
    assert machine.session.feedback_round == 3


def test_confirm_is_the_only_path_to_clone(tmp_path):
    machine = _machine(tmp_path)
    for state in (
        "NORMALIZE_TARGET",
        "PROBE_OPENGROK",
        "SEARCH_INITIAL",
        "TRACE_EVIDENCE",
        "ATTRIBUTION_SERVER",
        "LOCATE_CLIENT_COMM",
        "RESOLVE_REPOSITORIES",
        "VERIFY_EVIDENCE",
        "AWAIT_USER_CONFIRMATION",
    ):
        machine.transition(state, summary_zh=state)
    machine.confirm(confirmation_id="confirm-1")
    assert machine.session.state == "CLONE"
    assert machine.store.events(machine.session.session_id).load()[-1].type == "user.confirmed"


def test_version_selection_required_is_resumable_and_persisted(tmp_path):
    machine = _machine(tmp_path)
    for state in (
        "NORMALIZE_TARGET",
        "PROBE_OPENGROK",
        "SEARCH_INITIAL",
        "TRACE_EVIDENCE",
        "ATTRIBUTION_SERVER",
        "LOCATE_CLIENT_COMM",
        "RESOLVE_REPOSITORIES",
        "VERIFY_EVIDENCE",
        "AWAIT_USER_CONFIRMATION",
        "CLONE",
    ):
        machine.transition(state, summary_zh=state)
    machine.transition(
        "VERSION_SELECTION_REQUIRED",
        summary_zh="拉取失败，等待选择远程版本",
        updates={
            "version_selection": {
                "artifact": "repository_version_candidates.json",
                "status": "ok",
                "candidate_count": 2,
                "candidate_revisions": ["OpenHarmony-6.1-LTS", "OpenHarmony-6.0-LTS"],
            }
        },
    )

    restored = LocatorSessionStore(tmp_path / "sessions").load(machine.session.session_id)
    assert restored.session.state == "VERSION_SELECTION_REQUIRED"
    assert restored.session.version_selection["candidate_count"] == 2
    # The state is a pause, not a terminal failure; explicit selection can
    # later transition it back to CLONE.
    restored.transition("CLONE", summary_zh="用户选择版本后重试")
    assert restored.session.state == "CLONE"


def test_select_version_requires_candidate_and_updates_resolved_mapping(tmp_path):
    machine = _machine(tmp_path)
    for state, updates in (
        ("NORMALIZE_TARGET", {}),
        ("PROBE_OPENGROK", {}),
        ("SEARCH_INITIAL", {}),
        ("TRACE_EVIDENCE", {}),
        ("ATTRIBUTION_SERVER", {}),
        ("LOCATE_CLIENT_COMM", {}),
        ("RESOLVE_REPOSITORIES", {
            "repository_mappings": {
                "mappings": [{
                    "project_name": "startup_init",
                    "status": "resolved",
                    "revision": "OpenHarmony-6.1-LTS",
                }]
            }
        }),
        ("VERIFY_EVIDENCE", {}),
        ("AWAIT_USER_CONFIRMATION", {}),
        ("CLONE", {}),
    ):
        machine.transition(state, summary_zh=state, updates=updates)
    machine.transition(
        "VERSION_SELECTION_REQUIRED",
        summary_zh="等待版本",
        updates={
            "version_selection": {
                "artifact": "repository_version_candidates.json",
                "status": "ok",
                "project_name": "startup_init",
                "candidate_revisions": ["OpenHarmony-6.1-LTS", "OpenHarmony-6.0-LTS"],
            }
        },
    )

    with pytest.raises(LocatorStateError):
        machine.select_version("feature/not-listed")

    selected = machine.select_version(
        "OpenHarmony-6.0-LTS",
        candidate_revisions=("OpenHarmony-6.1-LTS", "OpenHarmony-6.0-LTS"),
        confirmation_id="version-choice-1",
    )
    assert selected.state == "CLONE"
    assert selected.repository_mappings["mappings"][0]["revision"] == "OpenHarmony-6.0-LTS"
    assert selected.version_selection["selected_revision"] == "OpenHarmony-6.0-LTS"
    assert selected.version_selection["selection_status"] == "selected"
    assert machine.store.events(selected.session_id).load()[-1].type == "user.version_selected"


def test_event_log_rejects_gaps_and_unsafe_artifacts(tmp_path):
    machine = _machine(tmp_path)
    log = machine.store.events(machine.session.session_id)
    with pytest.raises(LocatorEventError):
        LocatorEvent(seq=1, session_id=machine.session.session_id, type="state.changed", state="INTAKE", summary_zh="ok", artifact="../secret")
    path = machine.store.session_dir(machine.session.session_id) / "events.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"seq": 3}) + "\n")
    with pytest.raises(LocatorEventError):
        log.load()
