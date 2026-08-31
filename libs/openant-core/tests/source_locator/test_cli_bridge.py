"""SL-09 Python CLI JSON bridge tests.

The Web worker invokes one command at a time.  These tests exercise the same
parser/handlers that the worker uses and assert that every command emits one
machine-readable envelope without leaking a traceback to stdout.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from openant.cli import build_parser  # noqa: E402
from core.source_locator import LocatorSession, LocatorSessionStore  # noqa: E402


def _invoke(capsys, argv: list[str]) -> tuple[int, dict]:
    args = build_parser().parse_args(argv)
    code = args.func(args)
    captured = capsys.readouterr()
    assert captured.err == ""
    # ``_output_json`` intentionally pretty-prints, but there must still be
    # exactly one top-level JSON document for the Go bridge to decode.
    payload = json.loads(captured.out)
    assert set(payload) >= {"status", "data", "errors"}
    return code, payload


@pytest.fixture
def session_args(tmp_path: Path) -> tuple[Path, str]:
    return tmp_path / "sessions", "loc_cli123456"


def test_create_status_and_events_are_single_json_envelopes(capsys, session_args):
    root, session_id = session_args
    code, created = _invoke(
        capsys,
        [
            "source-locator",
            "create",
            "/dev/unix/socket/paramservice",
            "--root",
            str(root),
            "--session-id",
            session_id,
            "--budget-json",
            '{"max_queries": 4}',
        ],
    )
    assert code == 0
    assert created["status"] == "success"
    assert created["data"]["session"]["state"] == "INTAKE"

    code, listed = _invoke(capsys, ["source-locator", "list", "--root", str(root)])
    assert code == 0
    assert [item["session_id"] for item in listed["data"]["sessions"]] == [session_id]

    code, status = _invoke(capsys, ["source-locator", "status", session_id, "--root", str(root)])
    assert code == 0
    assert status["data"]["event_count"] == 1

    code, events = _invoke(capsys, ["source-locator", "events", session_id, "--root", str(root)])
    assert code == 0
    assert [event["type"] for event in events["data"]["events"]] == ["session.created"]


def test_delete_removes_session_and_emits_json(capsys, session_args):
    root, session_id = session_args
    _invoke(
        capsys,
        ["source-locator", "create", "paramservice", "--root", str(root), "--session-id", session_id],
    )

    code, deleted = _invoke(
        capsys,
        ["source-locator", "delete", session_id, "--root", str(root)],
    )
    assert code == 0
    assert deleted["status"] == "success"
    assert deleted["data"]["session_id"] == session_id
    assert deleted["data"]["deleted"] is True
    assert not (root / session_id).exists()


def test_transition_confirm_and_cancel_follow_state_machine(capsys, session_args):
    root, session_id = session_args
    _invoke(
        capsys,
        ["source-locator", "create", "paramservice", "--root", str(root), "--session-id", session_id],
    )
    _invoke(
        capsys,
        [
            "source-locator",
            "transition",
            session_id,
            "NORMALIZE_TARGET",
            "--root",
            str(root),
            "--summary-zh",
            "已标准化目标",
            "--updates-json",
            '{"target":{"kind":"socket","value":"paramservice"}}',
        ],
    )
    code, failed = _invoke(
        capsys,
        ["source-locator", "confirm", session_id, "--root", str(root)],
    )
    assert code == 2
    assert failed["status"] == "error"
    assert "等待用户确认" in failed["errors"][0]

    code, cancelled = _invoke(
        capsys,
        ["source-locator", "cancel", session_id, "--root", str(root), "--reason", "测试取消"],
    )
    assert code == 0
    assert cancelled["data"]["session"]["state"] == "CANCELLED"


def test_reject_requires_confirmation_state_and_rejects_invalid_json(capsys, session_args):
    root, session_id = session_args
    _invoke(capsys, ["source-locator", "create", "paramservice", "--root", str(root), "--session-id", session_id])

    code, invalid = _invoke(
        capsys,
        [
            "source-locator",
            "transition",
            session_id,
            "NORMALIZE_TARGET",
            "--root",
            str(root),
            "--summary-zh",
            "标准化",
            "--updates-json",
            "[]",
        ],
    )
    assert code == 2
    assert invalid["status"] == "error"
    assert "JSON 对象" in invalid["errors"][0]

    code, rejected = _invoke(
        capsys,
        ["source-locator", "reject", session_id, "--root", str(root), "--reason", "尚未得到证据"],
    )
    assert code == 2
    assert rejected["status"] == "error"
    assert "等待用户确认" in rejected["errors"][0]


def test_handoff_returns_only_verified_done_artifact(capsys, tmp_path: Path):
    root = tmp_path / "sessions"
    store = LocatorSessionStore(root)
    session_id = "loc_handoff123456"
    store.ensure_session_dir(session_id)
    handoff = {
        "schema_version": "openant.source-locator.post-clone-verification.v1",
        "status": "ready_for_analysis",
        "project_name": "startup_init",
        "repository_path": "/tmp/source_code_base/startup_init",
        "repo_url": "https://gitcode.com/openharmony/startup_init.git",
        "revision": "OpenHarmony-6.1-LTS",
        "resolved_commit": "0123456789abcdef0123456789abcdef01234567",
        "source_paths": ["services/param/param_service.c"],
        "evidence_ids": ["E-handoff"],
    }
    session = LocatorSession(
        session_id=session_id,
        raw_target="/dev/unix/socket/paramservice",
        state="DONE",
        handoff=handoff,
        artifacts={"source_handoff.json": "已验证的静态扫描交接对象"},
    )
    store.save(session)
    (root / session_id / "source_handoff.json").write_text(json.dumps(handoff), encoding="utf-8")

    code, payload = _invoke(
        capsys,
        ["source-locator", "handoff", session_id, "--root", str(root)],
    )
    assert code == 0
    assert payload["data"]["primary_analysis_repo"].endswith("startup_init")
    assert payload["data"]["handoff"]["status"] == "ready_for_analysis"
