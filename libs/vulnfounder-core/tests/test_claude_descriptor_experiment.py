"""Claude Code 协议描述符旁路实验器测试。"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from utilities.openharmony_dynamic.claude_descriptor_experiment import (  # noqa: E402
    run_claude_descriptor_experiment,
)


def _make_fake_claude(tmp_path: Path, payload: dict) -> Path:
    script = tmp_path / "fake-claude"
    encoded = json.dumps(payload, ensure_ascii=False)
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"print({encoded!r})\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _finding(repo: Path, source: Path) -> Path:
    path = repo / "finding_input.json"
    path.write_text(json.dumps({
        "finding_id": "fixture-1",
        "repo_root": str(repo),
        "source_paths": [source.name],
        "analysis_context": {"source_evidence": [f"{source.name}:1"]},
    }), encoding="utf-8")
    return path


def _draft() -> dict:
    return {
        "descriptor_id": "fixture_protocol",
        "endianness": "ascii",
        "framing": "single_message",
        "transports": ["udp"],
        "fields": [{"name": "command", "type": "string", "order": 0,
                     "evidence": "handler.cpp:1"}],
        "known_guards": [],
        "on_send_transforms": [],
        "structure_evidence": "handler parses command::value",
        "encoder_kind": "key_value",
        "wire_format": {"pair_separator": "::", "record_separator": "\\n", "terminator": ""},
        "legal_probe": {"mode": "udp", "host": "127.0.0.1", "port": 8283,
                        "first": "command::ping", "second": "", "third": "",
                        "evidence": "handler.cpp:1"},
    }


def test_claude_descriptor_sidecar_reuses_deterministic_checks(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "handler.cpp"
    source.write_text(
        'const char* command = "command";\n'
        'auto value = SplitMsg(recvBuf, "::");\n', encoding="utf-8",
    )
    finding = _finding(repo, source)
    fake = _make_fake_claude(tmp_path, {
        "result": json.dumps(_draft(), ensure_ascii=False),
        "session_id": "fixture-session",
    })

    result = run_claude_descriptor_experiment(
        finding, claude_bin=str(fake), output_path=tmp_path / "result.json",
        timeout_seconds=5,
    )

    assert result.status == "validated"
    assert result.validation["errors"] == []
    assert result.descriptor["descriptor_id"] == "fixture_protocol"
    saved = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert saved["provider"] == "claude_code_sidecar"
    assert saved["status"] == "validated"
    assert "--allowed-tools" in saved["command"]
    assert "Edit" not in saved["command"]


def test_claude_descriptor_sidecar_surfaces_cli_auth_or_network_failure(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "handler.cpp"
    source.write_text("void Handle() {}\n", encoding="utf-8")
    finding = _finding(repo, source)
    fake = tmp_path / "fake-claude-error"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'result': 'Not logged in · Please run /login'}))\n"
        "raise SystemExit(1)\n", encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    result = run_claude_descriptor_experiment(finding, claude_bin=str(fake), timeout_seconds=5)

    assert result.status == "claude_unavailable"
    assert "Not logged in" in result.error


def test_claude_descriptor_sidecar_does_not_accept_invalid_probe(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "handler.cpp"
    source.write_text('const char* command = "command";\n', encoding="utf-8")
    finding = _finding(repo, source)
    draft = _draft()
    draft["legal_probe"]["first"] = "command::echo hack"
    fake = _make_fake_claude(tmp_path, {"result": json.dumps(draft, ensure_ascii=False)})

    result = run_claude_descriptor_experiment(finding, claude_bin=str(fake), timeout_seconds=5)

    assert result.status == "rejected_by_deterministic_checks"
    assert any("命令执行词" in item for item in result.validation["errors"])
