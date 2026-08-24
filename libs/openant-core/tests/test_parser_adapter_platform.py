"""Platform forwarding contracts for parser adapter and C subprocess argv."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core import parser_adapter
from core.schemas import ParseResult


def _fake_subprocess(
    monkeypatch,
    output_dir: Path,
    commands: list[list[str]],
    scope: dict | None = None,
):
    def run(cmd, **kwargs):
        commands.append(cmd)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "dataset.json").write_text('{"units": []}', encoding="utf-8")
        if scope is not None:
            (output_dir / "scan_results.json").write_text(
                json.dumps({"scope": scope}),
                encoding="utf-8",
            )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(parser_adapter.subprocess, "run", run)


def test_c_subprocess_receives_explicit_openharmony_platform(monkeypatch, tmp_path):
    commands: list[list[str]] = []
    _fake_subprocess(monkeypatch, tmp_path / "out", commands)

    parser_adapter._parse_via_subprocess(
        "c",
        str(tmp_path / "repo"),
        str(tmp_path / "out"),
        "all",
        platform="openharmony",
    )

    assert "--platform" in commands[0]
    assert commands[0][commands[0].index("--platform") + 1] == "openharmony"


def test_non_c_subprocess_does_not_receive_openharmony_flag(monkeypatch, tmp_path):
    commands: list[list[str]] = []
    _fake_subprocess(monkeypatch, tmp_path / "out", commands)

    parser_adapter._parse_via_subprocess(
        "go",
        str(tmp_path / "repo"),
        str(tmp_path / "out"),
        "all",
        platform="openharmony",
    )

    assert "--platform" not in commands[0]


def test_c_subprocess_exposes_scope_as_parse_result_coverage(monkeypatch, tmp_path):
    commands: list[list[str]] = []
    scope = {"platform": "openharmony", "coverage": {"parsed_files": 6}}
    _fake_subprocess(monkeypatch, tmp_path / "out", commands, scope=scope)

    result = parser_adapter._parse_via_subprocess(
        "c",
        str(tmp_path / "repo"),
        str(tmp_path / "out"),
        "all",
        platform="openharmony",
    )

    assert result.platform_coverage == scope


def test_parse_repository_forwards_platform_only_to_c_parser(monkeypatch, tmp_path):
    captured: dict = {}

    def fake_c_parser(*args, **kwargs):
        captured.update(kwargs)
        return ParseResult(
            dataset_path=str(tmp_path / "dataset.json"),
            language="c",
            units_count=1,
        )

    monkeypatch.setattr(parser_adapter, "_parse_c", fake_c_parser)
    parser_adapter.parse_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        language="c",
        processing_level="all",
        platform="openharmony",
    )

    assert captured["platform"] == "openharmony"


def test_parse_repository_multi_forwards_platform_to_c_parser(monkeypatch, tmp_path):
    captured: list[str] = []

    def fake_c_parser(*args, **kwargs):
        captured.append(kwargs["platform"])
        return ParseResult(
            dataset_path=str(tmp_path / "c" / "dataset.json"),
            language="c",
            units_count=1,
        )

    monkeypatch.setattr(parser_adapter, "_parse_c", fake_c_parser)
    outcomes = parser_adapter.parse_repository_multi(
        repo_path=str(tmp_path),
        run_dir=str(tmp_path / "run"),
        languages=["c"],
        processing_level="all",
        platform="openharmony",
    )

    assert outcomes[0].ok is True
    assert captured == ["openharmony"]
