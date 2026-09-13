"""Platform selection plumbing for the parse command."""

import json
from pathlib import Path

from core.schemas import ParseResult
from openant import cli


def test_parse_platform_flag_defaults_to_auto_and_accepts_supported_values():
    parser = cli.build_parser()

    assert parser.parse_args(["parse", "/repo"]).platform == "auto"
    for platform in ("generic", "openharmony"):
        assert parser.parse_args(["parse", "/repo", "--platform", platform]).platform == platform


def test_parse_platform_flag_rejects_unknown_platform():
    try:
        cli.build_parser().parse_args(["parse", "/repo", "--platform", "android"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("unknown platform must be rejected")


def test_parse_result_serializes_explicit_platform_without_changing_default():
    assert "platform_selection" not in ParseResult(dataset_path="/out/dataset.json").to_dict()
    payload = json.loads(json.dumps(
        ParseResult(
            dataset_path="/out/dataset.json",
            platform_selection="openharmony",
        ).to_dict()
    ))
    assert payload["platform_selection"] == "openharmony"


def test_cmd_parse_records_explicit_platform_after_parser_returns(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n")
    output = tmp_path / "out"
    captured = {}

    def fake_parse_repository(**kwargs):
        captured.update(kwargs)
        return ParseResult(
            dataset_path=str(Path(kwargs["output_dir"]) / "dataset.json"),
            language="python",
            units_count=1,
        )

    import core.parser_adapter

    monkeypatch.setattr(core.parser_adapter, "parse_repository", fake_parse_repository)
    args = cli.build_parser().parse_args(
        [
            "parse", str(repo), "--output", str(output), "--language", "python",
            "--platform", "openharmony",
        ]
    )

    assert cli.cmd_parse(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["platform_selection"] == "openharmony"
    assert captured["platform"] == "openharmony"
