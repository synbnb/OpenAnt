"""Platform selection must be explicit, validated, and observable."""

import json

import pytest

from core.schemas import ScanResult
from openant import cli


def test_scan_platform_flag_defaults_to_auto_and_accepts_supported_values():
    parser = cli.build_parser()

    assert parser.parse_args(["scan", "/repo"]).platform == "auto"
    for platform in ("generic", "openharmony"):
        assert parser.parse_args(["scan", "/repo", "--platform", platform]).platform == platform


def test_scan_platform_flag_rejects_unknown_platform():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["scan", "/repo", "--platform", "android"])


def test_explicit_platform_selection_is_serialized_without_changing_default_output():
    assert "platform_selection" not in ScanResult(output_dir="/out").to_dict()

    payload = json.loads(json.dumps(
        ScanResult(output_dir="/out", platform_selection="openharmony").to_dict()
    ))
    assert payload["platform_selection"] == "openharmony"


def test_scan_forwards_explicit_platform_to_scanner(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "sample.py").write_text("def sample():\n    return 1\n")
    captured = {}

    def fake_scan_repository(**kwargs):
        captured.update(kwargs)
        return ScanResult(output_dir=kwargs["output_dir"])

    import core.scanner

    monkeypatch.setattr(core.scanner, "scan_repository", fake_scan_repository)
    args = cli.build_parser().parse_args(
        [
            "scan", str(repo), "--platform", "openharmony", "--no-context",
            "--no-enhance", "--no-report",
        ]
    )

    assert cli.cmd_scan(args) == 0
    assert captured["platform"] == "openharmony"
