"""Compatibility contract for the OpenAnt -> VulnFounder rename."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

from utilities.llm import empty_config, get_builtin_default, resolve_llm_config
from utilities.llm.registry import (
    CONFIG_FILE_ENV,
    LEGACY_CONFIG_FILE_ENV,
    LEGACY_PROJECT_ROOT_ENV,
    PROJECT_CONFIG_RELATIVE_PATH,
    PROJECT_ROOT_ENV,
    default_config_path,
    load_config_file,
)


def _write_config(path: Path, name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"default_llm": name}), encoding="utf-8")


def test_vulnfounder_config_constants_are_primary() -> None:
    assert CONFIG_FILE_ENV == "VULNFOUNDER_CONFIG_FILE"
    assert LEGACY_CONFIG_FILE_ENV == "OPENANT_CONFIG_FILE"
    assert PROJECT_ROOT_ENV == "VULNFOUNDER_PROJECT_ROOT"
    assert LEGACY_PROJECT_ROOT_ENV == "OPENANT_PROJECT_ROOT"
    assert PROJECT_CONFIG_RELATIVE_PATH == Path("config/vulnfounder/config.json")


def test_new_config_environment_wins_over_legacy(tmp_path: Path, monkeypatch) -> None:
    primary = tmp_path / "vulnfounder.json"
    legacy = tmp_path / "openant.json"
    _write_config(primary, "primary")
    _write_config(legacy, "legacy")
    monkeypatch.setenv("VULNFOUNDER_CONFIG_FILE", str(primary))
    monkeypatch.setenv("OPENANT_CONFIG_FILE", str(legacy))

    assert default_config_path() == primary.resolve()
    assert load_config_file().default_llm == "primary"


def test_legacy_config_environment_remains_readable(tmp_path: Path, monkeypatch) -> None:
    legacy = tmp_path / "openant.json"
    _write_config(legacy, "legacy")
    monkeypatch.delenv("VULNFOUNDER_CONFIG_FILE", raising=False)
    monkeypatch.setenv("OPENANT_CONFIG_FILE", str(legacy))

    assert default_config_path() == legacy.resolve()
    assert load_config_file().default_llm == "legacy"


def test_new_and_legacy_python_cli_modules_are_importable() -> None:
    primary = importlib.import_module("vulnfounder.cli")
    legacy = importlib.import_module("openant.cli")
    assert primary.main is legacy.main


def test_vulnfounder_default_is_primary_and_legacy_name_is_an_alias() -> None:
    config = empty_config()
    builtin = get_builtin_default()
    assert config.default_llm == "vulnfounder-default"
    assert builtin.name == "vulnfounder-default"
    assert resolve_llm_config(config, "vulnfounder-default") is builtin
    assert resolve_llm_config(config, "openant-default") is builtin
