"""OH-20 tests for the versioned, fail-safe rule catalog loader."""

from __future__ import annotations

import hashlib
import copy
from pathlib import Path

from core.rules.loader import RuleLoader
from core.rules.schema import RULE_SCHEMA_VERSION


VALID_RULE = {
    "id": "OH-IPC-001",
    "version": "1.0.0",
    "title": "Parcel read return value",
    "description": "Detect unchecked Parcel read results.",
    "platforms": ["openharmony"],
    "severity": "high",
    "detector": "parcel_read_return_value",
    "config": {"read_methods": ["ReadInt32", "ReadString"]},
    "references": ["security-skill-library://check-read-return-value"],
    "tags": ["ipc", "parcel"],
}


def _document(*rules: dict) -> str:
    import yaml

    return yaml.safe_dump(
        {
            "schema_version": RULE_SCHEMA_VERSION,
            "rules": [copy.deepcopy(rule) for rule in rules],
        },
        sort_keys=False,
    )


def test_valid_rule_loads_with_stable_source_hash(tmp_path: Path):
    path = tmp_path / "valid.yaml"
    path.write_text(_document(VALID_RULE), encoding="utf-8")

    first = RuleLoader().load_file(path)
    second = RuleLoader().load_file(path)

    assert first.schema_version == RULE_SCHEMA_VERSION
    assert [rule.id for rule in first.rules] == ["OH-IPC-001"]
    assert first.issues == ()
    assert first.source_sha256 == second.source_sha256
    assert first.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert first.rules[0].platforms == ("openharmony",)
    assert first.rules[0].config["read_methods"] == ["ReadInt32", "ReadString"]


def test_invalid_rule_does_not_block_valid_sibling(tmp_path: Path):
    invalid = {**VALID_RULE, "id": "OH-IPC-002", "severity": "catastrophic"}
    path = tmp_path / "mixed.yaml"
    path.write_text(_document(VALID_RULE, invalid), encoding="utf-8")

    result = RuleLoader().load_file(path)

    assert [rule.id for rule in result.rules] == ["OH-IPC-001"]
    assert any(issue.code == "invalid_severity" for issue in result.issues)
    assert all(issue.rule_id != "OH-IPC-001" for issue in result.issues)


def test_unknown_fields_and_duplicate_ids_are_rejected(tmp_path: Path):
    unknown = {**VALID_RULE, "id": "OH-IPC-002", "arbitrary_code": "ignored"}
    duplicate = {**VALID_RULE, "title": "second copy"}
    path = tmp_path / "duplicates.yaml"
    path.write_text(_document(VALID_RULE, unknown, duplicate), encoding="utf-8")

    result = RuleLoader().load_file(path)

    assert [rule.id for rule in result.rules] == ["OH-IPC-001"]
    assert {issue.code for issue in result.issues} >= {
        "unknown_field",
        "duplicate_rule_id",
    }


def test_malformed_yaml_is_fail_safe(tmp_path: Path):
    path = tmp_path / "broken.yaml"
    path.write_text("schema_version: [\nrules: [", encoding="utf-8")

    result = RuleLoader().load_file(path)

    assert result.rules == ()
    assert any(issue.code == "yaml_parse_error" for issue in result.issues)


def test_yaml_aliases_are_rejected_before_expansion(tmp_path: Path):
    path = tmp_path / "alias.yaml"
    path.write_text(
        """schema_version: 1
rules:
  - id: OH-IPC-001
    version: 1.0.0
    title: Alias rule
    description: Must not expand aliases.
    platforms: [openharmony]
    severity: high
    detector: parcel_read_return_value
    config: &shared
      read_methods: [ReadInt32]
  - id: OH-IPC-002
    version: 1.0.0
    title: Alias use
    description: Must not expand aliases.
    platforms: [openharmony]
    severity: high
    detector: parcel_read_return_value
    config: *shared
""",
        encoding="utf-8",
    )

    result = RuleLoader().load_file(path)

    assert result.rules == ()
    assert any(issue.code == "yaml_alias_not_allowed" for issue in result.issues)


def test_oversized_rule_file_is_rejected_without_loading(tmp_path: Path):
    path = tmp_path / "large.yaml"
    path.write_text("x" * 128, encoding="utf-8")

    result = RuleLoader(max_file_bytes=64).load_file(path)

    assert result.rules == ()
    assert result.source_sha256 is None
    assert any(issue.code == "file_too_large" for issue in result.issues)


def test_too_many_rules_are_rejected_as_a_file_level_limit(tmp_path: Path):
    path = tmp_path / "many.yaml"
    rules = [
        {**VALID_RULE, "id": f"OH-IPC-{index:03d}"}
        for index in range(1, 4)
    ]
    path.write_text(_document(*rules), encoding="utf-8")

    result = RuleLoader(max_rules_per_file=2).load_file(path)

    assert result.rules == ()
    assert any(issue.code == "too_many_rules" for issue in result.issues)


def test_deep_config_is_rejected_before_detector_use(tmp_path: Path):
    nested: dict = {}
    cursor = nested
    for index in range(14):
        cursor["level"] = {}
        cursor = cursor["level"]
    path = tmp_path / "deep.yaml"
    path.write_text(
        _document({**VALID_RULE, "config": nested}), encoding="utf-8"
    )

    result = RuleLoader().load_file(path)

    assert result.rules == ()
    assert any(issue.code == "config_too_deep" for issue in result.issues)


def test_loader_catalog_deduplicates_rules_across_files(tmp_path: Path):
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text(_document(VALID_RULE), encoding="utf-8")
    second.write_text(
        _document({**VALID_RULE, "title": "duplicate from second file"}),
        encoding="utf-8",
    )

    catalog = RuleLoader().load([first, second])

    assert [rule.id for rule in catalog.rules] == ["OH-IPC-001"]
    assert any(issue.code == "duplicate_rule_id" for issue in catalog.issues)
    assert len(catalog.files) == 2


def test_default_rules_are_discoverable_from_package_resources():
    catalog = RuleLoader().load()

    assert catalog.files
    assert any(rule.id == "OH-IPC-001" for rule in catalog.rules)


def test_wheel_declares_packaged_default_rule_catalog():
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")

    assert "core/rules/defaults/openharmony.yaml" in text
