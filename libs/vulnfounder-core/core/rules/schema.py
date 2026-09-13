"""Strict data model for VulnFounder security rules.

The schema is deliberately detector-agnostic.  OH-20 validates the identity,
scope and bounded JSON-like configuration of a rule; later stages decide how a
detector interprets that configuration.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


RULE_SCHEMA_VERSION = 1
SUPPORTED_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})

_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SLUG_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")

MAX_RULE_ID_LENGTH = 64
MAX_VERSION_LENGTH = 32
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 4000
MAX_STRING_LENGTH = 4096
MAX_LIST_ITEMS = 256
MAX_CONFIG_DEPTH = 12
MAX_CONFIG_NODES = 4096


class RuleValidationError(ValueError):
    """A rule violates the OH-20 schema contract."""

    def __init__(self, message: str, *, code: str = "invalid_rule", rule_id: str | None = None):
        super().__init__(message)
        self.code = code
        self.rule_id = rule_id


@dataclass(frozen=True)
class RuleIssue:
    """Non-fatal or fatal issue encountered while loading a rule source."""

    code: str
    message: str
    source_path: str | None = None
    rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {"code": self.code, "message": self.message}
        if self.source_path is not None:
            result["source_path"] = self.source_path
        if self.rule_id is not None:
            result["rule_id"] = self.rule_id
        return result


@dataclass(frozen=True)
class Rule:
    """Validated, immutable representation of one security rule."""

    id: str
    version: str
    title: str
    description: str
    platforms: tuple[str, ...]
    severity: str
    detector: str
    config: Mapping[str, Any]
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "platforms": list(self.platforms),
            "severity": self.severity,
            "detector": self.detector,
            "config": copy.deepcopy(dict(self.config)),
            "references": list(self.references),
            "tags": list(self.tags),
        }


def _require_string(value: Any, field: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(f"{field} must be a non-empty string", code="invalid_field")
    value = value.strip()
    if len(value) > max_length:
        raise RuleValidationError(
            f"{field} exceeds the {max_length}-character limit",
            code="field_too_long",
        )
    return value


def _require_slug(value: Any, field: str) -> str:
    value = _require_string(value, field, max_length=64)
    if not _SLUG_RE.fullmatch(value):
        raise RuleValidationError(
            f"{field} must be a lowercase slug", code="invalid_field"
        )
    return value


def _require_string_list(value: Any, field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RuleValidationError(f"{field} must be a list", code="invalid_field")
    if len(value) > MAX_LIST_ITEMS:
        raise RuleValidationError(
            f"{field} contains too many items", code="list_too_long"
        )
    values = tuple(
        _require_string(item, f"{field}[]", max_length=MAX_STRING_LENGTH)
        for item in value
    )
    if not allow_empty and not values:
        raise RuleValidationError(f"{field} must not be empty", code="invalid_field")
    if len(set(values)) != len(values):
        raise RuleValidationError(f"{field} contains duplicates", code="duplicate_value")
    return values


def _validate_json_like(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> Any:
    """Validate and copy config values without accepting executable objects."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_CONFIG_NODES:
        raise RuleValidationError("config contains too many values", code="config_too_large")
    if depth > MAX_CONFIG_DEPTH:
        raise RuleValidationError("config nesting is too deep", code="config_too_deep")
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
            raise RuleValidationError(
                "config string is too long", code="field_too_long"
            )
        # JSON rejects NaN/Infinity; checking through the encoder also keeps
        # the provenance representation deterministic.
        if isinstance(value, float):
            try:
                json.dumps(value, allow_nan=False)
            except ValueError as exc:
                raise RuleValidationError(
                    "config contains a non-finite number", code="invalid_config"
                ) from exc
        return value
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise RuleValidationError("config list is too long", code="list_too_long")
        return [
            _validate_json_like(item, depth=depth + 1, nodes=nodes)
            for item in value
        ]
    if isinstance(value, dict):
        if len(value) > MAX_LIST_ITEMS:
            raise RuleValidationError("config mapping is too large", code="config_too_large")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.strip():
                raise RuleValidationError(
                    "config keys must be non-empty strings", code="invalid_config"
                )
            if len(key) > MAX_STRING_LENGTH:
                raise RuleValidationError(
                    "config key is too long", code="field_too_long"
                )
            result[key] = _validate_json_like(item, depth=depth + 1, nodes=nodes)
        return result
    raise RuleValidationError(
        f"config contains unsupported value type: {type(value).__name__}",
        code="invalid_config",
    )


def parse_rule(raw: Any) -> Rule:
    """Validate one raw mapping and return an immutable :class:`Rule`."""
    if not isinstance(raw, Mapping):
        raise RuleValidationError("rule must be a mapping", code="invalid_rule")

    allowed = {
        "id",
        "version",
        "title",
        "description",
        "platforms",
        "severity",
        "detector",
        "config",
        "references",
        "tags",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RuleValidationError(
            f"unknown rule field(s): {', '.join(str(item) for item in unknown)}",
            code="unknown_field",
            rule_id=raw.get("id") if isinstance(raw.get("id"), str) else None,
        )

    rule_id = _require_string(raw.get("id"), "id", max_length=MAX_RULE_ID_LENGTH)
    if not _RULE_ID_RE.fullmatch(rule_id):
        raise RuleValidationError("id has an invalid format", code="invalid_id", rule_id=rule_id)
    version = _require_string(raw.get("version"), "version", max_length=MAX_VERSION_LENGTH)
    if not _VERSION_RE.fullmatch(version):
        raise RuleValidationError(
            "version must use MAJOR.MINOR.PATCH format",
            code="invalid_version",
            rule_id=rule_id,
        )
    title = _require_string(raw.get("title"), "title", max_length=MAX_TITLE_LENGTH)
    description = _require_string(
        raw.get("description"), "description", max_length=MAX_DESCRIPTION_LENGTH
    )
    platforms = _require_string_list(raw.get("platforms"), "platforms", allow_empty=False)
    for platform in platforms:
        if not _SLUG_RE.fullmatch(platform):
            raise RuleValidationError(
                "platforms must contain lowercase slugs",
                code="invalid_platform",
                rule_id=rule_id,
            )
    severity = _require_string(raw.get("severity"), "severity", max_length=16).lower()
    if severity not in SUPPORTED_SEVERITIES:
        raise RuleValidationError(
            f"unsupported severity: {severity}",
            code="invalid_severity",
            rule_id=rule_id,
        )
    detector = _require_slug(raw.get("detector"), "detector")
    config = raw.get("config", {})
    if not isinstance(config, Mapping):
        raise RuleValidationError("config must be a mapping", code="invalid_config", rule_id=rule_id)
    config = _validate_json_like(dict(config))
    references = _require_string_list(raw.get("references", []), "references")
    tags = _require_string_list(raw.get("tags", []), "tags")
    return Rule(
        id=rule_id,
        version=version,
        title=title,
        description=description,
        platforms=platforms,
        severity=severity,
        detector=detector,
        config=config,
        references=references,
        tags=tags,
    )
