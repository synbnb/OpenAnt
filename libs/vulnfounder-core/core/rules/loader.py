"""Secure discovery and loading of versioned YAML security rules."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

import yaml

from .schema import (
    RULE_SCHEMA_VERSION,
    Rule,
    RuleIssue,
    RuleValidationError,
    parse_rule,
)


DEFAULT_MAX_FILE_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_RULES_PER_FILE = 256
DEFAULT_MAX_FILES = 128
_ALLOWED_SUFFIXES = {".yaml", ".yml"}


@dataclass(frozen=True)
class RuleFileResult:
    """Result for one rule source; malformed input never raises to callers."""

    schema_version: int | None
    rules: tuple[Rule, ...]
    source_path: str
    source_sha256: str | None
    source_bytes: int
    issues: tuple[RuleIssue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "rules": [rule.to_dict() for rule in self.rules],
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "source_bytes": self.source_bytes,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True)
class RuleCatalog:
    """Merged rule set and provenance from one or more rule files."""

    rules: tuple[Rule, ...]
    files: tuple[RuleFileResult, ...]
    issues: tuple[RuleIssue, ...]
    catalog_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": [rule.to_dict() for rule in self.rules],
            "files": [source.to_dict() for source in self.files],
            "issues": [issue.to_dict() for issue in self.issues],
            "catalog_sha256": self.catalog_sha256,
        }


class RuleLoader:
    """Load trusted-schema rules while treating files as untrusted input."""

    def __init__(
        self,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_rules_per_file: int = DEFAULT_MAX_RULES_PER_FILE,
        max_files: int = DEFAULT_MAX_FILES,
    ):
        if max_file_bytes <= 0 or max_rules_per_file <= 0 or max_files <= 0:
            raise ValueError("rule loader limits must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_rules_per_file = max_rules_per_file
        self.max_files = max_files

    def load_file(self, source: Any) -> RuleFileResult:
        """Load one filesystem path or importlib resource safely."""
        source_path = str(source)
        issues: list[RuleIssue] = []

        if isinstance(source, (str, Path)):
            path = Path(source)
            source_path = str(path)
            try:
                if path.is_symlink():
                    return RuleFileResult(
                        None,
                        (),
                        source_path,
                        None,
                        0,
                        (
                            RuleIssue(
                                "symlink_not_allowed",
                                "rule source symlinks are not accepted",
                                source_path,
                            ),
                        ),
                    )
            except OSError as exc:
                return RuleFileResult(
                    None,
                    (),
                    source_path,
                    None,
                    0,
                    (RuleIssue("io_error", str(exc), source_path),),
                )

        try:
            raw = source.read_bytes() if hasattr(source, "read_bytes") else Path(source).read_bytes()
        except (OSError, TypeError, ValueError) as exc:
            return RuleFileResult(
                None,
                (),
                source_path,
                None,
                0,
                (RuleIssue("io_error", str(exc), source_path),),
            )

        source_bytes = len(raw)
        if source_bytes > self.max_file_bytes:
            return RuleFileResult(
                None,
                (),
                source_path,
                None,
                source_bytes,
                (
                    RuleIssue(
                        "file_too_large",
                        f"rule file exceeds {self.max_file_bytes} bytes",
                        source_path,
                    ),
                ),
            )

        source_sha256 = hashlib.sha256(raw).hexdigest()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            return RuleFileResult(
                None,
                (),
                source_path,
                source_sha256,
                source_bytes,
                (RuleIssue("invalid_utf8", str(exc), source_path),),
            )

        try:
            self._reject_yaml_aliases(text)
            document = yaml.safe_load(text)
        except _YamlAliasRejected as exc:
            return RuleFileResult(
                None,
                (),
                source_path,
                source_sha256,
                source_bytes,
                (RuleIssue("yaml_alias_not_allowed", str(exc), source_path),),
            )
        except yaml.YAMLError as exc:
            return RuleFileResult(
                None,
                (),
                source_path,
                source_sha256,
                source_bytes,
                (RuleIssue("yaml_parse_error", str(exc), source_path),),
            )

        if not isinstance(document, dict):
            return self._failed_document(
                source_path,
                source_sha256,
                source_bytes,
                "invalid_document",
                "rule document must be a mapping",
            )
        unknown = sorted(set(document) - {"schema_version", "rules"})
        if unknown:
            return self._failed_document(
                source_path,
                source_sha256,
                source_bytes,
                "unknown_field",
                f"unknown document field(s): {', '.join(str(item) for item in unknown)}",
            )
        schema_version = document.get("schema_version")
        if isinstance(schema_version, bool) or schema_version != RULE_SCHEMA_VERSION:
            return self._failed_document(
                source_path,
                source_sha256,
                source_bytes,
                "unsupported_schema_version",
                f"expected schema_version {RULE_SCHEMA_VERSION}",
            )
        raw_rules = document.get("rules")
        if not isinstance(raw_rules, list):
            return self._failed_document(
                source_path,
                source_sha256,
                source_bytes,
                "invalid_rules",
                "rules must be a list",
            )
        if len(raw_rules) > self.max_rules_per_file:
            return self._failed_document(
                source_path,
                source_sha256,
                source_bytes,
                "too_many_rules",
                f"rule file contains more than {self.max_rules_per_file} rules",
            )

        rules: list[Rule] = []
        seen_ids: set[str] = set()
        for raw_rule in raw_rules:
            try:
                rule = parse_rule(raw_rule)
            except RuleValidationError as exc:
                issues.append(
                    RuleIssue(exc.code, str(exc), source_path, exc.rule_id)
                )
                continue
            if rule.id in seen_ids:
                issues.append(
                    RuleIssue(
                        "duplicate_rule_id",
                        f"duplicate rule id: {rule.id}",
                        source_path,
                        rule.id,
                    )
                )
                continue
            seen_ids.add(rule.id)
            rules.append(rule)

        return RuleFileResult(
            RULE_SCHEMA_VERSION,
            tuple(rules),
            source_path,
            source_sha256,
            source_bytes,
            tuple(issues),
        )

    def load(self, paths: Iterable[Any] | Any | None = None) -> RuleCatalog:
        """Discover and merge rule files, retaining all load diagnostics."""
        discovered = self.discover_rule_files(paths)
        issues: list[RuleIssue] = []
        if len(discovered) > self.max_files:
            issues.append(
                RuleIssue(
                    "too_many_files",
                    f"rule discovery returned more than {self.max_files} files",
                )
            )
            discovered = discovered[: self.max_files]

        files = tuple(self.load_file(source) for source in discovered)
        issues.extend(issue for result in files for issue in result.issues)
        rules: list[Rule] = []
        seen_ids: set[str] = set()
        for result in files:
            for rule in result.rules:
                if rule.id in seen_ids:
                    issues.append(
                        RuleIssue(
                            "duplicate_rule_id",
                            f"duplicate rule id across files: {rule.id}",
                            result.source_path,
                            rule.id,
                        )
                    )
                    continue
                seen_ids.add(rule.id)
                rules.append(rule)

        fingerprint = [
            {
                "source_path": result.source_path,
                "source_sha256": result.source_sha256,
            }
            for result in files
        ]
        catalog_sha256 = hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return RuleCatalog(tuple(rules), files, tuple(issues), catalog_sha256)

    def discover_rule_files(self, paths: Iterable[Any] | Any | None = None) -> tuple[Any, ...]:
        """Return deterministic YAML sources from paths or packaged defaults."""
        if paths is None:
            try:
                root = resources.files("core.rules.defaults")
            except (ModuleNotFoundError, FileNotFoundError):
                return ()
            return tuple(
                sorted(
                    (
                        entry
                        for entry in root.iterdir()
                        if entry.is_file() and Path(entry.name).suffix.lower() in _ALLOWED_SUFFIXES
                    ),
                    key=lambda item: item.name,
                )
            )

        if isinstance(paths, (str, Path)) or hasattr(paths, "read_bytes"):
            paths = [paths]
        discovered: list[Any] = []
        for raw_path in paths:
            path = Path(raw_path)
            if path.is_dir():
                discovered.extend(
                    item
                    for item in sorted(path.rglob("*"))
                    if item.is_file() and item.suffix.lower() in _ALLOWED_SUFFIXES
                )
            elif path.suffix.lower() in _ALLOWED_SUFFIXES:
                discovered.append(path)
        return tuple(discovered)

    @staticmethod
    def _reject_yaml_aliases(text: str) -> None:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                raise _YamlAliasRejected("YAML anchors and aliases are not supported")

    @staticmethod
    def _failed_document(
        source_path: str,
        source_sha256: str,
        source_bytes: int,
        code: str,
        message: str,
    ) -> RuleFileResult:
        return RuleFileResult(
            None,
            (),
            source_path,
            source_sha256,
            source_bytes,
            (RuleIssue(code, message, source_path),),
        )


class _YamlAliasRejected(ValueError):
    """Internal marker used to distinguish aliases from ordinary YAML errors."""
