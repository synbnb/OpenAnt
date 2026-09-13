"""Versioned, platform-neutral contracts for repository analysis.

Platform adapters populate these plain-data objects.  The generic pipeline can
carry their serialized form without importing any platform-specific module.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol


def _schema_version(payload: dict[str, Any]) -> int:
    """Return the required schema version from a decoded contract payload."""
    version = payload.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("schema_version must be a positive integer")
    return version


def _positive_schema_version(version: Any) -> None:
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("schema_version must be a positive integer")


def _nonnegative_count(name: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _list_of_dicts(name: str, value: Any) -> None:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{name} must be a list of objects")


def _list_of_nonempty_strings(name: str, value: Any) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must be a list of non-empty strings")


@dataclass
class CoverageReport:
    """Observable coverage and omission information for a platform profile."""

    schema_version: int
    discovered_files: int = 0
    eligible_files: int = 0
    parsed_files: int = 0
    unsupported_files: list[dict[str, Any]] = field(default_factory=list)
    parse_failures: list[dict[str, Any]] = field(default_factory=list)
    roles: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_schema_version(self.schema_version)
        for name in ("discovered_files", "eligible_files", "parsed_files"):
            _nonnegative_count(name, getattr(self, name))
        if self.parsed_files > self.eligible_files:
            raise ValueError("parsed_files must not exceed eligible_files")
        if self.eligible_files > self.discovered_files:
            raise ValueError("eligible_files must not exceed discovered_files")
        _list_of_dicts("unsupported_files", self.unsupported_files)
        _list_of_dicts("parse_failures", self.parse_failures)
        if not isinstance(self.roles, dict):
            raise ValueError("roles must be an object")
        for role, count in self.roles.items():
            if not isinstance(role, str) or not role:
                raise ValueError("roles keys must be non-empty strings")
            _nonnegative_count("roles values", count)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CoverageReport":
        return cls(
            schema_version=_schema_version(payload),
            discovered_files=payload.get("discovered_files", 0),
            eligible_files=payload.get("eligible_files", 0),
            parsed_files=payload.get("parsed_files", 0),
            unsupported_files=payload.get("unsupported_files", []),
            parse_failures=payload.get("parse_failures", []),
            roles=payload.get("roles", {}),
        )


@dataclass
class RepositoryProfile:
    """A normalized description of a repository on a detected platform."""

    schema_version: int
    platform: str
    detection: dict[str, Any]
    repository_root: str
    components: list[dict[str, Any]] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    coverage: CoverageReport = field(default_factory=lambda: CoverageReport(schema_version=1))
    provenance: dict[str, Any] = field(default_factory=dict)
    # Optional build-system inventory.  Empty metadata is omitted from the
    # serialized contract so generic profiles retain their previous shape.
    build_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_schema_version(self.schema_version)
        if not isinstance(self.platform, str) or not self.platform:
            raise ValueError("platform must be a non-empty string")
        if not isinstance(self.repository_root, str) or not self.repository_root:
            raise ValueError("repository_root must be a non-empty string")
        if not isinstance(self.detection, dict):
            raise ValueError("detection must be an object")
        confidence = self.detection.get("confidence")
        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not 0 <= confidence <= 1
        ):
            raise ValueError("detection confidence must be between 0 and 1")
        _list_of_nonempty_strings("detection evidence", self.detection.get("evidence"))
        _list_of_dicts("components", self.components)
        _list_of_nonempty_strings("languages", self.languages)
        _list_of_nonempty_strings("boundaries", self.boundaries)
        if not isinstance(self.coverage, CoverageReport):
            raise ValueError("coverage must be a CoverageReport")
        if self.coverage.schema_version != self.schema_version:
            raise ValueError("coverage schema_version must match profile schema_version")
        if not isinstance(self.provenance, dict):
            raise ValueError("provenance must be an object")
        if not isinstance(self.build_metadata, dict):
            raise ValueError("build_metadata must be an object")

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if not self.build_metadata:
            payload.pop("build_metadata", None)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RepositoryProfile":
        coverage_payload = payload.get("coverage", {})
        coverage = (
            coverage_payload
            if isinstance(coverage_payload, CoverageReport)
            else CoverageReport.from_dict(coverage_payload)
        )
        return cls(
            schema_version=_schema_version(payload),
            platform=payload.get("platform", "generic"),
            detection=payload.get("detection", {}),
            repository_root=payload.get("repository_root", ""),
            components=payload.get("components", []),
            languages=payload.get("languages", []),
            boundaries=payload.get("boundaries", []),
            coverage=coverage,
            provenance=payload.get("provenance", {}),
            build_metadata=payload.get("build_metadata", {}),
        )


@dataclass
class SemanticNode:
    """A node that can participate in a cross-language semantic graph."""

    schema_version: int
    id: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SemanticNode":
        return cls(
            schema_version=_schema_version(payload),
            id=payload.get("id", ""),
            kind=payload.get("kind", ""),
            attributes=payload.get("attributes", {}),
        )


@dataclass
class SemanticEdge:
    """An evidence-backed relation, including non-syntactic platform edges."""

    schema_version: int
    source_id: str
    target_id: str
    kind: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0
    resolver_version: int = 1
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SemanticEdge":
        return cls(
            schema_version=_schema_version(payload),
            source_id=payload.get("source_id", ""),
            target_id=payload.get("target_id", ""),
            kind=payload.get("kind", ""),
            evidence=payload.get("evidence", []),
            confidence=payload.get("confidence", 1.0),
            resolver_version=payload.get("resolver_version", 1),
            attributes=payload.get("attributes", {}),
        )


class PlatformProfileBuilder(Protocol):
    """Interface implemented by platform adapters in later implementation stages."""

    def build(self, repository_root: str, **kwargs: Any) -> RepositoryProfile | None:
        """Build a profile without changing the generic scanner contract."""
