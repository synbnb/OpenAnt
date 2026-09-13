"""Safe, read-only parsing of OpenHarmony ``bundle.json`` manifests.

The manifest is treated as untrusted repository input.  This module only reads
bounded JSON files, keeps all reported paths repository-relative, and records a
parse failure instead of allowing one malformed component to abort discovery of
the remaining components.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


MAX_BUNDLE_BYTES = 1024 * 1024
MAX_BUNDLE_FILES = 10000


def _relative_path(root: Path, path: Path) -> str:
    """Return a safe POSIX path relative to *root* or raise ``ValueError``."""
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("manifest path escapes repository") from exc
    result = PurePosixPath(relative.as_posix())
    if result.is_absolute() or ".." in result.parts:
        raise ValueError("manifest path escapes repository")
    return result.as_posix()


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value else ()
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _target_names(value: Any) -> tuple[str, ...]:
    """Normalize nested bundle build groups containing names or named objects."""
    names: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, str) and item:
            names.append(item)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif isinstance(item, dict):
            named = item.get("name")
            if isinstance(named, str) and named:
                names.append(named)
            else:
                for child in item.values():
                    visit(child)

    visit(value)
    return _unique(names)


@dataclass(frozen=True)
class BundleManifest:
    """Normalized component information from one ``bundle.json`` file."""

    path: str
    package_name: str = ""
    component_name: str = ""
    subsystem: str = ""
    syscaps: tuple[str, ...] = ()
    system_types: tuple[str, ...] = ()
    build_targets: tuple[str, ...] = ()
    test_targets: tuple[str, ...] = ()
    inner_kits: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    third_party_dependencies: tuple[str, ...] = ()

    def to_component(self) -> dict[str, Any]:
        """Return the platform-neutral component shape used by RepositoryProfile."""
        return {
            "manifest_path": self.path,
            "package_name": self.package_name,
            "name": self.component_name,
            "subsystem": self.subsystem,
            "syscaps": list(self.syscaps),
            "system_types": list(self.system_types),
            "build_targets": list(self.build_targets),
            "test_targets": list(self.test_targets),
            "inner_kits": list(self.inner_kits),
            "dependencies": list(self.dependencies),
            "third_party_dependencies": list(self.third_party_dependencies),
        }


@dataclass
class BundleManifestInventory:
    """All valid manifests and bounded parse failures found under a repository."""

    manifests: list[BundleManifest] = field(default_factory=list)
    parse_failures: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": [manifest.to_component() for manifest in self.manifests],
            "parse_failures": list(self.parse_failures),
        }


def parse_bundle_manifest(relative_path: str, text: str) -> BundleManifest:
    """Parse one JSON document into a normalized manifest.

    The function deliberately accepts manifests with missing optional fields;
    the profile detector decides whether the resulting component is strong
    enough platform evidence.
    """
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("bundle.json must contain a JSON object")

    raw_component = payload.get("component")
    component = raw_component if isinstance(raw_component, dict) else {}
    raw_module = payload.get("module")
    module = raw_module if isinstance(raw_module, dict) else {}
    package_name = payload.get("name") if isinstance(payload.get("name"), str) else ""

    component_name = ""
    for candidate in (component.get("name"), module.get("name")):
        if isinstance(candidate, str) and candidate:
            component_name = candidate
            break
    if not component_name and package_name and not package_name.startswith("@"):
        component_name = package_name

    deps = component.get("deps")
    deps = deps if isinstance(deps, dict) else {}
    build = component.get("build")
    build = build if isinstance(build, dict) else {}

    inner_kits: list[str] = []
    for item in build.get("inner_kits", []):
        if isinstance(item, str) and item:
            inner_kits.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
            inner_kits.append(item["name"])

    return BundleManifest(
        path=relative_path,
        package_name=package_name,
        component_name=component_name,
        subsystem=component.get("subsystem", "")
        if isinstance(component.get("subsystem", ""), str)
        else "",
        syscaps=_unique(
            (*_strings(component.get("syscap")), *_strings(component.get("syscaps")))
        ),
        system_types=_unique(
            (
                *_strings(component.get("adapted_system_type")),
                *_strings(component.get("system_types")),
            )
        ),
        build_targets=_unique(
            (
                *_target_names(build.get("sub_component", [])),
                *_target_names(build.get("sub_components", [])),
                *_target_names(build.get("group_type", {})),
                *_target_names(build.get("targets", [])),
            )
        ),
        test_targets=_target_names(build.get("test", [])),
        inner_kits=_unique(inner_kits),
        dependencies=_unique(_strings(deps.get("components"))),
        third_party_dependencies=_unique(
            (*_strings(deps.get("third_party")), *_strings(deps.get("third_party_components")))
        ),
    )


class BundleManifestReader:
    """Discover and parse bundle manifests without executing repository code."""

    def __init__(
        self,
        repository_root: str | Path,
        *,
        max_bytes: int = MAX_BUNDLE_BYTES,
        max_files: int = MAX_BUNDLE_FILES,
    ) -> None:
        if max_bytes <= 0 or max_files <= 0:
            raise ValueError("manifest limits must be positive")
        self.repository_root = Path(repository_root).resolve()
        self.max_bytes = max_bytes
        self.max_files = max_files

    def _candidates(self) -> list[Path]:
        root = self.repository_root
        if not root.is_dir():
            return []
        candidates: list[Path] = []
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            dirpath = Path(directory)
            dirnames[:] = [name for name in dirnames if not (dirpath / name).is_symlink()]
            if "bundle.json" not in {name.lower() for name in filenames}:
                continue
            for filename in filenames:
                if filename.lower() != "bundle.json":
                    continue
                path = dirpath / filename
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    _relative_path(root, path)
                except ValueError:
                    continue
                candidates.append(path)
        return sorted(candidates, key=lambda path: _relative_path(root, path))[: self.max_files]

    def collect(self) -> BundleManifestInventory:
        inventory = BundleManifestInventory()
        for path in self._candidates():
            relative = _relative_path(self.repository_root, path)
            try:
                if path.stat().st_size > self.max_bytes:
                    raise ValueError(f"manifest exceeds {self.max_bytes} bytes")
                text = path.read_text(encoding="utf-8")
                inventory.manifests.append(parse_bundle_manifest(relative, text))
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                reason = str(exc).replace(str(path), relative)
                inventory.parse_failures.append({"path": relative, "reason": reason})
        return inventory
