"""Bounded parsing of OpenHarmony System Ability (SA) profiles.

OpenHarmony repositories use both JSON and legacy XML SA profile files.  This
module normalizes their common fields without loading generated code or
executing any repository content.  XML entities/DTDs are rejected explicitly
before the bounded standard-library parser is used.
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


DEFAULT_MAX_FILE_BYTES = 512 * 1024
DEFAULT_MAX_FILES = 10000
_XML_UNSAFE_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


@dataclass
class SystemAbility:
    sa_id: str
    libpath: str = ""
    run_on_create: bool | None = None
    distributed: bool | None = None
    auto_restart: bool | None = None
    dump_level: int | None = None
    extension: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sa_id": self.sa_id,
            "libpath": self.libpath,
            "run_on_create": self.run_on_create,
            "distributed": self.distributed,
            "auto_restart": self.auto_restart,
            "dump_level": self.dump_level,
            "extension": list(self.extension),
            "permissions": list(self.permissions),
        }


@dataclass
class SAProfile:
    path: str
    format: str
    process: str = ""
    system_abilities: list[SystemAbility] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "process": self.process,
            "system_abilities": [ability.to_dict() for ability in self.system_abilities],
        }


@dataclass
class SAParseResult:
    files: list[str] = field(default_factory=list)
    profiles: list[SAProfile] = field(default_factory=list)
    parse_failures: list[dict[str, str]] = field(default_factory=list)

    def extend(self, other: "SAParseResult") -> None:
        self.files.extend(other.files)
        self.profiles.extend(other.profiles)
        self.parse_failures.extend(other.parse_failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": list(self.files),
            "profiles": [profile.to_dict() for profile in self.profiles],
            "parse_failures": [dict(failure) for failure in self.parse_failures],
        }


def _normalize_relative_path(relative_path: str | Path) -> str:
    raw = str(relative_path).replace("\\", "/")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"relative path escapes repository: {relative_path}")
    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts:
        raise ValueError("relative path must not be empty")
    return "/".join(parts)


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    return None


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 10)
        except ValueError:
            return None
    return None


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [item for item in (_text(child) for child in value) if item]
    return []


def _entry_value(entry: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in entry:
            return entry[key]
    return None


def _normalize_ability(entry: dict[str, Any]) -> SystemAbility:
    permissions = _strings(
        _entry_value(entry, "permissions", "permission", "access_permission", "access-permission")
    )
    return SystemAbility(
        sa_id=_text(_entry_value(entry, "name", "sa_id", "sa-id")),
        libpath=_text(_entry_value(entry, "libpath", "lib_path", "lib-path")),
        run_on_create=_boolean(_entry_value(entry, "run-on-create", "run_on_create")),
        distributed=_boolean(_entry_value(entry, "distributed")),
        auto_restart=_boolean(_entry_value(entry, "auto-restart", "auto_restart")),
        dump_level=_integer(_entry_value(entry, "dump-level", "dump_level")),
        extension=_unique(_strings(_entry_value(entry, "extension", "extensions"))),
        permissions=_unique(permissions),
    )


def _xml_mapping(element: ET.Element) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for child in list(element):
        key = child.tag.rsplit("}", 1)[-1]
        if list(child):
            mapping[key] = [_xml_mapping(child)]
        else:
            mapping[key] = (child.text or "").strip()
    return mapping


class OpenHarmonySAProfileParser:
    """Parse JSON/XML SA profiles with bounded, fail-safe I/O."""

    def __init__(self, *, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES, max_files: int = DEFAULT_MAX_FILES):
        if max_file_bytes <= 0 or max_files <= 0:
            raise ValueError("SA profile limits must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    def parse_file(self, path: str | Path, *, relative_path: str | Path | None = None) -> SAParseResult:
        file_path = Path(path)
        relative = _normalize_relative_path(relative_path or file_path.name)
        try:
            if file_path.is_symlink():
                raise ValueError("symlink SA profile is not allowed")
            text = self._read_bounded(file_path)
        except (OSError, UnicodeError, ValueError) as exc:
            return SAParseResult(parse_failures=[{"path": relative, "reason": str(exc)}])
        return self.parse_text(relative, text)

    def parse_text(
        self,
        relative_path: str | Path,
        text: str,
        *,
        format_hint: str | None = None,
    ) -> SAParseResult:
        relative = _normalize_relative_path(relative_path)
        if len(text.encode("utf-8")) > self.max_file_bytes:
            return SAParseResult(
                parse_failures=[
                    {"path": relative, "reason": f"SA profile exceeds {self.max_file_bytes} bytes"}
                ]
            )
        selected_format = (format_hint or PurePosixPath(relative).suffix.lstrip(".")).lower()
        try:
            if selected_format == "json":
                profile = self._parse_json(relative, text)
            elif selected_format == "xml":
                profile = self._parse_xml(relative, text)
            else:
                raise ValueError("SA profile format must be json or xml")
        except (ValueError, UnicodeError, json.JSONDecodeError, ET.ParseError) as exc:
            return SAParseResult(
                parse_failures=[{"path": relative, "reason": str(exc)}]
            )
        return SAParseResult(files=[relative], profiles=[profile])

    @staticmethod
    def _parse_json(relative: str, text: str) -> SAProfile:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError("SA profile JSON must contain an object")
        raw_abilities = payload.get("systemability", payload.get("system_ability", []))
        if isinstance(raw_abilities, dict):
            raw_abilities = [raw_abilities]
        if not isinstance(raw_abilities, list):
            raise ValueError("systemability must be an object or list")
        abilities = [
            _normalize_ability(item)
            for item in raw_abilities
            if isinstance(item, dict)
        ]
        return SAProfile(
            path=relative,
            format="json",
            process=_text(payload.get("process")),
            system_abilities=abilities,
        )

    @staticmethod
    def _parse_xml(relative: str, text: str) -> SAProfile:
        if _XML_UNSAFE_RE.search(text):
            raise ValueError("XML entities and doctypes are not allowed")
        root = ET.fromstring(text)
        process = ""
        process_node = root.find(".//process")
        if process_node is not None and process_node.text:
            process = process_node.text.strip()
        abilities: list[SystemAbility] = []
        for element in root.findall(".//systemability"):
            abilities.append(_normalize_ability(_xml_mapping(element)))
        return SAProfile(
            path=relative,
            format="xml",
            process=process,
            system_abilities=abilities,
        )

    def collect(self, repository_root: str | Path) -> SAParseResult:
        root = Path(repository_root)
        if not root.is_dir() or root.is_symlink():
            return SAParseResult(
                parse_failures=[
                    {"path": str(repository_root), "reason": "repository root is not a directory"}
                ]
            )
        root_real = root.resolve()
        result = SAParseResult()
        file_count = 0
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(
                directory
                for directory in directories
                if not (current_path / directory).is_symlink()
            )
            for filename in sorted(filenames):
                if file_count >= self.max_files:
                    result.parse_failures.append(
                        {"path": ".", "reason": f"SA profile file count exceeds {self.max_files}"}
                    )
                    break
                path = current_path / filename
                if path.is_symlink() or path.suffix.lower() not in {".json", ".xml"} or not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                parts = {part.lower() for part in PurePosixPath(relative).parts[:-1]}
                if not parts.intersection({"sa_profile", "sa_profiles"}):
                    continue
                try:
                    path.resolve().relative_to(root_real)
                    text = self._read_bounded(path)
                except (OSError, UnicodeError, ValueError) as exc:
                    result.parse_failures.append({"path": relative, "reason": str(exc)})
                    continue
                result.extend(self.parse_text(relative, text))
                file_count += 1
        result.files = sorted(_unique(result.files))
        result.profiles.sort(key=lambda profile: profile.path)
        result.parse_failures.sort(key=lambda item: (item.get("path", ""), item.get("reason", "")))
        return result

    def _read_bounded(self, path: Path) -> str:
        if path.is_symlink():
            raise ValueError("symlink SA profile is not allowed")
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise ValueError(f"SA profile exceeds {self.max_file_bytes} bytes")
        return path.read_text(encoding="utf-8")


SAProfileParser = OpenHarmonySAProfileParser


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILES",
    "OpenHarmonySAProfileParser",
    "SAParseResult",
    "SAProfile",
    "SAProfileParser",
    "SystemAbility",
]
