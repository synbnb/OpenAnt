"""Bounded, read-only extraction of common OpenHarmony GN metadata.

GN is a programming language, not a data format.  This module intentionally
implements only a small static subset that is useful for inventory and scope
selection.  It never imports or executes repository files, evaluates GN
expressions, or invokes ``gn``.  Unsupported expressions are retained as
unknown conditions so callers can report the coverage limit explicitly.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


DEFAULT_MAX_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_TARGETS = 2048
DEFAULT_MAX_CONDITIONS = 4096
DEFAULT_MAX_DEPTH = 64
GN_SUFFIXES = frozenset({".gn", ".gni"})

_TARGET_KIND_PATTERN = (
    r"(?:group|executable|static_library|shared_library|source_set|"
    r"action|action_foreach|component|"
    r"host_[A-Za-z0-9_]+|test_group|unittest|moduletest|lite_component|"
    r"ohos_[A-Za-z0-9_]+|rust_[A-Za-z0-9_]+|generate_[A-Za-z0-9_]+)"
)
_TARGET_HEAD_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<kind>{_TARGET_KIND_PATTERN})\s*\(",
    re.MULTILINE,
)
_IF_HEAD_RE = re.compile(r"(?<![A-Za-z0-9_])if\s*\(", re.MULTILINE)
_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key>sources|deps|external_deps|defines|include_dirs)"
    r"\s*(?:\+?=)\s*\[",
    re.MULTILINE,
)
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass
class GNTarget:
    """Static metadata extracted from one GN target declaration."""

    path: str
    kind: str
    name: str
    sources: list[str] = field(default_factory=list)
    deps: list[str] = field(default_factory=list)
    external_deps: list[str] = field(default_factory=list)
    defines: list[str] = field(default_factory=list)
    include_dirs: list[str] = field(default_factory=list)
    unknown_conditions: list[str] = field(default_factory=list)

    @property
    def is_fuzz(self) -> bool:
        return self.role == "fuzz"

    @property
    def is_test(self) -> bool:
        return self.role == "test"

    @property
    def role(self) -> str:
        """Return a conservative production/test/fuzz target role."""
        path_text = f"{self.path}/{self.name}".lower().replace("\\", "/")
        parts = tuple(part for part in path_text.split("/") if part)
        name = self.name.lower()
        kind = self.kind.lower()
        if (
            "fuzz" in kind
            or "fuzz" in name
            or "fuzzer" in name
            or any(part in {"fuzz", "fuzztest", "fuzz_tests"} for part in parts)
        ):
            return "fuzz"
        if (
            "test" in kind
            or any(part in {"test", "tests", "testdata", "unittest", "unit_test", "unittests"} for part in parts)
            or name.startswith("test_")
            or name.endswith("_test")
            or name.endswith("test")
        ):
            return "test"
        return "production"

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible metadata for reports and caches."""
        return {
            "path": self.path,
            "kind": self.kind,
            "name": self.name,
            "role": self.role,
            "is_test": self.is_test,
            "is_fuzz": self.is_fuzz,
            "sources": list(self.sources),
            "deps": list(self.deps),
            "external_deps": list(self.external_deps),
            "defines": list(self.defines),
            "include_dirs": list(self.include_dirs),
            "unknown_conditions": list(self.unknown_conditions),
            "unknown_condition_count": len(self.unknown_conditions),
        }


@dataclass
class GNParseResult:
    """Result of parsing one file or a repository collection."""

    files: list[str] = field(default_factory=list)
    targets: list[GNTarget] = field(default_factory=list)
    unknown_conditions: list[str] = field(default_factory=list)
    parse_failures: list[dict[str, str]] = field(default_factory=list)

    @property
    def unknown_condition_count(self) -> int:
        return len(self.unknown_conditions)

    def extend(self, other: "GNParseResult") -> None:
        self.files.extend(other.files)
        self.targets.extend(other.targets)
        self.unknown_conditions.extend(other.unknown_conditions)
        self.parse_failures.extend(other.parse_failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": list(self.files),
            "targets": [target.to_dict() for target in self.targets],
            "unknown_conditions": list(self.unknown_conditions),
            "unknown_condition_count": self.unknown_condition_count,
            "parse_failures": [dict(item) for item in self.parse_failures],
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


def _strip_comments(text: str) -> str:
    """Remove GN comments while preserving string contents and line offsets."""
    output: list[str] = []
    index = 0
    length = len(text)
    quote: str | None = None
    escaped = False
    while index < length:
        char = text[index]
        next_char = text[index + 1] if index + 1 < length else ""
        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "#" or (char == "/" and next_char == "/"):
            output.append(" ")
            index += 1
            if char == "/":
                output.append(" ")
                index += 1
            while index < length and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 2
            while index < length:
                if text[index] == "*" and index + 1 < length and text[index + 1] == "/":
                    output.extend((" ", " "))
                    index += 2
                    break
                output.append("\n" if text[index] in "\r\n" else " ")
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _mask_strings(text: str) -> str:
    """Replace string contents with spaces, preserving all offsets/newlines."""
    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(text):
        char = text[index]
        if quote is None:
            if char in {"'", '"'}:
                quote = char
                escaped = False
                output.append(" ")
            else:
                output.append(char)
            index += 1
            continue
        if char in "\r\n":
            output.append(char)
        else:
            output.append(" ")
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            quote = None
        index += 1
    return "".join(output)


def _find_matching(text: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _read_quoted(text: str, start: int) -> tuple[str, int] | None:
    index = start
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] not in {"'", '"'}:
        return None
    quote = text[index]
    index += 1
    value: list[str] = []
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            value.append({"n": "\n", "r": "\r", "t": "\t"}.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return "".join(value), index + 1
        else:
            value.append(char)
        index += 1
    return None


def _quoted_values(text: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(text):
        parsed = _read_quoted(text, index)
        if parsed is None:
            index += 1
            continue
        value, end = parsed
        if value:
            values.append(value)
        index = end
    return values


def _normalize_condition(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text.strip())


def _conditions(text: str) -> list[str]:
    stripped = _strip_comments(text)
    masked = _mask_strings(stripped)
    values: list[str] = []
    for match in _IF_HEAD_RE.finditer(masked):
        opening = match.end() - 1
        closing = _find_matching(stripped, opening, "(", ")")
        if closing is None:
            values.append("<unbalanced>")
            continue
        values.append(_normalize_condition(stripped[opening + 1 : closing]))
    return values


def _list_assignments(original: str, masked: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {
        "sources": [],
        "deps": [],
        "external_deps": [],
        "defines": [],
        "include_dirs": [],
    }
    for match in _ASSIGNMENT_RE.finditer(masked):
        opening = match.end() - 1
        closing = _find_matching(original, opening, "[", "]")
        if closing is None:
            continue
        key = match.group("key")
        values[key].extend(_quoted_values(original[opening + 1 : closing]))
    return {key: _unique(items) for key, items in values.items()}


class OpenHarmonyGNParser:
    """Parse a bounded subset of GN without evaluating repository code."""

    def __init__(
        self,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_targets: int = DEFAULT_MAX_TARGETS,
        max_conditions: int = DEFAULT_MAX_CONDITIONS,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> None:
        for name, value in {
            "max_file_bytes": max_file_bytes,
            "max_targets": max_targets,
            "max_conditions": max_conditions,
            "max_depth": max_depth,
        }.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_targets = max_targets
        self.max_conditions = max_conditions
        self.max_depth = max_depth

    def parse_file(self, path: str | Path, *, relative_path: str | Path | None = None) -> GNParseResult:
        """Parse one already-selected GN file, returning failures as data."""
        file_path = Path(path)
        relative = _normalize_relative_path(relative_path or file_path.name)
        try:
            text = self._read_bounded(file_path)
        except (OSError, UnicodeError, ValueError) as exc:
            return GNParseResult(parse_failures=[{"path": relative, "reason": str(exc)}])
        return self.parse_text(relative, text)

    def parse_text(self, relative_path: str | Path, text: str) -> GNParseResult:
        """Parse GN text using only lexical balancing and quoted literals."""
        relative = _normalize_relative_path(relative_path)
        try:
            encoded_size = len(text.encode("utf-8"))
        except UnicodeError as exc:
            return GNParseResult(parse_failures=[{"path": relative, "reason": str(exc)}])
        if encoded_size > self.max_file_bytes:
            return GNParseResult(
                parse_failures=[
                    {
                        "path": relative,
                        "reason": f"GN file exceeds {self.max_file_bytes} bytes",
                    }
                ]
            )

        stripped = _strip_comments(text)
        masked = _mask_strings(stripped)
        conditions = _conditions(stripped)
        result = GNParseResult(files=[relative], unknown_conditions=conditions)
        if len(conditions) > self.max_conditions:
            result.parse_failures.append(
                {
                    "path": relative,
                    "reason": f"GN condition count exceeds {self.max_conditions}",
                }
            )
            result.unknown_conditions = conditions[: self.max_conditions]

        for match in _TARGET_HEAD_RE.finditer(masked):
            if len(result.targets) >= self.max_targets:
                result.parse_failures.append(
                    {
                        "path": relative,
                        "reason": f"GN target count exceeds {self.max_targets}",
                    }
                )
                break
            parsed_name = _read_quoted(stripped, match.end())
            if parsed_name is None:
                continue
            name, cursor = parsed_name
            while cursor < len(stripped) and stripped[cursor].isspace():
                cursor += 1
            if cursor >= len(stripped) or stripped[cursor] != ")":
                continue
            cursor += 1
            while cursor < len(stripped) and stripped[cursor].isspace():
                cursor += 1
            if cursor >= len(stripped) or stripped[cursor] != "{":
                continue
            closing = _find_matching(stripped, cursor, "{", "}")
            if closing is None:
                result.parse_failures.append(
                    {"path": relative, "reason": f"unbalanced target block: {name}"}
                )
                continue
            original_block = stripped[cursor + 1 : closing]
            masked_block = masked[cursor + 1 : closing]
            assignments = _list_assignments(original_block, masked_block)
            target = GNTarget(
                path=relative,
                kind=match.group("kind"),
                name=name,
                sources=assignments["sources"],
                deps=assignments["deps"],
                external_deps=assignments["external_deps"],
                defines=assignments["defines"],
                include_dirs=assignments["include_dirs"],
                unknown_conditions=_conditions(original_block),
            )
            result.targets.append(target)

        return result

    def collect(self, repository_root: str | Path) -> GNParseResult:
        """Collect ``.gn``/``.gni`` files beneath a root without following symlinks."""
        root = Path(repository_root)
        if not root.is_dir() or root.is_symlink():
            return GNParseResult(
                parse_failures=[
                    {"path": str(repository_root), "reason": "repository root is not a directory"}
                ]
            )
        root_real = root.resolve()
        result = GNParseResult()
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            try:
                current_relative = current_path.relative_to(root).as_posix()
            except ValueError:
                directories[:] = []
                continue
            depth = 0 if current_relative == "." else len(PurePosixPath(current_relative).parts)
            directories[:] = sorted(
                directory
                for directory in directories
                if not (current_path / directory).is_symlink() and depth + 1 <= self.max_depth
            )
            for filename in sorted(filenames):
                path = current_path / filename
                if path.is_symlink() or path.suffix.lower() not in GN_SUFFIXES or not path.is_file():
                    continue
                try:
                    relative = path.relative_to(root).as_posix()
                    path.resolve().relative_to(root_real)
                    text = self._read_bounded(path)
                except (OSError, UnicodeError, ValueError) as exc:
                    result.parse_failures.append({"path": path.relative_to(root).as_posix(), "reason": str(exc)})
                    continue
                parsed = self.parse_text(relative, text)
                result.extend(parsed)

        result.files = sorted(_unique(result.files))
        result.targets.sort(key=lambda target: (target.path, target.name, target.kind))
        result.unknown_conditions = list(result.unknown_conditions)
        result.parse_failures.sort(key=lambda item: (item.get("path", ""), item.get("reason", "")))
        return result

    def _read_bounded(self, path: Path) -> str:
        if path.is_symlink():
            raise ValueError("symlink GN file is not allowed")
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise ValueError(f"GN file exceeds {self.max_file_bytes} bytes")
        return path.read_text(encoding="utf-8")


# Short alias for callers that use the generic parser naming convention.
GNParser = OpenHarmonyGNParser


__all__ = [
    "DEFAULT_MAX_CONDITIONS",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_TARGETS",
    "GNParseResult",
    "GNParser",
    "GNTarget",
    "OpenHarmonyGNParser",
]
