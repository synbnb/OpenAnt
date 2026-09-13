"""Bounded, read-only extraction of OpenHarmony IDL contracts.

OpenHarmony IDL describes IPC interfaces and parcelable data types.  The
parser intentionally operates on a small lexical subset: it records interface
methods, parameter directions and type declarations without invoking an IDL
compiler or executing any repository-provided code.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


DEFAULT_MAX_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_FILES = 10000
DEFAULT_MAX_INTERFACES = 2048
DEFAULT_MAX_METHODS = 20000

_PACKAGE_RE = re.compile(r"\bpackage\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;", re.MULTILINE)
_IMPORT_RE = re.compile(r"\bimport\s+([A-Za-z_][A-Za-z0-9_./]*)\s*;", re.MULTILINE)
_SEQUENCEABLE_RE = re.compile(
    r"\bsequenceable\s+([A-Za-z_][A-Za-z0-9_.]*(?:\.\.[A-Za-z_][A-Za-z0-9_.]*)?)\s*;",
    re.MULTILINE,
)
_INTERFACE_RE = re.compile(
    r"\binterface\s+([A-Za-z_][A-Za-z0-9_.]*)\s*(?P<terminator>[;{])",
    re.MULTILINE,
)
_ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\{", re.MULTILINE)
_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\{", re.MULTILINE)
_METHOD_PREFIX_RE = re.compile(
    r"(?P<return>[A-Za-z_][A-Za-z0-9_.,<>\[\]]*(?:\s+[A-Za-z_][A-Za-z0-9_.,<>\[\]]*)*)"
    r"\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)$"
)
_METHOD_ANNOTATION_RE = re.compile(
    r"^\[\s*(?P<value>[^\]]+?)\s*\]\s*"
)
_IPCCODE_RE = re.compile(r"^ipccode\s+(?P<code>[0-9]+)$", re.IGNORECASE)
_PARAM_RE = re.compile(r"(?P<type>.+?)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)$")
_DIRECTION_RE = re.compile(r"^\[\s*(?P<direction>inout|in|out)\s*\]\s*", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass
class IDLParameter:
    direction: str
    type: str
    name: str
    line: int
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction,
            "type": self.type,
            "name": self.name,
            "line": self.line,
            "path": self.path,
        }


@dataclass
class IDLMethod:
    name: str
    return_type: str
    parameters: list[IDLParameter] = field(default_factory=list)
    line: int = 0
    path: str = ""
    interface: str = ""
    annotations: list[str] = field(default_factory=list)
    ipc_code: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "return_type": self.return_type,
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "annotations": list(self.annotations),
            "ipc_code": self.ipc_code,
            "line": self.line,
            "path": self.path,
            "interface": self.interface,
        }


@dataclass
class IDLInterface:
    name: str
    methods: list[IDLMethod] = field(default_factory=list)
    line: int = 0
    path: str = ""
    forward_declaration: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "methods": [method.to_dict() for method in self.methods],
            "line": self.line,
            "path": self.path,
            "forward_declaration": self.forward_declaration,
        }


@dataclass
class IDLField:
    type: str
    name: str
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "name": self.name, "line": self.line}


@dataclass
class IDLTypeDeclaration:
    kind: str
    name: str
    fields: list[IDLField] = field(default_factory=list)
    values: list[str] = field(default_factory=list)
    line: int = 0
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "fields": [field.to_dict() for field in self.fields],
            "values": list(self.values),
            "line": self.line,
            "path": self.path,
        }


@dataclass
class IDLParseResult:
    path: str = ""
    files: list[str] = field(default_factory=list)
    package: str = ""
    imports: list[str] = field(default_factory=list)
    sequenceables: list[str] = field(default_factory=list)
    interfaces: list[IDLInterface] = field(default_factory=list)
    enums: list[IDLTypeDeclaration] = field(default_factory=list)
    structs: list[IDLTypeDeclaration] = field(default_factory=list)
    parse_failures: list[dict[str, str]] = field(default_factory=list)

    def extend(self, other: "IDLParseResult") -> None:
        self.files.extend(other.files)
        if not self.package:
            self.package = other.package
        self.imports = _unique((*self.imports, *other.imports))
        self.sequenceables = _unique((*self.sequenceables, *other.sequenceables))
        self.interfaces.extend(other.interfaces)
        self.enums.extend(other.enums)
        self.structs.extend(other.structs)
        self.parse_failures.extend(other.parse_failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "files": list(self.files),
            "package": self.package,
            "imports": list(self.imports),
            "sequenceables": list(self.sequenceables),
            "interfaces": [interface.to_dict() for interface in self.interfaces],
            "enums": [declaration.to_dict() for declaration in self.enums],
            "structs": [declaration.to_dict() for declaration in self.structs],
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


def _strip_comments(text: str) -> str:
    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
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
            while index < len(text) and text[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            output.extend((" ", " "))
            index += 2
            while index < len(text):
                if text[index] == "*" and index + 1 < len(text) and text[index + 1] == "/":
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
        output.append(char if char in "\r\n" else " ")
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
        elif char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _normalize_space(value: str) -> str:
    return _WHITESPACE_RE.sub(" ", value.strip())


def _split_top_level(value: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    angle = square = paren = 0
    for index, char in enumerate(value):
        if char == "<":
            angle += 1
        elif char == ">" and angle:
            angle -= 1
        elif char == "[":
            square += 1
        elif char == "]" and square:
            square -= 1
        elif char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == delimiter and angle == square == paren == 0:
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return parts


def _parse_parameters(text: str, *, path: str, source: str, offset: int) -> list[IDLParameter]:
    parameters: list[IDLParameter] = []
    for item in _split_top_level(text):
        raw = _normalize_space(item)
        if not raw:
            continue
        direction_match = _DIRECTION_RE.match(raw)
        direction = direction_match.group("direction").lower() if direction_match else "in"
        if direction_match:
            raw = _normalize_space(raw[direction_match.end() :])
        match = _PARAM_RE.match(raw)
        if match is None:
            continue
        parameters.append(
            IDLParameter(
                direction=direction,
                type=_normalize_space(match.group("type")),
                name=match.group("name"),
                line=_line_number(source, offset),
                path=path,
            )
        )
    return parameters


def _parse_method_annotations(prefix: str) -> tuple[str, list[str], int | None]:
    """Remove method annotations and extract the optional numeric IPC code."""
    remaining = prefix.lstrip()
    annotations: list[str] = []
    ipc_code: int | None = None
    while remaining.startswith("["):
        match = _METHOD_ANNOTATION_RE.match(remaining)
        if match is None:
            break
        annotation = _normalize_space(match.group("value"))
        if not annotation:
            break
        annotations.append(annotation)
        code_match = _IPCCODE_RE.fullmatch(annotation)
        if code_match is not None and ipc_code is None:
            ipc_code = int(code_match.group("code"))
        remaining = remaining[match.end() :].lstrip()
    return remaining, annotations, ipc_code


def _parse_methods(body: str, *, path: str, source: str, offset: int, interface: str) -> list[IDLMethod]:
    methods: list[IDLMethod] = []
    masked = _mask_strings(body)
    statement_start = 0
    index = 0
    while index < len(body):
        char = masked[index]
        if char == "(":
            closing = _find_matching(body, index, "(", ")")
            if closing is None:
                break
            cursor = closing + 1
            while cursor < len(body) and body[cursor].isspace():
                cursor += 1
            if cursor >= len(body) or body[cursor] != ";":
                index = closing + 1
                continue
            prefix = _normalize_space(body[statement_start:index])
            prefix, annotations, ipc_code = _parse_method_annotations(prefix)
            match = _METHOD_PREFIX_RE.match(prefix)
            if match is not None:
                absolute = offset + statement_start
                methods.append(
                    IDLMethod(
                        name=match.group("name"),
                        return_type=_normalize_space(match.group("return")),
                        parameters=_parse_parameters(
                            body[index + 1 : closing],
                            path=path,
                            source=source,
                            offset=offset + index + 1,
                        ),
                        annotations=annotations,
                        ipc_code=ipc_code,
                        line=_line_number(source, absolute),
                        path=path,
                        interface=interface,
                    )
                )
            statement_start = cursor + 1
            index = cursor + 1
            continue
        if char == ";":
            statement_start = index + 1
        index += 1
    return methods


def _parse_fields(body: str, *, source: str, offset: int) -> list[IDLField]:
    fields: list[IDLField] = []
    for item in body.split(";"):
        raw = _normalize_space(item)
        if not raw:
            continue
        match = _PARAM_RE.match(raw)
        if match is None:
            continue
        fields.append(
            IDLField(
                type=_normalize_space(match.group("type")),
                name=match.group("name"),
                line=_line_number(source, offset),
            )
        )
    return fields


class OpenHarmonyIDLParser:
    """Parse common OpenHarmony IDL declarations without code execution."""

    def __init__(
        self,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
        max_interfaces: int = DEFAULT_MAX_INTERFACES,
        max_methods: int = DEFAULT_MAX_METHODS,
    ) -> None:
        for name, value in {
            "max_file_bytes": max_file_bytes,
            "max_files": max_files,
            "max_interfaces": max_interfaces,
            "max_methods": max_methods,
        }.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.max_interfaces = max_interfaces
        self.max_methods = max_methods

    def parse_file(self, path: str | Path, *, relative_path: str | Path | None = None) -> IDLParseResult:
        file_path = Path(path)
        relative = _normalize_relative_path(relative_path or file_path.name)
        try:
            if file_path.is_symlink():
                raise ValueError("symlink IDL file is not allowed")
            text = self._read_bounded(file_path)
        except (OSError, UnicodeError, ValueError) as exc:
            return IDLParseResult(path=relative, parse_failures=[{"path": relative, "reason": str(exc)}])
        return self.parse_text(relative, text)

    def parse_text(self, relative_path: str | Path, text: str) -> IDLParseResult:
        relative = _normalize_relative_path(relative_path)
        if len(text.encode("utf-8")) > self.max_file_bytes:
            return IDLParseResult(
                path=relative,
                parse_failures=[
                    {"path": relative, "reason": f"IDL file exceeds {self.max_file_bytes} bytes"}
                ],
            )

        stripped = _strip_comments(text)
        masked = _mask_strings(stripped)
        result = IDLParseResult(path=relative, files=[relative])
        package_match = _PACKAGE_RE.search(masked)
        if package_match:
            result.package = package_match.group(1)
        result.imports = _unique(match.group(1) for match in _IMPORT_RE.finditer(masked))
        result.sequenceables = _unique(match.group(1) for match in _SEQUENCEABLE_RE.finditer(masked))

        for match in _ENUM_RE.finditer(masked):
            closing = _find_matching(stripped, match.end() - 1, "{", "}")
            if closing is None:
                result.parse_failures.append(
                    {"path": relative, "reason": f"unbalanced enum block: {match.group(1)}"}
                )
                continue
            values = [
                _normalize_space(item)
                for item in _split_top_level(stripped[match.end() : closing])
                if _normalize_space(item)
            ]
            result.enums.append(
                IDLTypeDeclaration(
                    kind="enum",
                    name=match.group(1),
                    values=values,
                    line=_line_number(text, match.start()),
                    path=relative,
                )
            )

        for match in _STRUCT_RE.finditer(masked):
            closing = _find_matching(stripped, match.end() - 1, "{", "}")
            if closing is None:
                result.parse_failures.append(
                    {"path": relative, "reason": f"unbalanced struct block: {match.group(1)}"}
                )
                continue
            result.structs.append(
                IDLTypeDeclaration(
                    kind="struct",
                    name=match.group(1),
                    fields=_parse_fields(stripped[match.end() : closing], source=text, offset=match.end()),
                    line=_line_number(text, match.start()),
                    path=relative,
                )
            )

        interfaces: dict[str, IDLInterface] = {}
        interface_order: list[str] = []
        for match in _INTERFACE_RE.finditer(masked):
            name = match.group(1)
            line = _line_number(text, match.start())
            if match.group("terminator") == ";":
                interface = interfaces.get(name)
                if interface is None:
                    interfaces[name] = IDLInterface(
                        name=name, line=line, path=relative, forward_declaration=True
                    )
                    interface_order.append(name)
                continue
            if len(interface_order) >= self.max_interfaces and name not in interfaces:
                result.parse_failures.append(
                    {
                        "path": relative,
                        "reason": f"IDL interface count exceeds {self.max_interfaces}",
                    }
                )
                break
            opening = match.end() - 1
            closing = _find_matching(stripped, opening, "{", "}")
            if closing is None:
                result.parse_failures.append(
                    {"path": relative, "reason": f"unbalanced interface block: {name}"}
                )
                continue
            body = stripped[opening + 1 : closing]
            methods = _parse_methods(
                body,
                path=relative,
                source=text,
                offset=opening + 1,
                interface=name,
            )
            if sum(len(item.methods) for item in interfaces.values()) + len(methods) > self.max_methods:
                result.parse_failures.append(
                    {"path": relative, "reason": f"IDL method count exceeds {self.max_methods}"}
                )
                methods = methods[: max(0, self.max_methods - sum(len(item.methods) for item in interfaces.values()))]
            interface = interfaces.get(name)
            if interface is None:
                interfaces[name] = IDLInterface(
                    name=name,
                    methods=methods,
                    line=line,
                    path=relative,
                    forward_declaration=False,
                )
                interface_order.append(name)
            else:
                interface.methods = methods
                interface.line = line
                interface.path = relative
                interface.forward_declaration = False

        result.interfaces = [interfaces[name] for name in interface_order]
        return result

    def collect(self, repository_root: str | Path) -> IDLParseResult:
        root = Path(repository_root)
        if not root.is_dir() or root.is_symlink():
            return IDLParseResult(
                parse_failures=[
                    {"path": str(repository_root), "reason": "repository root is not a directory"}
                ]
            )
        root_real = root.resolve()
        result = IDLParseResult()
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
                        {"path": ".", "reason": f"IDL file count exceeds {self.max_files}"}
                    )
                    break
                path = current_path / filename
                if path.is_symlink() or path.suffix.lower() != ".idl" or not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                try:
                    path.resolve().relative_to(root_real)
                    text = self._read_bounded(path)
                except (OSError, UnicodeError, ValueError) as exc:
                    result.parse_failures.append({"path": relative, "reason": str(exc)})
                    continue
                result.extend(self.parse_text(relative, text))
                file_count += 1
        result.files = sorted(_unique(result.files))
        result.interfaces.sort(key=lambda interface: (interface.path, interface.name))
        result.enums.sort(key=lambda declaration: (declaration.path, declaration.name))
        result.structs.sort(key=lambda declaration: (declaration.path, declaration.name))
        result.parse_failures.sort(key=lambda item: (item.get("path", ""), item.get("reason", "")))
        return result

    def _read_bounded(self, path: Path) -> str:
        if path.is_symlink():
            raise ValueError("symlink IDL file is not allowed")
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise ValueError(f"IDL file exceeds {self.max_file_bytes} bytes")
        return path.read_text(encoding="utf-8")


IDLParser = OpenHarmonyIDLParser


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_INTERFACES",
    "DEFAULT_MAX_METHODS",
    "IDLField",
    "IDLInterface",
    "IDLMethod",
    "IDLParameter",
    "IDLParseResult",
    "IDLParser",
    "IDLTypeDeclaration",
    "OpenHarmonyIDLParser",
]
