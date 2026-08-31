"""Extract auditable integer evidence for OpenHarmony dispatch selectors.

The call-graph diagnostics already tell us that a dispatch table connects a
selector to a candidate handler.  This module adds the missing value layer:
it resolves simple C/C++ integer constants (enum members, macros, and
``constexpr``/``const`` definitions) without guessing when a symbol is
ambiguous or unsupported.

The result is an independent evidence artifact.  It is deliberately not a
call-graph mutator and does not execute a transaction against a device.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_INTEGER_SUFFIX = re.compile(
    r"(?P<number>0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|[0-9]+)"
    r"(?P<suffix>[uUlL]+)\b"
)
_CONST_DECLARATION = re.compile(
    rf"\b(?:(?:static|inline|extern|volatile|mutable)\s+)*"
    rf"(?:constexpr|const)\s+[^;\n=]*?\b(?P<name>{_IDENTIFIER})\s*"
    rf"=\s*(?P<expression>[^;\n,]+)"
)
_MACRO_DECLARATION = re.compile(
    rf"^\s*#\s*define\s+(?P<name>{_IDENTIFIER})(?!\s*\()"
    rf"\s+(?P<expression>.+?)\s*$",
    re.MULTILINE,
)
_ENUM_START = re.compile(
    rf"\benum(?:\s+(?:class|struct)\s+)?(?P<name>{_IDENTIFIER})?\s*\{{"
)
_ENUMERATOR = re.compile(
    rf"^(?P<name>{_IDENTIFIER})\s*(?:=\s*(?P<expression>.*))?$",
    re.DOTALL,
)


@dataclass(frozen=True)
class _Definition:
    symbol: str
    expression: str | None
    kind: str
    file: str
    line: int
    text: str


@dataclass(frozen=True)
class _Resolution:
    value: int | None
    state: str
    definitions: tuple[_Definition, ...] = ()


def _strip_comments(source: str) -> str:
    """Remove comments while preserving line numbers."""

    def preserve_lines(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    source = re.sub(r"/\*.*?\*/", preserve_lines, source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, max(0, offset)) + 1


def _line_text(source: str, line: int) -> str:
    lines = source.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def _split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
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
        elif char in "([{<":
            depth += 1
        elif char in ")]}>" and depth:
            depth -= 1
        elif char == delimiter and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 1
    quote: str | None = None
    escaped = False
    for index in range(opening, len(source)):
        char = source[index]
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
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _collect_definitions(source_files: Iterable[tuple[str, str]]) -> dict[str, list[_Definition]]:
    definitions: dict[str, list[_Definition]] = {}
    for file_path, original in source_files:
        cleaned = _strip_comments(original)
        lines = original.splitlines()

        def add(
            symbol: str,
            expression: str | None,
            kind: str,
            line: int,
            text: str | None = None,
        ) -> None:
            symbol = symbol.strip()
            if not symbol:
                return
            definition = _Definition(
                symbol=symbol,
                expression=expression.strip() if expression else None,
                kind=kind,
                file=file_path,
                line=max(1, line),
                text=(text or (lines[line - 1].strip() if 0 < line <= len(lines) else "")),
            )
            definitions.setdefault(symbol, []).append(definition)

        for match in _MACRO_DECLARATION.finditer(cleaned):
            expression = match.group("expression").strip()
            if expression.endswith("\\"):
                expression = expression[:-1].rstrip()
            add(
                match.group("name"),
                expression,
                "macro",
                _line_number(cleaned, match.start()),
            )

        for match in _CONST_DECLARATION.finditer(cleaned):
            line = _line_number(cleaned, match.start())
            add(
                match.group("name"),
                match.group("expression"),
                "constant",
                line,
            )

        for enum_match in _ENUM_START.finditer(cleaned):
            closing = _matching_brace(cleaned, enum_match.end() - 1)
            if closing is None:
                continue
            enum_name = (enum_match.group("name") or "").strip()
            body = cleaned[enum_match.end():closing]
            current_value: int | None = None
            for raw_entry in _split_top_level(body):
                entry = raw_entry.strip()
                if not entry:
                    continue
                enumerator = _ENUMERATOR.match(entry)
                if enumerator is None:
                    continue
                name = enumerator.group("name")
                explicit = enumerator.group("expression")
                if explicit is None:
                    expression = str(current_value + 1) if current_value is not None else "0"
                else:
                    expression = explicit.strip()
                raw_offset = body.find(raw_entry)
                line_offset = enum_match.end() + raw_offset + (
                    len(raw_entry) - len(raw_entry.lstrip())
                )
                line = _line_number(cleaned, line_offset)
                add(name, expression, "enum", line, entry)
                if enum_name:
                    add(f"{enum_name}::{name}", expression, "enum", line, entry)
                current_value = _literal_value(expression)
                if current_value is None and explicit is not None:
                    # A later implicit member must not be guessed when the
                    # explicit expression itself was not a simple integer.
                    current_value = None
    return definitions


def _literal_value(expression: str | None) -> int | None:
    if not expression:
        return None
    value = _normalise_expression(expression)
    if not re.fullmatch(r"[+-]?(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|[0-9]+)", value):
        return None
    try:
        sign = -1 if value.startswith("-") else 1
        unsigned = value[1:] if value[:1] in "+-" else value
        return sign * int(unsigned, 0)
    except ValueError:
        return None


def _normalise_expression(expression: str) -> str:
    value = expression.strip()
    # Remove common C++ cast wrappers while retaining the enclosed expression.
    previous = None
    while value != previous:
        previous = value
        value = re.sub(
            r"\b(?:static_cast|reinterpret_cast|const_cast|dynamic_cast)\s*<[^<>]*>\s*\(([^()]*)\)",
            r"(\1)",
            value,
        )
    value = _INTEGER_SUFFIX.sub(r"\g<number>", value)
    return value.replace("::", "__")


def _evaluate_expression(
    expression: str | None,
    resolve_symbol: Callable[[str, tuple[str, ...]], _Resolution],
    stack: tuple[str, ...],
) -> int | None:
    if not expression:
        return None
    normalised = _normalise_expression(expression)
    try:
        tree = ast.parse(normalised, mode="eval")
    except (SyntaxError, ValueError):
        return None

    def evaluate(node: ast.AST, depth: int = 0) -> int | None:
        if depth > 64:
            return None
        if isinstance(node, ast.Expression):
            return evaluate(node.body, depth + 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            return int(node.value)
        if isinstance(node, ast.Name):
            resolution = resolve_symbol(node.id.replace("__", "::"), stack)
            return resolution.value if resolution.state == "resolved" else None
        if isinstance(node, ast.UnaryOp):
            operand = evaluate(node.operand, depth + 1)
            if operand is None:
                return None
            if isinstance(node.op, ast.UAdd):
                return operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.Invert):
                return ~operand
            return None
        if isinstance(node, ast.BinOp):
            left = evaluate(node.left, depth + 1)
            right = evaluate(node.right, depth + 1)
            if left is None or right is None:
                return None
            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return int(left / right)
                if isinstance(node.op, ast.FloorDiv):
                    return left // right
                if isinstance(node.op, ast.Mod):
                    return left % right
                if isinstance(node.op, ast.LShift):
                    return left << right
                if isinstance(node.op, ast.RShift):
                    return left >> right
                if isinstance(node.op, ast.BitOr):
                    return left | right
                if isinstance(node.op, ast.BitAnd):
                    return left & right
                if isinstance(node.op, ast.BitXor):
                    return left ^ right
            except (ArithmeticError, ValueError):
                return None
        return None

    return evaluate(tree)


def _resolve_definitions(
    definitions: Mapping[str, list[_Definition]],
) -> Callable[[str, tuple[str, ...]], _Resolution]:
    cache: dict[str, _Resolution] = {}

    def resolve(symbol: str, stack: tuple[str, ...] = ()) -> _Resolution:
        symbol = symbol.strip()
        if symbol in cache and not stack:
            return cache[symbol]
        if not symbol or symbol in stack:
            return _Resolution(None, "unresolved_symbol")
        candidates = list(definitions.get(symbol, []))
        if not candidates and "::" in symbol:
            candidates = list(definitions.get(symbol.rsplit("::", 1)[-1], []))
        if not candidates:
            return _Resolution(None, "unresolved_symbol")

        resolved_values: list[int] = []
        usable_definitions: list[_Definition] = []
        unresolved_definition = False
        for definition in candidates:
            value = _evaluate_expression(
                definition.expression,
                resolve,
                (*stack, symbol),
            )
            if value is None:
                unresolved_definition = True
                continue
            resolved_values.append(value)
            usable_definitions.append(definition)

        unique_values = set(resolved_values)
        if len(unique_values) > 1 or (unresolved_definition and unique_values):
            result = _Resolution(None, "ambiguous_symbol", tuple(candidates))
        elif len(unique_values) == 1:
            result = _Resolution(
                next(iter(unique_values)),
                "resolved",
                tuple(usable_definitions or candidates),
            )
        else:
            result = _Resolution(None, "unresolved_symbol", tuple(candidates))
        if not stack:
            cache[symbol] = result
        return result

    return resolve


def _source_files(
    repository: str | Path | None,
    provided: Mapping[str, str] | None,
    *,
    max_files: int,
    max_file_bytes: int,
) -> tuple[list[tuple[str, str]], list[str]]:
    if provided is not None:
        return (
            sorted(
                (str(path), str(source))
                for path, source in provided.items()
                if isinstance(path, str) and isinstance(source, str)
            ),
            [],
        )
    if repository is None:
        return [], ["source repository was not provided"]

    root = Path(repository).expanduser().resolve()
    if not root.is_dir():
        return [], [f"source repository is not a directory: {root}"]
    files: list[tuple[str, str]] = []
    errors: list[str] = []
    for path in sorted(root.rglob("*")):
        if len(files) >= max_files:
            errors.append(f"source file limit reached: {max_files}")
            break
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                errors.append(f"skipped oversized source file: {path.relative_to(root)}")
                continue
            files.append((str(path.relative_to(root)), path.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            errors.append(f"could not read {path.relative_to(root)}: {exc}")
    return files, errors


def _normalise_evidence(raw: Any, kind: str) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    record: dict[str, Any] = {"kind": kind}
    for key in ("file", "start_line", "end_line", "text"):
        if key in raw:
            record[key] = raw[key]
    return record


def _site_id(site: Mapping[str, Any], dispatch_kind: str) -> str:
    explicit = site.get("site_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    seed = "|".join(
        str(site.get(key, ""))
        for key in ("caller_id", "file", "line", "expression")
    )
    return f"{dispatch_kind}:{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"


def build_dispatch_code_evidence(
    diagnostics: Mapping[str, Any],
    repository: str | Path | None = None,
    *,
    source_files: Mapping[str, str] | None = None,
    max_files: int = 20_000,
    max_file_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Build a JSON-serialisable dispatch selector/value evidence report.

    ``source_files`` is an in-memory seam for tests and integrations that
    already loaded a repository.  Production callers should pass ``repository``;
    only C/C++ source and header files under that directory are read.
    """
    files, errors = _source_files(
        repository,
        source_files,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
    )
    definitions = _collect_definitions(files)
    resolve = _resolve_definitions(definitions)

    raw_sites: list[tuple[str, Mapping[str, Any]]] = []
    ordinary = diagnostics.get("unresolved_call_sites", []) if isinstance(diagnostics, Mapping) else []
    if isinstance(ordinary, list):
        raw_sites.extend(
            ("native", item) for item in ordinary if isinstance(item, Mapping)
        )
    lambda_payload = diagnostics.get("lambda_dispatch", {}) if isinstance(diagnostics, Mapping) else {}
    lambda_sites = lambda_payload.get("call_sites", []) if isinstance(lambda_payload, Mapping) else []
    if isinstance(lambda_sites, list):
        raw_sites.extend(
            ("lambda", item) for item in lambda_sites if isinstance(item, Mapping)
        )

    sites: list[dict[str, Any]] = []
    resolved_cases = 0
    unresolved_symbols = 0
    conflicts = 0
    candidate_cases = 0
    for dispatch_kind, site in raw_sites:
        symbols = site.get("symbols")
        dispatch_table = symbols.get("dispatch_table") if isinstance(symbols, Mapping) else None
        cases: list[dict[str, Any]] = []
        candidates = site.get("candidates", [])
        if not isinstance(candidates, list):
            candidates = []
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            selector = candidate.get("selector")
            if not isinstance(selector, str) or not selector.strip():
                continue
            selector = selector.strip()
            candidate_cases += 1
            resolution = resolve(selector)
            registration = _normalise_evidence(candidate.get("evidence"), "registration")
            evidence = [registration] if registration is not None else []
            for definition in resolution.definitions:
                evidence.append({
                    "kind": "constant_definition",
                    "file": definition.file,
                    "start_line": definition.line,
                    "end_line": definition.line,
                    "text": definition.text,
                    "definition_kind": definition.kind,
                    "symbol": definition.symbol,
                    "expression": definition.expression,
                })
            case: dict[str, Any] = {
                "selector": selector,
                "target_id": candidate.get("target_id", ""),
                "target_name": candidate.get("target_name", ""),
                "value": resolution.value,
                "resolution": resolution.state,
                "evidence": evidence,
            }
            cases.append(case)
            if resolution.state == "resolved":
                resolved_cases += 1
            elif resolution.state == "ambiguous_symbol":
                conflicts += 1
            else:
                unresolved_symbols += 1

        sites.append({
            "site_id": _site_id(site, dispatch_kind),
            "dispatch_kind": dispatch_kind,
            "caller_id": site.get("caller_id", ""),
            "file": site.get("file", ""),
            "line": site.get("line"),
            "expression": site.get("expression", ""),
            "reason": site.get("reason", ""),
            "dispatch_table": dispatch_table or "",
            "candidate_count": len(cases),
            "cases": cases,
        })

    status = "complete" if not errors else ("partial" if files else "failed")
    return {
        "schema_version": SCHEMA_VERSION,
        "platform": "openharmony",
        "status": status,
        "repository": str(repository) if repository is not None else "<memory>",
        "summary": {
            "sites": len(sites),
            "candidate_cases": candidate_cases,
            "resolved_cases": resolved_cases,
            "unresolved_symbols": unresolved_symbols,
            "conflicts": conflicts,
            "files_scanned": len(files),
            "definitions": sum(len(items) for items in definitions.values()),
        },
        "sites": sites,
        "errors": errors,
    }


__all__ = ["SCHEMA_VERSION", "build_dispatch_code_evidence"]
