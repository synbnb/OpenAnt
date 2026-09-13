"""Bounded source retrieval for OpenHarmony indirect-call registration sites.

The LLM recovery prompt initially contains a residual caller and indexed target
functions, but not the code that populates a dispatch table.  This module adds
that missing context without changing a native call graph: it searches only
inside the declared repository root, returns relative source paths and line
ranges, and applies explicit file/byte/character bounds.

It is deliberately a small retrieval layer rather than a C++ semantic parser.
The parser remains the authority for function IDs and candidate sets; this
module only gathers source excerpts that a later prompt builder can present to
the model.  A missing or ambiguous excerpt is reported as ``not_found`` and is
never converted into a guessed edge.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


CONTEXT_SCHEMA_VERSION = 1
DEFAULT_MAX_FILES = 512
DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_CONTEXT_CHARS = 16_000
_CONTEXT_RADIUS = 2
_SOURCE_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".inc",
        ".inl",
        ".ipp",
        ".mm",
    }
)
_REGISTRATION_MARKERS = (
    "register",
    "initialize",
    "initialise",
    "constructor",
    "emplace",
    "try_emplace",
)
_GENERIC_NAME_PARTS = frozenset(
    {
        "callback",
        "call",
        "create",
        "execute",
        "get",
        "handle",
        "init",
        "initialize",
        "instance",
        "parse",
        "process",
        "run",
        "set",
    }
)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _normalize_functions(functions: Any) -> dict[str, Mapping[str, Any]]:
    if isinstance(functions, Mapping) and isinstance(functions.get("functions"), Mapping):
        functions = functions["functions"]
    if not isinstance(functions, Mapping):
        return {}
    return {
        _text(function_id): function
        for function_id, function in functions.items()
        if _text(function_id) and isinstance(function, Mapping)
    }


def _flatten_text(value: Any) -> list[str]:
    if isinstance(value, (str, bytes)):
        text = _text(value)
        return [text] if text else []
    if isinstance(value, Mapping):
        values: list[str] = []
        for key, item in value.items():
            values.extend(_flatten_text(key))
            values.extend(_flatten_text(item))
        return values
    if isinstance(value, Iterable):
        values = []
        for item in value:
            values.extend(_flatten_text(item))
        return values
    text = _text(value)
    return [text] if text else []


def _function_name(function_id: str, function: Mapping[str, Any]) -> str:
    return _text(function.get("name")) or function_id.rsplit(":", 1)[-1]


def _name_parts(function_id: str, function: Mapping[str, Any]) -> set[str]:
    name = _function_name(function_id, function)
    parts: set[str] = set()
    for part in (name, function_id.rsplit(":", 1)[-1]):
        if len(part.strip()) >= 4 and part.strip().lower() not in _GENERIC_NAME_PARTS:
            parts.add(part.strip())
    qualified = name.replace(".", "::")
    parts.add(qualified)
    if "::" in qualified:
        split = qualified.split("::")
        leaf = split[-1]
        if leaf.lower() not in _GENERIC_NAME_PARTS:
            parts.add(leaf)
        if len(split) > 1:
            parts.add(split[-2])
    return {part.strip() for part in parts if len(part.strip()) >= 4}


def _repository_root(repository: str | Path | None) -> Path | None:
    if repository is None:
        return None
    try:
        root = Path(repository).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return root if root.is_dir() else None


def _relative_path(root: Path, value: Any) -> Path | None:
    raw = _text(value)
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
        relative = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return relative if relative.parts else None


def _is_source_file(path: Path) -> bool:
    return path.suffix.lower() in _SOURCE_EXTENSIONS


def _candidate_files(
    root: Path,
    prioritized: list[Path],
    *,
    secondary: list[Path] | None = None,
    priority_terms: Iterable[str] = (),
    max_files: int,
) -> list[tuple[Path, bool]]:
    """Return deterministic source files, keeping caller/target files first."""
    if max_files <= 0:
        return []
    selected: list[tuple[Path, bool]] = []
    seen: set[Path] = set()

    def add(path: Path, priority: bool) -> None:
        if len(selected) >= max_files or path in seen:
            return
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            return
        if not resolved.is_file() or not _is_source_file(resolved):
            return
        seen.add(resolved)
        selected.append((resolved, priority))

    for path in prioritized:
        add(path, True)

    # The scanner's default production scope skips tests/examples.  Excluding
    # those directories here prevents common names such as ``Instance`` from
    # consuming the bounded context before a production registration header is
    # reached.  Caller and candidate files are still added first even if a
    # caller explicitly points into one of these directories.
    ignored = {
        ".git",
        "build",
        "out",
        "node_modules",
        "third_party",
        "test",
        "tests",
        "unittest",
        "benchmark",
        "benchmarks",
        "example",
        "examples",
        "fuzz",
        "fuzztest",
    }
    discovered: list[Path] = []
    try:
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file() or not _is_source_file(path):
                continue
            if any(part in ignored for part in path.relative_to(root).parts):
                continue
            discovered.append(path)
    except (OSError, RuntimeError):
        discovered = []
    normalized_terms = tuple(
        term.lower().replace("::", "_").replace("-", "_")
        for term in priority_terms
        if _text(term)
    )

    def related_score(path: Path) -> int:
        stem = path.stem.lower()
        return sum(1 for term in normalized_terms if term and term in stem)

    for path in sorted(
        discovered,
        key=lambda item: (-related_score(item), item.as_posix()),
    ):
        add(path, related_score(path) > 0)
    for path in secondary or []:
        add(path, True)
    return selected


def _read_lines(path: Path, max_file_bytes: int) -> tuple[list[str], bool]:
    try:
        raw = path.read_bytes()
    except OSError:
        return [], False
    truncated = len(raw) > max_file_bytes
    if truncated:
        raw = raw[:max_file_bytes]
    return raw.decode("utf-8", errors="replace").splitlines(), truncated


def _line_terms(
    site: Mapping[str, Any],
    functions: Mapping[str, Mapping[str, Any]],
) -> list[tuple[str, str]]:
    terms: dict[str, str] = {}
    symbols = site.get("symbols")
    dispatch_values = (
        symbols.get("dispatch_table")
        if isinstance(symbols, Mapping)
        else None
    )
    for value in _flatten_text(dispatch_values):
        if len(value) >= 3:
            terms[value] = "dispatch_table"

    caller_id = _text(site.get("caller_id"))
    caller = site.get("caller")
    if not isinstance(caller, Mapping):
        caller = functions.get(caller_id, {})
    caller_name = _function_name(caller_id, caller)
    qualified_caller = caller_name.replace(".", "::")
    if "::" in qualified_caller:
        owner = qualified_caller.split("::")[-2].strip()
        if len(owner) >= 4:
            # A constructor or one-time initializer often lives in the
            # caller's header and does not mention the dispatch-table member.
            # The owner term lets us retrieve that cross-file context without
            # globally collecting every line containing "register".
            terms.setdefault(owner, "caller_symbol")

    candidate_ids = site.get("candidate_target_ids", [])
    if not isinstance(candidate_ids, list):
        candidate_ids = []
    for function_id in candidate_ids:
        function_id = _text(function_id)
        function = functions.get(function_id, {})
        for part in _name_parts(function_id, function):
            terms.setdefault(part, "candidate_name")
    return sorted(terms.items(), key=lambda item: (-len(item[0]), item[0]))


def _registration_line(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in _REGISTRATION_MARKERS)


def _merge_ranges(
    matches: list[tuple[int, set[str]]],
    line_count: int,
) -> list[tuple[int, int, set[str]]]:
    if not matches:
        return []
    expanded = [
        (
            max(1, line - _CONTEXT_RADIUS),
            min(line_count, line + _CONTEXT_RADIUS),
            set(reasons),
        )
        for line, reasons in matches
    ]
    expanded.sort(key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, set[str]]] = []
    for start, end, reasons in expanded:
        if merged and start <= merged[-1][1] + 1:
            old_start, old_end, old_reasons = merged[-1]
            merged[-1] = (old_start, max(old_end, end), old_reasons | reasons)
        else:
            merged.append((start, end, set(reasons)))
    return merged


def build_registration_context(
    site: Mapping[str, Any],
    functions: Any,
    *,
    repository: str | Path | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_context_chars: int = DEFAULT_MAX_CONTEXT_CHARS,
) -> dict[str, Any]:
    """Collect bounded source excerpts related to one residual call site.

    ``site`` is a worklist item (or an equivalent residual record).  The
    function never follows paths outside ``repository`` and never treats a
    matching text line as a resolved edge.  The result is advisory context for
    a later prompt builder.
    """
    index = _normalize_functions(functions)
    root = _repository_root(repository)
    symbols = site.get("symbols") if isinstance(site, Mapping) else {}
    dispatch_table = (
        _text(symbols.get("dispatch_table"))
        if isinstance(symbols, Mapping)
        else ""
    )
    base: dict[str, Any] = {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "status": "source_unavailable" if root is None else "not_found",
        "repository": str(root) if root is not None else "",
        "dispatch_table": dispatch_table,
        "search_terms": [],
        "files_scanned": 0,
        "matched_files": 0,
        "truncated": False,
        "snippets": [],
    }
    if root is None or not isinstance(site, Mapping):
        return base

    terms = _line_terms(site, index)
    base["search_terms"] = [term for term, _reason in terms]
    caller_file = _relative_path(root, site.get("file"))
    prioritized: list[Path] = []
    if caller_file is not None:
        prioritized.append(root / caller_file)
    secondary: list[Path] = []
    candidate_ids = site.get("candidate_target_ids", [])
    if isinstance(candidate_ids, list):
        for function_id in candidate_ids:
            function = index.get(_text(function_id))
            if not isinstance(function, Mapping):
                continue
            target_file = _relative_path(
                root,
                function.get("file_path") or function.get("filePath"),
            )
            if target_file is not None:
                secondary.append(root / target_file)
    caller_id = _text(site.get("caller_id"))
    caller = site.get("caller")
    if not isinstance(caller, Mapping):
        caller = index.get(caller_id, {})
    caller_name = _function_name(caller_id, caller)
    caller_owner = ""
    if "::" in caller_name:
        caller_owner = caller_name.replace(".", "::").split("::")[-2].strip()
    owner_path_tokens = [caller_owner]
    if caller_owner:
        # Match both CamelCase and snake_case filenames, e.g.
        # ``MinidumpStreamFactory`` → ``minidump_factory.h``.
        snake_owner = ""
        for char in caller_owner:
            if char.isupper() and snake_owner:
                snake_owner += "_"
            snake_owner += char.lower()
        owner_path_tokens.append(snake_owner)
        owner_path_tokens.extend(
            part for part in snake_owner.split("_") if len(part) >= 4
        )
    files = _candidate_files(
        root,
        prioritized,
        secondary=secondary,
        priority_terms=[*owner_path_tokens, dispatch_table],
        max_files=max(0, int(max_files)),
    )
    base["files_scanned"] = len(files)
    term_pairs = [(term, reason) for term, reason in terms if term]
    snippets: list[dict[str, Any]] = []
    matched_files = 0
    total_chars = 0
    for path, is_priority in files:
        lines, file_truncated = _read_lines(path, max(1, int(max_file_bytes)))
        if file_truncated:
            base["truncated"] = True
        matches: list[tuple[int, set[str]]] = []
        for line_number, line in enumerate(lines, start=1):
            reasons = {
                reason for term, reason in term_pairs if term in line
            }
            # A prioritized target/header file may contain the constructor or
            # registration helper call without naming a candidate on that
            # particular line (e.g. ``Factory() { RegisterDefaultCreator(); }``).
            if is_priority and _registration_line(line):
                reasons.add("registration_marker")
            if reasons:
                matches.append((line_number, reasons))
        ranges = _merge_ranges(matches, len(lines))
        if not ranges:
            continue
        matched_files += 1
        for start, end, reasons in ranges:
            text = "\n".join(lines[start - 1 : end])
            remaining = max(0, int(max_context_chars) - total_chars)
            if remaining <= 0:
                base["truncated"] = True
                break
            if len(text) > remaining:
                text = text[:remaining]
                base["truncated"] = True
            snippets.append(
                {
                    "file": path.relative_to(root).as_posix(),
                    "start_line": start,
                    "end_line": end,
                    "text": text,
                    # Keep ``text`` source-compatible for evidence matching,
                    # while giving the model an unambiguous line-numbered
                    # view for its returned evidence spans.
                    "line_numbered_text": "\n".join(
                        f"{line_number:>6} | {lines[line_number - 1]}"
                        for line_number in range(start, min(end, len(lines)) + 1)
                    ),
                    "match_reasons": sorted(reasons),
                }
            )
            total_chars += len(text)
            if total_chars >= max(0, int(max_context_chars)):
                break
        if total_chars >= max(0, int(max_context_chars)):
            break

    base["matched_files"] = matched_files
    base["snippets"] = snippets
    if snippets:
        base["status"] = "found"
    return base


__all__ = [
    "CONTEXT_SCHEMA_VERSION",
    "DEFAULT_MAX_CONTEXT_CHARS",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FILES",
    "build_registration_context",
]
