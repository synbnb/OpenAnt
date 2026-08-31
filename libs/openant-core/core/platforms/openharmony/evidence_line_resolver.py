"""Deterministically reconcile LLM evidence line numbers with source files.

The recovery model is allowed to describe evidence, but it is not a reliable
source of line-number arithmetic when a prompt contains a bounded excerpt.  A
model can quote the right registration statement and still report the line of
the table header.  This module treats the quoted text as the primary signal,
searches only inside the declared repository, and annotates each evidence
item with the resolution outcome.  It never creates or removes a graph edge.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


_MAX_SOURCE_BYTES = 2_000_000
_NEARBY_LINE_RADIUS = 3
_MAX_WINDOW_LINES = 32
_RESOLVED = frozenset({"exact", "nearby_unique", "function_index"})


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _line(value: Any, default: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, parsed)


def _normalize(value: Any) -> str:
    """Collapse formatting differences while retaining source tokens."""
    return re.sub(r"\s+", " ", _text(value)).strip()


def _repository_root(repository: str | Path | None) -> Path | None:
    if repository is None:
        return None
    try:
        root = Path(repository).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return root if root.is_dir() else None


def _source_path(root: Path, file_path: Any) -> Path | None:
    raw = _text(file_path)
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def _read_source(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    if len(raw) > _MAX_SOURCE_BYTES:
        raw = raw[:_MAX_SOURCE_BYTES]
    return raw.decode("utf-8", errors="replace").splitlines()


def _line_matches(lines: Sequence[str], evidence_text: str) -> list[tuple[int, int]]:
    """Find exact/whitespace-normalized evidence spans in a source file.

    Most registration statements occupy one line.  A small bounded sliding
    window also handles a model quoting a wrapped call or initializer.  The
    minimum length check avoids treating generic snippets such as ``return``
    as source evidence.
    """
    needle = _normalize(evidence_text)
    if len(needle) < 8:
        return []
    normalized = [_normalize(line) for line in lines]
    matches: set[tuple[int, int]] = set()
    evidence_line_count = max(
        1,
        len([line for line in evidence_text.splitlines() if _text(line)]),
    )
    for index, line in enumerate(normalized, start=1):
        if not line:
            continue
        if needle == line or needle in line:
            matches.add((index, index))

    # A one-line registration/call-site quote is resolved by the direct line
    # search above.  Sliding windows would also contain that line and create
    # artificial duplicate spans such as ``(header, registration)``.
    if evidence_line_count == 1:
        return sorted(matches)

    # The quoted evidence is usually no more than a few source lines.  Keep
    # this search bounded so a large generated source file cannot turn result
    # validation into an unbounded quadratic scan.
    max_window = min(_MAX_WINDOW_LINES, max(evidence_line_count + 4, 1))
    for start in range(len(normalized)):
        if not normalized[start]:
            continue
        combined = ""
        for end in range(start, min(len(normalized), start + max_window)):
            if normalized[end]:
                combined = f"{combined} {normalized[end]}".strip()
            if not combined:
                continue
            if combined == needle or needle in combined:
                matches.add((start + 1, end + 1))
                break
    return sorted(matches)


def _nearby_unique(
    matches: Sequence[tuple[int, int]],
    reported_start: int,
    reported_end: int,
) -> tuple[int, int] | None:
    lower = max(1, reported_start - _NEARBY_LINE_RADIUS)
    upper = reported_end + _NEARBY_LINE_RADIUS
    nearby = [
        match
        for match in matches
        if match[1] >= lower and match[0] <= upper
    ]
    return nearby[0] if len(nearby) == 1 else None


def _function_index_span(
    evidence: Mapping[str, Any],
    functions: Mapping[str, Mapping[str, Any]],
    target_id: str = "",
) -> tuple[int, int] | None:
    if _text(evidence.get("kind")) != "target":
        return None
    function_id = _text(evidence.get("function_id")) or _text(target_id)
    function = functions.get(function_id)
    if not isinstance(function, Mapping):
        return None
    function_file = _text(function.get("file_path") or function.get("filePath"))
    if function_file and function_file != _text(evidence.get("file")):
        return None
    start = _line(function.get("start_line", function.get("startLine", 1)))
    end = _line(function.get("end_line", function.get("endLine", start)), start)
    return start, max(start, end)


def resolve_evidence_item(
    evidence: Mapping[str, Any],
    *,
    repository: str | Path | None,
    functions: Mapping[str, Mapping[str, Any]] | None = None,
    target_id: str = "",
    source_cache: dict[Path, list[str]] | None = None,
) -> dict[str, Any]:
    """Return one evidence item with a conservative line-resolution status.

    ``reported_start_line``/``reported_end_line`` preserve the model's raw
    values for audit.  ``start_line``/``end_line`` are changed only when one
    source span can be selected deterministically.  Ambiguous and unavailable
    evidence keeps the original span and is explicitly marked.
    """
    item = dict(evidence)
    reported_start = _line(item.get("start_line", 1))
    reported_end = _line(item.get("end_line", reported_start), reported_start)
    item["reported_start_line"] = reported_start
    item["reported_end_line"] = reported_end
    item["line_match_count"] = 0
    item["line_resolution"] = "unavailable"

    root = _repository_root(repository)
    path = _source_path(root, item.get("file")) if root is not None else None
    if path is None:
        return item
    cache = source_cache if source_cache is not None else {}
    lines = cache.setdefault(path, _read_source(path))
    if not lines:
        item["line_resolution"] = "source_unavailable"
        return item

    matches = _line_matches(lines, _text(item.get("text")))
    item["line_match_count"] = len(matches)
    chosen: tuple[int, int] | None = None
    status = "not_found"
    if len(matches) == 1:
        chosen = matches[0]
        status = "exact"
    elif len(matches) > 1:
        chosen = _nearby_unique(matches, reported_start, reported_end)
        if chosen is not None:
            status = "nearby_unique"
        else:
            status = "ambiguous"

    if chosen is None and functions:
        indexed = _function_index_span(item, functions, target_id)
        if indexed is not None and status in {"not_found", "ambiguous"}:
            chosen = indexed
            status = "function_index"

    item["line_resolution"] = status
    if chosen is not None and status in _RESOLVED:
        item["start_line"], item["end_line"] = chosen
    return item


def normalize_recovery_evidence(
    proposals: Sequence[Mapping[str, Any]],
    worklist: Sequence[Mapping[str, Any]],
    functions: Any,
    *,
    repository: str | Path | None,
) -> list[dict[str, Any]]:
    """Normalize all proposal evidence without changing proposal decisions."""
    if not isinstance(proposals, Sequence):
        return [dict(item) for item in proposals if isinstance(item, Mapping)]
    index: Mapping[str, Mapping[str, Any]]
    if isinstance(functions, Mapping) and isinstance(functions.get("functions"), Mapping):
        index = {
            _text(key): value
            for key, value in functions["functions"].items()
            if _text(key) and isinstance(value, Mapping)
        }
    elif isinstance(functions, Mapping):
        index = {
            _text(key): value
            for key, value in functions.items()
            if _text(key) and isinstance(value, Mapping)
        }
    else:
        index = {}
    sites = {
        _text(item.get("site_id")): item
        for item in worklist
        if isinstance(item, Mapping) and _text(item.get("site_id"))
    }
    cache: dict[Path, list[str]] = {}
    normalized: list[dict[str, Any]] = []
    for raw in proposals:
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        site = sites.get(_text(item.get("site_id")))
        evidence = item.get("evidence")
        if site is None or not isinstance(evidence, list):
            normalized.append(item)
            continue
        item["evidence"] = [
            resolve_evidence_item(
                entry,
                repository=repository,
                functions=index,
                target_id=_text(item.get("target_id")),
                source_cache=cache,
            )
            if isinstance(entry, Mapping)
            else entry
            for entry in evidence
        ]
        normalized.append(item)
    return normalized


def summarize_line_resolution(proposals: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Count evidence resolution statuses for telemetry and UI reporting."""
    summary: dict[str, int] = {}
    for proposal in proposals:
        evidence = proposal.get("evidence") if isinstance(proposal, Mapping) else None
        if not isinstance(evidence, list):
            continue
        for entry in evidence:
            if not isinstance(entry, Mapping):
                continue
            status = _text(entry.get("line_resolution")) or "not_checked"
            summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items()))


__all__ = [
    "normalize_recovery_evidence",
    "resolve_evidence_item",
    "summarize_line_resolution",
]
