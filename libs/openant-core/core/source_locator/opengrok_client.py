"""Small, read-only OpenGrok protocol layer.

This module deliberately has no scan-pipeline or LLM dependency.  It defines
the data contracts used by the future source-locator worker and the pure
normalization rules needed to keep OpenGrok HTML snippets from being mistaken
for source code.  HTTP operations are added only after these contracts are
covered by tests.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from html import unescape
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


_HTML_TAG_RE = re.compile(r"<[^>]*>")


class OpenGrokError(RuntimeError):
    """Base error for source-locator OpenGrok operations."""


class OpenGrokPathError(OpenGrokError, ValueError):
    """Raised when a path cannot be safely sent to an OpenGrok endpoint."""


class OpenGrokProtocolError(OpenGrokError, ValueError):
    """Raised when an OpenGrok response does not match the expected shape."""


def normalize_base_url(base_url: str) -> str:
    """Validate and normalize an OpenGrok deployment base URL.

    The deployment context (for example ``/source``) is part of the base URL;
    only a trailing slash is removed.  Query strings, fragments and embedded
    credentials are rejected so later endpoint construction cannot silently
    change the target.
    """

    if not isinstance(base_url, str) or not base_url.strip():
        raise OpenGrokPathError("OpenGrok base URL must be a non-empty string")
    value = base_url.strip()
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise OpenGrokPathError("OpenGrok base URL must use http(s) with a host")
    if parsed.username is not None or parsed.password is not None:
        raise OpenGrokPathError("OpenGrok base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise OpenGrokPathError("OpenGrok base URL must not contain query or fragment")
    return value.rstrip("/")


def normalize_source_path(path: str) -> str:
    """Return a safe, slash-prefixed source path.

    OpenGrok paths are untrusted input.  The check is intentionally strict:
    absolute URLs, query/fragment delimiters, NULs, backslashes and traversal
    components are rejected rather than normalized into a different file.
    """

    if not isinstance(path, str) or not path.strip():
        raise OpenGrokPathError("source path must be a non-empty string")
    value = path.strip()
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise OpenGrokPathError("source path must be a path, not a URL")
    if "\x00" in value or "\\" in value:
        raise OpenGrokPathError("source path contains a forbidden character")
    parts = value.split("/")
    if any(part in {".", ".."} for part in parts):
        raise OpenGrokPathError("source path contains a traversal component")
    clean = "/".join(part for part in parts if part)
    if not clean:
        raise OpenGrokPathError("source path must contain a file or directory")
    return "/" + clean


def normalize_search_line(value: str) -> str:
    """Strip OpenGrok emphasis tags and decode entities in a hit snippet.

    Tags are removed *before* HTML entity decoding so escaped source text such
    as ``&lt;T&gt;`` remains source text rather than being interpreted as a tag.
    CRLF and bare CR are converted to LF.  The original value is retained on
    :class:`SearchHit.raw_line` for audit/evidence purposes.
    """

    if not isinstance(value, str):
        raise OpenGrokProtocolError("search hit line must be a string")
    line = value.replace("\r\n", "\n").replace("\r", "\n")
    return unescape(_HTML_TAG_RE.sub("", line))


def _required_mapping(payload: Any, *, name: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise OpenGrokProtocolError(f"{name} must be a JSON object")
    return payload


@dataclass(frozen=True)
class SearchHit:
    """One line hit from OpenGrok's ``results`` map."""

    line: str
    line_number: str = ""
    tag: str | None = None
    raw_line: str = ""

    @classmethod
    def from_payload(cls, payload: Any) -> "SearchHit":
        data = _required_mapping(payload, name="search hit")
        raw_line = data.get("line", "")
        if not isinstance(raw_line, str):
            raise OpenGrokProtocolError("search hit line must be a string")
        line_number = data.get("lineNumber", "")
        if line_number is None:
            line_number = ""
        elif not isinstance(line_number, (str, int)):
            raise OpenGrokProtocolError("search hit lineNumber must be a string or integer")
        tag = data.get("tag")
        if tag is not None and not isinstance(tag, str):
            raise OpenGrokProtocolError("search hit tag must be a string or null")
        return cls(
            line=normalize_search_line(raw_line),
            line_number=str(line_number),
            tag=tag,
            raw_line=raw_line,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SearchResponse:
    """Normalized OpenGrok REST search response."""

    time_ms: int | None
    result_count: int
    start_document: int
    end_document: int
    results: dict[str, tuple[SearchHit, ...]] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Any) -> "SearchResponse":
        data = _required_mapping(payload, name="search response")

        def integer(key: str, *, default: int | None = None) -> int | None:
            value = data.get(key, default)
            if value is None:
                return None
            if isinstance(value, bool) or not isinstance(value, int):
                raise OpenGrokProtocolError(f"search response {key} must be an integer")
            return value

        result_count = integer("resultCount")
        start_document = integer("startDocument")
        end_document = integer("endDocument")
        if result_count is None or start_document is None or end_document is None:
            raise OpenGrokProtocolError("search response is missing pagination fields")
        time_ms = integer("time")
        if "results" not in data:
            raise OpenGrokProtocolError("search response is missing results")
        raw_results = data["results"]
        if not isinstance(raw_results, Mapping):
            raise OpenGrokProtocolError("search response results must be an object")
        results: dict[str, tuple[SearchHit, ...]] = {}
        for path, raw_hits in raw_results.items():
            if not isinstance(path, str):
                raise OpenGrokProtocolError("search response result path must be a string")
            if not isinstance(raw_hits, list):
                raise OpenGrokProtocolError("search response result hits must be an array")
            results[path] = tuple(SearchHit.from_payload(hit) for hit in raw_hits)
        return cls(time_ms, result_count, start_document, end_document, results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "time": self.time_ms,
            "resultCount": self.result_count,
            "startDocument": self.start_document,
            "endDocument": self.end_document,
            "results": {
                path: [hit.to_dict() for hit in hits]
                for path, hits in self.results.items()
            },
        }


@dataclass(frozen=True)
class RequestAttempt:
    """Safe audit metadata for one upstream request attempt."""

    endpoint: str
    status_code: int | None = None
    source: str = ""
    error: str | None = None


@dataclass(frozen=True)
class SourceDocument:
    """Source text returned by a future API/raw fallback chain."""

    path: str
    content: str
    source: str
    content_type: str | None = None
    status_code: int = 200
    truncated: bool = False
    attempts: tuple[RequestAttempt, ...] = ()


@dataclass(frozen=True)
class EndpointCapability:
    """Result of probing one endpoint without exposing response bodies."""

    name: str
    available: bool
    status_code: int | None = None
    requires_auth: bool = False
    detail: str | None = None


@dataclass(frozen=True)
class ProbeResult:
    """Capability snapshot for one OpenGrok deployment."""

    base_url: str
    api_prefix: str
    reachable: bool
    version: str | None = None
    index_time: str | None = None
    capabilities: dict[str, EndpointCapability] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "api_prefix": self.api_prefix,
            "reachable": self.reachable,
            "version": self.version,
            "index_time": self.index_time,
            "capabilities": {
                name: asdict(capability)
                for name, capability in self.capabilities.items()
            },
            "warnings": list(self.warnings),
        }
