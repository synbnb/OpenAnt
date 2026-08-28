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
import json
import re
import time
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

import httpx


_HTML_TAG_RE = re.compile(r"<[^>]*>")


class OpenGrokError(RuntimeError):
    """Base error for source-locator OpenGrok operations."""


class OpenGrokPathError(OpenGrokError, ValueError):
    """Raised when a path cannot be safely sent to an OpenGrok endpoint."""


class OpenGrokProtocolError(OpenGrokError, ValueError):
    """Raised when an OpenGrok response does not match the expected shape."""


class OpenGrokHTTPError(OpenGrokError):
    """Raised when a read-only OpenGrok request ends unsuccessfully."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
        attempts: tuple["RequestAttempt", ...] = (),
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.endpoint = endpoint
        self.attempts = attempts


class OpenGrokTransportError(OpenGrokHTTPError):
    """Raised when the upstream cannot be reached after retrying."""


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


@dataclass(frozen=True)
class _HTTPResult:
    """Internal response plus redacted attempt metadata."""

    response: httpx.Response | None
    attempts: tuple[RequestAttempt, ...]
    transport_error: str | None = None


_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_API_AUTH_OR_MISSING_STATUS = frozenset({401, 403, 404, 406, 410})


def _normalize_api_prefix(api_prefix: str) -> str:
    if not isinstance(api_prefix, str) or not api_prefix.strip():
        raise OpenGrokPathError("OpenGrok API prefix must be a non-empty path")
    value = api_prefix.strip()
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise OpenGrokPathError("OpenGrok API prefix must be a path")
    if "\x00" in value or "\\" in value:
        raise OpenGrokPathError("OpenGrok API prefix contains a forbidden character")
    parts = value.split("/")
    if any(part in {".", ".."} for part in parts):
        raise OpenGrokPathError("OpenGrok API prefix contains a traversal component")
    clean = "/".join(part for part in parts if part)
    if not clean:
        raise OpenGrokPathError("OpenGrok API prefix must contain a path")
    return "/" + clean


def _validate_positive_int(value: int, *, name: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def _validate_non_negative_int(value: int, *, name: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def _clean_error(value: str) -> str:
    return " ".join(str(value).split())[:240]


def _is_source_content_type(value: str | None) -> bool:
    """Accept text/binary source responses, never an HTML error document."""

    if not value:
        return True
    media_type = value.split(";", 1)[0].strip().lower()
    if media_type in {"text/html", "application/xhtml+xml"}:
        return False
    return media_type.startswith("text/") or media_type == "application/octet-stream"


class OpenGrokClient:
    """Read-only client for OpenGrok REST plus the plain-text ``/raw`` route.

    The client intentionally exposes only GET operations.  ``/raw`` is used as
    a capability-detected fallback because some deployments protect
    ``/api/v1/file/content`` while leaving the web raw route readable.
    """

    def __init__(
        self,
        base_url: str,
        *,
        project: str = "openharmony",
        api_prefix: str = "/api/v1",
        token: str | None = None,
        timeout_seconds: float = 15.0,
        max_retries: int = 1,
        retry_backoff_seconds: float = 0.2,
        max_source_bytes: int = 32 * 1024,
        verify: bool | str = True,
        trust_env: bool = True,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        if not isinstance(project, str) or not project.strip():
            raise ValueError("OpenGrok project must be a non-empty string")
        if any(char in project for char in "\r\n\x00"):
            raise ValueError("OpenGrok project contains a forbidden character")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= 3:
            raise ValueError("max_retries must be an integer between 0 and 3")
        if retry_backoff_seconds < 0:
            raise ValueError("retry_backoff_seconds must be non-negative")
        self.project = project.strip()
        self.api_prefix = _normalize_api_prefix(api_prefix)
        self.timeout_seconds = float(timeout_seconds)
        self.max_retries = max_retries
        self.retry_backoff_seconds = float(retry_backoff_seconds)
        self.max_source_bytes = _validate_positive_int(
            max_source_bytes, name="max_source_bytes", maximum=16 * 1024 * 1024
        )
        self.token = token.strip() if isinstance(token, str) and token.strip() else None
        headers = {"Accept": "application/json", "User-Agent": "OpenAnt-SourceLocator/0.1"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if client is None:
            self._http = httpx.Client(
                timeout=self.timeout_seconds,
                verify=verify,
                trust_env=trust_env,
                headers=headers,
                transport=transport,
            )
            self._owns_client = True
        else:
            self._http = client
            self._http.headers.update(headers)
            self._owns_client = False

    def __enter__(self) -> "OpenGrokClient":
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def _url(self, endpoint: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            raise OpenGrokPathError("absolute endpoint URLs are not accepted")
        suffix = endpoint if endpoint.startswith("/") else "/" + endpoint
        return self.base_url + suffix

    def _api_endpoint(self, resource: str) -> str:
        if not isinstance(resource, str) or not resource.strip():
            raise ValueError("OpenGrok API resource must be a non-empty path")
        value = resource.strip("/")
        parts = value.split("/")
        if any(not part or part in {".", ".."} or "\\" in part or "\x00" in part for part in parts):
            raise OpenGrokPathError("OpenGrok API resource contains an unsafe component")
        return f"{self.api_prefix}/{value}"

    def _get(
        self,
        endpoint: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        source: str,
    ) -> _HTTPResult:
        """Perform a GET with bounded retries and redacted audit metadata."""

        if not endpoint.startswith("/"):
            raise OpenGrokPathError("endpoint must start with '/'")
        attempts: list[RequestAttempt] = []
        last_error: str | None = None
        for attempt_index in range(self.max_retries + 1):
            try:
                response = self._http.get(self._url(endpoint), params=params, headers=headers)
            except httpx.RequestError as exc:
                last_error = _clean_error(exc)
                attempts.append(RequestAttempt(endpoint=endpoint, source=source, error=last_error))
                if attempt_index < self.max_retries:
                    if self.retry_backoff_seconds:
                        time.sleep(self.retry_backoff_seconds)
                    continue
                return _HTTPResult(None, tuple(attempts), last_error)

            attempts.append(RequestAttempt(endpoint=endpoint, status_code=response.status_code, source=source))
            if response.status_code in _RETRYABLE_STATUS and attempt_index < self.max_retries:
                if self.retry_backoff_seconds:
                    time.sleep(self.retry_backoff_seconds)
                continue
            return _HTTPResult(response, tuple(attempts))
        return _HTTPResult(None, tuple(attempts), last_error or "request failed")

    @staticmethod
    def _json(response: httpx.Response, *, endpoint: str) -> Any:
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise OpenGrokProtocolError(f"invalid JSON from {endpoint}") from exc

    @staticmethod
    def _capability(name: str, result: _HTTPResult) -> EndpointCapability:
        if result.response is None:
            return EndpointCapability(
                name=name,
                available=False,
                detail=result.transport_error or "transport error",
            )
        status = result.response.status_code
        return EndpointCapability(
            name=name,
            available=200 <= status < 300,
            status_code=status,
            requires_auth=status in {401, 403},
            detail=None if 200 <= status < 300 else f"HTTP {status}",
        )

    def search(
        self,
        *,
        full: str | None = None,
        definition: str | None = None,
        symbol: str | None = None,
        path: str | None = None,
        history: str | None = None,
        file_type: str | None = None,
        projects: str | list[str] | tuple[str, ...] | None = None,
        max_results: int = 50,
        start: int = 0,
        max_hits_per_file: int = 3,
        sort: str = "relevancy",
    ) -> SearchResponse:
        """Search indexed source and return normalized hits.

        ``definition`` maps to the REST parameter ``def``; ``file_type`` maps
        to ``type``.  At least one query field is required to avoid accidentally
        downloading an unbounded index listing.
        """

        values = {
            "full": full,
            "def": definition,
            "symbol": symbol,
            "path": path,
            "hist": history,
        }
        provided = 0
        params: dict[str, Any] = {}
        for key, value in values.items():
            if value is None:
                continue
            if not isinstance(value, str):
                raise ValueError(f"{key} query must be a string")
            if value:
                params[key] = value
                provided += 1
        if file_type is not None:
            if not isinstance(file_type, str) or not file_type.strip():
                raise ValueError("file_type must be a non-empty string")
            params["type"] = file_type.strip()
        if provided == 0:
            raise ValueError("at least one OpenGrok search field is required")
        _validate_positive_int(max_results, name="max_results", maximum=1000)
        _validate_non_negative_int(start, name="start", maximum=10_000_000)
        _validate_non_negative_int(max_hits_per_file, name="max_hits_per_file", maximum=1000)
        if sort not in {"relevancy", "fullpath", "lastmodtime"}:
            raise ValueError("sort must be relevancy, fullpath or lastmodtime")
        if projects is None:
            project_value = self.project
        elif isinstance(projects, str):
            project_value = projects.strip()
        elif isinstance(projects, (list, tuple)):
            project_value = ",".join(str(item).strip() for item in projects if str(item).strip())
        else:
            raise ValueError("projects must be a string or a list of strings")
        if not project_value:
            raise ValueError("projects must not be empty")
        params.update(
            {
                "projects": project_value,
                "maxresults": max_results,
                "start": start,
                "maxhitsperfile": max_hits_per_file,
                "sort": sort,
            }
        )
        endpoint = self._api_endpoint("search")
        result = self._get(endpoint, params=params, source="search")
        if result.response is None:
            raise OpenGrokTransportError(
                f"OpenGrok search transport failed: {result.transport_error or 'unknown error'}",
                endpoint=endpoint,
                attempts=result.attempts,
            )
        if result.response.status_code != 200:
            raise OpenGrokHTTPError(
                f"OpenGrok search returned HTTP {result.response.status_code}",
                status_code=result.response.status_code,
                endpoint=endpoint,
                attempts=result.attempts,
            )
        return SearchResponse.from_payload(self._json(result.response, endpoint=endpoint))

    def _path_endpoint(self, route: str, path: str) -> str:
        normalized = normalize_source_path(path)
        encoded = quote(normalized.lstrip("/"), safe="/")
        return f"/{route.strip('/')}/{encoded}"

    def _document_from_result(
        self,
        *,
        result: _HTTPResult,
        source: str,
        path: str,
        max_bytes: int,
        attempts: tuple[RequestAttempt, ...] = (),
    ) -> SourceDocument | None:
        all_attempts = attempts + result.attempts
        if result.response is None or not 200 <= result.response.status_code < 300:
            return None
        if not _is_source_content_type(result.response.headers.get("content-type")):
            return None
        raw = result.response.content
        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]
        content = raw.decode("utf-8", errors="replace")
        return SourceDocument(
            path=path,
            content=content,
            source=source,
            content_type=result.response.headers.get("content-type"),
            status_code=result.response.status_code,
            truncated=truncated,
            attempts=all_attempts,
        )

    def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
        """Read source through REST file content, then the plain-text raw route."""

        normalized = normalize_source_path(path)
        limit = self.max_source_bytes if max_bytes is None else _validate_positive_int(
            max_bytes, name="max_bytes", maximum=16 * 1024 * 1024
        )
        attempts: tuple[RequestAttempt, ...] = ()
        api_endpoint = self._api_endpoint("file/content")
        api_result = self._get(
            api_endpoint,
            params={"path": normalized},
            headers={"Accept": "text/plain"},
            source="api_file_content",
        )
        attempts += api_result.attempts
        if (
            api_result.response is not None
            and 200 <= api_result.response.status_code < 300
            and _is_source_content_type(api_result.response.headers.get("content-type"))
        ):
            raw = api_result.response.content
            truncated = len(raw) > limit
            if truncated:
                raw = raw[:limit]
            return SourceDocument(
                path=normalized,
                content=raw.decode("utf-8", errors="replace"),
                source="api_file_content",
                content_type=api_result.response.headers.get("content-type"),
                status_code=api_result.response.status_code,
                truncated=truncated,
                attempts=attempts,
            )

        raw_endpoint = self._path_endpoint("raw", normalized)
        raw_result = self._get(raw_endpoint, source="raw")
        raw_document = self._document_from_result(
            result=raw_result,
            source="raw",
            path=normalized,
            max_bytes=limit,
            attempts=attempts,
        )
        if raw_document is not None:
            return raw_document

        status = None
        if api_result.response is not None:
            status = api_result.response.status_code
        if raw_result.response is not None:
            status = raw_result.response.status_code
        attempts += raw_result.attempts
        if api_result.response is None and api_result.transport_error:
            detail = api_result.transport_error
        elif status is not None:
            detail = f"HTTP {status}"
        else:
            detail = "unknown upstream error"
        raise OpenGrokHTTPError(
            f"cannot read OpenGrok source {normalized}: {detail}",
            status_code=status,
            endpoint=raw_endpoint,
            attempts=attempts,
        )

    def probe(self, *, probe_path: str | None = None) -> ProbeResult:
        """Probe public read-only capabilities and optionally a known source path."""

        capabilities: dict[str, EndpointCapability] = {}
        warnings: list[str] = []

        root_result = self._get("/", source="root")
        version: str | None = None
        if root_result.response is not None and 200 <= root_result.response.status_code < 300:
            version = self._extract_version(root_result.response.text)
        elif root_result.response is None:
            warnings.append("OpenGrok 根页面连接失败")

        ping_endpoint = self._api_endpoint("system/ping")
        ping_result = self._get(ping_endpoint, source="ping")
        capabilities["ping"] = self._capability("ping", ping_result)

        index_endpoint = self._api_endpoint("system/indextime")
        index_result = self._get(index_endpoint, source="indextime")
        capabilities["indextime"] = self._capability("indextime", index_result)
        index_time: str | None = None
        if index_result.response is not None and index_result.response.status_code == 200:
            try:
                value = self._json(index_result.response, endpoint=index_endpoint)
            except OpenGrokProtocolError as exc:
                warnings.append(_clean_error(exc))
            else:
                if isinstance(value, str):
                    index_time = value
                else:
                    warnings.append("OpenGrok indextime 返回的不是字符串")

        suggest_endpoint = self._api_endpoint("suggest/config")
        suggest_result = self._get(suggest_endpoint, source="suggest_config")
        capabilities["suggest_config"] = self._capability("suggest_config", suggest_result)

        search_endpoint = self._api_endpoint("search")
        search_result = self._get(
            search_endpoint,
            params={"full": "__openant_probe__", "projects": self.project, "maxresults": 1, "maxhitsperfile": 1},
            source="search_probe",
        )
        capabilities["search"] = self._capability("search", search_result)
        if search_result.response is not None and search_result.response.status_code == 200:
            try:
                SearchResponse.from_payload(self._json(search_result.response, endpoint=search_endpoint))
            except OpenGrokProtocolError as exc:
                capabilities["search"] = EndpointCapability(
                    name="search",
                    available=False,
                    status_code=200,
                    detail=_clean_error(exc),
                )

        if probe_path is not None:
            normalized = normalize_source_path(probe_path)
            file_endpoint = self._api_endpoint("file/content")
            file_result = self._get(
                file_endpoint,
                params={"path": normalized},
                headers={"Accept": "text/plain"},
                source="file_content_probe",
            )
            capabilities["file_content"] = self._capability("file_content", file_result)
            raw_endpoint = self._path_endpoint("raw", normalized)
            raw_result = self._get(raw_endpoint, source="raw_probe")
            capabilities["raw"] = self._capability("raw", raw_result)
            xref_endpoint = self._path_endpoint("xref", normalized)
            xref_result = self._get(xref_endpoint, source="xref_probe")
            capabilities["xref"] = self._capability("xref", xref_result)
        else:
            warnings.append("未提供 probe_path，file_content/raw/xref 未进行路径级探测")

        reachable = any(cap.available for cap in capabilities.values())
        if not index_time:
            warnings.append("未能读取 OpenGrok 索引时间")
        return ProbeResult(
            base_url=self.base_url,
            api_prefix=self.api_prefix,
            reachable=reachable,
            version=version,
            index_time=index_time,
            capabilities=capabilities,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _extract_version(html_text: str) -> str | None:
        for tag in re.findall(r"<meta\b[^>]*>", html_text, flags=re.IGNORECASE):
            if not re.search(r"\bname\s*=\s*['\"]generator['\"]", tag, flags=re.IGNORECASE):
                continue
            match = re.search(r"\bcontent\s*=\s*['\"]([^'\"]+)", tag, flags=re.IGNORECASE)
            if match:
                return match.group(1).strip().lstrip("{").strip()
        return None
