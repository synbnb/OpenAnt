"""Read-only OpenGrok client tests using httpx.MockTransport."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.source_locator.opengrok_client import (  # noqa: E402
    OpenGrokClient,
    OpenGrokHTTPError,
    OpenGrokTransportError,
)


def _response(request: httpx.Request, status: int, *, json=None, text=None, headers=None):
    return httpx.Response(status, json=json, text=text, headers=headers, request=request)


def test_search_builds_api_query_and_normalizes_hits():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request):
        seen.append(request)
        return _response(
            request,
            200,
            json={
                "time": 10,
                "resultCount": 1,
                "startDocument": 0,
                "endDocument": 0,
                "results": {
                    "/openharmony/base/a.c": [
                        {"line": "int <b>OnIncomingConnect</b>(void)\r", "lineNumber": "42", "tag": "function"}
                    ]
                },
            },
        )

    with OpenGrokClient(
        "https://grok.test/source/",
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        result = client.search(
            definition="OnIncomingConnect",
            file_type="c",
            max_results=5,
            max_hits_per_file=2,
        )

    assert seen[0].url.path == "/source/api/v1/search"
    assert seen[0].url.params["def"] == "OnIncomingConnect"
    assert seen[0].url.params["type"] == "c"
    assert seen[0].url.params["projects"] == "openharmony"
    hit = result.results["/openharmony/base/a.c"][0]
    assert hit.line == "int OnIncomingConnect(void)\n"
    assert hit.raw_line.endswith("\r")


def test_read_source_falls_back_to_raw_after_auth_failure_and_keeps_attempts():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path == "/source/api/v1/file/content":
            assert request.headers["authorization"] == "Bearer test-token"
            assert request.headers["accept"] == "text/plain"
            return _response(request, 401, text="unauthorized")
        assert request.url.path == "/source/raw/openharmony/base/a.c"
        return _response(request, 200, text="int main() {}\n", headers={"content-type": "text/plain"})

    with OpenGrokClient(
        "https://grok.test/source",
        token="test-token",
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        document = client.read_source("/openharmony/base/a.c")

    assert document.source == "raw"
    assert document.path == "/openharmony/base/a.c"
    assert document.content == "int main() {}\n"
    assert [attempt.status_code for attempt in document.attempts] == [401, 200]
    assert [request.url.path for request in seen] == [
        "/source/api/v1/file/content",
        "/source/raw/openharmony/base/a.c",
    ]


def test_read_source_applies_byte_limit_to_raw_fallback():
    def handler(request: httpx.Request):
        if request.url.path.endswith("/file/content"):
            return _response(request, 404, text="missing")
        return _response(request, 200, text="0123456789", headers={"content-type": "text/plain"})

    with OpenGrokClient(
        "https://grok.test/source",
        max_source_bytes=4,
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        document = client.read_source("openharmony/a.c")

    assert document.content == "0123"
    assert document.truncated is True


def test_read_source_does_not_treat_html_success_as_source():
    def handler(request: httpx.Request):
        if request.url.path.endswith("/file/content"):
            return _response(request, 200, text="<html>login</html>", headers={"content-type": "text/html"})
        return _response(request, 200, text="int safe;\n", headers={"content-type": "text/plain"})

    with OpenGrokClient(
        "https://grok.test/source",
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        document = client.read_source("/openharmony/a.c")

    assert document.source == "raw"
    assert document.content == "int safe;\n"


def test_retryable_search_status_is_retried_once():
    calls = 0

    def handler(request: httpx.Request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _response(request, 503, text="busy")
        return _response(
            request,
            200,
            json={"time": 1, "resultCount": 0, "startDocument": 0, "endDocument": -1, "results": {}},
        )

    with OpenGrokClient(
        "https://grok.test/source",
        max_retries=1,
        retry_backoff_seconds=0,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = client.search(full="needle")

    assert calls == 2
    assert result.result_count == 0


def test_probe_reports_public_and_auth_required_capabilities():
    def handler(request: httpx.Request):
        path = request.url.path
        if path == "/source/":
            return _response(
                request,
                200,
                text='<html><meta name="generator" content="OpenGrok 1.14.11 (abc)"></html>',
            )
        if path == "/source/api/v1/system/ping":
            return _response(request, 200, text="")
        if path == "/source/api/v1/system/indextime":
            return _response(request, 200, json="2026-04-09T10:21:31.737+00:00")
        if path == "/source/api/v1/suggest/config":
            return _response(request, 200, json={"enabled": True, "maxResults": 10})
        if path == "/source/api/v1/search":
            return _response(
                request,
                200,
                json={"time": 1, "resultCount": 0, "startDocument": 0, "endDocument": -1, "results": {}},
            )
        if path == "/source/api/v1/file/content":
            return _response(request, 401, text="unauthorized")
        if path == "/source/raw/openharmony/base/a.c":
            return _response(request, 200, text="x")
        if path == "/source/xref/openharmony/base/a.c":
            return _response(request, 200, text="<html>x</html>")
        raise AssertionError(f"unexpected probe path: {path}")

    with OpenGrokClient(
        "https://grok.test/source",
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        result = client.probe(probe_path="/openharmony/base/a.c")

    assert result.reachable is True
    assert result.version == "OpenGrok 1.14.11 (abc)"
    assert result.index_time == "2026-04-09T10:21:31.737+00:00"
    assert result.capabilities["search"].available is True
    assert result.capabilities["file_content"].requires_auth is True
    assert result.capabilities["raw"].available is True
    assert result.capabilities["xref"].available is True
    assert result.warnings == ()


def test_probe_without_path_marks_path_capabilities_as_unprobed_warning():
    def handler(request: httpx.Request):
        path = request.url.path
        if path == "/source/":
            return _response(request, 404, text="not found")
        if path == "/source/api/v1/system/ping":
            return _response(request, 200, text="")
        if path == "/source/api/v1/system/indextime":
            return _response(request, 200, json="2026-04-09T10:21:31.737+00:00")
        if path == "/source/api/v1/suggest/config":
            return _response(request, 200, json={})
        if path == "/source/api/v1/search":
            return _response(
                request,
                200,
                json={"time": 1, "resultCount": 0, "startDocument": 0, "endDocument": -1, "results": {}},
            )
        raise AssertionError(f"unexpected probe path: {path}")

    with OpenGrokClient(
        "https://grok.test/source",
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        result = client.probe()

    assert result.reachable is True
    assert any("未提供 probe_path" in warning for warning in result.warnings)


def test_transport_failure_surfaces_redacted_attempts():
    def handler(request: httpx.Request):
        raise httpx.ConnectError("connection failed", request=request)

    with OpenGrokClient(
        "https://grok.test/source",
        token="secret-token",
        max_retries=1,
        retry_backoff_seconds=0,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(OpenGrokTransportError) as raised:
            client.search(full="needle")

    assert len(raised.value.attempts) == 2
    assert all("secret-token" not in str(attempt) for attempt in raised.value.attempts)


def test_http_error_contains_status_without_response_body():
    def handler(request: httpx.Request):
        return _response(request, 403, text="private details should not escape")

    with OpenGrokClient(
        "https://grok.test/source",
        transport=httpx.MockTransport(handler),
        retry_backoff_seconds=0,
    ) as client:
        with pytest.raises(OpenGrokHTTPError) as raised:
            client.search(full="needle")

    assert raised.value.status_code == 403
    assert "private details" not in str(raised.value)
