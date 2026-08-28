"""Pure OpenGrok protocol/model tests (no network)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.source_locator.opengrok_client import (  # noqa: E402
    OpenGrokPathError,
    OpenGrokProtocolError,
    SearchHit,
    SearchResponse,
    normalize_base_url,
    normalize_search_line,
    normalize_source_path,
)


def test_base_url_keeps_context_path_and_removes_trailing_slash():
    assert normalize_base_url("https://example.test/source///") == "https://example.test/source"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "example.test/source",
        "https://example.test/source?x=1",
        "https://user:secret@example.test/source",
    ],
)
def test_base_url_rejects_unsafe_values(value):
    with pytest.raises(OpenGrokPathError):
        normalize_base_url(value)


def test_source_path_normalization_is_strict_and_slash_prefixed():
    assert normalize_source_path("/openharmony/a/b.cpp") == "/openharmony/a/b.cpp"
    assert normalize_source_path("openharmony/a/b.cpp") == "/openharmony/a/b.cpp"


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.test/a.cpp",
        "/openharmony/../secret.cpp",
        "/openharmony/a\\b.cpp",
        "/openharmony/a.cpp?download=1",
        "/openharmony/\x00a.cpp",
    ],
)
def test_source_path_rejects_url_and_traversal(value):
    with pytest.raises(OpenGrokPathError):
        normalize_source_path(value)


def test_search_line_preserves_source_text_after_markup_cleanup():
    raw = "  x-&gt;y &amp;&amp; &lt;T&gt; <b>hit</b>\r\n"
    assert normalize_search_line(raw) == "  x->y && <T> hit\n"


def test_search_hit_keeps_raw_and_clean_lines():
    hit = SearchHit.from_payload(
        {"line": "int <b>InitParamService</b>(void)\r", "lineNumber": "412", "tag": "function"}
    )
    assert hit.line == "int InitParamService(void)\n"
    assert hit.raw_line.endswith("\r")
    assert hit.line_number == "412"
    assert hit.tag == "function"


def test_search_response_parses_realistic_opengrok_shape():
    response = SearchResponse.from_payload(
        {
            "time": 10,
            "resultCount": 2,
            "startDocument": 0,
            "endDocument": 1,
            "results": {
                "/openharmony/base/startup/init/services/param/linux/param_service.c": [
                    {"line": "int <b>InitParamService</b>(void)\r", "lineNumber": "412", "tag": "function"}
                ],
                "/openharmony/base/startup/init/services/param/liteos/param_service.c": [],
            },
        }
    )
    assert response.result_count == 2
    assert response.end_document == 1
    assert response.results["/openharmony/base/startup/init/services/param/linux/param_service.c"][0].line == "int InitParamService(void)\n"
    assert response.to_dict()["results"]["/openharmony/base/startup/init/services/param/linux/param_service.c"][0]["raw_line"].endswith("\r")


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"resultCount": 1, "startDocument": 0, "endDocument": 0},
        {"time": 1, "resultCount": 1, "startDocument": 0, "endDocument": 0, "results": []},
        {"time": 1, "resultCount": 1, "startDocument": 0, "endDocument": 0, "results": {"/x": {}}},
    ],
)
def test_search_response_rejects_malformed_shapes(payload):
    with pytest.raises(OpenGrokProtocolError):
        SearchResponse.from_payload(payload)
