"""Replay the sanitized 2026-08-28 OpenGrok 1.14.11 capability snapshot."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import OpenGrokClient  # noqa: E402


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "opengrok" / "live_1_14_11"
SNAPSHOT_PATH = FIXTURE_DIR / "capability_snapshot.json"
SEARCH_PATH = FIXTURE_DIR / "search_init_param_service.json"
RAW_PATH = FIXTURE_DIR / "raw_param_service_excerpt.c"
FAKE_BASE_URL = "https://opengrok-fixture.test/source"


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _transport(snapshot: dict, search_payload: dict, raw_excerpt: str) -> httpx.MockTransport:
    by_path = {item["path"]: item for item in snapshot["responses"].values()}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        spec = by_path[request.url.path]
        if request.url.path.endswith("/search") and request.url.params.get("def") == "InitParamService":
            return httpx.Response(
                200,
                json=search_payload,
                headers={"content-type": "application/json"},
                request=request,
            )
        body_kind = spec["body_kind"]
        headers = {"content-type": spec["content_type"]}
        if body_kind == "json":
            return httpx.Response(spec["status"], json=spec["body"], headers=headers, request=request)
        body = raw_excerpt if body_kind == "file" else spec["body"]
        return httpx.Response(spec["status"], text=body, headers=headers, request=request)

    return httpx.MockTransport(handler)


def test_live_fixture_is_small_and_contains_no_credentials():
    fixture_files = sorted(path for path in FIXTURE_DIR.iterdir() if path.is_file())
    assert {path.name for path in fixture_files} == {
        "capability_snapshot.json",
        "raw_param_service_excerpt.c",
        "search_init_param_service.json",
    }
    combined = "\n".join(path.read_text(encoding="utf-8") for path in fixture_files).lower()
    for forbidden in ("set-cookie:", "jsessionid=", "authorization:", "bearer ", "api_key"):
        assert forbidden not in combined
    assert all(path.stat().st_size < 16 * 1024 for path in fixture_files)
    assert sum(path.stat().st_size for path in fixture_files) < 24 * 1024


def test_live_fixture_replays_probe_search_and_raw_fallback():
    snapshot = _load_json(SNAPSHOT_PATH)
    search_payload = _load_json(SEARCH_PATH)
    raw_excerpt = RAW_PATH.read_text(encoding="utf-8")

    with OpenGrokClient(
        FAKE_BASE_URL,
        project=snapshot["project"],
        max_retries=0,
        retry_backoff_seconds=0,
        transport=_transport(snapshot, search_payload, raw_excerpt),
    ) as client:
        probe = client.probe(probe_path=snapshot["probe_path"])
        search = client.search(
            definition="InitParamService",
            file_type="c",
            max_results=5,
            max_hits_per_file=2,
        )
        document = client.read_source(snapshot["probe_path"])

    assert probe.reachable is True
    assert probe.version == snapshot["version"]
    assert probe.index_time == snapshot["index_time"]
    assert probe.capabilities["search"].available is True
    assert probe.capabilities["file_content"].status_code == 401
    assert probe.capabilities["file_content"].requires_auth is True
    assert probe.capabilities["raw"].available is True
    assert probe.capabilities["xref"].available is True

    assert search.result_count == 2
    assert list(search.results) == [
        "/openharmony/base/startup/init/services/param/liteos/param_service.c",
        "/openharmony/base/startup/init/services/param/linux/param_service.c",
    ]
    linux_hit = search.results["/openharmony/base/startup/init/services/param/linux/param_service.c"][0]
    assert linux_hit.line_number == "412"
    assert linux_hit.line == "int InitParamService(void)\n"
    assert linux_hit.raw_line.endswith("\r")

    assert document.source == "raw"
    assert document.truncated is False
    assert [attempt.status_code for attempt in document.attempts] == [401, 200]
    assert "info.server = PIPE_NAME" in document.content
    assert "info.incomingConnect = OnIncomingConnect" in document.content
