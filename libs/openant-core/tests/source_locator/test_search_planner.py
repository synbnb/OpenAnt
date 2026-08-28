"""Tests for bounded OpenGrok query-plan execution."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    LocatorQuery,
    OpenGrokClient,
    OpenGrokHTTPError,
    SearchHit,
    SearchPlanResult,
    SearchPlanner,
    SearchPlannerError,
    SearchResponse,
    normalize_target,
)


def _response(path: str = "/openharmony/base/a.c") -> SearchResponse:
    return SearchResponse(
        time_ms=1,
        result_count=1,
        start_document=0,
        end_document=0,
        results={path: (SearchHit(line="int target(void)\n", line_number="7"),)},
    )


def _query(kind: str = "definition", value: str = "target", query_id: str = "Q-0001") -> LocatorQuery:
    return LocatorQuery(query_id, kind, value, "c", "test query")


class _FakeClient:
    def __init__(self, responses=None):
        self.calls: list[dict] = []
        self.responses = list(responses or [_response()])

    def search(self, **kwargs):
        self.calls.append(kwargs)
        response = self.responses.pop(0) if self.responses else _response()
        if isinstance(response, BaseException):
            raise response
        return response


def test_execute_maps_query_kind_and_limits_to_client_arguments():
    client = _FakeClient()
    planner = SearchPlanner(client, max_results=9, max_hits_per_file=2, max_queries=4)
    result = planner.execute([_query("symbol", "OnIncomingConnect")])

    assert isinstance(result, SearchPlanResult)
    assert result.successful_queries == 1
    assert result.failed_queries == 0
    assert client.calls == [
        {
            "full": None,
            "definition": None,
            "symbol": "OnIncomingConnect",
            "path": None,
            "file_type": "c",
            "max_results": 9,
            "max_hits_per_file": 2,
        }
    ]
    assert result.unique_result_paths == ("/openharmony/base/a.c",)
    assert result.to_dict()["summary"]["unique_result_files"] == 1


def test_execute_initial_uses_normalized_plan_in_order_without_llm():
    target = normalize_target("/dev/unix/socket/paramservice")
    client = _FakeClient()
    result = SearchPlanner(client, max_results=5, max_hits_per_file=1).execute_initial(target)

    assert result.target == target
    assert len(client.calls) == len(result.executions) <= 12
    assert client.calls[0]["definition"] == "paramservice"
    assert client.calls[0]["file_type"] == "c"
    assert all(call["file_type"] in {"c", "cxx"} for call in client.calls)
    assert all("cpp" not in json.dumps(call) for call in client.calls)


def test_duplicate_query_is_recorded_and_not_sent_twice():
    client = _FakeClient()
    query = _query()
    result = SearchPlanner(client, max_queries=3).execute([query, query])

    assert [execution.status for execution in result.executions] == ["ok", "skipped_duplicate"]
    assert result.skipped_queries == 1
    assert len(client.calls) == 1


def test_typed_open_grok_failure_is_recorded_and_later_queries_continue():
    client = _FakeClient(
        [
            OpenGrokHTTPError(
                "OpenGrok search returned HTTP 401",
                status_code=401,
                endpoint="/api/v1/search",
            ),
            _response("/openharmony/base/b.c"),
        ]
    )
    result = SearchPlanner(client, max_queries=2).execute(
        [_query("definition", "first", "Q-0001"), _query("path", "b.c", "Q-0002")]
    )

    assert [execution.status for execution in result.executions] == ["error", "ok"]
    assert result.failed_queries == 1
    assert result.executions[0].error_type == "OpenGrokHTTPError"
    assert result.executions[0].status_code == 401
    assert "401" in (result.executions[0].error_message or "")
    assert result.unique_result_paths == ("/openharmony/base/b.c",)


def test_plan_rejects_empty_or_over_budget_queries():
    client = _FakeClient()
    planner = SearchPlanner(client, max_queries=1)
    with pytest.raises(SearchPlannerError, match="不能为空"):
        planner.execute([])
    with pytest.raises(SearchPlannerError, match="超过上限"):
        planner.execute([_query(), _query("symbol", "other", "Q-0002")])


def test_plan_rejects_non_search_response_instead_of_serializing_unknown_data():
    client = _FakeClient([{"resultCount": 1}])
    with pytest.raises(SearchPlannerError, match="SearchResponse"):
        SearchPlanner(client).execute([_query()])


def test_plan_replays_captured_init_param_service_search_response():
    fixture_dir = Path(__file__).parent / "fixtures" / "opengrok" / "live_1_14_11"
    payload = json.loads((fixture_dir / "search_init_param_service.json").read_text(encoding="utf-8"))
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request):
        seen.append(request)
        assert request.url.path == "/source/api/v1/search"
        if request.url.params.get("def") == "InitParamService":
            return httpx.Response(200, json=payload, request=request)
        return httpx.Response(
            200,
            json={"time": 1, "resultCount": 0, "startDocument": 0, "endDocument": -1, "results": {}},
            request=request,
        )

    query = LocatorQuery(
        "Q-0001", "definition", "InitParamService", "c", "回放真实 OpenGrok 定义搜索"
    )
    with OpenGrokClient(
        "https://opengrok-fixture.test/source",
        max_retries=0,
        retry_backoff_seconds=0,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = SearchPlanner(client, max_results=5, max_hits_per_file=2).execute([query])

    assert result.successful_queries == 1
    assert result.unique_result_paths == (
        "/openharmony/base/startup/init/services/param/liteos/param_service.c",
        "/openharmony/base/startup/init/services/param/linux/param_service.c",
    )
    assert seen[0].url.params["def"] == "InitParamService"
    assert seen[0].url.params["type"] == "c"
